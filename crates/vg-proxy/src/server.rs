use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::error::ProxyError;
use crate::route::{classify, RouteVerdict};

/// Binds the M1 loopback listener. Refuses non-loopback addresses (doubt-pass finding,
/// independently raised by two reviewers): the module docs assert "plain HTTP on loopback,"
/// but nothing previously enforced it — a misconfigured caller passing `0.0.0.0` would have
/// exposed the deny-by-default classifier off-host with no error. Enforced here instead of
/// left to caller discipline.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    if !addr.ip().is_loopback() {
        return Err(ProxyError::NotLoopback { addr });
    }
    TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })
}

/// Runs the M1 transport + routing skeleton (plan §10.3, milestone 1): a plain-HTTP loopback
/// server with no TLS layer and no upstream client at all. Every accepted connection is
/// classified by [`crate::route::classify`]; matched routes (`Mask`/`Pass`) get a test-double
/// response, never a forwarded one — egress is impossible by construction in this milestone,
/// not merely policy-denied. Unmatched routes are rejected. Runs until `shutdown` resolves.
pub async fn run(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ProxyError> {
    let listener = bind(addr).await?;
    run_with_listener(listener, shutdown).await
}

/// Serves an already-bound `listener` until `shutdown` resolves. Split out from [`run`] so
/// tests can bind an OS-assigned port (`127.0.0.1:0`) and read the real port back via
/// `TcpListener::local_addr` before connecting — closing the doubt-pass finding that the only
/// test coverage exercised `route::classify` directly and never the real
/// `handle`/`path_and_query` extraction path.
///
/// **Re-checks loopback itself (round-2 doubt-pass finding), not just trusting the caller.**
/// This function is `pub` — round 1 made it so for testability — which means [`bind`]'s
/// loopback check is not actually load-bearing for every caller: anyone who binds their own
/// `TcpListener` (to `0.0.0.0`, say) and calls this directly bypasses it entirely, silently
/// reopening the exact gap round 1's `bind()` fix was written to close. Checking again here,
/// against whatever `listener` actually turns out to be bound to, makes the invariant hold
/// regardless of entry point instead of only for callers that happen to go through `bind()`
/// first — this is the guarantee M2's `daemon.rs` (the next real caller) actually needs.
///
/// Note on shutdown semantics (accepted M1 trade-off, doubt-pass finding): returning `Ok(())`
/// does not wait for already-spawned per-connection tasks to finish — they are detached and
/// may keep serving briefly after this function returns. Full graceful drain belongs to M2's
/// `daemon.rs`, which owns the server's lifecycle; M1 only owns accept-and-classify.
pub async fn run_with_listener(
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ProxyError> {
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        return Err(ProxyError::NotLoopback { addr: local_addr });
    }

    tokio::pin!(shutdown);
    // Round-2 doubt-pass finding: accept()-time errors (fd exhaustion, a burst of peers that
    // connect-then-RST before the handshake completes) can recur immediately and repeatedly —
    // the listening socket keeps reporting readable each time. A bare `continue` with no yield
    // point busy-spins under exactly those conditions, competing for scheduler time instead of
    // giving other connections a chance to close and free descriptors (the same failure mode
    // Go's `net/http.Server.Serve` backs off for). Capped exponential backoff, reset on the
    // next successful accept.
    let mut accept_error_backoff: Option<Duration> = None;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(pair) => {
                        accept_error_backoff = None;
                        pair
                    }
                    Err(err) => {
                        let backoff = accept_error_backoff
                            .map(|prev| (prev * 2).min(Duration::from_secs(1)))
                            .unwrap_or(Duration::from_millis(5));
                        eprintln!("vg-proxy: accept() error, retrying in {backoff:?}: {err}");
                        // Round-3 doubt-pass finding: once `select!` commits to this branch,
                        // `shutdown` isn't polled again until the branch finishes — a bare
                        // `sleep(backoff).await` would delay shutdown observation by up to the
                        // backoff (capped at 1s) per iteration, repeatedly, during exactly the
                        // sustained accept-error storm the backoff exists to survive. Racing
                        // the sleep against `shutdown` too keeps "runs until shutdown resolves"
                        // true even mid-backoff.
                        tokio::select! {
                            _ = &mut shutdown => return Ok(()),
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        accept_error_backoff = Some(backoff);
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(handle))
                        .await
                    {
                        eprintln!("vg-proxy: connection error: {err}");
                    }
                });
            }
        }
    }
}

/// Doubt-pass design invariants (both reviewed, neither changes M1's behavior, both are load-
/// bearing for later milestones and are recorded here rather than left implicit):
/// - **The request body is never read**, for any verdict. A `GET` carrying a body (legal, if
///   unusual, per HTTP) is not a leak risk in M1 because nothing downstream of `classify` ever
///   looks at the body — this stops being free the moment a future milestone forwards `Pass`
///   routes unchanged; that milestone must not assume `Pass` routes are always bodyless.
/// - **Only `path_and_query()` reaches `classify` — the URI's scheme/authority, if present
///   (an absolute-form request-target, e.g. `POST http://attacker.example/v1/messages`), is
///   silently discarded before matching.** This is safe only because the plan's own design
///   (§8.1) never derives the forwarding upstream from the client's request-target — the real
///   upstream URL is proxy-config-owned. If a future milestone ever changes that, this
///   extraction point is where a confused-deputy check would need to live.
async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    Ok(test_double_response(
        classify(&method, &target),
        &method,
        &target,
    ))
}

/// Reflected request-targets in test-double bodies are capped so an arbitrarily long
/// request-target can't grow a response body unbounded (doubt-pass finding).
const MAX_ECHOED_TARGET_LEN: usize = 2048;

fn truncate_for_echo(target: &str) -> &str {
    match target.char_indices().nth(MAX_ECHOED_TARGET_LEN) {
        Some((byte_idx, _)) => &target[..byte_idx],
        None => target,
    }
}

/// M1's stand-in for "forward to the real upstream" — there is no upstream client in this
/// milestone, so a matched route is echoed back to the caller instead, never dispatched
/// anywhere. `Block` fails closed with 403, matching the plan's fail-closed rule (§5 step 2:
/// "any other route BLOCKS; it is never passed through").
fn test_double_response(
    verdict: RouteVerdict,
    method: &Method,
    target: &str,
) -> Response<Full<Bytes>> {
    let target = truncate_for_echo(target);
    match verdict {
        RouteVerdict::Mask | RouteVerdict::Pass => Response::builder()
            .status(StatusCode::OK)
            .header("x-vg-proxy-verdict", verdict_name(verdict))
            .body(Full::new(Bytes::from(format!(
                "vg-proxy M1 test double: {method} {target} matched ({}) \
                 — not forwarded, no upstream client exists yet\n",
                verdict_name(verdict)
            ))))
            .expect("static response is well-formed"),
        RouteVerdict::Block => Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("x-vg-proxy-verdict", "block")
            .body(Full::new(Bytes::from(format!(
                "vg-proxy: {method} {target} is not a recognized route — fail closed\n"
            ))))
            .expect("static response is well-formed"),
    }
}

fn verdict_name(verdict: RouteVerdict) -> &'static str {
    match verdict {
        RouteVerdict::Mask => "mask",
        RouteVerdict::Pass => "pass",
        RouteVerdict::Block => "block",
    }
}
