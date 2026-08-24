use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::daemon::Daemon;
use crate::error::ProxyError;
use crate::mask_request::MaskRequestError;
use crate::route::{classify, RouteVerdict};
use crate::session::NAMESPACE_HEADER;
use crate::upstream::{self, UpstreamConfig};

/// Binds the loopback listener. Refuses non-loopback addresses (doubt-pass finding,
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

/// Runs the proxy (plan §10.3, milestone M3): a plain-HTTP loopback server that classifies
/// every request, masks the body for `Mask` routes through `daemon` (M3, real
/// `vg_core::mask` calls), forwards `Mask`/`Pass` routes to `upstream` (M3, real HTTP
/// forwarding — no demasking of the response, that's M4), and fails closed with 403 for
/// anything unmatched. Runs until `shutdown` resolves.
pub async fn run(
    addr: SocketAddr,
    daemon: Arc<Daemon>,
    upstream: UpstreamConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ProxyError> {
    let listener = bind(addr).await?;
    run_with_listener(listener, daemon, upstream, shutdown).await
}

/// Serves an already-bound `listener` until `shutdown` resolves. Split out from [`run`] so
/// tests can bind an OS-assigned port (`127.0.0.1:0`) and read the real port back via
/// `TcpListener::local_addr` before connecting.
///
/// **Re-checks loopback itself** (not just trusting the caller): this function is `pub` —
/// testability — which means [`bind`]'s loopback check is not actually load-bearing for every
/// caller: anyone who binds their own `TcpListener` (to `0.0.0.0`, say) and calls this directly
/// bypasses it entirely. Checking again here, against whatever `listener` actually turns out
/// to be bound to, makes the invariant hold regardless of entry point.
///
/// Note on shutdown semantics (accepted M1 trade-off): returning `Ok(())` does not wait for
/// already-spawned per-connection tasks to finish — they are detached and may keep serving
/// briefly after this function returns. Full graceful drain is a later concern.
pub async fn run_with_listener(
    listener: TcpListener,
    daemon: Arc<Daemon>,
    upstream: UpstreamConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ProxyError> {
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        return Err(ProxyError::NotLoopback { addr: local_addr });
    }

    tokio::pin!(shutdown);
    // accept()-time errors (fd exhaustion, a burst of peers that connect-then-RST before the
    // handshake completes) can recur immediately and repeatedly — the listening socket keeps
    // reporting readable each time. A bare `continue` with no yield point busy-spins under
    // exactly those conditions. Capped exponential backoff, reset on the next successful accept.
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
                        // Once `select!` commits to this branch, `shutdown` isn't polled again
                        // until the branch finishes — racing the sleep against `shutdown` too
                        // keeps "runs until shutdown resolves" true even mid-backoff.
                        tokio::select! {
                            _ = &mut shutdown => return Ok(()),
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        accept_error_backoff = Some(backoff);
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        handle(req, Arc::clone(&daemon), upstream, local_addr)
                    });
                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        eprintln!("vg-proxy: connection error: {err}");
                    }
                });
            }
        }
    }
}

/// One request, dispatched by [`RouteVerdict`]. `local_addr` is this connection's own bound
/// address, passed through to [`Daemon::mask_request`]'s H2 port-fallback namespace resolution
/// (unused when the caller sends the `X-VG-Namespace` header, which every real M3 test does —
/// the fallback path degrades to "one shared namespace per shared listener" until a future
/// milestone builds per-session listeners; not a new gap, M2's own shim already documents this).
async fn handle(
    req: Request<Incoming>,
    daemon: Arc<Daemon>,
    upstream: UpstreamConfig,
    local_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    match classify(&method, &target) {
        RouteVerdict::Block => Ok(block_response(&method, &target)),
        RouteVerdict::Mask => {
            Ok(handle_mask(req, &method, &target, &daemon, upstream, local_addr).await)
        }
        RouteVerdict::Pass => Ok(handle_pass(req, &method, &target, upstream).await),
    }
}

/// `Mask`: read the body, mask it through `daemon` (real `vg_core::mask` calls), forward the
/// masked body to `upstream`. A masking failure (malformed JSON, an unrecognized/blocked
/// content-block type, ...) fails closed — 400, never forwarded — matching this crate's
/// existing "anything this proxy can't safely handle never reaches the network" discipline.
async fn handle_mask(
    req: Request<Incoming>,
    method: &Method,
    target: &str,
    daemon: &Daemon,
    upstream: UpstreamConfig,
    local_addr: SocketAddr,
) -> Response<Full<Bytes>> {
    let namespace_header = match header_str(req.headers(), NAMESPACE_HEADER) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let headers = req.headers().clone();
    let body = match collect_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };

    let (masked_body, stats) =
        match daemon.mask_request(&body, namespace_header.as_deref(), local_addr) {
            Ok(result) => result,
            Err(ProxyError::MaskRequest(err)) => return mask_blocked_response(&err),
            Err(err) => return internal_error_response(&err),
        };

    match upstream::forward(upstream, method.clone(), target, &headers, masked_body).await {
        Ok(mut resp) => {
            resp.headers_mut()
                .insert("x-vg-proxy-verdict", HeaderValue::from_static("mask"));
            let entities = total_masked_entities(&stats);
            if let Ok(value) = HeaderValue::from_str(&entities.to_string()) {
                resp.headers_mut()
                    .insert("x-vg-proxy-masked-entities", value);
            }
            resp
        }
        Err(err) => upstream_error_response(&err),
    }
}

/// `Pass`: forward the body **unmasked** — a direct consequence of `upstream.rs` existing at
/// all now, not extra scope (leaving `Pass` on the old M1 test-double while `Mask` forwards for
/// real would be a confusing half-real/half-fake state). `Pass` routes are non-context-carrying
/// probes/metadata by the route table's own definition (`route.rs`), so nothing here needs
/// masking.
async fn handle_pass(
    req: Request<Incoming>,
    method: &Method,
    target: &str,
    upstream: UpstreamConfig,
) -> Response<Full<Bytes>> {
    let headers = req.headers().clone();
    let body = match collect_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };

    match upstream::forward(upstream, method.clone(), target, &headers, body).await {
        Ok(mut resp) => {
            resp.headers_mut()
                .insert("x-vg-proxy-verdict", HeaderValue::from_static("pass"));
            resp
        }
        Err(err) => upstream_error_response(&err),
    }
}

/// Round-2 doubt-pass finding (Codex): a header PRESENT but not valid UTF-8 must never
/// collapse to "absent." `session.rs`'s own module doc named this exact trap in advance, for
/// "whichever milestone adds header-extraction code" — this milestone is that one, and an
/// earlier version of this function fell into it (`.to_str().ok()`, silently mapping a garbled
/// `X-VG-Namespace` header to `None`, which would have fallen through to the port-fallback
/// resolution path instead of failing closed). `Ok(None)` only for a genuinely absent header;
/// a present-but-invalid one is `Err`, a 400, before `Daemon::mask_request` is ever called.
fn header_str(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, Box<Response<Full<Bytes>>>> {
    match headers.get(name) {
        None => Ok(None),
        Some(value) => match value.to_str() {
            Ok(s) => Ok(Some(s.to_string())),
            Err(_) => Err(Box::new(invalid_header_response(name))),
        },
    }
}

fn invalid_header_response(name: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("x-vg-proxy-verdict", "block")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: {name} header is present but not valid UTF-8 — fail closed\n"
        ))))
        .expect("static response is well-formed")
}

/// Reads the full request body. `MAX_ECHOED_TARGET_LEN`-style bounding doesn't apply here (the
/// body isn't echoed anywhere) — a malformed/oversized body still fails closed downstream, in
/// `mask_request`'s own JSON-parse step or the upstream's own request-size limits.
async fn collect_body(req: Request<Incoming>) -> Result<Vec<u8>, Response<Full<Bytes>>> {
    req.into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .map_err(|err| {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("x-vg-proxy-verdict", "block")
                .body(Full::new(Bytes::from(format!(
                    "vg-proxy: failed to read request body: {err}\n"
                ))))
                .expect("static response is well-formed")
        })
}

fn total_masked_entities(stats: &vg_core::MaskStats) -> usize {
    stats.counts.0.values().sum()
}

/// Reflected request-targets in response bodies are capped so an arbitrarily long
/// request-target can't grow a response body unbounded.
const MAX_ECHOED_TARGET_LEN: usize = 2048;

fn truncate_for_echo(target: &str) -> &str {
    match target.char_indices().nth(MAX_ECHOED_TARGET_LEN) {
        Some((byte_idx, _)) => &target[..byte_idx],
        None => target,
    }
}

/// `Block` fails closed with 403, matching the plan's fail-closed rule (§5 step 2: "any other
/// route BLOCKS; it is never passed through"). Unchanged from M1/M2 — no body read, no
/// forwarding, no upstream contact.
fn block_response(method: &Method, target: &str) -> Response<Full<Bytes>> {
    let target = truncate_for_echo(target);
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("x-vg-proxy-verdict", "block")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: {method} {target} is not a recognized route — fail closed\n"
        ))))
        .expect("static response is well-formed")
}

/// A `Mask` route's body failed to mask safely (malformed JSON, an unrecognized/blocked
/// content-block type, a malformed `system`/`messages` shape). Fails closed — 400, never
/// forwarded. This is a local, loopback-only proxy talking to its own wrapped client, not a
/// public-facing service, so echoing the specific reason (matching this crate's existing
/// `block_response` transparency) is more useful than withholding it.
fn mask_blocked_response(err: &MaskRequestError) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("x-vg-proxy-verdict", "block")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: refusing to forward — {err}\n"
        ))))
        .expect("static response is well-formed")
}

/// The upstream couldn't be reached or didn't respond — 502, matching standard proxy semantics.
fn upstream_error_response(err: &ProxyError) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("x-vg-proxy-verdict", "upstream-error")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: upstream request failed: {err}\n"
        ))))
        .expect("static response is well-formed")
}

/// Any other `Daemon::mask_request` error (namespace resolution, vault I/O) — not the client's
/// fault, but still fails closed rather than forwarding an unmasked body.
fn internal_error_response(err: &ProxyError) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("x-vg-proxy-verdict", "block")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: internal error, refusing to forward — {err}\n"
        ))))
        .expect("static response is well-formed")
}
