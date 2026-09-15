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

use crate::codec::MaskRequestError;
use crate::daemon::Daemon;
use crate::error::ProxyError;
use crate::route::RouteVerdict;
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
                // `UpstreamConfig` stopped being `Copy` once it grew a `String` host and an
                // `Option<Arc<rustls::ClientConfig>>` (A2) — cloned once per accepted
                // connection here, and again per request inside the `Fn` service closure below
                // (which may be called more than once per keep-alive connection), since neither
                // scope can move the same value out twice. Both clones are cheap: a `String`
                // clone plus an `Arc` clone, not a deep copy of the TLS config itself.
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        handle(req, Arc::clone(&daemon), upstream.clone(), local_addr)
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

    match daemon.classify_route(&method, &target) {
        RouteVerdict::Block => Ok(block_response(&method, &target)),
        RouteVerdict::Mask => {
            Ok(handle_mask(req, &method, &target, &daemon, upstream, local_addr).await)
        }
        RouteVerdict::Pass => Ok(handle_pass(req, &method, &target, &daemon, upstream).await),
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
    let body = match collect_body(req.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };

    let (masked_body, stats, namespace) =
        match daemon.mask_request(&body, namespace_header.as_deref(), local_addr) {
            Ok(result) => result,
            Err(ProxyError::MaskRequest(err)) => return mask_blocked_response(&err),
            Err(err) => return internal_error_response(&err),
        };

    let selected_headers = daemon.select_headers(&headers);
    match upstream::forward(
        upstream,
        method.clone(),
        target,
        &selected_headers.forward,
        masked_body,
    )
    .await
    {
        Ok(resp) => {
            // M4: demask the response before it reaches the client — the whole point of the
            // proxy. Infallible (see `demask_response`'s own doc): a malformed/unexpected
            // response shape or an unresolvable binding never blocks a successful response.
            // `upstream::forward` already buffered the body into a `Full<Bytes>`, so
            // `.collect()` here resolves immediately (no real I/O, matching how
            // `upstream.rs`'s own `buffer_response` extracts bytes from a `Full` body).
            let (parts, body) = resp.into_parts();
            let raw_body = body
                .collect()
                .await
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            // A2 (`amendment-2026-09-14-001.yaml`): the upstream's own `content-type` — not a
            // client-side guess, and not the *request's* `stream` field, which the upstream is
            // free to ignore or honor on its own terms — decides which demask path applies.
            // `text/event-stream` is Anthropic's own real signal for an SSE response; anything
            // else (including no content-type at all) goes through the original, non-streaming
            // JSON path unchanged. Track H, H2c (Codex cross-model critique): this used to be
            // its own inline, case-sensitive `starts_with` check — the exact same bug
            // duplicated in `upstream.rs`'s own copy — now a single shared, correct
            // implementation (`upstream::is_event_stream_content_type`) instead of two.
            let is_sse = parts
                .headers
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(upstream::is_event_stream_content_type);
            let demasked_body = if is_sse {
                daemon.demask_streaming_response(&raw_body, &namespace)
            } else {
                daemon.demask_response(&raw_body, &namespace)
            };
            let demasked_len = demasked_body.len();
            let mut parts = parts;
            // The demasked body's length is not necessarily the upstream's original length
            // (a restored raw value is rarely the same byte length as the placeholder it
            // replaced) — the upstream's own `Content-Length` header, copied verbatim into
            // `parts`, would now be stale. Recomputed fresh, matching `upstream.rs`'s own
            // "never trust a copied length/host value" precedent. `Transfer-Encoding` is
            // removed outright rather than left alone (round-2 doubt-pass finding): the body
            // below is always a single, fully-buffered `Full<Bytes>` — never actually chunked
            // — so a `Transfer-Encoding: chunked` header copied from an upstream that *did*
            // stream its response would leave both headers set on a non-chunked body, an
            // invalid/ambiguous framing per RFC 7230 §3.3.3.
            parts.headers.remove(hyper::header::TRANSFER_ENCODING);
            parts.headers.insert(
                hyper::header::CONTENT_LENGTH,
                HeaderValue::from_str(&demasked_len.to_string())
                    .expect("a decimal length is always a valid header value"),
            );
            let mut resp = Response::from_parts(parts, Full::new(Bytes::from(demasked_body)));
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
    daemon: &Daemon,
    upstream: UpstreamConfig,
) -> Response<Full<Bytes>> {
    let headers = req.headers().clone();
    let body = match collect_body(req.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };

    let selected_headers = daemon.select_headers(&headers);
    match upstream::forward(
        upstream,
        method.clone(),
        target,
        &selected_headers.forward,
        body,
    )
    .await
    {
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

/// The upper bound on an inbound request body (Track H, H2c — closes the request-body half of
/// plan §1.2 item 9; `upstream.rs`'s `MAX_RESPONSE_BODY_BYTES` closes the response half). A real
/// Claude Code/Codex request, even a long multi-turn conversation with large tool outputs, is
/// far smaller than this; the bound exists to fail an oversized or hostile request closed rather
/// than read it into memory without limit. Not vendor-sourced — a reasoned engineering default.
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Reads the full request body, bounded by [`MAX_REQUEST_BODY_BYTES`] (Track H, H2c — before
/// this milestone, `collect()` read an inbound body with no length check at all). A body
/// exceeding the bound fails closed with 413, never reaching `mask_request`'s own JSON-parse
/// step or the upstream.
async fn collect_body<B>(body: B) -> Result<Vec<u8>, Response<Full<Bytes>>>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .map_err(|err| {
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                return request_too_large_response();
            }
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("x-vg-proxy-verdict", "block")
                .body(Full::new(Bytes::from(format!(
                    "vg-proxy: failed to read request body: {err}\n"
                ))))
                .expect("static response is well-formed")
        })
}

fn request_too_large_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .header("x-vg-proxy-verdict", "block")
        .body(Full::new(Bytes::from(format!(
            "vg-proxy: request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte bound — fail closed\n"
        ))))
        .expect("static response is well-formed")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Track H, H2c: `collect_body`'s request-body bound, exercised at its real production
    /// size (`MAX_REQUEST_BODY_BYTES`, 32 MiB) — not a scaled-down stand-in — but against an
    /// in-memory `Full<Bytes>` body rather than a real socket, so the test is fast and
    /// deterministic instead of racing a real server's response against a client still writing
    /// tens of megabytes (a real hazard: `collect_body` can return its 413 before the client
    /// finishes sending, and a raw-socket test would need to handle that race explicitly).
    /// `collect_body` was made generic over the body type specifically to make this possible.
    #[tokio::test]
    async fn a_request_body_over_the_bound_fails_closed_with_413() {
        let oversized = vec![b'a'; MAX_REQUEST_BODY_BYTES + 1];
        let body = Full::new(Bytes::from(oversized));
        let resp = collect_body(body)
            .await
            .expect_err("a body one byte over the bound must fail closed");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The mirror-image case: a body AT the bound (not over it) must still succeed — proving
    /// this is a real "greater than," not an off-by-one that also rejects the exact limit.
    #[tokio::test]
    async fn a_request_body_at_the_bound_is_accepted() {
        let at_limit = vec![b'a'; MAX_REQUEST_BODY_BYTES];
        let body = Full::new(Bytes::from(at_limit.clone()));
        let collected = collect_body(body)
            .await
            .expect("a body exactly at the bound must be accepted");
        assert_eq!(collected.len(), MAX_REQUEST_BODY_BYTES);
    }
}
