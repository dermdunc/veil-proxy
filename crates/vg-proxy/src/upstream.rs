//! Forwards a matched (`Mask`/`Pass`) request to an upstream (plan §10.2 `upstream.rs`) and
//! returns its response verbatim — no masking/demasking here, that's the caller's job
//! (`server.rs` masks before calling this; response *de*masking is M4, already built).
//!
//! **A2 (this milestone): real TLS to the real upstream.** M3 only ever reached a mock upstream
//! over plain HTTP (`UpstreamConfig` was a bare loopback `SocketAddr` with no TLS surface at
//! all); this milestone adds a real `rustls` client — chosen over `native-tls` after an explicit
//! human choice (veilgremlin's own new dependency, `governance.yaml`'s `dependency_changes:
//! human_required` in veil-ecosystem): pure-Rust, no OpenSSL/Security.framework FFI, matching
//! XREPO-015's own precedent for this family's telemetry-TLS surface (veil-ecosystem
//! `docs/decisions.md`, 2026-09-13). Certificate validation is real WebPKI chain + hostname
//! verification via `rustls`'s own default verifier — never disabled, never bypassed; an
//! invalid, expired, self-signed, or wrong-host certificate fails the connection closed, proven
//! against a real local TLS server presenting exactly such a certificate in this crate's
//! `tests/tls_upstream.rs`.
//!
//! `UpstreamConfig` connects by **hostname**, not a pre-resolved `SocketAddr` (M3's original
//! shape): a real upstream needs DNS resolution at connect time, and TLS SNI/hostname
//! verification need the name itself, not just an IP `server.rs` never had in the first place.
//!
//! Low-level `hyper::client::conn::http1` (not a pooling client crate) — the same style choice
//! M3 already made; TLS is layered underneath via `tokio_rustls`, not by switching to a
//! higher-level connector crate like `hyper-rustls`, since this module already owns its own
//! connection lifecycle and one connection per forwarded request (connection reuse/pooling is a
//! later latency-hardening concern, plan §10.3 milestone M10, unchanged from M3).
//!
//! **Track H, H2c: bounds and timeouts.** A2 named "no connect/request timeout and no bound on
//! response-body buffering" as an accepted gap; this milestone closes it in both directions.
//! [`Timeouts`] names five separately-tripped timeouts (connect, response-headers, idle-body,
//! streaming-idle, total-request) — see its own doc for each one's scope and default. Response
//! bodies are bounded by [`MAX_RESPONSE_BODY_BYTES`]; request bodies are bounded in `server.rs`'s
//! `collect_body` (the mirror-image gap named at the same milestone). Defaults are chosen against
//! GROUND-13/14 (`docs/architecture/multi-harness-proxy-plan.md`): Claude Code's own documented
//! streaming watchdogs (event-level and byte-level, both ~300s) and Codex's
//! `stream_idle_timeout_ms` (300000ms default) — so a valid, legitimately slow-but-alive
//! generation is never killed by an over-tight default tuned for the fast, non-streaming case.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::ProxyError;

/// The upper bound on a buffered upstream response body (Track H, H2c). A real Claude/Codex
/// text response, even a very long one, is many orders of magnitude smaller than this; the
/// bound exists to fail a runaway or hostile upstream closed rather than let it grow this
/// process's memory without limit. Not vendor-sourced — a reasoned engineering default, generous
/// enough that no real response should ever approach it.
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Whether `content_type` names the `text/event-stream` media type (RFC 9110 §8.3.1: type/
/// subtype tokens are case-insensitive; any `;parameter=...` suffix, e.g. a charset, is not
/// part of the type/subtype and must be ignored, not merely tolerated by a prefix match).
///
/// Track H, H2c (Codex cross-model critique): the original check (`starts_with`, case-sensitive)
/// both under- and over-matched — `Text/Event-Stream` (a valid, differently-cased real value)
/// was missed, while `text/event-streaming` (a different, unrelated media type sharing only a
/// prefix) was wrongly accepted. Shared here (not duplicated) specifically because this exact
/// bug was found duplicated between this module and `server.rs`'s own copy — one correct
/// implementation, two callers, rather than two copies that can silently drift apart.
pub(crate) fn is_event_stream_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("text/event-stream")
}

/// Track H, H2c: five separately-tripped timeouts governing one forwarded request. Each has its
/// own dedicated test (`tests/upstream_timeouts.rs`) proving it — and only it — fires under the
/// matching failure condition. `Default` gives the production values; tests construct their own
/// short-duration `Timeouts` to isolate exactly one without a real multi-minute wait.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Bounds establishing the connection: `TcpStream::connect` plus, when TLS is configured,
    /// the full TLS handshake. Not vendor-sourced — a reasoned default generous enough for a
    /// slow real-world network path.
    ///
    /// **Named residual limitation (Codex cross-model critique, H2c), not fixed here:** for a
    /// hostname target, `TcpStream::connect` resolves DNS via `tokio::task::spawn_blocking`
    /// (a real `getaddrinfo` call), and tokio does not support cancelling an already-started
    /// blocking task. Dropping this future when the timeout fires returns control to the caller
    /// promptly, but the underlying resolver call can keep running on tokio's blocking thread
    /// pool until the OS's own (much longer) resolver timeout — so a resolver that is itself
    /// stalled, hit repeatedly, can accumulate blocking-pool work independent of this timeout.
    /// A fully async resolver would close this; out of this milestone's own scope.
    pub connect: Duration,
    /// Bounds `hyper`'s `send_request` call end to end — which resolves once response headers
    /// are available, before the body is read. **Not scoped to "waiting for headers" alone**
    /// (Codex cross-model critique, H2c): `send_request` also covers writing the request body
    /// over the wire, so a very large request (up to `server.rs`'s own 32 MiB bound) sent over a
    /// slow or backpressured connection could plausibly exhaust this budget during upload, not
    /// while genuinely waiting on the upstream — a real, named edge case, not fixed by adding a
    /// sixth timeout (the plan names exactly five), since real request bodies this proxy forwards
    /// are far smaller than the bound in practice. `ProxyError::UpstreamResponseHeadersTimeout`'s
    /// own message is worded to cover both possibilities rather than assert only one. Not
    /// vendor-sourced.
    pub response_headers: Duration,
    /// Bounds the gap between successive body-read progress for a NON-streaming (not
    /// `text/event-stream`) response — resets every time bytes arrive. Not vendor-sourced; short
    /// relative to `streaming_idle` because a non-streaming JSON response is fully assembled
    /// server-side before any bytes are sent, so a real gap this long means something is stuck,
    /// not that the model is still generating.
    pub idle_body: Duration,
    /// Like `idle_body`, but applied once the response's own `content-type` is seen to be
    /// `text/event-stream` — GROUND-13/14: Claude Code's own byte-level streaming watchdog and
    /// Codex's `stream_idle_timeout_ms` both default to 300s. A real, slow-but-alive generation
    /// can legitimately go this long between SSE keep-alives; this is the number that keeps
    /// H2c from killing it.
    pub streaming_idle: Duration,
    /// A hard ceiling on the entire forwarded request (connect through the last response byte),
    /// independent of whether any single gap ever triggers `idle_body`/`streaming_idle` — bounds
    /// a response that keeps trickling just enough to never go idle but never actually finishes.
    /// Not vendor-sourced; set well above `streaming_idle` so a real long generation (which can
    /// legitimately run several minutes) is not cut off by this ceiling in the ordinary case.
    pub total_request: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            response_headers: Duration::from_secs(30),
            idle_body: Duration::from_secs(30),
            streaming_idle: Duration::from_secs(300),
            total_request: Duration::from_secs(900),
        }
    }
}

/// Where `server.rs` forwards a matched request. `tls_config: None` is plain HTTP (M3's
/// original mock-upstream test path, unchanged in shape); `Some(_)` performs a real TLS
/// handshake with the given `rustls::ClientConfig`, verifying the certificate chain and
/// hostname against `host` before any request is sent.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Connected via `TcpStream::connect((host, port))` and, when `tls_config` is `Some`, used
    /// as the TLS server-name (SNI) and the name certificate-hostname verification checks
    /// against — the same string serves both roles, matching how every real TLS client works.
    pub host: String,
    pub port: u16,
    pub tls_config: Option<Arc<ClientConfig>>,
    /// Track H, H2c. Defaults to [`Timeouts::default`] via every constructor below; tests
    /// override individual fields to isolate one timeout at a time.
    pub timeouts: Timeouts,
    /// Track H, H2c. Defaults to [`MAX_RESPONSE_BODY_BYTES`] via every constructor below; tests
    /// override this to a small value so a bound-exceeded test doesn't need to actually transfer
    /// tens of megabytes over a loopback socket.
    pub max_response_body_bytes: usize,
}

impl UpstreamConfig {
    /// M3's original test/dev shape: plain HTTP to a given host:port, no TLS. Existing
    /// mock-upstream tests (`tests/server_smoke.rs`) use this.
    pub fn plain(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls_config: None,
            timeouts: Timeouts::default(),
            max_response_body_bytes: MAX_RESPONSE_BODY_BYTES,
        }
    }

    /// A real TLS upstream with the given `rustls::ClientConfig` — the general form
    /// `real_anthropic` and this crate's own TLS tests both build on, so a test can inject a
    /// custom root store (e.g. a locally-generated test CA) without this module knowing
    /// anything about tests.
    pub fn tls(host: impl Into<String>, port: u16, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            host: host.into(),
            port,
            tls_config: Some(tls_config),
            timeouts: Timeouts::default(),
            max_response_body_bytes: MAX_RESPONSE_BODY_BYTES,
        }
    }

    /// A2: the real Anthropic Messages API endpoint, over real TLS trusting the real OS trust
    /// store (`rustls-native-certs`, macOS `Security.framework` — beta's own scoped platform)
    /// rather than a bundled CA list: switched from `webpki-roots` during this milestone's own
    /// build after `cargo deny check licenses` rejected that crate's CDLA-Permissive-2.0
    /// license (not in this repo's `deny.toml` allow-list); native-certs is dual MIT/Apache-2.0,
    /// already allowed, and ties trust to whatever CAs the device itself already trusts instead
    /// of a list that ships on this crate's own release cadence. The underlying `ClientConfig`
    /// is built once per process (`OnceLock`): loading the OS store is a real, blocking
    /// syscall-backed read, and callers may build many `UpstreamConfig`s (one per forwarded
    /// request) cheaply via `Arc::clone` instead of repeating it.
    pub fn real_anthropic() -> Self {
        Self::tls("api.anthropic.com", 443, Arc::clone(default_tls_config()))
    }
}

fn default_tls_config() -> &'static Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        // A cert the OS store returns that `rustls`'s own parser rejects is skipped, not a
        // hard failure — matches `rustls-native-certs`'s own documented posture: a single
        // malformed/unusual system entry shouldn't take down every other trusted root. Every
        // real error is still surfaced (`eprintln!`, matching this crate's existing
        // connection-error logging convention in `forward()` below), not silently swallowed.
        for err in &loaded.errors {
            eprintln!("vg-proxy: skipping one OS trust-store entry: {err}");
        }
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    })
}

/// A single connection's I/O, plain or TLS — `hyper::client::conn::http1::handshake` needs one
/// concrete `AsyncRead + AsyncWrite` type, and `TcpStream`/`TlsStream<TcpStream>` are different
/// concrete types, so this enum picks between them at runtime and forwards every poll method to
/// whichever variant is active. Both inner types are `Unpin` (`TcpStream` always is;
/// `tokio_rustls::client::TlsStream<T>` is `Unpin` whenever `T: Unpin`), so plain `Pin::new`
/// per-arm is sound without an external pin-projection crate.
enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Forwards `method path_and_query body` to `config.host:config.port` — over TLS if
/// `config.tls_config` is `Some`, verifying the certificate chain and hostname against
/// `config.host` before sending anything — copying only `headers_to_forward` (the
/// caller's active codec has already applied its own header-forwarding policy, Track H
/// fork F4 — this module holds no provider-shaped header policy of its own, per D-H-1),
/// and returns the upstream's response verbatim (status, body, headers) once fully
/// received. The response is buffered here (not handed back as a live `Incoming` body for
/// the caller to stream — true incremental streaming is H6's job), but Track H H2c now bounds
/// that buffering: a size limit ([`MAX_RESPONSE_BODY_BYTES`]) and an idle-gap timeout
/// (`config.timeouts.idle_body`/`streaming_idle`, selected by the response's own `content-type`)
/// that resets on every chunk of real progress, so a genuinely slow-but-alive stream survives
/// while a truly stalled one fails closed instead of holding this connection (and its memory)
/// forever.
///
/// **Security note, named at H2b (Codex cross-model critique, finding 3): this function
/// applies NO header policy of its own and forwards `headers_to_forward` verbatim,
/// unconditionally.** Before H2b, this module's own `FORWARDED_HEADERS` constant
/// enforced a fixed five-header allow-list internally, so calling `forward()` with an
/// arbitrary `HeaderMap` was safe regardless of what the caller passed. That
/// self-enforcement is gone: the safety property now depends entirely on every caller
/// having already run the active codec's `select_headers` (fork F4) before calling this
/// function. `server.rs` (the only production caller) does this correctly. A future
/// caller that skips it — a new H0 launch path, a test, a second binary — would forward
/// whatever it passes, including credential- or cookie-shaped headers, with no
/// enforcement at this layer. This trade-off is deliberate (D-H-1: the transport layer
/// sees "an origin and bytes," never provider-shaped policy) but is a real reduction in
/// defense-in-depth from the pre-H2b shape, named here rather than left implicit. Not
/// fixed in H2b's own scope: doing so would mean either reintroducing a policy into the
/// transport layer (contradicting D-H-1) or gating this function behind a
/// caller-supplied, already-filtered-marker type — a real design question for whoever
/// adds the next caller of `forward()`, not resolved here.
pub async fn forward(
    config: UpstreamConfig,
    method: Method,
    path_and_query: &str,
    headers_to_forward: &[(HeaderName, HeaderValue)],
    body: Vec<u8>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let host = config.host.clone();
    let total_request_timeout = config.timeouts.total_request;
    match tokio::time::timeout(
        total_request_timeout,
        forward_inner(config, method, path_and_query, headers_to_forward, body),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(ProxyError::UpstreamTotalRequestTimeout {
            host,
            timeout: total_request_timeout,
        }),
    }
}

async fn forward_inner(
    config: UpstreamConfig,
    method: Method,
    path_and_query: &str,
    headers_to_forward: &[(HeaderName, HeaderValue)],
    body: Vec<u8>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let io = connect(&config).await?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(ProxyError::UpstreamHandshake)?;
    // Detached, like `server.rs`'s own per-connection tasks: this forwarding call has already
    // returned everything it needs once `send_request` resolves below; driving the connection
    // to completion afterward (or logging if it errors) doesn't need to block the caller.
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("vg-proxy: upstream connection error: {err}");
        }
    });

    // The `Host` header is the bare hostname when the port is the scheme's default (443 for
    // TLS, 80 for plain), and `host:port` otherwise — RFC 7230 §5.4 doesn't require the default
    // port be included, and the real Anthropic API (TLS, port 443) expects exactly
    // `api.anthropic.com`, not `api.anthropic.com:443`. M3's own mock-upstream tests run on an
    // OS-assigned non-default port, so they exercise the `host:port` branch instead.
    let is_default_port = (config.tls_config.is_some() && config.port == 443)
        || (config.tls_config.is_none() && config.port == 80);
    let host_header = if is_default_port {
        config.host.clone()
    } else {
        format!("{}:{}", config.host, config.port)
    };

    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", host_header);
    for (name, value) in headers_to_forward {
        builder = builder.header(name.clone(), value.clone());
    }
    let req = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(ProxyError::UpstreamRequestBuild)?;

    let resp = tokio::time::timeout(config.timeouts.response_headers, sender.send_request(req))
        .await
        .map_err(|_elapsed| ProxyError::UpstreamResponseHeadersTimeout {
            host: config.host.clone(),
            timeout: config.timeouts.response_headers,
        })?
        .map_err(ProxyError::UpstreamSend)?;
    buffer_response(
        resp,
        &config.host,
        &config.timeouts,
        config.max_response_body_bytes,
    )
    .await
}

/// Establishes the connection — TCP connect, then (if configured) the full TLS handshake — under
/// a single `config.timeouts.connect` budget (Track H, H2c). Both failure modes (a peer that
/// never completes the TCP handshake, and one that completes it but stalls mid-TLS-negotiation)
/// are the same practical failure from a caller's perspective: "establishing a connection never
/// finished," so one timeout covers both rather than splitting them.
async fn connect(config: &UpstreamConfig) -> Result<TokioIo<MaybeTlsStream>, ProxyError> {
    let attempt = async {
        let tcp = TcpStream::connect((config.host.as_str(), config.port))
            .await
            .map_err(|source| ProxyError::UpstreamConnect {
                host: config.host.clone(),
                port: config.port,
                source,
            })?;

        match &config.tls_config {
            None => Ok(TokioIo::new(MaybeTlsStream::Plain(tcp))),
            Some(tls_config) => {
                let server_name = ServerName::try_from(config.host.clone()).map_err(|source| {
                    ProxyError::UpstreamInvalidServerName {
                        host: config.host.clone(),
                        source,
                    }
                })?;
                let connector = TlsConnector::from(Arc::clone(tls_config));
                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|source| ProxyError::UpstreamTls {
                        host: config.host.clone(),
                        source,
                    })?;
                Ok(TokioIo::new(MaybeTlsStream::Tls(Box::new(tls_stream))))
            }
        }
    };

    match tokio::time::timeout(config.timeouts.connect, attempt).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProxyError::UpstreamConnectTimeout {
            host: config.host.clone(),
            port: config.port,
            timeout: config.timeouts.connect,
        }),
    }
}

/// Buffers the upstream response body, bounded in both size ([`MAX_RESPONSE_BODY_BYTES`]) and
/// idle time (Track H, H2c). Reads frame-by-frame rather than a single `.collect()` so an
/// idle-gap timeout can reset on every real chunk of progress instead of applying to the whole
/// read as one lump sum — the exact distinction that lets a slow-but-alive stream survive while
/// a truly stalled one still fails closed. The idle timeout itself is selected by the response's
/// own `content-type`, known from the headers before any body byte is read: `text/event-stream`
/// gets the longer `streaming_idle` budget (matching real vendor SSE-keepalive behavior,
/// GROUND-13/14); everything else gets the shorter `idle_body` budget, since a non-streaming
/// response is fully assembled server-side before any of it is sent.
async fn buffer_response(
    resp: Response<Incoming>,
    host: &str,
    timeouts: &Timeouts,
    max_response_body_bytes: usize,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let (parts, body) = resp.into_parts();
    let is_sse = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_event_stream_content_type);
    let idle_timeout = if is_sse {
        timeouts.streaming_idle
    } else {
        timeouts.idle_body
    };

    let mut body = Limited::new(body, max_response_body_bytes);
    let mut collected: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(idle_timeout, body.frame()).await {
            Err(_elapsed) => {
                return Err(ProxyError::UpstreamIdleTimeout {
                    host: host.to_string(),
                    timeout: idle_timeout,
                    streaming: is_sse,
                })
            }
            Ok(None) => break,
            Ok(Some(Err(err))) => {
                if err
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    return Err(ProxyError::UpstreamResponseTooLarge {
                        limit: max_response_body_bytes,
                    });
                }
                return Err(ProxyError::UpstreamResponseBody(err));
            }
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    collected.extend_from_slice(data);
                }
            }
        }
    }

    Ok(Response::from_parts(
        parts,
        Full::new(Bytes::from(collected)),
    ))
}
