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
//! **Named gap, not solved by this milestone:** no connect/request timeout and no bound on
//! response-body buffering — a hung or slow-drip real upstream can block a forwarded request
//! indefinitely, or an unbounded response can grow memory without limit. Accepted as a
//! documented trade-off (see `docs/next-actions.md`'s A2 entry) rather than built here, to keep
//! this milestone's scope to what its own intent's confirmation criteria actually require;
//! production-grade network hardening across every failure mode (DNS failure, peer close
//! mid-handshake, partial reads) is real, named work for a later milestone.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};

use http_body_util::{BodyExt, Full};
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
}

impl UpstreamConfig {
    /// M3's original test/dev shape: plain HTTP to a given host:port, no TLS. Existing
    /// mock-upstream tests (`tests/server_smoke.rs`) use this.
    pub fn plain(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls_config: None,
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
/// received — M3/A2 are both non-streaming, so the response is buffered here rather
/// than handed back as a live `Incoming` body for the caller to stream.
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
    let tcp = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|source| ProxyError::UpstreamConnect {
            host: config.host.clone(),
            port: config.port,
            source,
        })?;

    let io = match &config.tls_config {
        None => TokioIo::new(MaybeTlsStream::Plain(tcp)),
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
            TokioIo::new(MaybeTlsStream::Tls(Box::new(tls_stream)))
        }
    };

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

    let resp = sender
        .send_request(req)
        .await
        .map_err(ProxyError::UpstreamSend)?;
    buffer_response(resp).await
}

async fn buffer_response(resp: Response<Incoming>) -> Result<Response<Full<Bytes>>, ProxyError> {
    let (parts, body) = resp.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(ProxyError::UpstreamResponseBody)?
        .to_bytes();
    Ok(Response::from_parts(parts, Full::new(collected)))
}
