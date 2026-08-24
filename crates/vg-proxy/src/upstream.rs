//! Forwards a matched (`Mask`/`Pass`) request to an upstream over plain HTTP/1.1 (plan §10.2
//! `upstream.rs`) and returns its response verbatim — no masking/demasking here, that's the
//! caller's job (`server.rs` masks before calling this; response *de*masking is M4, not built).
//!
//! **Plain-HTTP, loopback-or-any `SocketAddr` only.** M3's own tests point this at a mock
//! upstream (a second `hyper` server bound to `127.0.0.1:0`); reaching the *real* Anthropic API
//! (`https://api.anthropic.com`) needs a TLS client this module doesn't build — that's M5's job
//! ("real Claude Code, Anthropic API-key mode"), a named, deferred gap, not silently assumed
//! solved by this milestone.
//!
//! Low-level `hyper::client::conn::http1` (not a pooling client crate) — the same style choice
//! `server.rs` already made on the listening side (`hyper::server::conn::http1::Builder`), and
//! sufficient for one connection per forwarded request; connection reuse/pooling is a later
//! latency-hardening concern (plan §10.3 milestone M10), not this one.

use std::net::SocketAddr;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{HeaderMap, Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::error::ProxyError;

/// Where `server.rs` forwards a matched request. Plain-HTTP-only — see this module's own doc
/// for why real-upstream HTTPS is out of scope here.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamConfig {
    pub addr: SocketAddr,
}

/// Headers forwarded verbatim from the inbound request to the upstream request — an explicit
/// allow-set (plan §8.4), not a blind copy of every inbound header. `content-length`/`host` are
/// deliberately excluded: the client below recomputes both fresh for the new body/upstream on
/// every request, so a stale copied value could never silently disagree with the real one sent.
const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "x-api-key",
    "authorization",
    "anthropic-version",
    "anthropic-beta",
];

/// Forwards `method path_and_query body` to `config.addr` over a fresh connection, copying only
/// [`FORWARDED_HEADERS`] from `original_headers`, and returns the upstream's response verbatim
/// (status, body, headers) once fully received — M3 is non-streaming, so the response is
/// buffered here rather than handed back as a live `Incoming` body for the caller to stream.
pub async fn forward(
    config: UpstreamConfig,
    method: Method,
    path_and_query: &str,
    original_headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let stream =
        TcpStream::connect(config.addr)
            .await
            .map_err(|source| ProxyError::UpstreamConnect {
                addr: config.addr,
                source,
            })?;
    let io = TokioIo::new(stream);

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

    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", config.addr.to_string());
    for name in FORWARDED_HEADERS {
        if let Some(value) = original_headers.get(*name) {
            builder = builder.header(*name, value.clone());
        }
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
