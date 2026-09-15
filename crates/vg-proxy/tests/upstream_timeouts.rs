//! Track H, H2c: dedicated tests proving each of the five named timeouts (connect,
//! response-headers, idle-body, streaming-idle, total-request) fires under its own matching
//! condition — and only that one — plus a "survives" test proving a genuine mid-length gap
//! doesn't trip the (longer) `streaming_idle` budget, and a response-body-bound test mirroring
//! `server.rs`'s request-body-bound one.
//!
//! Uses a raw, hand-written TCP server (not hyper's own `service_fn`/`Response`-returning
//! abstraction) so each test controls precisely when — and whether — bytes are written back.
//! Hyper's higher-level server interface doesn't allow injecting a mid-response pause; only
//! reading/writing a raw `TcpStream` directly does.

use std::time::Duration;

use hyper::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vg_proxy::error::ProxyError;
use vg_proxy::upstream::{self, Timeouts, UpstreamConfig};

/// Generous timeouts for the four fields a given test isn't exercising, so only the one field
/// under test can plausibly fire.
fn generous_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(30),
        response_headers: Duration::from_secs(30),
        idle_body: Duration::from_secs(30),
        streaming_idle: Duration::from_secs(30),
        total_request: Duration::from_secs(30),
    }
}

/// Binds a loopback listener, accepts exactly one connection, reads (and discards) the request
/// up through the header/body blank-line separator, then hands the raw stream to `respond` for
/// full control over what (if anything) is written back and when.
async fn spawn_raw_server<F, Fut>(respond: F) -> std::net::SocketAddr
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_request_headers(&mut stream).await;
        respond(stream).await;
    });
    addr
}

async fn read_request_headers(stream: &mut TcpStream) {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// A near-zero connect timeout raced against a real (even loopback) `TcpStream::connect` proved
/// non-deterministic under load in practice (observed flaking in the full workspace test run,
/// where the connect apparently won a race against a 1ns deadline and the test fell through to
/// the 30s `response_headers` timeout instead). A first fix (racing a short timeout against a
/// connection attempt to `192.0.2.1`, RFC 5737 TEST-NET-1) was itself found non-hermetic by a
/// Codex cross-model critique: RFC 5737 only recommends that routers not forward such addresses
/// ("SHOULD"-level guidance), it does not guarantee packets are silently dropped, and that
/// review's own sandboxed run received an immediate `PermissionDenied` there instead of a
/// timeout — a real environment dependency, not merely a hypothetical one.
///
/// This version tests the SAME `connect` budget deterministically, entirely on loopback: a real
/// TCP listener accepts the bare TCP connection (so the TCP half of `connect` genuinely
/// succeeds, immediately), then never writes a single TLS handshake byte back. The client's
/// `rustls` `ClientHello` then waits for a `ServerHello` that never arrives — hanging within
/// `connect`'s own timeout exactly as a real stalled TLS peer would, with no dependency on any
/// external network's routing behavior. This also closes a real coverage gap the critique named:
/// no prior test exercised `connect`'s TLS-handshake half stalling, only its TCP half.
#[tokio::test]
async fn connect_timeout_fires_and_only_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        // Bound (not discarded) for the same reason as `response_headers_timeout_fires_and_only_it`
        // above: it must be moved into this future so the socket stays open through the sleep.
        let _stream = stream;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });

    let mut config = UpstreamConfig::tls("127.0.0.1", addr.port(), empty_client_config());
    config.timeouts = Timeouts {
        connect: Duration::from_millis(200),
        ..generous_timeouts()
    };

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("a stalled TLS handshake must time out within the connect budget");
    assert!(
        matches!(err, ProxyError::UpstreamConnectTimeout { .. }),
        "expected UpstreamConnectTimeout, got: {err:?}"
    );
}

/// A `rustls::ClientConfig` trusting nothing — sufficient here because the handshake this test
/// drives never gets far enough to reach certificate validation at all.
fn empty_client_config() -> std::sync::Arc<rustls::ClientConfig> {
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn response_headers_timeout_fires_and_only_it() {
    let addr = spawn_raw_server(|stream| async move {
        // Never write anything back — hold the connection open. Binding (not discarding)
        // `stream` here is load-bearing: it must be moved into this future so the socket stays
        // open through the sleep, rather than being dropped (closing the connection) the
        // instant the closure returns, which would surface as an immediate `IncompleteMessage`
        // on the client side instead of the response-headers timeout this test means to prove.
        let _stream = stream;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = Timeouts {
        response_headers: Duration::from_millis(100),
        ..generous_timeouts()
    };

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("response-headers timeout must fire when the upstream never responds");
    assert!(
        matches!(err, ProxyError::UpstreamResponseHeadersTimeout { .. }),
        "expected UpstreamResponseHeadersTimeout, got: {err:?}"
    );
}

#[tokio::test]
async fn idle_body_timeout_fires_for_a_non_streaming_response_and_only_it() {
    let addr = spawn_raw_server(|mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
            .await
            .expect("write headers");
        stream
            .write_all(b"partial")
            .await
            .expect("write partial body");
        stream.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_secs(3600)).await;
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = Timeouts {
        idle_body: Duration::from_millis(100),
        ..generous_timeouts()
    };

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("idle-body timeout must fire on a stalled non-streaming response");
    match err {
        ProxyError::UpstreamIdleTimeout { streaming, .. } => {
            assert!(
                !streaming,
                "expected the non-streaming idle timeout, not streaming_idle"
            )
        }
        other => panic!("expected UpstreamIdleTimeout, got: {other:?}"),
    }
}

#[tokio::test]
async fn streaming_idle_timeout_fires_for_an_sse_response_and_only_it() {
    let addr = spawn_raw_server(|mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 100\r\n\r\n",
            )
            .await
            .expect("write headers");
        stream.write_all(b"partial").await.expect("write partial body");
        stream.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_secs(3600)).await;
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = Timeouts {
        // Deliberately long — proves `streaming_idle`, not `idle_body`, is what governs an
        // SSE response.
        idle_body: Duration::from_secs(30),
        streaming_idle: Duration::from_millis(100),
        ..generous_timeouts()
    };

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("streaming-idle timeout must fire on a stalled SSE response");
    match err {
        ProxyError::UpstreamIdleTimeout { streaming, .. } => {
            assert!(
                streaming,
                "expected the streaming idle timeout, not idle_body"
            )
        }
        other => panic!("expected UpstreamIdleTimeout, got: {other:?}"),
    }
}

#[tokio::test]
async fn total_request_timeout_fires_even_when_no_single_gap_goes_idle() {
    let addr = spawn_raw_server(|mut stream| async move {
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000000\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        // Trickle one byte at a time, each gap well under idle_body's own (generous) budget,
        // so idle_body never fires — only total_request's own ceiling should, since no single
        // gap is ever long enough to look "idle."
        loop {
            if stream.write_all(b"x").await.is_err() {
                break;
            }
            if stream.flush().await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = Timeouts {
        total_request: Duration::from_millis(150),
        ..generous_timeouts()
    };

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("total-request timeout must fire even though no single gap ever idles out");
    assert!(
        matches!(err, ProxyError::UpstreamTotalRequestTimeout { .. }),
        "expected UpstreamTotalRequestTimeout, got: {err:?}"
    );
}

/// The strengthened confirmation criterion (Codex cross-model critique on the accepted intent):
/// a genuinely slow-but-alive SSE response must NOT be killed. Two gaps, each individually
/// UNDER `streaming_idle`'s own test budget, but SUMMING to well over it — specifically to
/// falsify a regression to a single fixed deadline computed once at stream-start rather than
/// reset on every real frame of progress (a second Codex finding: the original single-pause
/// version of this test used a pause so far under its own generous `streaming_idle` budget that
/// it would have passed even under that exact regression, proving nothing about the reset
/// mechanism specifically). If `streaming_idle` were ever implemented as one fixed deadline
/// instead of resetting per frame, this response — total elapsed time exceeding the budget, but
/// no single gap exceeding it — would be killed; with correct per-frame reset, it isn't.
///
/// **Named limitation, not fixed by this or any unit test (Codex cross-model critique):** this
/// proves the RESET MECHANISM is wired correctly for whatever duration `streaming_idle` is
/// configured to. It does NOT — cannot, without a real multi-minute test — prove that the real
/// *production default* (300s, GROUND-13/14's vendor numbers) is itself well-chosen against real
/// Claude Code/Codex generation behavior; that claim rests on `scripts/a2-live-proof.sh` and the
/// vendor documentation cited in `Timeouts::streaming_idle`'s own doc comment, not on this test.
#[tokio::test]
async fn a_genuine_pause_under_the_streaming_idle_budget_survives() {
    let addr = spawn_raw_server(|mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 15\r\n\r\n",
            )
            .await
            .expect("write headers");
        for _ in 0..2 {
            stream
                .write_all(b"five!")
                .await
                .expect("write a five-byte chunk");
            stream.flush().await.expect("flush");
            // Each gap is under the 300ms streaming_idle budget below; the two together (400ms)
            // are not.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        stream
            .write_all(b"five!")
            .await
            .expect("write the final chunk");
        stream.flush().await.expect("flush");
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = Timeouts {
        idle_body: Duration::from_millis(50),
        streaming_idle: Duration::from_millis(300),
        ..generous_timeouts()
    };

    let resp = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect(
            "two gaps each under streaming_idle, summing over it, must survive under correct \
             per-frame reset",
        );
    let (_, body) = resp.into_parts();
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(&bytes[..], b"five!five!five!");
}

/// Mirrors `server.rs`'s request-body-bound tests, on the response side: a response body over
/// the configured bound fails closed (mapped to 502 by `server.rs`'s generic upstream-error
/// handling), and a response exactly at the bound succeeds. Uses a small configured bound
/// (`UpstreamConfig::max_response_body_bytes`, Track H H2c) rather than the real 64 MiB
/// production default so the test doesn't need to transfer tens of megabytes.
#[tokio::test]
async fn response_body_over_the_configured_bound_fails_closed() {
    let addr = spawn_raw_server(|mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 20\r\n\r\n")
            .await
            .expect("write headers");
        stream
            .write_all(b"01234567890123456789")
            .await
            .expect("write oversized body");
        stream.flush().await.expect("flush");
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = generous_timeouts();
    config.max_response_body_bytes = 10;

    let err = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect_err("a response body over the configured bound must fail closed");
    assert!(
        matches!(err, ProxyError::UpstreamResponseTooLarge { limit: 10 }),
        "expected UpstreamResponseTooLarge {{ limit: 10 }}, got: {err:?}"
    );
}

#[tokio::test]
async fn response_body_at_the_configured_bound_is_accepted() {
    let addr = spawn_raw_server(|mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n")
            .await
            .expect("write headers");
        stream
            .write_all(b"0123456789")
            .await
            .expect("write body at the bound");
        stream.flush().await.expect("flush");
    })
    .await;

    let mut config = UpstreamConfig::plain("127.0.0.1", addr.port());
    config.timeouts = generous_timeouts();
    config.max_response_body_bytes = 10;

    let resp = upstream::forward(config, Method::GET, "/", &[], Vec::new())
        .await
        .expect("a response body exactly at the bound must be accepted");
    let (_, body) = resp.into_parts();
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(&bytes[..], b"0123456789");
}
