//! Dev-only wire capture (`src/capture.rs`), exercised over real HTTP against a mock upstream.
//! Built only with `cargo test -p vg-proxy --features capture`.
//!
//! This is its own test binary, with a single test, on purpose: capture is configured by a
//! process-wide environment variable read once per process, so sharing a binary with other tests
//! would make them race on it.

#![cfg(feature = "capture")]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use vg_core::PolicyLayers;
use vg_proxy::capture::CAPTURE_DIR_ENV;
use vg_proxy::daemon::Daemon;
use vg_proxy::upstream::UpstreamConfig;
use vg_vault::VaultConfig;

const TEST_KEY: [u8; 32] = [7u8; 32];
const RAW_EMAIL: &str = "jane.doe@example.com";
const MOCK_RESPONSE: &str = r#"{"id":"msg_mock","type":"message","role":"assistant","content":[{"type":"text","text":"noted EMAIL_001"}]}"#;

fn global_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
}

type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Records every request's `(path, body)` and answers with `MOCK_RESPONSE`.
fn spawn_mock_upstream() -> (SocketAddr, Received, tokio::sync::oneshot::Sender<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = TcpListener::from_std(listener).expect("tokio listener");
    let addr = listener.local_addr().expect("mock addr");
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    let received_task = Arc::clone(&received);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let received = Arc::clone(&received_task);
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let received = Arc::clone(&received);
                            async move {
                                let path = req.uri().path().to_string();
                                let body = req.into_body().collect().await
                                    .map(|c| c.to_bytes().to_vec()).unwrap_or_default();
                                received.lock().unwrap().push((path, body));
                                Ok::<_, Infallible>(Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(MOCK_RESPONSE)))
                                    .unwrap())
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service).await;
                    });
                }
            }
        }
    });
    (addr, received, shutdown_tx)
}

async fn send(
    addr: SocketAddr,
    method: &str,
    target: &str,
    body: &[u8],
    ns: Option<&str>,
) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let ns_header = ns
        .map(|n| format!("X-VG-Namespace: {n}\r\n"))
        .unwrap_or_default();
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         {ns_header}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    stream.write_all(&request).await.expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("read");
    response
}

fn capture_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Capture records exactly the bytes that crossed the wire on the `Mask` route, and nothing from
/// the `Pass` route (which forwards raw bodies) or from a request that failed closed.
#[tokio::test]
async fn capture_records_the_exact_masked_wire_bytes_and_only_for_the_mask_route() {
    let capture_dir = TempDir::new().expect("capture dir");
    // Set before the proxy handles its first request: capture reads the variable once.
    std::env::set_var(CAPTURE_DIR_ENV, capture_dir.path());

    let state_dir = TempDir::new().expect("state dir");
    let daemon = Arc::new(
        Daemon::open_with_key(
            VaultConfig::new(state_dir.path().join("vault.db")),
            TEST_KEY,
            PolicyLayers {
                global: global_policy_path(),
                repo: None,
                session: None,
            },
            state_dir.path().join("audit.jsonl"),
        )
        .expect("daemon opens"),
    );
    let (upstream_addr, received, upstream_shutdown) = spawn_mock_upstream();
    let upstream = UpstreamConfig::plain(upstream_addr.ip().to_string(), upstream_addr.port());
    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(vg_proxy::server::run_with_listener(
        listener,
        daemon,
        upstream,
        async {
            let _ = shutdown_rx.await;
        },
    ));
    let ns = Uuid::new_v4().to_string();

    // 1. Mask route: captured.
    let mask_body = format!(
        r#"{{"model":"claude-x","system":"contact {RAW_EMAIL}","messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    let resp = send(
        addr,
        "POST",
        "/v1/messages",
        mask_body.as_bytes(),
        Some(&ns),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "mask route: {resp}");

    // 2. Pass route carrying a raw value: forwarded raw by design, and must NOT be captured.
    let pass_body = format!(r#"{{"note":"{RAW_EMAIL}"}}"#);
    let resp = send(addr, "GET", "/v1/models", pass_body.as_bytes(), None).await;
    assert!(
        resp.contains("x-vg-proxy-verdict: pass"),
        "pass route: {resp}"
    );

    // 3. Mask route that fails closed (image block): nothing reaches upstream, nothing captured.
    let blocked = r#"{"model":"claude-x","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}"#;
    let resp = send(addr, "POST", "/v1/messages", blocked.as_bytes(), Some(&ns)).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "blocked request: {resp}");

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server shuts down")
        .expect("server task ok")
        .expect("clean shutdown");
    let _ = upstream_shutdown.send(());

    // Exactly one exchange captured: the successful mask-route round trip.
    assert_eq!(
        capture_files(capture_dir.path()),
        vec!["000001-request.masked.json", "000001-response.raw.json"],
        "only the Mask-route exchange may be captured"
    );

    let received: Vec<(String, Vec<u8>)> = received.lock().unwrap().clone();
    let upstream_mask_body = &received
        .iter()
        .find(|(p, _)| p == "/v1/messages")
        .expect("upstream got the mask request")
        .1;
    let upstream_pass_body = &received
        .iter()
        .find(|(p, _)| p == "/v1/models")
        .expect("upstream got the pass request")
        .1;

    // The captured request is byte-for-byte what the upstream received: masked, not raw.
    let captured_request =
        std::fs::read(capture_dir.path().join("000001-request.masked.json")).expect("request file");
    assert_eq!(
        &captured_request, upstream_mask_body,
        "capture must equal the real wire bytes"
    );
    let captured_request = String::from_utf8_lossy(&captured_request);
    assert!(
        !captured_request.contains(RAW_EMAIL),
        "raw value in capture: {captured_request}"
    );
    assert!(
        captured_request.contains("EMAIL_001"),
        "placeholder missing: {captured_request}"
    );

    // The captured response is the upstream's exact bytes, before demasking (placeholder kept).
    let captured_response =
        std::fs::read(capture_dir.path().join("000001-response.raw.json")).expect("response file");
    assert_eq!(
        captured_response,
        MOCK_RESPONSE.as_bytes(),
        "capture must be pre-demask bytes"
    );

    // Sanity: the Pass route really did forward the raw value, which is exactly why it must stay
    // out of the capture.
    assert!(String::from_utf8_lossy(upstream_pass_body).contains(RAW_EMAIL));
}
