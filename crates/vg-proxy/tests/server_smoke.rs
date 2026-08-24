use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
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
use vg_proxy::daemon::Daemon;
use vg_proxy::upstream::UpstreamConfig;
use vg_vault::VaultConfig;

const TEST_KEY: [u8; 32] = [7u8; 32];

fn global_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
}

fn open_daemon(dir: &TempDir) -> Daemon {
    Daemon::open_with_key(
        VaultConfig::new(dir.path().join("vault.db")),
        TEST_KEY,
        PolicyLayers {
            global: global_policy_path(),
            repo: None,
            session: None,
        },
        dir.path().join("audit.jsonl"),
    )
    .expect("daemon opens")
}

/// A no-op `Policy` for tests that never reach masking (the two loopback-refusal tests below,
/// whose server never accepts a connection at all) — only exists because `Daemon::open_with_key`
/// requires *some* valid policy fixture to construct, not because these tests exercise it.
fn unused_daemon(dir: &TempDir) -> Daemon {
    open_daemon(dir)
}

#[derive(Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// `(addr, captured requests, shutdown sender, server task handle)`.
type MockUpstream = (
    SocketAddr,
    Arc<Mutex<Vec<CapturedRequest>>>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
);

/// A minimal mock upstream: accepts connections until `shutdown` fires, records every request
/// it receives (method/path/body), and replies with a fixed, well-formed JSON body.
/// Proves what the *real* proxy sends onward — the point of this whole test file (plan §10.2's
/// `mask_request.rs`/`server.rs` M3 test requirement: "upstream receives a masked body, not the
/// raw one").
fn spawn_mock_upstream() -> MockUpstream {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = TcpListener::from_std(listener).expect("tokio listener");
    let addr = listener
        .local_addr()
        .expect("mock upstream has a local addr");

    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_task = Arc::clone(&captured);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let io = TokioIo::new(stream);
                    let captured = Arc::clone(&captured_for_task);
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let captured = Arc::clone(&captured);
                            async move {
                                let method = req.method().to_string();
                                let path = req.uri().path().to_string();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes().to_vec())
                                    .unwrap_or_default();
                                captured.lock().unwrap().push(CapturedRequest {
                                    method,
                                    path,
                                    body,
                                });
                                let resp = Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(
                                        r#"{"id":"msg_mock","type":"message","role":"assistant","content":[]}"#,
                                    )))
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        let _ = http1::Builder::new().serve_connection(io, service).await;
                    });
                }
            }
        }
    });

    (addr, captured, shutdown_tx, join)
}

/// Doubt-pass finding (carried from M1/M2): `route_classification.rs` only ever called
/// `route::classify` directly — it never proved the real wire path behaves the same way. This
/// exercises the real `bind`/`run_with_listener`/`handle` chain over real TCP connections for
/// all three verdicts, now (M3) proving the real end-to-end consequence of each: `Mask`
/// forwards a *masked* body to the upstream, `Pass` forwards the body unmodified, `Block` never
/// contacts the upstream at all.
#[tokio::test]
async fn mask_pass_and_block_routes_respond_correctly_over_real_http() {
    let dir = TempDir::new().expect("temp dir");
    let daemon = Arc::new(open_daemon(&dir));
    let (upstream_addr, captured, upstream_shutdown, upstream_join) = spawn_mock_upstream();
    let upstream = UpstreamConfig {
        addr: upstream_addr,
    };

    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind should succeed on loopback");
    let addr = listener.local_addr().expect("listener has a local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(vg_proxy::server::run_with_listener(
        listener,
        Arc::clone(&daemon),
        upstream,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let mask_body = br#"{"model":"claude-x","system":"contact jane.doe@example.com","messages":[{"role":"user","content":"hi"}]}"#;
    let namespace = session_header();
    let mask = send_request_with_namespace(
        addr,
        "POST",
        "/v1/messages?beta=true",
        mask_body,
        Some(&namespace),
    )
    .await;
    assert!(mask.starts_with("HTTP/1.1 200"), "mask route: {mask}");
    assert!(
        mask.contains("x-vg-proxy-verdict: mask"),
        "mask route: {mask}"
    );

    let pass = send_request(addr, "GET", "/v1/models?limit=1000", b"").await;
    assert!(pass.starts_with("HTTP/1.1 200"), "pass route: {pass}");
    assert!(
        pass.contains("x-vg-proxy-verdict: pass"),
        "pass route: {pass}"
    );

    let block = send_request(addr, "GET", "/unknown", b"").await;
    assert!(block.starts_with("HTTP/1.1 403"), "block route: {block}");
    assert!(
        block.contains("x-vg-proxy-verdict: block"),
        "block route: {block}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server should shut down promptly")
        .expect("server task should not panic")
        .expect("server should shut down cleanly");

    // The real point of this test: what did the mock upstream actually receive? Copied out of
    // the mutex and the guard dropped immediately after — the assertions below `.await` later
    // in this function (draining `upstream_join`), and holding a `std::sync::MutexGuard`
    // across an `.await` point is a real hazard (clippy's `await_holding_lock`), not merely a
    // style nit.
    let received: Vec<CapturedRequest> = captured.lock().unwrap().clone();
    assert_eq!(
        received.len(),
        2,
        "upstream should see exactly the mask and pass requests, never the blocked one: \
         got {} requests",
        received.len()
    );

    let mask_received = received
        .iter()
        .find(|r| r.path == "/v1/messages")
        .expect("upstream received the mask request");
    let mask_received_str = String::from_utf8_lossy(&mask_received.body);
    assert!(
        !mask_received_str.contains("jane.doe@example.com"),
        "upstream must never receive the raw email: {mask_received_str}"
    );
    assert!(
        mask_received_str.contains("EMAIL_001"),
        "upstream should receive the masked placeholder: {mask_received_str}"
    );

    let pass_received = received
        .iter()
        .find(|r| r.path == "/v1/models")
        .expect("upstream received the pass request");
    assert_eq!(pass_received.method, "GET");

    let _ = upstream_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_join).await;
}

/// A malformed masking body (not valid JSON) on a `Mask` route fails closed — 400, and the
/// upstream is never contacted.
#[tokio::test]
async fn a_malformed_mask_route_body_fails_closed_and_never_reaches_upstream() {
    let dir = TempDir::new().expect("temp dir");
    let daemon = Arc::new(open_daemon(&dir));
    let (upstream_addr, captured, upstream_shutdown, upstream_join) = spawn_mock_upstream();
    let upstream = UpstreamConfig {
        addr: upstream_addr,
    };

    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind should succeed on loopback");
    let addr = listener.local_addr().expect("listener has a local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(vg_proxy::server::run_with_listener(
        listener,
        Arc::clone(&daemon),
        upstream,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let namespace = session_header();
    let response =
        send_request_with_namespace(addr, "POST", "/v1/messages", b"not json", Some(&namespace))
            .await;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "malformed body must fail closed: {response}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server should shut down promptly")
        .expect("server task should not panic")
        .expect("server should shut down cleanly");

    assert!(
        captured.lock().unwrap().is_empty(),
        "upstream must never be contacted for a request that failed to mask"
    );

    let _ = upstream_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_join).await;
}

/// Round-2 doubt-pass regression (Codex): `session.rs`'s own module doc named this exact trap
/// in advance for "whichever milestone adds header-extraction code" — a present-but-invalid
/// (non-UTF-8) `X-VG-Namespace` header must fail closed (400), never silently collapse to
/// "absent" and fall through to the port-fallback resolution path. Sends the header's raw,
/// invalid bytes directly over the wire (a valid UTF-8 request line can't carry them via
/// `format!`), since this is specifically about what happens when `HeaderValue::to_str()`
/// itself fails.
#[tokio::test]
async fn a_present_but_invalid_namespace_header_fails_closed_not_silently_absent() {
    let dir = TempDir::new().expect("temp dir");
    let daemon = Arc::new(open_daemon(&dir));
    let (upstream_addr, captured, upstream_shutdown, upstream_join) = spawn_mock_upstream();
    let upstream = UpstreamConfig {
        addr: upstream_addr,
    };

    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind should succeed on loopback");
    let addr = listener.local_addr().expect("listener has a local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(vg_proxy::server::run_with_listener(
        listener,
        Arc::clone(&daemon),
        upstream,
        async {
            let _ = shutdown_rx.await;
        },
    ));

    let body = b"{}";
    let mut request = Vec::new();
    request.extend_from_slice(b"POST /v1/messages HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: 127.0.0.1\r\n");
    request.extend_from_slice(b"Connection: close\r\n");
    // Invalid UTF-8 (a lone continuation byte) — not a value any HeaderValue::to_str() call
    // can succeed on.
    request.extend_from_slice(b"X-VG-Namespace: \xFF\xFE\r\n");
    request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    request.extend_from_slice(body);

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    stream.write_all(&request).await.expect("write request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");

    assert!(
        response.starts_with("HTTP/1.1 400"),
        "an invalid namespace header must fail closed: {response}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server should shut down promptly")
        .expect("server task should not panic")
        .expect("server should shut down cleanly");

    assert!(
        captured.lock().unwrap().is_empty(),
        "upstream must never be contacted when the namespace header fails to parse"
    );

    let _ = upstream_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), upstream_join).await;
}

#[tokio::test]
async fn bind_refuses_non_loopback_address() {
    let err = vg_proxy::server::bind("0.0.0.0:0".parse().unwrap())
        .await
        .expect_err("binding a non-loopback address must fail");
    assert!(matches!(err, vg_proxy::ProxyError::NotLoopback { .. }));
}

/// `run_with_listener` is `pub` (testability) and takes an already-bound listener, so `bind()`'s
/// check alone doesn't prove the invariant holds for every entry point — a caller could bind a
/// non-loopback listener directly (bypassing `server::bind` entirely) and call
/// `run_with_listener` with it. This binds via the raw `tokio::net::TcpListener` (not
/// `server::bind`) to prove `run_with_listener` itself refuses to serve a non-loopback
/// listener, independent of how it was constructed.
///
/// **Wrapped in a timeout.** If the loopback re-check this test guards were ever removed,
/// `run_with_listener` would fall into its accept loop; nothing ever connects to this
/// `0.0.0.0:0` listener and `_shutdown_tx` isn't dropped until the test function itself
/// returns — which can't happen while this `.await` is still pending. Without a timeout, that
/// regression would hang the test (and CI) forever instead of failing it.
#[tokio::test]
async fn run_with_listener_refuses_a_non_loopback_listener_even_when_bind_was_bypassed() {
    let dir = TempDir::new().expect("temp dir");
    let daemon = Arc::new(unused_daemon(&dir));
    let upstream = UpstreamConfig {
        addr: "127.0.0.1:1".parse().unwrap(),
    };

    let raw_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("binding 0.0.0.0 at the OS level should succeed");

    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        vg_proxy::server::run_with_listener(raw_listener, daemon, upstream, async {
            let _ = shutdown_rx.await;
        }),
    )
    .await
    .expect(
        "run_with_listener should return promptly instead of entering its accept loop \
         (regression: was the loopback re-check removed?)",
    );
    assert!(matches!(
        result,
        Err(vg_proxy::ProxyError::NotLoopback { .. })
    ));
}

/// A fresh session token for the `X-VG-Namespace` header — the real per-session identity a
/// `Mask` route needs to resolve a `Namespace` (`session.rs`'s `resolve`); the local listener's
/// own port-fallback path only kicks in when this header is absent, and this crate has no
/// per-session listener registered in these tests, so a `Mask` request needs the header.
fn session_header() -> String {
    Uuid::new_v4().to_string()
}

async fn send_request(addr: SocketAddr, method: &str, target: &str, body: &[u8]) -> String {
    send_request_with_namespace(addr, method, target, body, None).await
}

async fn send_request_with_namespace(
    addr: SocketAddr,
    method: &str,
    target: &str,
    body: &[u8],
    namespace: Option<&str>,
) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    let namespace_header = namespace
        .map(|ns| format!("X-VG-Namespace: {ns}\r\n"))
        .unwrap_or_default();
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         {namespace_header}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    stream.write_all(&request).await.expect("write request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    response
}
