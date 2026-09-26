//! Dev-only wire capture refuses a non-empty capture directory: sequence numbers restart at 1 per
//! process, so a reused directory could silently mix an earlier run's files into this one's.
//! Its own test binary for the same reason as `tests/capture.rs`: the configuration is read once
//! per process from a process-wide environment variable.

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

/// A capture directory that already holds files disables capture entirely: nothing new is written,
/// and the stale files are left untouched for the operator to deal with.
#[tokio::test]
async fn capture_refuses_a_non_empty_capture_dir() {
    let capture_dir = TempDir::new().expect("capture dir");
    let stale = capture_dir.path().join("000002-request.masked.json");
    std::fs::write(&stale, b"stale from an earlier run").expect("seed stale file");
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
    let (upstream_addr, _received, upstream_shutdown) = spawn_mock_upstream();
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

    let mask_body = format!(
        r#"{{"model":"claude-x","system":"contact {RAW_EMAIL}","messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    let ns = Uuid::new_v4().to_string();
    let resp = send(
        addr,
        "POST",
        "/v1/messages",
        mask_body.as_bytes(),
        Some(&ns),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "proxying must be unaffected: {resp}"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server shuts down")
        .expect("server task ok")
        .expect("clean shutdown");
    let _ = upstream_shutdown.send(());

    assert_eq!(
        capture_files(capture_dir.path()),
        vec!["000002-request.masked.json"],
        "a non-empty dir must disable capture: no marker, no new files"
    );
}
