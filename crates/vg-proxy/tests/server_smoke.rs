use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Doubt-pass finding: `route_classification.rs` only ever called `route::classify` directly —
/// it never proved the real wire path (`server::handle`'s `req.uri().path_and_query()`
/// extraction, then dispatch into `classify`) actually behaves the same way. This exercises
/// the real `bind`/`run_with_listener`/`handle` chain over a real TCP connection for one case
/// per verdict.
#[tokio::test]
async fn mask_pass_and_block_routes_respond_correctly_over_real_http() {
    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind should succeed on loopback");
    let addr = listener.local_addr().expect("listener has a local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(vg_proxy::server::run_with_listener(listener, async {
        let _ = shutdown_rx.await;
    }));

    let mask = send_request(addr, "POST", "/v1/messages?beta=true").await;
    assert!(mask.starts_with("HTTP/1.1 200"), "mask route: {mask}");
    assert!(
        mask.contains("x-vg-proxy-verdict: mask"),
        "mask route: {mask}"
    );

    let pass = send_request(addr, "GET", "/v1/models?limit=1000").await;
    assert!(pass.starts_with("HTTP/1.1 200"), "pass route: {pass}");
    assert!(
        pass.contains("x-vg-proxy-verdict: pass"),
        "pass route: {pass}"
    );

    let block = send_request(addr, "GET", "/unknown").await;
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
}

#[tokio::test]
async fn bind_refuses_non_loopback_address() {
    let err = vg_proxy::server::bind("0.0.0.0:0".parse().unwrap())
        .await
        .expect_err("binding a non-loopback address must fail");
    assert!(matches!(err, vg_proxy::ProxyError::NotLoopback { .. }));
}

/// Round-2 doubt-pass finding: `run_with_listener` is `pub` (round 1 made it so for
/// testability) and takes an already-bound listener, so `bind()`'s check alone doesn't prove
/// the invariant holds for every entry point — a caller could bind a non-loopback listener
/// directly (bypassing `server::bind` entirely) and call `run_with_listener` with it. This
/// binds via the raw `tokio::net::TcpListener` (not `server::bind`) to prove
/// `run_with_listener` itself refuses to serve a non-loopback listener, independent of how it
/// was constructed.
///
/// **Wrapped in a timeout (round-3 doubt-pass finding).** If the loopback re-check this test
/// guards were ever removed, `run_with_listener` would fall into its accept loop; nothing ever
/// connects to this `0.0.0.0:0` listener and `_shutdown_tx` isn't dropped until the test
/// function itself returns — which can't happen while this `.await` is still pending. Without
/// a timeout, that regression would hang the test (and CI) forever instead of failing it,
/// which defeats the point of a regression test.
#[tokio::test]
async fn run_with_listener_refuses_a_non_loopback_listener_even_when_bind_was_bypassed() {
    let raw_listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("binding 0.0.0.0 at the OS level should succeed");

    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        vg_proxy::server::run_with_listener(raw_listener, async {
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

async fn send_request(addr: SocketAddr, method: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    let request =
        format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read response");
    response
}
