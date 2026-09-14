//! A2's minimal dev/test harness for the live-run proof (INT-2026-09-13-001 confirmation
//! criterion 2, amended per amendment-2026-09-13-001.yaml): starts a real `vg-proxy` listener
//! wired to the real Anthropic upstream (`UpstreamConfig::real_anthropic()`), registers its own
//! bound loopback address to one fresh session namespace via the H2 port-fallback path (so an
//! unmodified `claude` CLI — which never sends the `X-VG-Namespace` header — still resolves,
//! per `session.rs`'s own documented fallback), prints the listening port on stdout as the only
//! line of output before serving, and runs until killed (`SIGTERM`/`SIGKILL`) — deliberately
//! **not** tied to stdin EOF: a first version of this harness used stdin-close as its shutdown
//! signal, which shut it down immediately when launched from a script whose own stdin was
//! already closed/non-interactive (`cargo run ... &` inherits the parent's stdin), leaving the
//! driving script's `claude` invocation talking to an already-dead proxy. Process-kill is the
//! only signal a script-driven harness can rely on unconditionally.
//!
//! `scripts/a2-live-proof.sh` drives this: reads the printed port, points a real, non-
//! interactive `claude -p` invocation's `ANTHROPIC_BASE_URL` at it, and kills this process by
//! PID afterward.
//!
//! **Not production daemon bootstrap (A3).** State/vault/audit files live in a fresh temp dir,
//! deleted on process exit; the vault key is the same fixed dev/test constant
//! `tests/server_smoke.rs` already uses (`TEST_KEY`), not sourced from the OS keychain — real
//! state-dir/keychain discovery for a `vg-proxy` daemon *binary* is A3's own, separate,
//! unscoped work, deliberately not built here (see this intent's own A3-scope-creep disproof
//! criterion).

use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;
use vg_core::{Namespace, PolicyLayers, SessionId};
use vg_proxy::daemon::Daemon;
use vg_proxy::upstream::UpstreamConfig;
use vg_vault::VaultConfig;

/// Same fixed dev/test key `tests/server_smoke.rs` uses — this harness is exactly that same
/// class of non-production artifact, not a new key-handling surface.
const TEST_KEY: [u8; 32] = [7u8; 32];

fn global_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
}

#[tokio::main]
async fn main() {
    let dir = tempfile::tempdir().expect("create temp state dir for this harness run");

    let daemon = Daemon::open_with_key(
        VaultConfig::new(dir.path().join("vault.db")),
        TEST_KEY,
        PolicyLayers {
            global: global_policy_path(),
            repo: None,
            session: None,
        },
        dir.path().join("audit.jsonl"),
    )
    .expect("open dev-harness daemon");
    let daemon = Arc::new(daemon);

    let listener = vg_proxy::server::bind("127.0.0.1:0".parse().expect("valid loopback addr"))
        .await
        .expect("bind loopback listener");
    let local_addr = listener.local_addr().expect("listener has a local addr");

    // The H2 port-fallback path (plan §5 H2, session.rs): registers this exact bound address to
    // one fresh namespace so a caller that never sends `X-VG-Namespace` (a real, unmodified
    // `claude` CLI) still resolves instead of failing closed with `UnregisteredAddr`.
    let namespace = Namespace::Session(SessionId(Uuid::new_v4()));
    daemon
        .register_port(local_addr, namespace)
        .expect("register this harness's own listener address to a namespace");

    let upstream = UpstreamConfig::real_anthropic();

    // The only stdout line before serving — `scripts/a2-live-proof.sh` parses exactly this.
    println!("VG_PROXY_LIVE_PROOF_PORT={}", local_addr.port());
    use std::io::Write;
    std::io::stdout().flush().expect("flush the port line");

    // Never resolves — this harness's only shutdown path is being killed by PID
    // (`scripts/a2-live-proof.sh`'s own `kill "$HARNESS_PID"` teardown). See the module doc for
    // why an earlier stdin-EOF-based shutdown was wrong for a script-driven, non-interactive
    // harness.
    let shutdown = std::future::pending::<()>();

    vg_proxy::server::run_with_listener(listener, daemon, upstream, shutdown)
        .await
        .expect("harness server should shut down cleanly");
}
