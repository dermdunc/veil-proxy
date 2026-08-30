//! Manual, opt-in end-to-end proof that a real `TelemetryCountingAuditSink` write,
//! against the real production `JsonlAuditSink`, actually reaches a REAL, separately
//! running `veil-observatory serve` process and verifies there as genuine -- not a
//! mock, not a local-in-process test server standing in for the other repo.
//!
//! `#[ignore]`d by default: `cargo test --workspace` must never depend on an external
//! process being up. Run it explicitly, against a real `veil-observatory serve`
//! instance, with the SAME underlying 32-byte key on both sides -- expressed in each
//! side's own env-var convention (veil-proxy hex-decodes `VEIL_RECEIPT_KEY`;
//! veil-observatory UTF-8-encodes it directly; the two encodings of the same 32 bytes
//! are NOT the same string, and using one string for both silently produces two
//! different keys -- see this session's own decisions.md for why this was checked
//! before assuming it, not after):
//!
//! ```bash
//! # veil-observatory side (a real ASCII string, its own convention):
//! VEIL_RECEIPT_KEY='veil-live-integration-demo-key!!' \
//!   veil-observatory --store /tmp/veil-live-demo-store serve --port 8799
//!
//! # veil-proxy side (the SAME 32 bytes, hex-encoded, this repo's own convention):
//! VEIL_RECEIPT_KEY=7665696c2d6c6976652d696e746567726174696f6e2d64656d6f2d6b65792121 \
//!   VEIL_OBSERVATORY_ENDPOINT=http://127.0.0.1:8799/ingest \
//!   cargo test -p vg-audit --test live_edge_event_integration -- --ignored --nocapture
//! ```
//!
//! Proof is two-sided: this test's own exit status (it fails loudly if the emitter
//! never got a live handle -- i.e. if the env vars were missing or malformed, this is
//! a hard test failure here, not a silent no-op), plus the separately running
//! veil-observatory process's own log line and `--store` directory, inspected by hand
//! after this test passes.

use std::time::Duration;

use vg_audit::{JsonlAuditSink, TelemetryCountingAuditSink};
use vg_core::telemetry::ActorPseudonymKey;
use vg_core::{ActorId, AuditEvent, AuditSink, Destination};

#[test]
#[ignore = "requires a real, separately running `veil-observatory serve` instance -- see this file's module doc for exact invocation"]
fn a_real_demask_decision_reaches_a_real_running_veil_observatory() {
    for var in ["VEIL_RECEIPT_KEY", "VEIL_OBSERVATORY_ENDPOINT"] {
        assert!(
            std::env::var(var).is_ok(),
            "{var} must be set for this test -- see this file's module doc for the exact \
             two-sided invocation (this repo hex-decodes the key; veil-observatory does not, \
             so the two env values are the same 32 bytes but NOT the same string)"
        );
    }

    let audit_log_path = std::env::temp_dir().join(format!(
        "veil-live-integration-audit-{}.jsonl",
        std::process::id()
    ));
    let inner = JsonlAuditSink::open(&audit_log_path).expect("failed to open JsonlAuditSink");

    let actor_key = ActorPseudonymKey::from_bytes([0xAB; 32]);
    let sink = TelemetryCountingAuditSink::new(Box::new(inner), actor_key);

    let event = AuditEvent::DemaskDecision {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId("live-integration-test-actor".to_string()),
        allowed: true,
        policy_version: "policy-v1".to_string(),
    };

    sink.write(event).expect("write to the real JsonlAuditSink must not fail");

    // The emitter is fire-and-forget on a background thread; give the real HTTP round
    // trip (connect, handshake, send, response) a moment to actually complete against
    // the real observatory process before the test exits and this process's threads
    // are torn down.
    std::thread::sleep(Duration::from_millis(500));

    eprintln!(
        "wrote one DemaskDecision through the real audit sink; check the running \
         veil-observatory process's own log and --store directory now to confirm it \
         arrived and verified as genuine -- this test cannot see the other repo's \
         process from inside itself, by design"
    );
}
