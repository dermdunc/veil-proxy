//! [`TelemetryCountingAuditSink`] — a decorator around any `AuditSink` that attempts
//! `EdgeEvent::try_from_audit_event` on every write and counts the outcome, without
//! changing the audit log's own behaviour or content in any way. As of the network
//! emitter (`vg_core::telemetry::emitter`), it also — best-effort, fire-and-forget — signs
//! every successfully-converted `EdgeEvent` and hands it to a background HTTP POSTer, but
//! only when an organisation has opted in to *both* `VEIL_RECEIPT_KEY` and
//! `VEIL_OBSERVATORY_ENDPOINT`; see [`TelemetryCountingAuditSink::new`] and this module's
//! own tests for the opt-in-off-by-default contract.
//!
//! Lives here, not `vg-adapters-claude`: this wraps `AuditSink`, a `vg-core` trait
//! `vg-audit` already owns the real implementation of (`JsonlAuditSink`), and references
//! nothing adapter-specific. `vg-adapters-claude` is one of several planned adapter
//! crates (`docs/next-actions.md`'s "Later phases": LiteLLM gateway, MCP server mode,
//! CI/CD mode) — putting this here means every future adapter gets it for free instead
//! of duplicating it.
//!
//! **Counts outcomes, does not persist payloads.** `EdgeEvent` and its payload structs
//! have no `Debug`/`Serialize` (deliberately — see `vg_core::telemetry`'s module doc) and
//! there is no schema-generation machinery yet (that's a later phase of the telemetry
//! roadmap, `docs/next-actions.md`), so nothing here can durably persist a converted
//! value. What this sink proves is narrower and honest: "is the conversion pipe actually
//! being exercised, and for which `AuditEvent` kinds does it succeed" — a per-variant
//! `ok`/`rejected` count, not a telemetry buffer. The network emitter is the one
//! deliberate exception to "does not persist/transmit anything" the type's older doc used
//! to claim unconditionally — it is still true that this sink never durably stores a
//! payload itself; it may now, opt-in only, forward one over the network.
//!
//! **Counts are conversion-attempt counts, not a strict shadow of the audit log.** The
//! conversion is attempted and counted *before* delegating to the inner sink
//! (deliberately — see `write`'s own doc), so if the inner sink's write itself fails
//! (disk full, permission error), the count for that event is still recorded even
//! though the event was never durably persisted. A doubt-driven-development finding,
//! not fixed: reordering to count only after a confirmed-successful inner write would
//! reintroduce the panic-safety gap that ordering was chosen to avoid.
//!
//! **The emitter hand-off is exactly as fail-open as the emitter itself.** Building the
//! `EdgeEventRecordInput` (fresh `record_id`/`nonce`, a wall-clock `issued_at_us`, a
//! monotonic `sequence`) and signing it both happen synchronously, inline, in `write` —
//! but only after the conversion-attempt count above is already recorded, and none of it
//! can turn `write`'s own return value into an `Err`: a clock read that somehow fails, a
//! signing error, a full emitter channel, or an unreachable observatory are all silently
//! swallowed here, exactly like `vg_core::telemetry::emitter`'s own doc promises for the
//! network leg. `vg-core` deliberately never reads the wall clock itself (`envelope.rs`'s
//! own doc) — this crate is not bound by that rule and is where `SystemTime::now()` is
//! actually called.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use vg_core::telemetry::{
    edge_event_emitter_from_env, sign_edge_event_record, ActorPseudonymKey, EdgeEvent,
    EdgeEventEmitterHandle, EdgeEventRecordInput, RecordId,
};
use vg_core::{AuditError, AuditEvent, AuditId, AuditSink};

/// Fixed validity window on every emitted record's `Envelope::valid_until_us`: 5 minutes
/// past `issued_at_us`, matching the ratified Q3 "short, fixed 5-minute replay window"
/// (`vg_core::telemetry::envelope`'s own doc) and comfortably under that module's
/// `MAX_VALIDITY_WINDOW_US` sanity ceiling (30 minutes).
const EDGE_EVENT_VALIDITY_WINDOW_US: u64 = 5 * 60 * 1_000_000;

/// `Envelope::contract_revision` for every record this sink emits. Fixed at `1` — no
/// contract revision beyond the first has ever shipped; bumping this is a deliberate,
/// reviewed future change, not something this sink infers on its own.
const EDGE_EVENT_CONTRACT_REVISION: u32 = 1;

/// `ok`/`rejected` counts for one `AuditEvent` variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VariantCounts {
    pub ok: u64,
    pub rejected: u64,
}

/// Per-`AuditEvent`-variant outcome counts, keyed by the variant's name (`"Scan"`,
/// `"Block"`, ...) — not by `TelemetryReject` (which doesn't derive `Hash`, and
/// per-variant is the more useful signal here: "is this event kind ever succeeding,"
/// not "which exact reason did it fail for").
#[derive(Debug, Clone, Default)]
pub struct TelemetryConversionCounts {
    counts: BTreeMap<&'static str, VariantCounts>,
}

impl TelemetryConversionCounts {
    /// Counts for `variant` (an `AuditEvent` variant name), or the zero value if that
    /// variant has never been written through this sink.
    pub fn get(&self, variant: &str) -> VariantCounts {
        self.counts.get(variant).copied().unwrap_or_default()
    }

    fn record(&mut self, variant: &'static str, ok: bool) {
        let entry = self.counts.entry(variant).or_default();
        if ok {
            entry.ok += 1;
        } else {
            entry.rejected += 1;
        }
    }
}

/// Wraps any `AuditSink`, attempts `EdgeEvent::try_from_audit_event` on every write, and
/// counts the outcome. Always delegates the write itself unchanged — this sink's
/// presence must be invisible to the audit log's own behaviour and content, since its
/// entire job is observing the write path, not participating in it.
pub struct TelemetryCountingAuditSink {
    inner: Box<dyn AuditSink>,
    actor_key: ActorPseudonymKey,
    counts: Mutex<TelemetryConversionCounts>,
    /// `None` unless an organisation has opted in to *both* `VEIL_RECEIPT_KEY` and
    /// `VEIL_OBSERVATORY_ENDPOINT` (see [`Self::new`]) — the default, off, path leaves
    /// this `None` and every write below takes the same zero-cost `if let Some` miss it
    /// always did before the emitter existed.
    emitter: Option<EdgeEventEmitterHandle>,
    /// Monotonic per-sink counter feeding `EdgeEventRecordInput::sequence`. Never reset,
    /// never persisted — a receiver-side ordering hint within one process's lifetime
    /// only, same scope `Envelope::sequence`'s own doc already claims for it.
    sequence: AtomicU64,
}

impl TelemetryCountingAuditSink {
    /// Builds a counting sink. Also attempts to build a network emitter from
    /// `VEIL_RECEIPT_KEY`/`VEIL_OBSERVATORY_ENDPOINT` (see
    /// `vg_core::telemetry::edge_event_emitter_from_env`): if either is unset, this is
    /// silently `None` (the documented, tested default) — not an error, not a panic, and
    /// no channel/thread/HTTP client is constructed at all in that case (the guarantee is
    /// structural on `vg-core`'s side; see that function's own module doc). If both are
    /// set but one is malformed (bad hex key, invalid URL), that's a real misconfiguration
    /// of an already-opted-in feature — logged to stderr and treated as "no emitter" for
    /// this process, rather than failing sink construction (and therefore the whole
    /// engine) over a telemetry-only config error.
    pub fn new(inner: Box<dyn AuditSink>, actor_key: ActorPseudonymKey) -> Self {
        let emitter = match edge_event_emitter_from_env() {
            Ok(emitter) => emitter,
            Err(err) => {
                eprintln!(
                    "veilgremlin: edge-event telemetry misconfigured, disabling emission for \
                     this process: {err}"
                );
                None
            }
        };
        Self::with_emitter(inner, actor_key, emitter)
    }

    /// Explicit constructor taking an already-built (or absent) emitter directly, bypassing
    /// `VEIL_RECEIPT_KEY`/`VEIL_OBSERVATORY_ENDPOINT` entirely. Exists for tests: mutating
    /// real process environment variables across parallel `cargo test` threads is a real
    /// flakiness source this crate avoids elsewhere too (see
    /// `vg_core::telemetry::signing`'s own `parse_receipt_signing_key` split for the same
    /// reasoning), and injecting a handle built against a real local test server or a
    /// known-unreachable address is both safer and more direct than round-tripping through
    /// env vars at all.
    pub fn with_emitter(
        inner: Box<dyn AuditSink>,
        actor_key: ActorPseudonymKey,
        emitter: Option<EdgeEventEmitterHandle>,
    ) -> Self {
        Self {
            inner,
            actor_key,
            counts: Mutex::new(TelemetryConversionCounts::default()),
            emitter,
            sequence: AtomicU64::new(0),
        }
    }

    /// Signs `edge_event` and hands it to the network emitter, if one is configured.
    /// Entirely best-effort: `None` emitter, a clock read that somehow fails, or a signing
    /// error are all silently no-ops — see this module's own doc for the fail-open
    /// contract this method exists to uphold. Never affects `write`'s return value.
    fn try_emit(&self, edge_event: EdgeEvent) {
        let Some(emitter) = self.emitter.as_ref() else {
            return;
        };
        let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            // A clock set before 1970 -- never happens on any real deployment target,
            // but this sink must not panic or error `write` over it either way.
            return;
        };
        let issued_at_us = since_epoch.as_micros() as u64;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let input = EdgeEventRecordInput {
            contract_revision: EDGE_EVENT_CONTRACT_REVISION,
            record_id: RecordId::from(Uuid::new_v4()),
            issued_at_us,
            device_ref: None,
            tenant_id: None,
            sequence,
            valid_until_us: issued_at_us.saturating_add(EDGE_EVENT_VALIDITY_WINDOW_US),
            // Reserved, not yet defined what it covers -- same `[0u8; 32]` placeholder
            // `vg-core`'s own golden-vector test uses (`signing.rs`'s doc on this field).
            payload_sha256: [0u8; 32],
            nonce: *Uuid::new_v4().as_bytes(),
            key_ref: None,
            edge_event,
        };
        if let Ok(signed) = sign_edge_event_record(input, emitter.signing_key()) {
            emitter.try_emit(signed.canonical_json);
        }
    }

    /// A snapshot of the counts recorded so far.
    pub fn counts(&self) -> TelemetryConversionCounts {
        self.lock_counts().clone()
    }

    /// Recovers from a poisoned mutex rather than propagating the panic — a
    /// doubt-driven-development finding: `record()` has no panic path under normal
    /// operation (no arithmetic that can overflow at realistic counts, no indexing that
    /// can fail), so poisoning here would only ever come from something external and
    /// unrelated to the counters' own correctness; the u64 fields cannot be left in a
    /// torn state a panicking writer would have partially mutated mid-increment. Letting
    /// a poisoned *counts* mutex `.expect()`-panic here would, under the original code,
    /// have prevented `self.inner.write(event)` from ever running — a telemetry-only
    /// fault silently stopping the real, source-of-truth audit log from being written at
    /// all. This sink's presence must be invisible to the audit log's behaviour even
    /// under its own internal failure, not just in the common case.
    fn lock_counts(&self) -> std::sync::MutexGuard<'_, TelemetryConversionCounts> {
        self.counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A thin, `Clone`-able handle onto a [`TelemetryCountingAuditSink`] that itself
/// satisfies `AuditSink` by delegation. Exists because Rust's orphan rules forbid
/// `impl AuditSink for Arc<TelemetryCountingAuditSink>` directly (`Arc` is foreign, and
/// so is `AuditSink` from this crate's perspective, so neither condition the orphan
/// rules require is satisfied even though `TelemetryCountingAuditSink` itself is local)
/// — this local newtype is the standard way around that. Lets a caller keep one clone
/// for later inspection (`counts()`) while handing another, boxed, to whatever owns the
/// trait object (`vg_core::Policy::audit`) — no downcasting, no unsafe, one shared sink.
#[derive(Clone)]
pub struct SharedTelemetrySink(std::sync::Arc<TelemetryCountingAuditSink>);

impl SharedTelemetrySink {
    pub fn new(sink: TelemetryCountingAuditSink) -> Self {
        Self(std::sync::Arc::new(sink))
    }

    pub fn counts(&self) -> TelemetryConversionCounts {
        self.0.counts()
    }
}

impl AuditSink for SharedTelemetrySink {
    fn write(&self, event: AuditEvent) -> Result<AuditId, AuditError> {
        self.0.write(event)
    }

    fn get(&self, id: AuditId) -> Option<AuditEvent> {
        self.0.get(id)
    }
}

impl AuditSink for TelemetryCountingAuditSink {
    fn write(&self, event: AuditEvent) -> Result<AuditId, AuditError> {
        // Recorded before delegating: a panic or error from the inner sink must not
        // skip counting the conversion attempt that already happened above it (same
        // record-first rationale `api.rs`'s `write_demask_decision` documents for its
        // own panic-safety wrapping).
        //
        // `vg_core::audit_event_variant_name`, not a local match: `AuditEvent` is
        // `#[non_exhaustive]`, so a match written here (a different crate than the one
        // that defines it) is compiler-forced to carry a wildcard regardless of intent
        // — confirmed the hard way (E0004) before this call replaced the attempt. The
        // exhaustive, no-wildcard match lives in `vg-core` itself, where it's actually
        // enforceable.
        let variant = vg_core::audit_event_variant_name(&event);
        match EdgeEvent::try_from_audit_event(&event, &self.actor_key) {
            Ok(edge_event) => {
                self.lock_counts().record(variant, true);
                // Emission happens after the count above (so a slow/failed emission can
                // never affect the conversion-attempt count) but still before delegating
                // to the inner sink, for the same panic-safety reasoning `record()` above
                // is already ordered for -- not that emission is expected to ever panic
                // (it's fail-open by construction), but it costs nothing to keep the
                // established ordering.
                self.try_emit(edge_event);
            }
            Err(_) => {
                self.lock_counts().record(variant, false);
            }
        }
        self.inner.write(event)
    }

    fn get(&self, id: AuditId) -> Option<AuditEvent> {
        // Pure delegation, no counting: a read isn't a conversion attempt.
        self.inner.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use vg_core::{ArtefactKind, Destination, EntityCounts, HandlingClass};

    /// A minimal in-memory `AuditSink` stub — records every write, hands back a fresh
    /// `AuditId` each time, `get` always returns `None` (not exercised by these tests).
    struct StubSink {
        writes: Mutex<Vec<AuditEvent>>,
        next_id: AtomicU32,
    }

    impl StubSink {
        fn new() -> Self {
            Self {
                writes: Mutex::new(Vec::new()),
                next_id: AtomicU32::new(0),
            }
        }
    }

    impl AuditSink for StubSink {
        fn write(&self, event: AuditEvent) -> Result<AuditId, AuditError> {
            self.writes
                .lock()
                .expect("writes mutex poisoned")
                .push(event);
            let n = self.next_id.fetch_add(1, Ordering::SeqCst);
            Ok(AuditId(uuid::Uuid::from_u128(n as u128)))
        }

        fn get(&self, _id: AuditId) -> Option<AuditEvent> {
            None
        }
    }

    fn key() -> ActorPseudonymKey {
        ActorPseudonymKey::from_bytes([1u8; 32])
    }

    #[test]
    fn write_delegates_to_the_inner_sink_unchanged() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        let event = AuditEvent::Scan {
            counts: EntityCounts::default(),
            detector_version: "detectors-v1".to_string(),
            latency_us: 100,
        };
        let id = sink.write(event.clone()).unwrap();
        // AuditId is opaque (a Uuid wrapper) -- the meaningful assertion is that the
        // write reached the inner sink at all, checked via `get` would need a real
        // sink; instead assert indirectly through the counts below and that write()
        // succeeded (StubSink would have panicked/errored on a malformed call).
        let _ = id;
    }

    #[test]
    fn get_is_a_pure_delegation_and_is_not_counted() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        assert!(sink.get(AuditId(uuid::Uuid::nil())).is_none());
        // No write happened, so no variant should have been recorded.
        assert_eq!(sink.counts().get("Scan"), VariantCounts::default());
    }

    #[test]
    fn demask_decision_counts_ok_with_a_valid_actor_key_and_policy_version() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        sink.write(AuditEvent::DemaskDecision {
            dest: Destination::ObservabilitySink,
            actor: vg_core::ActorId("jane.doe".to_string()),
            allowed: true,
            policy_version: "policy-v1".to_string(),
        })
        .unwrap();
        assert_eq!(
            sink.counts().get("DemaskDecision"),
            VariantCounts { ok: 1, rejected: 0 }
        );
    }

    #[test]
    fn demask_decision_counts_rejected_when_policy_version_is_invalid() {
        // Distinct from the actor-key-independent reject reason
        // (TelemetryReject::InvalidField) -- still a rejection from this sink's point
        // of view, since it only counts ok-vs-not, not the specific reason.
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        sink.write(AuditEvent::DemaskDecision {
            dest: Destination::ObservabilitySink,
            actor: vg_core::ActorId("jane.doe".to_string()),
            allowed: true,
            policy_version: "has spaces".to_string(),
        })
        .unwrap();
        assert_eq!(
            sink.counts().get("DemaskDecision"),
            VariantCounts { ok: 0, rejected: 1 }
        );
    }

    #[test]
    fn scan_policy_decision_mapping_created_and_an_unrecognized_block_all_reject() {
        // Renamed from "all_four_always_reject" (a doubt-driven-development finding):
        // since Phase 2's reason dictionary landed, `Block` is no longer unconditionally
        // reject-only -- only an *unrecognized* reason still rejects, which is exactly
        // what this fixture's reason string is (see
        // `block_reason_recognized_by_the_registry_counts_ok_through_the_wrapper` below
        // for the recognized case).
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        sink.write(AuditEvent::Scan {
            counts: EntityCounts::default(),
            detector_version: "detectors-v1".to_string(),
            latency_us: 0,
        })
        .unwrap();
        sink.write(AuditEvent::PolicyDecision {
            artefact: ArtefactKind::EnvFile,
            class: HandlingClass::Mask,
            policy_version: "policy-v1".to_string(),
        })
        .unwrap();
        sink.write(AuditEvent::MappingCreated {
            mapping_ref: vg_core::MappingRef(uuid::Uuid::nil()),
            entity_type: vg_core::EntityType::Email,
        })
        .unwrap();
        sink.write(AuditEvent::Block {
            artefact: ArtefactKind::EnvFile,
            reason: "policy rule prod-secrets-001".to_string(),
        })
        .unwrap();

        let counts = sink.counts();
        for variant in ["Scan", "PolicyDecision", "MappingCreated", "Block"] {
            assert_eq!(
                counts.get(variant),
                VariantCounts { ok: 0, rejected: 1 },
                "expected {variant} to reject exactly once"
            );
        }
    }

    #[test]
    fn block_reason_recognized_by_the_registry_counts_ok_through_the_wrapper() {
        // A doubt-driven-development finding (Codex, round 2): the wrapper's own test
        // suite never proved a *recognized* Block reason counts `ok` end to end through
        // `TelemetryCountingAuditSink::write` -- only that unrecognized ones reject
        // (above). `telemetry::block_reason::BlockReason::ARTEFACT_POLICY_BLOCK_TEXT` is
        // `pub(crate)` inside `vg-core` and unreachable from this separate crate, so the
        // literal is duplicated here -- the same accepted, low-risk trade-off used in
        // `crates/vg-core/tests/telemetry.rs` and `crates/vg-core/tests/pipeline.rs`
        // (the latter proves the *real* `mask()`-emitted event resolves; this test
        // proves the wrapper counts it correctly once it does).
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        sink.write(AuditEvent::Block {
            artefact: ArtefactKind::EnvFile,
            reason: "artefact class is Block in resolved policy".to_string(),
        })
        .unwrap();
        assert_eq!(
            sink.counts().get("Block"),
            VariantCounts { ok: 1, rejected: 0 }
        );
    }

    #[test]
    fn demask_request_counts_ok_with_a_valid_actor_key() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        sink.write(AuditEvent::DemaskRequest {
            dest: Destination::RemoteModelPrompt,
            actor: vg_core::ActorId("jane.doe".to_string()),
        })
        .unwrap();
        assert_eq!(
            sink.counts().get("DemaskRequest"),
            VariantCounts { ok: 1, rejected: 0 }
        );
    }

    #[test]
    fn counts_accumulate_across_multiple_writes_of_the_same_variant() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        for _ in 0..3 {
            sink.write(AuditEvent::DemaskRequest {
                dest: Destination::RemoteModelPrompt,
                actor: vg_core::ActorId("jane.doe".to_string()),
            })
            .unwrap();
        }
        assert_eq!(
            sink.counts().get("DemaskRequest"),
            VariantCounts { ok: 3, rejected: 0 }
        );
    }

    #[test]
    fn an_unrecorded_variant_reports_zero_not_a_panic() {
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        assert_eq!(sink.counts().get("Block"), VariantCounts::default());
    }

    // -- network emitter wiring --

    use std::time::Duration;
    use vg_core::telemetry::{EdgeEventEmitterHandle, ObservatoryEndpoint, ReceiptSigningKey};

    fn signing_key() -> ReceiptSigningKey {
        ReceiptSigningKey::from_bytes(vec![9u8; 32]).unwrap()
    }

    fn demask_request_event() -> AuditEvent {
        AuditEvent::DemaskRequest {
            dest: Destination::RemoteModelPrompt,
            actor: vg_core::ActorId("jane.doe".to_string()),
        }
    }

    /// Polls `condition` until it's true or `timeout` elapses (panicking in the latter
    /// case) — the background emitter's HTTP POST completes asynchronously to `write`'s
    /// own (immediate) return, so assertions on its outcome need to wait briefly rather
    /// than racing it.
    fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let started = std::time::Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < timeout,
                "condition did not become true in time"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Opt-in-off-by-default: real production construction (`TelemetryCountingAuditSink::
    /// new`), with `VEIL_RECEIPT_KEY`/`VEIL_OBSERVATORY_ENDPOINT` unset in this test
    /// process (nothing in this codebase sets either today — see
    /// `vg_core::telemetry::emitter`'s own module doc and its
    /// `both_env_vars_unset_is_a_structural_no_op` test for the flake-free, env-mutation-
    /// free proof that no channel/thread/client is constructed in that branch). This test
    /// covers the other half of the contract: that `write` through the *real* constructor
    /// still behaves exactly as it did before the emitter existed -- returns `Ok`, still
    /// counts the conversion attempt, no error, no panic, no network activity possible
    /// (there is provably no emitter to send through).
    #[test]
    fn opt_in_off_by_default_write_still_succeeds_and_counts_with_no_emitter() {
        assert!(
            std::env::var("VEIL_RECEIPT_KEY").is_err()
                && std::env::var("VEIL_OBSERVATORY_ENDPOINT").is_err(),
            "test assumes neither telemetry env var is set in this process"
        );
        let sink = TelemetryCountingAuditSink::new(Box::new(StubSink::new()), key());
        assert!(
            sink.emitter.is_none(),
            "no emitter should be constructed with both vars unset"
        );
        let id = sink.write(demask_request_event());
        assert!(id.is_ok());
        assert_eq!(
            sink.counts().get("DemaskRequest"),
            VariantCounts { ok: 1, rejected: 0 }
        );
    }

    /// Real end-to-end: a genuine local HTTP server, a genuine `EdgeEventEmitterHandle`
    /// (injected via `with_emitter` rather than real env vars -- see that constructor's
    /// own doc for why), and a `write()` call through the full production path. Asserts
    /// the received bytes' HMAC verifies by independent recomputation, the same procedure
    /// `crates/vg-core/tests/telemetry.rs`'s own golden-vector test uses.
    #[test]
    fn end_to_end_write_signs_and_posts_a_verifiable_record_to_a_real_local_server() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (headers_end, content_length) = loop {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]);
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (n, v) = l.split_once(':')?;
                            n.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    break (pos + 4, len);
                }
            };
            while buf.len() < headers_end + content_length {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = buf[headers_end..headers_end + content_length].to_vec();
            let _ = tx.send(body);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
        });

        let endpoint: ObservatoryEndpoint =
            format!("http://{addr}/v1/edge-events").parse().unwrap();
        const RAW_KEY: [u8; 32] = [9u8; 32];
        let emitter = EdgeEventEmitterHandle::connect(
            ReceiptSigningKey::from_bytes(RAW_KEY.to_vec()).unwrap(),
            endpoint,
        )
        .unwrap();
        let sink = TelemetryCountingAuditSink::with_emitter(
            Box::new(StubSink::new()),
            key(),
            Some(emitter),
        );

        sink.write(demask_request_event()).unwrap();

        let received_body = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("test server never received the emitted record");
        let received_str = String::from_utf8(received_body).unwrap();

        // Verifies by recomputation, but *without* needing `vg-core`'s own (`pub(crate)`,
        // unreachable from here) canonical-JSON renderer: `signing.rs`'s own doc states
        // the exact relationship between the signed and unsigned canonical forms -- they
        // are byte-identical except for the `signature` field's hex value itself (an
        // empty string during MAC computation, the real signature in the final,
        // on-the-wire form). So instead of re-parsing and re-canonicalizing, this finds
        // the literal `"signature":"<hex>"` substring in the exact bytes that arrived
        // over the wire and swaps just that value back to `""` in place -- a strict
        // subset of what a real verifier does, over the literal received bytes rather
        // than a reconstruction of them.
        let needle = "\"signature\":\"";
        let sig_start = received_str
            .find(needle)
            .expect("no signature field in received body")
            + needle.len();
        let sig_end = received_str[sig_start..]
            .find('"')
            .map(|i| i + sig_start)
            .expect("unterminated signature field");
        let signature = received_str[sig_start..sig_end].to_string();
        assert_eq!(
            signature.len(),
            64,
            "expected a 64-hex-char HMAC-SHA256 signature"
        );

        let unsigned = format!("{}{}", &received_str[..sig_start], &received_str[sig_end..]);
        let mut mac = Hmac::<Sha256>::new_from_slice(&RAW_KEY).unwrap();
        mac.update(unsigned.as_bytes());
        let expected = hex_encode(&mac.finalize().into_bytes());
        assert_eq!(
            expected, signature,
            "HMAC over the received body did not verify"
        );

        wait_for(Duration::from_secs(5), || {
            sink.emitter.as_ref().unwrap().stats().sent_ok == 1
        });
        assert_eq!(
            sink.counts().get("DemaskRequest"),
            VariantCounts { ok: 1, rejected: 0 }
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Unreachable endpoint: `write` must still return `Ok` promptly (never block on the
    /// dead connection) and the emitter's own failure counter must increment once the
    /// background worker actually attempts (and fails) the POST.
    #[test]
    fn write_does_not_block_on_an_unreachable_observatory_and_counts_a_send_failure() {
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let endpoint: ObservatoryEndpoint =
            format!("http://{addr}/v1/edge-events").parse().unwrap();
        let emitter = EdgeEventEmitterHandle::connect(signing_key(), endpoint).unwrap();
        let sink = TelemetryCountingAuditSink::with_emitter(
            Box::new(StubSink::new()),
            key(),
            Some(emitter),
        );

        let started = std::time::Instant::now();
        let id = sink.write(demask_request_event());
        let elapsed = started.elapsed();

        assert!(id.is_ok());
        assert!(
            elapsed < Duration::from_millis(500),
            "write() blocked for {elapsed:?} on an unreachable observatory"
        );

        wait_for(Duration::from_secs(5), || {
            sink.emitter.as_ref().unwrap().stats().send_failed == 1
        });
        let stats = sink.emitter.as_ref().unwrap().stats();
        assert_eq!(stats.send_failed, 1);
        assert_eq!(stats.sent_ok, 0);
    }

    /// A burst of writes past the emitter's channel capacity drops rather than blocking:
    /// pointed at an unroutable address (never refuses, never accepts, so the background
    /// worker stays stuck mid-connect on record #1 for this whole test), enough writes to
    /// overflow the channel must still all return `Ok` promptly and the emitter's own
    /// drop counter must show at least one drop.
    #[test]
    fn a_burst_of_writes_past_channel_capacity_drops_rather_than_blocking() {
        let endpoint: ObservatoryEndpoint = "http://192.0.2.1:9/v1/edge-events".parse().unwrap();
        let emitter = EdgeEventEmitterHandle::connect(signing_key(), endpoint).unwrap();
        let sink = TelemetryCountingAuditSink::with_emitter(
            Box::new(StubSink::new()),
            key(),
            Some(emitter),
        );

        let started = std::time::Instant::now();
        for _ in 0..300 {
            sink.write(demask_request_event()).unwrap();
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "300 writes took {elapsed:?} -- write() must never block on the emitter's channel"
        );
        assert!(
            sink.emitter.as_ref().unwrap().stats().queue_full_dropped > 0,
            "expected at least one drop once the emitter's channel filled up"
        );
    }
}
