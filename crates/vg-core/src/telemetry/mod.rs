//! `TelemetryEvent` — the wire-contract type system for the masked, opt-in telemetry
//! `veil-proxy` sends to `veil-observatory`, per the ratified cross-repo reconciliation at
//! `docs/architecture/telemetry-receipt-reconciliation-plan.md` (2026-08-23) and this
//! crate's own amended `docs/architecture/implementation-plan.md` §3.2-3.4.
//!
//! **Status: type system only, not wired to production.** `TryFrom<&AuditEvent>` below
//! has an explicit, reviewed arm for all six `AuditEvent` variants — required because
//! `AuditEvent` is `#[non_exhaustive]` (`crate::audit`) and a wildcard arm outside
//! `vg-core` would be a silent leak path for future variants (`docs/decisions.md:2883`)
//! — but **every arm currently returns `Err`**. That is not a placeholder oversight; it
//! is the honest state of the codebase this type system was built against:
//!
//! - `Scan`/`PolicyDecision` need trace-scoped aggregation across multiple
//!   `AuditEvent`s to become a [`Receipt`] (per the reconciliation plan's own §3.2: "an
//!   in-emitter aggregator... new machinery... not yet budgeted"), and no trace id
//!   exists anywhere upstream in `vg-core` to aggregate by — `mask()`'s only
//!   identity-bearing parameter is `ns: &Namespace`, and no `AuditEvent` variant carries
//!   an invocation/trace identifier at all.
//! - `Block` is a different gap, not an aggregation one: every current production
//!   `Block` fires pre-send, so it maps to [`EdgeEvent::BlockedAttempt`] (no trace
//!   linkage needed at all) — the only missing piece is `reason: String` →
//!   `ReasonCode`, which needs the not-yet-built reason dictionary. (A second
//!   doubt-driven-development round checked whether `EdgeEvent::BlockedAttempt` secretly
//!   needed anything else `AuditEvent::Block` doesn't carry — e.g. `policy_version` —
//!   and confirmed it now doesn't: `BlockedAttempt`'s fields were corrected to match
//!   `AuditEvent::Block`'s actual shape exactly, so the reason dictionary really is the
//!   only blocker.)
//! - `DemaskRequest`/`DemaskDecision` need a pseudonymized actor identity to become
//!   [`EdgeEvent::DemaskRequest`]/[`EdgeEvent::DemaskDecision`], but `ActorId`
//!   (`crate::ids`) is still a raw `String` — the ratified "keyed HMAC pseudonym,
//!   computed locally" fix has not been built yet (`docs/next-actions.md`'s
//!   six-raw-capable-surfaces item, sequenced *before* this type system and not yet
//!   done). Same cross-check as `Block` above: both `EdgeEvent` variants' fields were
//!   corrected to match their source `AuditEvent` variant exactly (no extra
//!   `policy_version` on `DemaskRequest`, which `AuditEvent::DemaskRequest` doesn't
//!   carry), so pseudonymization really is the only blocker for each.
//! - `MappingCreated` defaults to excluded from v1 telemetry — this is an **open
//!   question (Q8), not a ratified exclusion** (`docs/decisions.md`, 2026-08-23: "left
//!   open as scoped in the plan... defaults to `TelemetryReject` until a concrete
//!   persona query needs `MappingCreated`"). Revisit if that need arises.
//!
//! Every reject is a distinct, named [`TelemetryReject`] variant, not a wildcard — so
//! when the aggregator or actor pseudonymization lands, the corresponding match arm is a
//! forced, reviewed touchpoint, not a silent gap. The value of this module today is the
//! exhaustive, compiler-enforced conversion and the zero-`String`, non-raw-capable
//! payload types themselves — not a working emitter, which is separate, larger,
//! not-yet-scoped work.
//!
//! **No `Debug` derives anywhere in this module or its submodules**, except on the
//! `thiserror::Error` types (`TelemetryReject` and friends), where `std::error::Error`
//! requires it. Their fields are either compile-time-fixed `&'static str` labels or
//! small runtime integers (byte lengths, timestamps) with no raw-string-carrying
//! capacity — safe to render, unlike the value types this rule targets, but not
//! literally "every field is a static label" as an earlier draft of this doc claimed
//! (caught by a fourth adversarial review round). A second-round
//! doubt-driven-development review (Codex) caught
//! `docs/architecture/implementation-plan.md:137`'s explicit "no `Debug` serialisation
//! path" requirement, which an earlier draft of this module missed entirely — every
//! value type derived `Debug` and several tests leaned on `format!("{:?}", ...)` to
//! prove the no-raw-value property. That proof is now purely structural (the bounded
//! types cannot hold a raw string, full stop) rather than a runtime check on a rendering
//! path this module isn't supposed to have at all.
//!
//! `#[allow(dead_code)]` module-wide: nothing here is called from production code yet
//! (see above). Most items are reachable from this module's own `#[cfg(test)]` blocks
//! or the integration tests in `crates/vg-core/tests/telemetry.rs`, which a plain
//! `cargo build`/`cargo clippy` (without `--tests`/`--all-targets`) does not compile —
//! but this repo's actual CI gate does run `--all-targets` (`.github/workflows/ci.yml`),
//! so `#[allow(dead_code)]` is doing real, load-bearing suppression under the gate that
//! actually runs, not just a hedge against a narrower invocation nobody uses. Remove
//! this once the aggregator or actor pseudonymization lands and something in production
//! actually constructs a [`Receipt`]/[`Alert`]/[`EdgeEvent`].
#![allow(dead_code)]

mod alert;
mod edge_event;
mod envelope;
mod ids;
mod pseudonymize;
mod receipt;
mod reject;

pub use alert::{Alert, Severity};
pub use edge_event::EdgeEvent;
pub use envelope::{Envelope, EnvelopeInvariantError, Integrity, SchemaVersion, SigningAlgorithm};
pub use ids::{
    ActorPseudonym, AlertRuleId, ArtefactKindId, DetectorSetId, DeviceRef, DeviceRefError,
    EntityClassId, ExceptionRuleId, KeyRef, ReasonCode, RecordId, RegistryRef, TenantId,
    TokenError, TraceId, VersionToken,
};
pub use pseudonymize::ActorPseudonymKey;
pub use receipt::{
    Action, Controls, ControlsInvariantError, Detection, Outcome, Receipt, TimingInvariantError,
    TraceLinkage,
};
pub use reject::TelemetryReject;

use crate::audit::AuditEvent;

/// Why a `TelemetryEvent` per-kind constructor rejected its input: the envelope's
/// `schema_version` didn't match the payload kind being wrapped. Added after a fourth
/// adversarial review round found nothing coupled `Envelope::schema_version` to the
/// `TelemetryEvent` variant it accompanies — `TelemetryEvent::Alert(env, alert)` could
/// wrap an envelope stamped `ReceiptV2`, and `Integrity::payload_sha256` is documented
/// as needing to cover `schema_version` once signing exists, so a mismatched pair could
/// have been *signed* as consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaVersionMismatch {
    // Not `{expected:?}`/`{got:?}`: `SchemaVersion` has no `Debug` impl (a `telemetry`
    // data type, not an error type; see `telemetry::ids`'s module doc for why), so the
    // message names each side via a static label instead — same pattern as
    // `receipt::outcome_label`.
    #[error("envelope schema_version {got} does not match payload kind {expected}")]
    Mismatch {
        expected: &'static str,
        got: &'static str,
    },
}

fn schema_version_label(v: SchemaVersion) -> &'static str {
    match v {
        SchemaVersion::ReceiptV2 => "ReceiptV2",
        SchemaVersion::AlertV1 => "AlertV1",
        SchemaVersion::EdgeEventV1 => "EdgeEventV1",
    }
}

/// One wire record: a signed envelope plus exactly one of the three ratified payload
/// kinds. See the module doc for why every conversion into this type currently rejects.
/// `#[non_exhaustive]`: this is the wire-contract enum itself — the module's own doc
/// (`§ Every reject is a distinct, named variant`) already anticipates growth as gaps
/// close (a fourth review round added the attribute here to match that stated intent).
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub enum TelemetryEvent {
    /// `veil.receipt.v2` — one per governed Bedrock invocation. Boxed: `Receipt` is by
    /// far the largest payload kind (linkage + invocation + caller + controls +
    /// timing), and clippy's `large_enum_variant` correctly flags the size gap against
    /// `Alert`/`EdgeEvent` otherwise.
    Receipt(Envelope, Box<Receipt>),
    /// `veil.alert.v1` — immediate lane, deliberately minimised.
    Alert(Envelope, Alert),
    /// `veil.edge_event.v1` — non-invocation-scoped local acts (demask, blocked-before-send).
    EdgeEvent(Envelope, EdgeEvent),
}

impl TelemetryEvent {
    /// Per-kind constructors, not bare tuple-variant literals: `TelemetryEvent::Receipt`
    /// etc. remain directly constructible by anything that already holds a valid
    /// `Envelope` + payload pair (Rust cannot restrict tuple-variant construction any
    /// more tightly than the fields it holds — see `telemetry::edge_event`'s module doc
    /// for the general version of this limit), but nothing today can obtain an
    /// `Envelope` or payload value without already having gone through one of these
    /// (`pub(crate)`) constructors or `TryFrom<&AuditEvent>`, so these are the sole
    /// intended construction path in practice. Each checks the envelope's
    /// `schema_version` actually matches the payload kind before pairing them.
    pub(crate) fn new_receipt(
        envelope: Envelope,
        receipt: Receipt,
    ) -> Result<Self, SchemaVersionMismatch> {
        Self::check_schema_version(&envelope, SchemaVersion::ReceiptV2)?;
        Ok(Self::Receipt(envelope, Box::new(receipt)))
    }

    pub(crate) fn new_alert(
        envelope: Envelope,
        alert: Alert,
    ) -> Result<Self, SchemaVersionMismatch> {
        Self::check_schema_version(&envelope, SchemaVersion::AlertV1)?;
        Ok(Self::Alert(envelope, alert))
    }

    pub(crate) fn new_edge_event(
        envelope: Envelope,
        edge_event: EdgeEvent,
    ) -> Result<Self, SchemaVersionMismatch> {
        Self::check_schema_version(&envelope, SchemaVersion::EdgeEventV1)?;
        Ok(Self::EdgeEvent(envelope, edge_event))
    }

    fn check_schema_version(
        envelope: &Envelope,
        expected: SchemaVersion,
    ) -> Result<(), SchemaVersionMismatch> {
        let got = envelope.schema_version();
        if got != expected {
            return Err(SchemaVersionMismatch::Mismatch {
                expected: schema_version_label(expected),
                got: schema_version_label(got),
            });
        }
        Ok(())
    }
}

impl TryFrom<&AuditEvent> for TelemetryEvent {
    type Error = TelemetryReject;

    /// Exhaustive over every current `AuditEvent` variant — no wildcard arm, per
    /// `docs/decisions.md:2883`. See the module doc for why every arm rejects today.
    fn try_from(event: &AuditEvent) -> Result<Self, Self::Error> {
        match event {
            AuditEvent::Scan { .. } => {
                Err(TelemetryReject::RequiresAggregation { variant: "Scan" })
            }
            AuditEvent::PolicyDecision { .. } => Err(TelemetryReject::RequiresAggregation {
                variant: "PolicyDecision",
            }),
            // NOT an aggregation gap, despite sitting next to Scan/PolicyDecision above
            // (caught in doubt-driven-development review — an earlier draft of this
            // match mislabeled it `RequiresAggregation`, which contradicted this
            // module's own `EdgeEvent::BlockedAttempt` design). Every current
            // production `Block` fires pre-send (`api.rs`'s artefact-level block runs
            // before parsing/sending), so it maps directly to `EdgeEvent::BlockedAttempt`
            // — no `TraceLinkage`, no aggregation needed. The only real blocker is
            // `reason: String` → `ReasonCode`, which needs the not-yet-built reason
            // dictionary.
            //
            // Residual assumption, flagged by a fourth adversarial review round: this
            // match receives only `&AuditEvent`, whose fields are all `pub` — nothing
            // stops a *future* caller elsewhere in this workspace from constructing a
            // `Block` that fires *after* content reached Bedrock (contract item 6's
            // missing "was this invocation issued" flag is resolved here by an ambient
            // assumption about how `api.rs` currently uses this variant, not by
            // anything `TryFrom`'s own signature can check). If this arm ever becomes
            // `Ok`, that assumption needs to become a real check first — a
            // `RequiresSendStatus` reject, or a flag threaded through construction.
            AuditEvent::Block { .. } => {
                Err(TelemetryReject::RequiresReasonDictionary { variant: "Block" })
            }
            AuditEvent::MappingCreated { .. } => Err(TelemetryReject::DeferredByDefault {
                variant: "MappingCreated",
                decision_ref: "Q8",
            }),
            AuditEvent::DemaskRequest { .. } => {
                Err(TelemetryReject::RequiresActorPseudonymization {
                    variant: "DemaskRequest",
                })
            }
            // Known residual (doubt-driven-development finding, not fixable here — this
            // signature is frozen, `docs/decisions.md:2883`): now that
            // `EdgeEvent::try_from_audit_event` can distinguish "needs a key"
            // (`RequiresActorPseudonymization`) from "policy_version is independently
            // malformed" (`TelemetryReject::InvalidField`), this arm's blanket
            // `RequiresActorPseudonymization` is a slight overstatement for a
            // `DemaskDecision` whose `policy_version` would fail conversion regardless
            // of the actor key. A caller using only this bare `TryFrom` cannot see that
            // distinction; one using `EdgeEvent::try_from_audit_event` can.
            AuditEvent::DemaskDecision { .. } => {
                Err(TelemetryReject::RequiresActorPseudonymization {
                    variant: "DemaskDecision",
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::envelope::{Integrity, SigningAlgorithm};
    use crate::telemetry::ids::{ActorPseudonym, AlertRuleId, DetectorSetId, RecordId, TraceId};
    use crate::telemetry::receipt::{
        Action, CallerContext, Controls, Detection, EdgeOutcome, InvocationContext, Outcome,
        TimingUs, TraceLinkage,
    };
    use crate::telemetry::{Alert, Severity};
    use uuid::Uuid;

    /// A fourth adversarial review round found nothing in this crate — not even a
    /// test — ever actually constructs a `TelemetryEvent`, `SchemaVersion::AlertV1`,
    /// `SchemaVersion::EdgeEventV1`, `EdgeOutcome::{Complete,Incomplete}`, or
    /// `DeploymentStage::{Testing,Staging,Production}`, despite `#![allow(dead_code)]`
    /// suppressing 19 lib-target warnings that would otherwise say so. These tests are
    /// that missing coverage, and exercise the new schema-version-consistency check.
    fn sample_integrity() -> Integrity {
        Integrity::new(
            [0u8; 32],
            [0u8; 16],
            SigningAlgorithm::HmacSha256,
            None,
            vec![0u8; 32],
        )
    }

    fn sample_envelope(schema_version: SchemaVersion) -> Envelope {
        Envelope::new(
            schema_version,
            1,
            RecordId::from(Uuid::nil()),
            0,
            None,
            None,
            0,
            300_000_000,
            sample_integrity(),
        )
        .unwrap()
    }

    #[test]
    fn new_alert_succeeds_when_schema_version_matches() {
        let envelope = sample_envelope(SchemaVersion::AlertV1);
        let alert = Alert::new(
            AlertRuleId::try_from("secret-in-prompt").unwrap(),
            Severity::High,
        );
        assert!(TelemetryEvent::new_alert(envelope, alert).is_ok());
    }

    #[test]
    fn new_alert_rejects_a_mismatched_schema_version() {
        let envelope = sample_envelope(SchemaVersion::ReceiptV2);
        let alert = Alert::new(
            AlertRuleId::try_from("secret-in-prompt").unwrap(),
            Severity::High,
        );
        assert!(matches!(
            TelemetryEvent::new_alert(envelope, alert),
            Err(SchemaVersionMismatch::Mismatch {
                expected: "AlertV1",
                got: "ReceiptV2"
            })
        ));
    }

    #[test]
    fn new_edge_event_succeeds_when_schema_version_matches() {
        let envelope = sample_envelope(SchemaVersion::EdgeEventV1);
        let edge_event = EdgeEvent::new_demask_request(
            crate::api::Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([1u8; 32]),
        );
        assert!(TelemetryEvent::new_edge_event(envelope, edge_event).is_ok());
    }

    #[test]
    fn new_edge_event_rejects_a_mismatched_schema_version() {
        let envelope = sample_envelope(SchemaVersion::AlertV1);
        let edge_event = EdgeEvent::new_demask_request(
            crate::api::Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([1u8; 32]),
        );
        assert!(TelemetryEvent::new_edge_event(envelope, edge_event).is_err());
    }

    fn sample_receipt() -> Receipt {
        let linkage = TraceLinkage::new(
            TraceId::from(Uuid::nil()),
            TraceId::from(Uuid::nil()),
            TraceId::from(Uuid::nil()),
            None,
            None,
            1,
        );
        let invocation = InvocationContext::new(false);
        let caller = CallerContext::new(ActorPseudonym::from_bytes([2u8; 32]), None, None, None);
        let controls = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("email").unwrap(),
            Outcome::SentUnmodified,
            vec![],
            None,
            vec![],
        )
        .unwrap();
        let timing = TimingUs::new(0, 100, 100).unwrap();
        Receipt::new(
            linkage,
            invocation,
            caller,
            controls,
            timing,
            EdgeOutcome::Complete,
        )
    }

    #[test]
    fn new_receipt_succeeds_when_schema_version_matches() {
        let envelope = sample_envelope(SchemaVersion::ReceiptV2);
        assert!(TelemetryEvent::new_receipt(envelope, sample_receipt()).is_ok());
    }

    #[test]
    fn new_receipt_rejects_a_mismatched_schema_version() {
        let envelope = sample_envelope(SchemaVersion::EdgeEventV1);
        assert!(TelemetryEvent::new_receipt(envelope, sample_receipt()).is_err());
    }

    // Unused imports guard: `Action`, `Detection` are exercised via `receipt.rs`'s own
    // tests, not needed again here — kept off this module's `use` list deliberately.
    #[test]
    fn edge_outcome_and_deployment_stage_variants_are_constructible() {
        let _ = EdgeOutcome::Incomplete;
        let _ = crate::telemetry::receipt::DeploymentStage::Testing;
        let _ = crate::telemetry::receipt::DeploymentStage::Staging;
        let _ = crate::telemetry::receipt::DeploymentStage::Production;
        let _detection = Detection::new(EntityClassId::Email, 1, Action::Masked);
    }
}
