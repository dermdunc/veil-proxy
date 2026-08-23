//! [`EdgeEvent`] — `veil.edge_event.v1`, discrete non-invocation-scoped local acts, from
//! `AuditEvent::DemaskRequest`/`DemaskDecision`/`Block` (pre-send). Never attaches to an
//! `ai_activity` invocation by any means, consistent with `veil-observatory`'s ADR-0014
//! no-fuzzy-matching rule, not a loophole in it.
//!
//! Each variant wraps a private-fielded payload struct (`DemaskRequestPayload`,
//! `DemaskDecisionPayload`, `BlockedAttemptPayload`) rather than declaring fields
//! directly on the enum. This matters because Rust enum variant fields cannot be marked
//! private — there is no `pub(crate) field: T` syntax for them; a field on a variant of
//! a `pub` enum is unconditionally as visible as the enum itself. A third
//! doubt-driven-development round caught that an earlier draft declared `EdgeEvent`'s
//! fields directly on the enum, which meant `BlockedAttempt` (whose field types —
//! `ArtefactKindId::from`, `ReasonCode::from(u16)` — are all unrestricted `pub`) could be
//! fully constructed from outside `vg-core`, bypassing `TryFrom<&AuditEvent>` and its
//! `pub(crate)` constructors entirely. Wrapping each variant's fields in a private
//! struct (the same pattern `TelemetryEvent::Alert(Envelope, Alert)` already uses for
//! `Alert`) closes that: only an opaque, already-validated payload value is visible from
//! outside this module, not its contents.
//!
//! **No `session` field.** An earlier draft added `session: Option<SessionId>` to all
//! three variants and claimed correlation "by `session_id`" — that same review round
//! found no `AuditEvent` variant carries a session id in any form, so under the ratified
//! `TryFrom<&AuditEvent>` signature (which receives only `&AuditEvent`) the field could
//! never be populated with anything but `None`, ever, making it decorative rather than
//! functional. Removed rather than kept-but-always-`None`: session/local-trace
//! correlation for `EdgeEvent` is real future work — it needs either `AuditEvent`
//! gaining a session-carrying field, or `TryFrom`'s signature widening to take ambient
//! context beyond the event itself — neither decided here.
//!
//! `MappingCreated` is deliberately absent: Q8 (`docs/decisions.md`, 2026-08-23,
//! explicitly left **open**, not ratified) defaults it to excluded from v1 telemetry
//! (`TelemetryReject::DeferredByDefault` in `telemetry::mod`) until a concrete persona
//! query needs it.
//!
//! No `Debug` derives here (`docs/architecture/implementation-plan.md` §3.2) — see
//! `telemetry::ids`'s module doc for why.

use super::ids::{ActorPseudonym, ArtefactKindId, ReasonCode, VersionToken};
use crate::api::Destination;

/// Mirrors `AuditEvent::DemaskRequest`'s fields exactly (`dest`, `actor`).
#[derive(Clone, PartialEq, Eq)]
pub struct DemaskRequestPayload {
    dest: Destination,
    actor: ActorPseudonym,
}

impl DemaskRequestPayload {
    pub(crate) fn new(dest: Destination, actor: ActorPseudonym) -> Self {
        Self { dest, actor }
    }
}

/// Mirrors `AuditEvent::DemaskDecision`'s fields exactly (`dest`, `actor`, `allowed`,
/// `policy_version`) — this is the one `AuditEvent` variant actually constructed in
/// production today (`crates/vg-core/src/api.rs`'s `write_demask_decision`), making it
/// the most concretely "next" conversion to unblock once actor pseudonymization lands.
#[derive(Clone, PartialEq, Eq)]
pub struct DemaskDecisionPayload {
    dest: Destination,
    actor: ActorPseudonym,
    allowed: bool,
    policy_version: VersionToken,
}

impl DemaskDecisionPayload {
    pub(crate) fn new(
        dest: Destination,
        actor: ActorPseudonym,
        allowed: bool,
        policy_version: VersionToken,
    ) -> Self {
        Self {
            dest,
            actor,
            allowed,
            policy_version,
        }
    }
}

/// Mirrors `AuditEvent::Block`'s fields exactly (`artefact`, `reason`) — no
/// `policy_version`, which `AuditEvent::Block` doesn't carry either.
#[derive(Clone, PartialEq, Eq)]
pub struct BlockedAttemptPayload {
    artefact: ArtefactKindId,
    reason: ReasonCode,
}

impl BlockedAttemptPayload {
    pub(crate) fn new(artefact: ArtefactKindId, reason: ReasonCode) -> Self {
        Self { artefact, reason }
    }
}

/// `#[non_exhaustive]`: the wire-contract enum for `veil.edge_event.v1` — a fourth
/// adversarial review round found this consistency gap (`Severity` had it, the module
/// most likely to actually grow a variant didn't).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdgeEvent {
    /// From `AuditEvent::DemaskRequest` — see `telemetry::mod`'s module doc for why the
    /// `TryFrom` conversion currently rejects it (actor pseudonymization not yet built).
    DemaskRequest(DemaskRequestPayload),
    /// From `AuditEvent::DemaskDecision` — see `telemetry::mod`'s module doc for why the
    /// `TryFrom` conversion currently rejects it (actor pseudonymization not yet built).
    DemaskDecision(DemaskDecisionPayload),
    /// From `AuditEvent::Block` where nothing reached Bedrock (pre-send block) — see
    /// `telemetry::mod`'s module doc for why the `TryFrom` conversion currently rejects
    /// `Block` (the reason dictionary that would supply `reason: ReasonCode` doesn't
    /// exist yet).
    BlockedAttempt(BlockedAttemptPayload),
}

impl EdgeEvent {
    pub(crate) fn new_demask_request(dest: Destination, actor: ActorPseudonym) -> Self {
        Self::DemaskRequest(DemaskRequestPayload::new(dest, actor))
    }

    pub(crate) fn new_demask_decision(
        dest: Destination,
        actor: ActorPseudonym,
        allowed: bool,
        policy_version: VersionToken,
    ) -> Self {
        Self::DemaskDecision(DemaskDecisionPayload::new(
            dest,
            actor,
            allowed,
            policy_version,
        ))
    }

    pub(crate) fn new_blocked_attempt(artefact: ArtefactKindId, reason: ReasonCode) -> Self {
        Self::BlockedAttempt(BlockedAttemptPayload::new(artefact, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demask_decision_requires_an_actual_bool_not_an_option() {
        // Structural proof, not a runtime assertion: `allowed: bool` (not
        // `Option<bool>`) means a `DemaskDecision` with no recorded outcome is
        // unrepresentable. Constructing one here with an explicit value is the only
        // thing left to exercise.
        let event = EdgeEvent::new_demask_decision(
            Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([7u8; 32]),
            false,
            VersionToken::try_from("policy-v1").unwrap(),
        );
        assert!(matches!(
            event,
            EdgeEvent::DemaskDecision(DemaskDecisionPayload { allowed: false, .. })
        ));
    }

    #[test]
    fn demask_request_carries_no_policy_version_field() {
        // Matches `AuditEvent::DemaskRequest`'s actual shape (`dest`, `actor` only) —
        // structural proof: this constructor takes no `policy_version` argument at all.
        let event = EdgeEvent::new_demask_request(
            Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([7u8; 32]),
        );
        assert!(matches!(event, EdgeEvent::DemaskRequest(_)));
    }

    #[test]
    fn blocked_attempt_carries_a_reason_code_not_free_text() {
        let event =
            EdgeEvent::new_blocked_attempt(ArtefactKindId::EnvFile, ReasonCode::from(42u16));
        assert!(matches!(
            event,
            EdgeEvent::BlockedAttempt(BlockedAttemptPayload {
                artefact: ArtefactKindId::EnvFile,
                ..
            })
        ));
    }

    // No test asserting "payload fields aren't publicly constructible": an earlier
    // draft had one, but its body (`let _ = BlockedAttemptPayload { ... };`, run from
    // *inside* this same private module) can never fail regardless of field
    // visibility — it would still compile and pass if the fields were made `pub`. A
    // fourth adversarial review round flagged it as asserting nothing while claiming to
    // be "structural proof." The actual property (these struct literals don't compile
    // from `crates/vg-core/tests/telemetry.rs`, a different crate) is real — verified by
    // hand at review time — but proving it in CI would need a `trybuild`-style
    // compile-fail test, a new dev-dependency not otherwise justified here. Recorded as
    // a claim a reviewer can re-verify by hand, not as a green check nobody can trust.
}
