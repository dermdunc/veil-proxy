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

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::ids::{ActorPseudonym, ArtefactKindId, ReasonCode, VersionToken};
use super::pseudonymize::{pseudonymize_actor, ActorPseudonymKey};
use super::reject::TelemetryReject;
use crate::api::Destination;
use crate::audit::AuditEvent;

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

impl Serialize for DemaskRequestPayload {
    /// `destination` reuses `Destination::id()`'s existing stable slug
    /// (`crate::api::Destination`'s `Serialize` impl) rather than a second, independently
    /// maintained string mapping — one source of truth for "what does this destination
    /// look like on any wire," policy-lookup or telemetry. `actor` is the already-opaque
    /// `ActorPseudonym` (32-byte HMAC output, hex-encoded) — the real `ActorId` string
    /// this payload was built from never reaches this impl at all (see this struct's own
    /// field: there is no raw actor field here to accidentally serialize).
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DemaskRequestPayload", 3)?;
        state.serialize_field("kind", "demask_request")?;
        state.serialize_field("destination", &self.dest)?;
        state.serialize_field("actor", &self.actor)?;
        state.end()
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

impl Serialize for DemaskDecisionPayload {
    /// Same `destination`/`actor` treatment as `DemaskRequestPayload`'s impl above.
    /// `policy_version` is `VersionToken` — a charset/length-bounded token, not the raw
    /// `String` `AuditEvent::DemaskDecision.policy_version` started as (see
    /// `EdgeEvent::try_from_audit_event`'s `VersionToken::try_from` conversion, which
    /// already rejects anything outside that bound before a `DemaskDecisionPayload` can
    /// even be constructed).
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("DemaskDecisionPayload", 5)?;
        state.serialize_field("kind", "demask_decision")?;
        state.serialize_field("destination", &self.dest)?;
        state.serialize_field("actor", &self.actor)?;
        state.serialize_field("allowed", &self.allowed)?;
        state.serialize_field("policy_version", &self.policy_version)?;
        state.end()
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

impl Serialize for BlockedAttemptPayload {
    /// `artefact` is the closed `ArtefactKindId` tag (`ArtefactKind::SourceCode`'s
    /// language name already collapsed away by `ArtefactKindId::from`, before this
    /// struct could ever be constructed — see `telemetry::ids`). `reason` is the
    /// integer `ReasonCode`, never `AuditEvent::Block.reason`'s original free-text
    /// string — `BlockReason::classify` in `EdgeEvent::try_from_audit_event` is the only
    /// path that produces one, and it maps a recognized string to this fixed code, never
    /// passes the string itself through.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("BlockedAttemptPayload", 3)?;
        state.serialize_field("kind", "blocked_attempt")?;
        state.serialize_field("artefact", &self.artefact)?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
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
    /// From `AuditEvent::Block` where nothing reached Bedrock (pre-send block). As of
    /// Phase 2 (`telemetry::block_reason`), `try_from_audit_event` resolves a
    /// *recognized* reason to this variant for real in production. The frozen bare
    /// `TryFrom<&AuditEvent>` still rejects `Block` regardless — see that impl's own
    /// arm — for an unrelated reason (`Envelope`/`Integrity` construction, not the
    /// reason dictionary).
    BlockedAttempt(BlockedAttemptPayload),
}

impl Serialize for EdgeEvent {
    /// Delegates straight to whichever payload struct's own `Serialize` impl (above) —
    /// each already emits its own `"kind"` discriminant tag
    /// (`"demask_request"`/`"demask_decision"`/`"blocked_attempt"`), so this impl adds no
    /// wrapping of its own. `#[non_exhaustive]` on this enum (from outside `vg-core`)
    /// doesn't affect this match: it lives inside the defining crate.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            EdgeEvent::DemaskRequest(p) => p.serialize(serializer),
            EdgeEvent::DemaskDecision(p) => p.serialize(serializer),
            EdgeEvent::BlockedAttempt(p) => p.serialize(serializer),
        }
    }
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

    /// A second conversion entry point, alongside (not replacing)
    /// `TryFrom<&AuditEvent> for TelemetryEvent` (`telemetry::mod`): that bare `TryFrom`
    /// can never take a key parameter (its signature is frozen, `docs/decisions.md:2883`),
    /// so it can never produce `Ok` for `DemaskRequest`/`DemaskDecision` no matter what
    /// gaps close elsewhere. This function takes the missing ingredient — an
    /// [`ActorPseudonymKey`] — directly, and so *can* produce those two payloads for
    /// real. It has strictly more context than `TryFrom`, never less: for
    /// `Scan`/`PolicyDecision`/`MappingCreated` it rejects here with exactly the same
    /// [`TelemetryReject`] value `TryFrom<&AuditEvent>` already returns for them (see
    /// `crates/vg-core/tests/telemetry.rs` for a direct consistency check) — nothing
    /// becomes constructible here that `TryFrom` would reject for a reason unrelated to
    /// the actor key. `Block` is the one deliberate exception, not a violation of that
    /// property: as of Phase 2, a *recognized* reason resolves to `Ok` here, while
    /// `TryFrom` still rejects the identical input — for the separate,
    /// unrelated-to-the-reason-dictionary matter of `Envelope`/`Integrity` construction,
    /// which this narrower entry point was never asked to provide either (see
    /// `crates/vg-core/tests/telemetry.rs`'s
    /// `edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose`
    /// for that asymmetry stated explicitly).
    ///
    /// Exhaustive over all six `AuditEvent` variants, no wildcard arm — same rule as
    /// `TryFrom<&AuditEvent>`, for the same reason (`AuditEvent` is `#[non_exhaustive]`;
    /// a wildcard here would silently swallow a future seventh variant instead of
    /// forcing a reviewed touchpoint).
    pub fn try_from_audit_event(
        event: &AuditEvent,
        actor_key: &ActorPseudonymKey,
    ) -> Result<Self, TelemetryReject> {
        match event {
            AuditEvent::DemaskRequest { dest, actor } => Ok(Self::new_demask_request(
                dest.clone(),
                pseudonymize_actor(actor_key, actor),
            )),
            AuditEvent::DemaskDecision {
                dest,
                actor,
                allowed,
                policy_version,
            } => {
                // policy_version: String -> VersionToken can itself fail (bounded-token
                // charset) -- a distinct, actor-key-independent failure mode, so it gets
                // its own reject reason (`InvalidField`) rather than being folded into
                // `RequiresActorPseudonymization`, which would wrongly imply a valid
                // actor key alone would fix it.
                let policy_version =
                    VersionToken::try_from(policy_version.as_str()).map_err(|_| {
                        TelemetryReject::InvalidField {
                            variant: "DemaskDecision",
                            field: "policy_version",
                            reason: "not a valid VersionToken",
                        }
                    })?;
                Ok(Self::new_demask_decision(
                    dest.clone(),
                    pseudonymize_actor(actor_key, actor),
                    *allowed,
                    policy_version,
                ))
            }
            AuditEvent::Scan { .. } => {
                Err(TelemetryReject::RequiresAggregation { variant: "Scan" })
            }
            AuditEvent::PolicyDecision { .. } => Err(TelemetryReject::RequiresAggregation {
                variant: "PolicyDecision",
            }),
            AuditEvent::Block { artefact, reason } => {
                // `reason: String` -> `ReasonCode` via the code-defined reason
                // dictionary (`telemetry::block_reason`) -- no external context needed
                // (unlike the Demask variants above), so this is a plain classification,
                // not another actor-key-shaped gap.
                match super::block_reason::BlockReason::classify(reason) {
                    Some(known) => Ok(Self::new_blocked_attempt(
                        ArtefactKindId::from(artefact),
                        known.reason_code(),
                    )),
                    None => Err(TelemetryReject::UnrecognizedReason {
                        variant: "Block",
                        field: "reason",
                        reason:
                            "no registered BlockReason matched this AuditEvent::Block.reason string",
                    }),
                }
            }
            AuditEvent::MappingCreated { .. } => Err(TelemetryReject::DeferredByDefault {
                variant: "MappingCreated",
                decision_ref: "Q8",
            }),
        }
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

    #[test]
    fn demask_request_serializes_with_the_expected_kind_and_fields() {
        let event = EdgeEvent::new_demask_request(
            Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([0xabu8; 32]),
        );
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["kind"], serde_json::json!("demask_request"));
        assert_eq!(v["destination"], serde_json::json!("remote-model-prompt"));
        assert_eq!(v["actor"], serde_json::json!("ab".repeat(32)));
        // No other keys leaked in (e.g. no raw actor string field exists to leak).
        assert_eq!(v.as_object().unwrap().len(), 3);
    }

    #[test]
    fn demask_decision_serializes_with_the_expected_kind_and_fields() {
        let event = EdgeEvent::new_demask_decision(
            Destination::ObservabilitySink,
            ActorPseudonym::from_bytes([0xcdu8; 32]),
            true,
            VersionToken::try_from("policy-v3.1").unwrap(),
        );
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["kind"], serde_json::json!("demask_decision"));
        assert_eq!(v["destination"], serde_json::json!("observability-sink"));
        assert_eq!(v["actor"], serde_json::json!("cd".repeat(32)));
        assert_eq!(v["allowed"], serde_json::json!(true));
        assert_eq!(v["policy_version"], serde_json::json!("policy-v3.1"));
        assert_eq!(v.as_object().unwrap().len(), 5);
    }

    #[test]
    fn blocked_attempt_serializes_the_reason_as_an_integer_never_the_original_string() {
        let event = EdgeEvent::new_blocked_attempt(ArtefactKindId::EnvFile, ReasonCode::from(1));
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["kind"], serde_json::json!("blocked_attempt"));
        assert_eq!(v["artefact"], serde_json::json!("env_file"));
        assert_eq!(v["reason"], serde_json::json!(1));
        assert!(v["reason"].is_number());
        assert_eq!(v.as_object().unwrap().len(), 3);
    }
}
