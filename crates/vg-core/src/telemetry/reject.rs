//! [`TelemetryReject`] — why `TryFrom<&AuditEvent> for TelemetryEvent` (and, since
//! Phase 1, `EdgeEvent::try_from_audit_event` too) declined to convert a given audit
//! event. `Clone, PartialEq, Eq` like [`crate::error::RehydrateDenied`] (a `pub struct`,
//! not an enum — an earlier draft of this doc claimed a shape match that didn't exist);
//! this is a per-cause `enum` instead, since callers/tests need to tell distinct
//! rejection reasons apart. Deliberately not a fixed count in this doc comment (an
//! earlier version said "four," which drifted stale as soon as a fifth variant landed)
//! — see the enum's own variant list for the current, authoritative set.

use thiserror::Error;

/// `#[non_exhaustive]`: this module's own doc already says new variants land as gaps
/// close — a fourth review round noted the attribute was missing given that stated
/// intent (an exhaustive downstream `match` over this enum compiles today and would
/// break the moment a fifth reason is added).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TelemetryReject {
    /// `Scan`/`PolicyDecision` need trace-scoped aggregation with the other
    /// `AuditEvent`s from the same invocation to become a `Receipt` — not yet built (see
    /// `telemetry::mod`'s module doc).
    #[error("{variant} requires trace-scoped aggregation, not yet implemented")]
    RequiresAggregation { variant: &'static str },

    /// `DemaskRequest`/`DemaskDecision` need a pseudonymized actor identity to become an
    /// `EdgeEvent::DemaskRequest`/`EdgeEvent::DemaskDecision` — `ActorId` is still a raw
    /// `String`, and the ratified keyed-HMAC pseudonymization fix has not been built
    /// yet.
    #[error("{variant} requires ActorId pseudonymization, not yet implemented")]
    RequiresActorPseudonymization { variant: &'static str },

    /// **Not a ratified permanent exclusion — a default pending an open decision.** For
    /// `MappingCreated` specifically: `docs/decisions.md`'s 2026-08-23 entry is explicit
    /// that "Q7, Q8 [were] left open as scoped in the plan," with Q8 "default[ing] to
    /// `TelemetryReject` until a concrete persona query needs `MappingCreated`" — the
    /// reconciliation plan's own disposition table (§0) says the same:
    /// "demoted to non-blocking with `TelemetryReject` as the stated default." An
    /// earlier draft of this variant (named `ExcludedByPolicy`, documented as "not a
    /// gap, a deliberate scope boundary") mischaracterised an explicitly-open question
    /// as settled — caught by a fourth adversarial review round, which flagged that the
    /// wrong reason code tells a future implementer to stop looking rather than to check
    /// whether Q8 has since been answered. `decision_ref` names the open question this
    /// default traces to (e.g. `"Q8"`).
    #[error("{variant} deferred pending open decision {decision_ref} (default, not ratified)")]
    DeferredByDefault {
        variant: &'static str,
        decision_ref: &'static str,
    },

    /// A field that has an actor-pseudonymization-independent conversion failure of its
    /// own — e.g. `DemaskDecision`'s `policy_version: String` failing
    /// `VersionToken`'s bounded-charset validation. Distinct from
    /// [`RequiresActorPseudonymization`](Self::RequiresActorPseudonymization): supplying
    /// a valid actor key would not fix this rejection, so conflating the two would hide
    /// a real, independently-actionable data problem behind "pseudonymization isn't
    /// built yet." Added for [`crate::telemetry::EdgeEvent::try_from_audit_event`],
    /// which has more context (an actor key) than the bare `TryFrom<&AuditEvent>` and so
    /// can surface this failure mode instead of always reporting
    /// `RequiresActorPseudonymization`.
    #[error("{variant}.{field} failed conversion: {reason}")]
    InvalidField {
        variant: &'static str,
        field: &'static str,
        reason: &'static str,
    },

    /// A free-text field that does not match any entry in a code-defined lookup
    /// registry — e.g. `Block.reason: String` failing to match
    /// `telemetry::block_reason::BlockReason::classify`'s known set of exact reason
    /// strings. Distinct from [`InvalidField`](Self::InvalidField): `InvalidField` is
    /// for a value that fails a *structural* check (a charset, a length bound);
    /// `UnrecognizedReason` is for a value that is well-formed but simply isn't one of
    /// the finitely many reasons this crate currently knows how to name — most likely
    /// because a new `AuditEvent`-producing call site was added without registering its
    /// reason. `reason` here is a static description of *what kind of thing* failed to
    /// match, never the raw input string — this boundary refuses free-text pass-through
    /// by construction, not by checking case-by-case whether a given string happens to
    /// be safe to echo.
    #[error("{variant}.{field} did not match a known reason: {reason}")]
    UnrecognizedReason {
        variant: &'static str,
        field: &'static str,
        reason: &'static str,
    },

    /// The variant's own payload genuinely *would* resolve — every other check (e.g.
    /// `Block.reason` matching a registered [`UnrecognizedReason`](Self::UnrecognizedReason)-free
    /// entry) has already passed — but a full `TelemetryEvent` still can't be built
    /// because `Envelope`/`Integrity` construction (timestamps, sequence, signing) isn't
    /// available yet, gated on `veil-custodian`'s device signing key, unbuilt. Only
    /// returned when the payload-level check truly passed first — a doubt-driven-
    /// development round caught an earlier draft returning this unconditionally for
    /// every `Block`, which was false for an unrecognized reason (that case would never
    /// resolve, envelope construction or not; see `Block`'s own arm in
    /// `impl TryFrom<&AuditEvent> for TelemetryEvent`, which now checks first and
    /// returns [`UnrecognizedReason`](Self::UnrecognizedReason) instead when that's the
    /// real blocker). Exists so the frozen `TryFrom<&AuditEvent>`'s rejects stay
    /// *accurate* even though its function *signature* itself can never change
    /// (`docs/decisions.md:2883`) — nothing stops it from returning a different, correct
    /// `TelemetryReject` variant.
    #[error("{variant} would resolve, but Envelope/Integrity construction is not available yet")]
    RequiresEnvelopeConstruction { variant: &'static str },
}
