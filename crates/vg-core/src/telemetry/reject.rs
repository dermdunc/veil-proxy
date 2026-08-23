//! [`TelemetryReject`] — why `TryFrom<&AuditEvent> for TelemetryEvent` declined to
//! convert a given audit event. `Clone, PartialEq, Eq` like
//! [`crate::error::RehydrateDenied`] (a `pub struct`, not an enum — an earlier draft of
//! this doc claimed a shape match that didn't exist); this is a per-cause `enum`
//! instead, since there are four distinct reasons a conversion currently fails and
//! callers/tests need to tell them apart.

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

    /// `Block` needs its free-text `reason: String` converted to a `ReasonCode` via a
    /// versioned reason dictionary — not yet built
    /// (`telemetry::ids::ReasonCode`'s doc, `telemetry-receipt-reconciliation-plan.md`
    /// §5). **Not an aggregation gap**: every current production `Block` fires pre-send
    /// (`crates/vg-core/src/api.rs`'s artefact-level block runs before parsing/sending),
    /// so it maps directly to `EdgeEvent::BlockedAttempt`, which carries no trace
    /// linkage and needs none — the reason dictionary is the only thing missing.
    #[error("{variant} requires the reason dictionary, not yet implemented")]
    RequiresReasonDictionary { variant: &'static str },

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
}
