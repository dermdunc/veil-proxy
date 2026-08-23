//! [`Receipt`] — `veil.receipt.v2`, one per governed Bedrock invocation. Field shapes
//! match the ratified field sketch in
//! `docs/architecture/telemetry-receipt-reconciliation-plan.md` §3.2 Kind A, with the
//! §2.2/§3.2 redaction-semantics fix applied: [`Action`] (per-entity-class) and
//! [`Outcome`] (per-invocation) are two independent dimensions, not one conflated enum —
//! the draft plan's `blocked_with_redaction` value was a modelling error the ratified
//! plan corrected (`IrreversibleRedact` is not `Block`; redacted content is normally
//! still sent).
//!
//! **Deliberately not exhaustive of every field the reconciliation plan's prose
//! mentions** (e.g. `aws_account_id`/`aws_region`/`effective_region_set`, `model_ref`,
//! `operation` are not yet typed here) — `Receipt` is unconstructible in production
//! either way this slice (see `telemetry::mod`'s module doc), so expanding every field
//! now adds surface without adding tested value. Flagged as a completeness question for
//! the doubt-driven-development pass, not a silent omission.
//!
//! No `Debug` derives here (`docs/architecture/implementation-plan.md:137`) — see
//! `telemetry::ids`'s module doc for why; `ControlsInvariantError` is the one exception,
//! for the same `thiserror`/safe-fields-only reason as `telemetry::ids`'s error types.

use thiserror::Error;

use super::ids::{
    ActorPseudonym, DetectorSetId, EntityClassId, ExceptionRuleId, ReasonCode, RecordId,
    RegistryRef, TraceId, VersionToken,
};
use crate::ids::SessionId;
use crate::types::HandlingClass;

/// Correlates a `Receipt` to the Bedrock invocation it describes. `veil_trace_id`
/// requires veil-proxy to adopt Bedrock `requestMetadata` stamping — currently absent
/// from the codebase entirely (`telemetry::mod`'s module doc).
#[derive(Clone, PartialEq, Eq)]
pub struct TraceLinkage {
    veil_trace_id: TraceId,
    logical_interaction_id: TraceId,
    local_trace_id: TraceId,
    parent: Option<RecordId>,
    session: Option<SessionId>,
    attempt: u16,
}

impl TraceLinkage {
    pub(crate) fn new(
        veil_trace_id: TraceId,
        logical_interaction_id: TraceId,
        local_trace_id: TraceId,
        parent: Option<RecordId>,
        session: Option<SessionId>,
        attempt: u16,
    ) -> Self {
        Self {
            veil_trace_id,
            logical_interaction_id,
            local_trace_id,
            parent,
            session,
            attempt,
        }
    }
}

/// Bedrock invocation context. Minimal for this slice — see module doc.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InvocationContext {
    streaming: bool,
}

impl InvocationContext {
    pub(crate) fn new(streaming: bool) -> Self {
        Self { streaming }
    }
}

/// Edge's own view of deployment stage, per ratified Q9: `caller.environment` was
/// dropped entirely (free-form, leaked infra naming); `deployment_stage`'s closed enum
/// was kept as the sole survivor of that field family.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeploymentStage {
    InteractiveDevelopment,
    Testing,
    Staging,
    Production,
}

/// Caller context. `principal_ref`/`repository_id`/`workspace_id` are pseudonym or
/// registry-ref types per the reconciliation plan §2.4/§3.2 — never raw paths or
/// identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct CallerContext {
    principal_ref: ActorPseudonym,
    repository_id: Option<RegistryRef>,
    workspace_id: Option<RegistryRef>,
    deployment_stage: Option<DeploymentStage>,
}

impl CallerContext {
    pub(crate) fn new(
        principal_ref: ActorPseudonym,
        repository_id: Option<RegistryRef>,
        workspace_id: Option<RegistryRef>,
        deployment_stage: Option<DeploymentStage>,
    ) -> Self {
        Self {
            principal_ref,
            repository_id,
            workspace_id,
            deployment_stage,
        }
    }
}

/// Per-entity-class handling — a 1:1 rename of `HandlingClass`
/// (`crate::types::HandlingClass`: `Mask`→`Masked`, `IrreversibleRedact`→`Redacted`,
/// `Block`→`Blocked`, `Pass`→`Allowed`), not an addition (an earlier draft's doc said
/// `Action` "gains `Redacted`," implying a widening that didn't happen — both enums
/// have always had four variants; caught by a fourth adversarial review round).
/// `#[non_exhaustive]`: telemetry's own wire-contract enum, not `HandlingClass` itself —
/// a future `HandlingClass` variant is still exhaustively matched by `From` below
/// (`HandlingClass` isn't `#[non_exhaustive]`), but downstream consumers of `Action`
/// should not assume this stays four variants forever.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Action {
    Masked,
    Redacted,
    Blocked,
    Allowed,
}

impl From<HandlingClass> for Action {
    /// Exhaustive over `HandlingClass`'s current variants, compiler-enforced (not
    /// `#[non_exhaustive]`, so no wildcard needed) — the same discipline
    /// `EntityClassId::from(&EntityType)` and `ArtefactKindId::from(&ArtefactKind)`
    /// apply, added here after a fourth adversarial review round noted `Action` claimed
    /// to be "a direct generation of `HandlingClass`" with no actual conversion linking
    /// the two.
    fn from(class: HandlingClass) -> Self {
        match class {
            HandlingClass::Mask => Action::Masked,
            HandlingClass::IrreversibleRedact => Action::Redacted,
            HandlingClass::Block => Action::Blocked,
            HandlingClass::Pass => Action::Allowed,
        }
    }
}

/// Per-invocation/artefact outcome — independent from [`Action`]. `BlockedBeforeSend`
/// only covers the artefact-level partial-block case; a wholly blocked attempt is a
/// `veil.edge_event.v1` record instead (`telemetry::edge_event::EdgeEvent::BlockedAttempt`),
/// since a wholly blocked invocation never reaches Bedrock and has no `TraceLinkage` to
/// attach a `Receipt` to (reconciliation plan §2.2(b)).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    SentUnmodified,
    SentMasked,
    SentRedacted,
    SentMaskedAndRedacted,
    BlockedBeforeSend,
}

/// One entity-class detection within an invocation. `count` must be at least 1 (see
/// [`Detection::new`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    class: EntityClassId,
    count: u32,
    action: Action,
}

/// Why `Detection::new` rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DetectionInvariantError {
    #[error("Detection::count must be at least 1, got 0")]
    ZeroCount,
}

impl Detection {
    /// Rejects `count == 0`. A fourth adversarial review round found this unchecked:
    /// `vec![Detection::new(Email, 0, Masked)]` satisfied `Controls::new`'s
    /// "detections must be non-empty" invariant (§2.4a-1) while carrying literally zero
    /// evidence of what was masked — exactly the failure §2.4a-1 exists to prevent,
    /// reintroduced one layer down.
    pub(crate) fn new(
        class: EntityClassId,
        count: u32,
        action: Action,
    ) -> Result<Self, DetectionInvariantError> {
        if count == 0 {
            return Err(DetectionInvariantError::ZeroCount);
        }
        Ok(Self {
            class,
            count,
            action,
        })
    }
}

/// Why `Controls::new` rejected its input. Derives `Debug`: required by
/// `std::error::Error` (`thiserror`) — which is why `DetectionsRequiredForOutcome`
/// carries `outcome_label: &'static str` rather than the raw `Outcome` value: `Outcome`
/// deliberately has no `Debug` impl (it's a `telemetry` data type, not an error type;
/// see this module's doc), and `#[derive(Debug)]` on this enum would require every
/// field's type to implement `Debug` too, not just the fields actually interpolated
/// into an `#[error(...)]` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ControlsInvariantError {
    #[error(
        "outcome {outcome_label} requires at least one Detection, none were provided \
         (reconciliation plan §2.4a-1)"
    )]
    DetectionsRequiredForOutcome { outcome_label: &'static str },
    #[error("outcome BlockedBeforeSend requires a block_reason, none was provided")]
    BlockReasonRequiredForBlockedOutcome,
}

/// Static label for `ControlsInvariantError`'s message — `Outcome` has no `Debug` impl
/// (see above), so this is the non-Debug way to name which outcome triggered the error.
fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::SentUnmodified => "SentUnmodified",
        Outcome::SentMasked => "SentMasked",
        Outcome::SentRedacted => "SentRedacted",
        Outcome::SentMaskedAndRedacted => "SentMaskedAndRedacted",
        Outcome::BlockedBeforeSend => "BlockedBeforeSend",
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Controls {
    policy_version: VersionToken,
    detector_version: DetectorSetId,
    outcome: Outcome,
    detections: Vec<Detection>,
    block_reason: Option<ReasonCode>,
    exceptions: Vec<ExceptionRuleId>,
}

impl Controls {
    /// Two invariants enforced here rather than left to convention:
    /// - `detections` must be non-empty whenever `outcome != Outcome::SentUnmodified`
    ///   (reconciliation plan §2.4a-1: "a receipt asserting `decision:
    ///   allow_with_masking` with no detections array... claims masking occurred while
    ///   carrying zero evidence of what was masked").
    /// - `block_reason` must be present whenever `outcome == Outcome::BlockedBeforeSend`.
    ///
    /// Checked in that order: a value violating both returns
    /// `DetectionsRequiredForOutcome`, not `BlockReasonRequiredForBlockedOutcome` — both
    /// violations are real, but only one is reported. Not currently a problem in
    /// practice (nothing constructs `Controls` outside tests yet), flagged so a future
    /// caller relying on this error to distinguish "which single thing is wrong" doesn't
    /// assume it's exhaustive.
    pub(crate) fn new(
        policy_version: VersionToken,
        detector_version: DetectorSetId,
        outcome: Outcome,
        detections: Vec<Detection>,
        block_reason: Option<ReasonCode>,
        exceptions: Vec<ExceptionRuleId>,
    ) -> Result<Self, ControlsInvariantError> {
        if outcome != Outcome::SentUnmodified && detections.is_empty() {
            return Err(ControlsInvariantError::DetectionsRequiredForOutcome {
                outcome_label: outcome_label(outcome),
            });
        }
        if outcome == Outcome::BlockedBeforeSend && block_reason.is_none() {
            return Err(ControlsInvariantError::BlockReasonRequiredForBlockedOutcome);
        }
        Ok(Self {
            policy_version,
            detector_version,
            outcome,
            detections,
            block_reason,
            exceptions,
        })
    }
}

/// Why `TimingUs::new` rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TimingInvariantError {
    #[error("completed_us ({completed_us}) must be >= started_us ({started_us})")]
    CompletedBeforeStarted { started_us: u64, completed_us: u64 },
}

/// Timing in microseconds throughout — the reconciliation plan's §2.7 fix: the draft
/// receipt schema's millisecond granularity "destroys the signal" for a hot path this
/// project treats "like a low-latency trading system."
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TimingUs {
    started_us: u64,
    completed_us: u64,
    latency_us: u64,
}

impl TimingUs {
    /// Rejects `completed_us < started_us` (a second doubt-driven-development round
    /// found this unchecked). Does **not** require `latency_us == completed_us -
    /// started_us` exactly — `latency_us` may legitimately be measured over a narrower
    /// or differently-instrumented span than the raw wall-clock delta, and forcing exact
    /// arithmetic equality would assert a precision this type has no way to verify.
    pub(crate) fn new(
        started_us: u64,
        completed_us: u64,
        latency_us: u64,
    ) -> Result<Self, TimingInvariantError> {
        if completed_us < started_us {
            return Err(TimingInvariantError::CompletedBeforeStarted {
                started_us,
                completed_us,
            });
        }
        Ok(Self {
            started_us,
            completed_us,
            latency_us,
        })
    }
}

/// `complete | incomplete` — the reconciliation plan's §2.4a-2 fix: the draft receipt
/// schema made this field optional with `default: "complete"`, which is fail-open on
/// exactly the coverage signal the field exists to carry (a "failure receipt stub" when
/// the edge crashed after sending the Bedrock request but before persisting the
/// receipt). No `Default` impl here, deliberately — every `Receipt` must state this
/// explicitly.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeOutcome {
    Complete,
    Incomplete,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Receipt {
    linkage: TraceLinkage,
    invocation: InvocationContext,
    caller: CallerContext,
    controls: Controls,
    timing_us: TimingUs,
    edge_outcome: EdgeOutcome,
}

impl Receipt {
    // No `#[allow(clippy::too_many_arguments)]`: 6 args is under clippy's default
    // threshold of 7. An earlier draft cargo-culted this from `Envelope::new` (9 args,
    // where the allow is genuinely needed) — caught by a fourth adversarial review
    // round (verified: removing it leaves `clippy -D warnings` clean).
    pub(crate) fn new(
        linkage: TraceLinkage,
        invocation: InvocationContext,
        caller: CallerContext,
        controls: Controls,
        timing_us: TimingUs,
        edge_outcome: EdgeOutcome,
    ) -> Self {
        Self {
            linkage,
            invocation,
            caller,
            controls,
            timing_us,
            edge_outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::ids::{ActorPseudonym, RecordId, TraceId};
    use uuid::Uuid;

    /// Exercises `TraceLinkage::new`, `InvocationContext::new`, `CallerContext::new`,
    /// and `Receipt::new` end to end — a doubt-driven-development review found these
    /// four constructors were never called anywhere in the crate, not even in tests,
    /// contradicting this module's own doc claim that everything here is exercised by
    /// `#[cfg(test)]` coverage. This is that missing coverage.
    #[test]
    fn receipt_constructs_end_to_end_with_all_fields_private_and_typed() {
        let linkage = TraceLinkage::new(
            TraceId::from(Uuid::nil()),
            TraceId::from(Uuid::nil()),
            TraceId::from(Uuid::nil()),
            Some(RecordId::from(Uuid::nil())),
            None,
            1,
        );
        let invocation = InvocationContext::new(false);
        let caller = CallerContext::new(
            ActorPseudonym::from_bytes([9u8; 32]),
            None,
            None,
            Some(DeploymentStage::InteractiveDevelopment),
        );
        let controls = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::SentMasked,
            vec![Detection::new(EntityClassId::Email, 1, Action::Masked).unwrap()],
            None,
            vec![],
        )
        .unwrap();
        let timing = TimingUs::new(0, 100, 100).unwrap();

        let receipt = Receipt::new(
            linkage,
            invocation,
            caller,
            controls,
            timing,
            EdgeOutcome::Complete,
        );

        // No Debug on `Receipt` (per this module's own rule) — the proof that nothing
        // here can hold a raw string is structural: `linkage`/`timing` are UUIDs and
        // integers, `controls`/`detections` are typed enums and bounded tokens,
        // `caller`'s identity field is a fixed-width pseudonym. PartialEq is the only
        // thing left to exercise against the fully-constructed value.
        assert!(receipt == receipt.clone());
    }

    #[test]
    fn controls_rejects_missing_detections_when_outcome_is_not_unmodified() {
        let result = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::SentMasked,
            vec![],
            None,
            vec![],
        );
        assert!(
            result
                == Err(ControlsInvariantError::DetectionsRequiredForOutcome {
                    outcome_label: "SentMasked"
                })
        );
    }

    #[test]
    fn controls_accepts_empty_detections_when_outcome_is_unmodified() {
        let result = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::SentUnmodified,
            vec![],
            None,
            vec![],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn controls_accepts_populated_detections_for_a_masked_outcome() {
        let result = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::SentMasked,
            vec![Detection::new(EntityClassId::Email, 1, Action::Masked).unwrap()],
            None,
            vec![],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn controls_rejects_blocked_before_send_with_no_block_reason() {
        let result = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::BlockedBeforeSend,
            vec![Detection::new(EntityClassId::Email, 1, Action::Blocked).unwrap()],
            None,
            vec![],
        );
        assert!(result == Err(ControlsInvariantError::BlockReasonRequiredForBlockedOutcome));
    }

    #[test]
    fn controls_accepts_blocked_before_send_with_a_block_reason() {
        let result = Controls::new(
            VersionToken::try_from("policy-v1").unwrap(),
            DetectorSetId::try_from("detectors-v1").unwrap(),
            Outcome::BlockedBeforeSend,
            vec![Detection::new(EntityClassId::Email, 1, Action::Blocked).unwrap()],
            Some(ReasonCode::from(1u16)),
            vec![],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn timing_us_rejects_completion_before_start() {
        assert!(
            TimingUs::new(1_000, 500, 0)
                == Err(TimingInvariantError::CompletedBeforeStarted {
                    started_us: 1_000,
                    completed_us: 500,
                })
        );
    }

    #[test]
    fn timing_us_accepts_completion_at_or_after_start() {
        assert!(TimingUs::new(0, 0, 0).is_ok());
        assert!(TimingUs::new(0, 100, 100).is_ok());
    }
}
