//! [`BlockReason`] — the code-defined reason dictionary that lets
//! `EdgeEvent::try_from_audit_event` turn `AuditEvent::Block`'s free-text `reason: String`
//! into a [`ReasonCode`].
//!
//! **Deliberately not a policy-pack-distributed mechanism**, unlike the rest of
//! `vg-policy`'s 3-layer (global/repo/session) config system — a scope decision made
//! after checking the actual code, not assumed from the reconciliation plan's original
//! sketch: there is exactly one production `AuditEvent::Block` construction site today
//! (`crates/vg-core/src/api.rs`'s `mask()`, the artefact-level policy-Block check), and
//! `vg-policy`'s `ResolvedPolicy` has no separate "reason text" concept anywhere — an
//! artefact is only ever `Block`ed because `artefact_default`/`by_extension`/
//! `by_language`/`by_mime` resolved to `HandlingClass::Block`, and `classify_artefact`
//! doesn't report *which* of those matched, only the resulting class. Building the full
//! pack-distributed mechanism (a `PolicyEngine` contract change, merge semantics for
//! reason ownership, inheriting `vg-policy`'s still-stubbed `verify_signature` risk) for
//! one fixed reason string would be premature. This registry is versioned the way
//! `detector_version`/`policy_version` strings are — shipped with the code — not
//! operator-editable.
//!
//! **Exact-match lookup, not fuzzy classification, deliberately.** Every current and
//! future `AuditEvent::Block` construction site is expected to use one of this module's
//! exported text constants verbatim (see `api.rs`'s call site), not compose its own free
//! text. An unrecognized string means a future `Block` site was added without
//! registering its reason here — a real, distinct rejection
//! (`TelemetryReject::UnrecognizedReason`), not a silently-assigned default.
//!
//! **That "every construction site uses a known constant" expectation is enforced by
//! review discipline, not by the type system** — a doubt-driven-development finding
//! worth stating plainly rather than implying otherwise. `AuditEvent` being
//! `#[non_exhaustive]` restricts *exhaustive matching* and *naming new variants* from
//! outside `vg-core`; it does **not** restrict *constructing existing variants* —
//! `crates/vg-audit/tests/sink.rs` already constructs `AuditEvent::Block` directly from
//! a different crate, with its own reason strings. `TelemetryReject::UnrecognizedReason`
//! is the actual safety net for that: an unregistered reason from any future call site,
//! anywhere in the workspace, is a named, honest rejection, never a silent default or a
//! panic — but nothing stops that call site from being added in the first place.
//!
//! **Why classification happens here, at telemetry-conversion time, not at
//! `AuditEvent::Block` construction time in `api.rs`** — `docs/next-actions.md`'s
//! original Phase 2 sketch asked for construction-time classification specifically so
//! "the free-text reason [doesn't] leak upstream of the boundary this effort exists to
//! close." On inspection that boundary is the *telemetry* boundary (what may leave the
//! machine), not the local audit log — `AuditEvent::Block.reason: String` is a frozen
//! local-audit-log field this task does not touch and was never asked to; it stays free
//! text regardless of when classification happens. Classifying at the point a value
//! actually crosses into `EdgeEvent` (here, in `try_from_audit_event`) is where it
//! matters — nothing upstream of that point makes any stronger promise, moving the
//! check earlier would not close a gap that exists today.
//!
//! **Named explicitly, not glossed over (a second, cross-model doubt-driven-development
//! round pushed back on the paragraph above being too quick to call this equivalent):**
//! a future `AuditEvent::Block` construction site with an unregistered reason string
//! still writes that string to the *local* audit log — unconditionally, regardless of
//! whether classification happens at construction time or here — before
//! `try_from_audit_event` ever runs and rejects it for telemetry purposes. Hard-failing
//! at construction time (refusing to even build the `AuditEvent`, or panicking) would
//! close that specific window, but is a materially bigger, unscoped behavior change —
//! making `mask()` itself fail on a policy-internal naming mismatch — not something this
//! phase was asked to add. The local audit log accepting free text is its own
//! long-standing, unrelated contract (`vg-audit`'s own module doc); this phase's actual
//! job — keeping that same free text out of what may leave the machine — holds
//! regardless of where in `mask()`'s call chain the string briefly exists unclassified.

use super::ids::ReasonCode;

/// Not `#[non_exhaustive]`: that attribute only affects matches/construction from
/// *outside* the defining crate, and this type is `pub(crate)` inside a `pub(crate) mod`
/// — it never crosses `vg-core`'s own boundary, so the attribute would be inert here.
/// Ordinary same-crate match-exhaustiveness (in [`reason_code`](Self::reason_code) and
/// [`classify`](Self::classify)) already forces a second variant to be handled in both
/// places the moment it's added — that's the real guard, not an attribute.
pub(crate) enum BlockReason {
    /// `mask()`'s artefact-level policy-Block check (`crates/vg-core/src/api.rs`) —
    /// the only production `AuditEvent::Block` site today.
    ArtefactPolicyBlock,
}

impl BlockReason {
    /// The exact string `AuditEvent::Block.reason` must carry for this reason — a
    /// shared constant, not a literal duplicated at the audit-log call site, so the
    /// writer and this lookup can never drift apart.
    pub(crate) const ARTEFACT_POLICY_BLOCK_TEXT: &'static str =
        "artefact class is Block in resolved policy";

    /// Stable, hand-assigned numbering. Only one entry exists today; a second entry
    /// must pick the next unused value and never reuse `1`. **No compiler-enforced
    /// uniqueness guard exists** — a doubt-driven-development finding, tracked as a
    /// named follow-up rather than solved here (`docs/next-actions.md`): the only thing
    /// forcing a second variant to be handled at all is ordinary match-exhaustiveness
    /// (a new `BlockReason` variant makes this `match` fail to compile until an arm is
    /// added), which says nothing about whether the *value* chosen collides with an
    /// existing one.
    pub(crate) fn reason_code(&self) -> ReasonCode {
        match self {
            Self::ArtefactPolicyBlock => ReasonCode::from(1),
        }
    }

    /// Exact-match lookup against every known reason string. `None` means `reason`
    /// isn't recognized — the caller's job to turn into a named, honest reject, not to
    /// guess at a best-effort classification.
    pub(crate) fn classify(reason: &str) -> Option<Self> {
        match reason {
            Self::ARTEFACT_POLICY_BLOCK_TEXT => Some(Self::ArtefactPolicyBlock),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognizes_the_exact_known_text() {
        assert!(matches!(
            BlockReason::classify(BlockReason::ARTEFACT_POLICY_BLOCK_TEXT),
            Some(BlockReason::ArtefactPolicyBlock)
        ));
    }

    #[test]
    fn classify_rejects_a_different_case() {
        let uppercased = BlockReason::ARTEFACT_POLICY_BLOCK_TEXT.to_uppercase();
        assert!(BlockReason::classify(&uppercased).is_none());
    }

    #[test]
    fn classify_rejects_trailing_whitespace() {
        let padded = format!("{} ", BlockReason::ARTEFACT_POLICY_BLOCK_TEXT);
        assert!(BlockReason::classify(&padded).is_none());
    }

    #[test]
    fn classify_rejects_unrelated_text() {
        assert!(BlockReason::classify("some other reason entirely").is_none());
    }

    #[test]
    fn classify_rejects_empty_string() {
        assert!(BlockReason::classify("").is_none());
    }
}
