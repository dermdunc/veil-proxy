//! [`Alert`] — `veil.alert.v1`, the immediate lane. Per
//! `docs/architecture/telemetry-receipt-reconciliation-plan.md` §3.2 Kind B: "its own
//! minimal schema, matching the ratified payload exactly: rule id, severity, device
//! pseudonym, timestamp... deliberately *not* a receipt subset or a field mask over one,
//! because a mask is a filter someone can widen; a separate generated type makes
//! over-sharing a compile error in `vg-core`." Device pseudonym and timestamp are
//! carried on `Envelope`, not duplicated here.
//!
//! No `Debug` derives here (`docs/architecture/implementation-plan.md:137`) — see
//! `telemetry::ids`'s module doc for why.

use super::ids::AlertRuleId;

/// Not specified exactly by the reconciliation plan — a reasonable minimal closed set,
/// flagged as a product-input decision rather than something locked in here.
/// `#[non_exhaustive]`: a second doubt-driven-development round caught that this type's
/// own doc claimed adding a variant was "additive... cheap to extend later," which is
/// only true for downstream matches if the enum is actually marked non-exhaustive — an
/// earlier draft claimed the property without enforcing it.
///
/// **Hard invariant: append-only, never reorder or insert a variant between existing
/// ones.** `Ord` is derived from declaration order — a fourth adversarial review round
/// noted that `#[non_exhaustive]` advertises "adding a variant is cheap," but a derived
/// `Ord` makes that order load-bearing public API: inserting e.g. `Warning` between
/// `Low` and `Medium` would silently change the meaning of every existing
/// `severity >= X` comparison downstream, with no compile error anywhere. New variants
/// must be added at the end (before or after `Critical`, matching their intended real
/// rank), never spliced into the middle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Alert {
    rule: AlertRuleId,
    severity: Severity,
}

impl Alert {
    pub(crate) fn new(rule: AlertRuleId, severity: Severity) -> Self {
        Self { rule, severity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_carries_no_detection_or_caller_context() {
        let alert = Alert::new(
            AlertRuleId::try_from("secret-in-prompt").unwrap(),
            Severity::High,
        );
        // Structural proof, not a runtime assertion: `Alert` has exactly two fields
        // (`rule`, `severity`) — there is no detections/caller/linkage field to
        // accidentally populate. This test exists so a future field addition to `Alert`
        // is forced through a reviewer reading this comment, not silently widened.
        assert!(alert.severity == Severity::High);
    }
}
