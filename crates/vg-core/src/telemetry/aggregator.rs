//! `TraceBuffer` — an in-memory, trace-keyed buffer of [`AuditEvent`]s, keyed by the
//! [`TraceId`] `mask()` now mints per call (`crates/vg-core/src/api.rs`).
//!
//! **Deliberately a skeleton, not the aggregator.** Turning buffered `AuditEvent`s into
//! a [`Receipt`](super::Receipt) needs `Controls`-level data (per-detection `outcome`/
//! `action`/`block_reason`/`exceptions`) that no current production code produces — an
//! open, separate, larger decision named in `docs/next-actions.md`'s Phase 3 entry, not
//! attempted here. This type only does the mechanical part: group events by trace, and
//! report which traces have gone stale by a caller-supplied cutoff.
//!
//! **No completion detection and no eviction policy.** [`TraceBuffer::aged_before`]
//! reports *which* traces are older than a cutoff; it does not remove them and does not
//! decide what "aged out" should mean (drop, re-mint, queue for partial delivery — the
//! Q3 replay-window question, still open). A caller that has made that decision uses
//! [`TraceBuffer::remove`] to act on it.
//!
//! **Not wired to anything yet.** Nothing constructs a `TraceBuffer` or calls `insert`
//! in production — matching this module's existing `#[allow(dead_code)]` precedent
//! (see the parent module doc) for a real, tested, not-yet-connected piece.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::audit::AuditEvent;
use crate::telemetry::ids::TraceId;

/// One trace's identity, buffered events, and the `Instant` its first event was inserted
/// at (the age baseline `aged_before` compares against). Keyed in `TraceBuffer` by
/// [`TraceId::ordering_key`] rather than by `TraceId` itself (see that method's doc), so
/// the entry carries its own `TraceId` back for lookups/removal/reporting.
struct TraceEntry {
    trace_id: TraceId,
    events: Vec<AuditEvent>,
    first_inserted_at: Instant,
}

pub(crate) struct TraceBuffer {
    entries: BTreeMap<u128, TraceEntry>,
}

impl TraceBuffer {
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Buffers `event` under `trace_id`. The first insert for a given `trace_id` records
    /// `now` as that trace's age baseline; later inserts for the same trace append to
    /// its event list without moving the baseline.
    pub(crate) fn insert(&mut self, trace_id: TraceId, event: AuditEvent, now: Instant) {
        self.entries
            .entry(trace_id.ordering_key())
            .or_insert_with(|| TraceEntry {
                trace_id,
                events: Vec::new(),
                first_inserted_at: now,
            })
            .events
            .push(event);
    }

    /// Every event buffered so far for `trace_id`, in insertion order. Empty (not an
    /// error) for a trace with no inserts.
    pub(crate) fn events_for(&self, trace_id: &TraceId) -> &[AuditEvent] {
        self.entries
            .get(&trace_id.ordering_key())
            .map(|entry| entry.events.as_slice())
            .unwrap_or(&[])
    }

    /// Trace ids whose first-inserted-at is strictly older than `cutoff`, **oldest first**.
    /// Reports only — does not evict or otherwise decide what happens to an aged-out
    /// trace; see this module's own doc for why that policy question stays open.
    ///
    /// Sorted explicitly by age rather than left in the underlying `BTreeMap`'s key
    /// order: that order is keyed by [`TraceId::ordering_key`] purely so the map can have
    /// a total order at all (`TraceId` itself withholds `Ord` — see its own doc), and
    /// carries no relationship to insertion time. Returning it unsorted would silently
    /// invite a caller doing prioritized eviction to assume oldest-first for free, which
    /// nothing here would actually guarantee.
    pub(crate) fn aged_before(&self, cutoff: Instant) -> Vec<TraceId> {
        let mut aged: Vec<&TraceEntry> = self
            .entries
            .values()
            .filter(|entry| entry.first_inserted_at < cutoff)
            .collect();
        aged.sort_by_key(|entry| entry.first_inserted_at);
        aged.into_iter().map(|entry| entry.trace_id).collect()
    }

    /// Removes `trace_id` and returns its buffered events in insertion order, or `None`
    /// if nothing was ever inserted for it.
    pub(crate) fn remove(&mut self, trace_id: &TraceId) -> Option<Vec<AuditEvent>> {
        self.entries
            .remove(&trace_id.ordering_key())
            .map(|entry| entry.events)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use uuid::Uuid;

    use super::TraceBuffer;
    use crate::audit::AuditEvent;
    use crate::telemetry::ids::TraceId;
    use crate::traits::ArtefactKind;
    use crate::types::{EntityCounts, HandlingClass};

    fn scan_event(latency_us: u64) -> AuditEvent {
        AuditEvent::Scan {
            counts: EntityCounts::default(),
            detector_version: "test-detectors-v1".to_string(),
            latency_us,
        }
    }

    fn policy_decision_event() -> AuditEvent {
        AuditEvent::PolicyDecision {
            artefact: ArtefactKind::PlainText,
            class: HandlingClass::Mask,
            policy_version: "test-policy-v1".to_string(),
        }
    }

    #[test]
    fn insert_accumulates_multiple_events_under_the_same_trace_in_order() {
        let mut buf = TraceBuffer::new();
        let trace = TraceId::from(Uuid::new_v4());
        let now = Instant::now();

        buf.insert(trace, scan_event(1), now);
        buf.insert(trace, policy_decision_event(), now);

        let events = buf.events_for(&trace);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], scan_event(1));
        assert_eq!(events[1], policy_decision_event());
    }

    #[test]
    fn different_traces_stay_independent() {
        let mut buf = TraceBuffer::new();
        let trace_a = TraceId::from(Uuid::new_v4());
        let trace_b = TraceId::from(Uuid::new_v4());
        let now = Instant::now();

        buf.insert(trace_a, scan_event(1), now);
        buf.insert(trace_b, scan_event(2), now);

        assert_eq!(buf.events_for(&trace_a), &[scan_event(1)]);
        assert_eq!(buf.events_for(&trace_b), &[scan_event(2)]);
    }

    #[test]
    fn aged_before_reports_only_traces_older_than_the_cutoff() {
        let mut buf = TraceBuffer::new();
        let old_trace = TraceId::from(Uuid::new_v4());
        let fresh_trace = TraceId::from(Uuid::new_v4());
        let base = Instant::now();

        buf.insert(old_trace, scan_event(1), base);
        buf.insert(fresh_trace, scan_event(1), base + Duration::from_secs(10));

        let cutoff = base + Duration::from_secs(5);
        let aged = buf.aged_before(cutoff);

        assert!(aged == vec![old_trace]);
    }

    #[test]
    fn aged_before_returns_multiple_aged_traces_oldest_first_not_by_trace_id_value() {
        // Deliberately inserted in an order where trace-id (u128) value and insertion/age
        // order run opposite: the highest-valued uuid is oldest, the lowest-valued is
        // newest. A buggy implementation that (re-)introduced reliance on the underlying
        // BTreeMap's key order (ascending trace-id value) would return these reversed.
        let mut buf = TraceBuffer::new();
        let oldest = TraceId::from(Uuid::from_u128(u128::MAX));
        let middle = TraceId::from(Uuid::from_u128(u128::MAX / 2));
        let newest = TraceId::from(Uuid::from_u128(0));
        let base = Instant::now();

        buf.insert(oldest, scan_event(1), base);
        buf.insert(middle, scan_event(1), base + Duration::from_secs(1));
        buf.insert(newest, scan_event(1), base + Duration::from_secs(2));

        let cutoff = base + Duration::from_secs(100);
        assert!(buf.aged_before(cutoff) == vec![oldest, middle, newest]);
    }

    #[test]
    fn a_later_insert_does_not_move_a_traces_age_baseline() {
        let mut buf = TraceBuffer::new();
        let trace = TraceId::from(Uuid::new_v4());
        let base = Instant::now();

        buf.insert(trace, scan_event(1), base);
        buf.insert(trace, scan_event(2), base + Duration::from_secs(100));

        // Cutoff sits after the first insert but before "now" — the trace must still
        // read as aged, proving the second insert didn't reset the baseline.
        let cutoff = base + Duration::from_secs(1);
        assert!(buf.aged_before(cutoff) == vec![trace]);
    }

    #[test]
    fn remove_drains_and_clears_a_trace() {
        let mut buf = TraceBuffer::new();
        let trace = TraceId::from(Uuid::new_v4());
        let now = Instant::now();
        buf.insert(trace, scan_event(1), now);

        let drained = buf.remove(&trace).expect("trace was inserted");
        assert_eq!(drained, vec![scan_event(1)]);

        assert!(buf.events_for(&trace).is_empty());
        assert_eq!(buf.remove(&trace), None);
    }

    #[test]
    fn a_trace_with_no_inserts_is_absent_from_events_for_and_aged_before() {
        let buf = TraceBuffer::new();
        let trace = TraceId::from(Uuid::new_v4());

        assert!(buf.events_for(&trace).is_empty());
        assert!(buf
            .aged_before(Instant::now() + Duration::from_secs(3600))
            .is_empty());
    }
}
