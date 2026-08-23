//! `AuditEvent` — the append-only audit record type. Owned by `vg-core` (not
//! `vg-audit`) because the `AuditSink` trait, also frozen in `vg-core`, is defined over
//! it; `vg-audit` (Squad 5) implements `AuditSink`, it does not own this type.

use crate::api::Destination;
use crate::ids::ActorId;
use crate::traits::ArtefactKind;
use crate::types::{EntityCounts, EntityType, HandlingClass, MappingRef};

/// An append-only audit record. **Contract: no raw values in any variant** — refs,
/// counts, and versions only. Checked by
/// [`crate::conformance::assert_audit_event_excludes_raw_values`].
///
/// `#[non_exhaustive]`: the draft contract's own ellipsis ("... provider destination,
/// build_provenance_version") signals more variants land later (Task T09/T10) — adding
/// them is additive, not a breaking change, and still goes through the contract-change
/// protocol.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AuditEvent {
    Scan {
        counts: EntityCounts,
        detector_version: String,
        latency_us: u64,
    },
    PolicyDecision {
        artefact: ArtefactKind,
        class: HandlingClass,
        policy_version: String,
    },
    MappingCreated {
        mapping_ref: MappingRef,
        entity_type: EntityType,
    },
    Block {
        artefact: ArtefactKind,
        reason: String,
    },
    DemaskRequest {
        dest: Destination,
        actor: ActorId,
    },
    DemaskDecision {
        dest: Destination,
        actor: ActorId,
        allowed: bool,
        policy_version: String,
    },
}

/// The variant name of `event`, as a stable `&'static str` (`"Scan"`, `"Block"`, ...).
///
/// Exhaustive over all six variants with no wildcard arm — deliberately placed *inside*
/// `vg-core`, not left for each consumer crate to write its own match: `AuditEvent` is
/// `#[non_exhaustive]`, so a match outside this crate is compiler-*forced* to carry a
/// wildcard regardless of intent (confirmed the hard way: `vg-audit`'s
/// `TelemetryCountingAuditSink` originally tried to write this match itself and hit
/// `E0004` even though its author knew all six current variants). Consumer crates that
/// need a name-per-variant (logging, counting, telemetry) should call this instead of
/// re-attempting an exhaustive match they cannot actually enforce — a future seventh
/// variant is then a forced touchpoint here, in the one place it can be.
pub fn variant_name(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::Scan { .. } => "Scan",
        AuditEvent::PolicyDecision { .. } => "PolicyDecision",
        AuditEvent::MappingCreated { .. } => "MappingCreated",
        AuditEvent::Block { .. } => "Block",
        AuditEvent::DemaskRequest { .. } => "DemaskRequest",
        AuditEvent::DemaskDecision { .. } => "DemaskDecision",
    }
}
