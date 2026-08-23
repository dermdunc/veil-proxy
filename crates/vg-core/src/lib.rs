//! `vg-core` — shared types and library API for VeilGremlin.
//!
//! Owns the canonical definitions described in `docs/architecture/interface-contracts.md`
//! (`EntityType`, `HandlingClass`, `Namespace`, `Finding`, `MaskedPack`, `scan`/`mask`/
//! `rehydrate`/`benchmark`) and the trait seams other crates implement against
//! (`Detector`, `Parser`, `VaultStore`, `PolicyEngine`, `AuditSink`).
//!
//! Scaffolded in Task T01 (workspace + CI). **Frozen in Task T02** (this crate's current
//! state) per the contract-change protocol in `docs/architecture/agent-factory-plan.md`
//! §6 — `interface-contracts.md` v1 is the source of truth; any change to a public type
//! or trait here must land there first.
//!
//! `scan`/`mask`/`rehydrate`/`benchmark` freeze their signatures now; most bodies are
//! pipeline assembly deferred to Task T07 (Wave C), once Wave B's trait implementations
//! exist to assemble. The one piece of `rehydrate` that does not depend on Wave B — the
//! destination hard-deny gate — is implemented for real here. See [`conformance`] for
//! the trait-conformance test scaffold Wave B squads build against.

mod api;
mod audit;
mod error;
mod ids;
mod keying;
mod traits;
mod types;

pub mod conformance;
pub mod telemetry;

pub use api::{
    benchmark, mask, rehydrate, scan, spans_overlap, Actor, Context, Corpus, CorpusSample,
    Destination, DestinationId, Input, Metrics, Policy,
};
pub use audit::AuditEvent;
pub use error::{AuditError, MaskError, PolicyError, RehydrateDenied, VaultError};
pub use ids::{ActorId, AuditId, DetectorId, OrgId, RepoId, SessionId};
pub use keying::{
    canonicalize, iban_mod97_is_valid, luhn_is_valid, placeholder_key, Keyed, Keyer, PlaceholderKey,
};
pub use traits::{
    ArtefactHint, ArtefactKind, AuditSink, Detector, Enricher, ParseResult, Parser, Placeholder,
    PolicyEngine, PolicyLayers, Secret, VaultStore,
};
pub use types::{
    EntityCounts, EntityType, Finding, HandlingClass, MappingRef, MaskStats, MaskedPack, Namespace,
    NodeKind, PlaceholderBinding, Span,
};
