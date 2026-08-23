//! Trait seams other crates implement: `Detector` (`vg-detectors`), `Parser`
//! (`vg-parsers`), `VaultStore` (`vg-vault`), `PolicyEngine` (`vg-policy`), `AuditSink`
//! (`vg-audit`). Frozen per `docs/architecture/interface-contracts.md` v1 — changes go
//! through the contract-change protocol in `agent-factory-plan.md` §6.

use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroize;

use crate::api::{Actor, Destination, DestinationId};
use crate::audit::AuditEvent;
use crate::error::{AuditError, PolicyError, VaultError};
use crate::ids::{AuditId, DetectorId};
use crate::types::{EntityType, Finding, HandlingClass, MappingRef, Namespace, Span};

/// Hints a caller can supply about an artefact before/without parsing it, used by
/// `Parser::can_parse` and `PolicyEngine::classify_artefact`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtefactHint {
    pub path: Option<PathBuf>,
    pub language_id: Option<String>,
    pub mime_type: Option<String>,
}

/// The structural kind a `Parser` determines an artefact to be.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtefactKind {
    Json,
    Yaml,
    Toml,
    Sql,
    Csv,
    LogLine,
    Diff,
    EnvFile,
    SourceCode(String),
    PlainText,
    Unknown,
}

/// Typed spans a `Parser` returns, so detectors can be field/structure-aware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseResult {
    pub spans: Vec<Span>,
    pub artefact_kind: ArtefactKind,
}

/// Hot-path detector. Contract: deterministic; bounded matching; no allocation surprises,
/// no I/O, no network, no ML. Benchmarked (p95 < 25 ms on the reference buffer).
pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn detect(&self, buf: &[u8], spans: &[Span]) -> Vec<Finding>;
    fn entity_types(&self) -> &[EntityType];
}

/// Warm-path only (e.g. GLiNER NER). Never invoked on the hot path; a type implements
/// either `Detector` or `Enricher`, never both.
pub trait Enricher: Send + Sync {
    fn enrich(&self, text: &str) -> Vec<Finding>;
}

/// Contract: must be robust to malformed input — returns best-effort spans, never
/// panics.
pub trait Parser: Send + Sync {
    fn can_parse(&self, artefact: &ArtefactHint) -> bool;
    fn parse(&self, buf: &[u8]) -> ParseResult;
}

/// A raw sensitive value, held only long enough to intern or resolve it. Zeroized on
/// drop; `Debug` never prints the value.
///
/// **Known limitation, inherent to the frozen contract, not introduced here:**
/// `expose_secret` returns a borrowed `&str`; a caller can `.to_string()` a copy that
/// escapes the zeroize-on-drop guarantee, and `rehydrate`'s frozen signature
/// (`-> Result<String, RehydrateDenied>`) requires returning an owned, non-zeroizing
/// `String` at the one exit point that matters. Callers of `expose_secret`/`rehydrate`'s
/// output are responsible for not persisting or logging the returned value — the type
/// system does not and cannot enforce this given the contract's shape.
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&"<redacted>").finish()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A stable, typed placeholder for a vault-interned value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    pub display: String,
    pub mapping_ref: MappingRef,
}

/// Contract: AES-256 at rest (SQLCipher); DB key wrapped by OS keychain, never persisted
/// plaintext; stable placeholder via salted HMAC over `(canonical(value), ty, ns)`.
/// `IrreversibleRedact` values are never passed to `intern`.
///
/// **Namespace isolation is part of the contract, not a convention**: `ns` in `resolve`
/// must match the `ns` the `Placeholder` was interned under. A value interned in one
/// `Namespace` (e.g. `Session(A)`) must never resolve when called with a different one
/// (e.g. `Session(B)`, or a different `Repo`/`Org`) — return
/// [`VaultError::NotFound`] on a namespace mismatch, the same as an unknown mapping.
/// This is exactly what `Namespace` scoping exists to guarantee (interface-contracts.md
/// §5: "the same raw value maps to the same placeholder only within the same
/// namespace") — a value leaking across namespaces on `resolve` defeats that guarantee
/// as surely as leaking it in `MaskedPack.text` would. [`crate::conformance`]'s
/// `assert_vault_roundtrip` checks this explicitly; any impl (including test mocks)
/// must not skip it.
pub trait VaultStore: Send + Sync {
    /// Returns the existing placeholder or creates one. Stores an encrypted mapping.
    fn intern(
        &self,
        value: &Secret,
        ty: EntityType,
        ns: &Namespace,
    ) -> Result<Placeholder, VaultError>;

    /// Reverses a placeholder to its raw value. Caller must already be
    /// policy-authorised. Must return `Err(VaultError::NotFound)` if `ns` does not
    /// match the namespace `p` was interned under — see the trait-level doc.
    fn resolve(&self, p: &Placeholder, ns: &Namespace) -> Result<Secret, VaultError>;

    fn purge_expired(&self) -> Result<usize, VaultError>;
}

/// The three policy layers, resolved session-overrides-repo-overrides-global.
#[derive(Debug, Clone)]
pub struct PolicyLayers {
    pub global: PathBuf,
    pub repo: Option<PathBuf>,
    pub session: Option<PathBuf>,
}

/// Contract: 3-layer resolution; signed-pack verification before load (stub in Phase 1,
/// enforced later); `demask_allowed` returns false for `RemoteModelPrompt`/
/// `ObservabilitySink` in default policy.
pub trait PolicyEngine: Send + Sync {
    fn load(layers: PolicyLayers) -> Result<Self, PolicyError>
    where
        Self: Sized;
    fn classify_artefact(&self, hint: &ArtefactHint) -> HandlingClass;
    fn classify_entity(&self, ty: EntityType) -> HandlingClass;
    fn destination_allows_masked_only(&self, dest: &DestinationId) -> bool;
    fn demask_allowed(&self, dest: Destination, actor: &Actor) -> bool;
    fn version(&self) -> &str;
    /// Whether opt-in telemetry is enabled per the resolved policy. A **default** method
    /// (not required), deliberately: adding a required method here would be a breaking
    /// change for every existing `PolicyEngine` implementer (`vg-policy`'s
    /// `LayeredPolicyEngine`, and the test stub in `crates/vg-core/tests/conformance_stubs.rs`).
    /// Defaults to `false` — fail-safe, matching ADR-015's "opt-in, never opt-out" —
    /// so an implementer that doesn't override this is telemetry-off by construction,
    /// not by omission.
    fn telemetry_enabled(&self) -> bool {
        false
    }
}

/// Contract: append-only; no raw values in any `AuditEvent` variant.
pub trait AuditSink: Send + Sync {
    fn write(&self, event: AuditEvent) -> Result<AuditId, AuditError>;
    fn get(&self, id: AuditId) -> Option<AuditEvent>;
}
