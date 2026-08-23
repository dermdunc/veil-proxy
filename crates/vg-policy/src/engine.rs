//! [`LayeredPolicyEngine`] — the concrete `vg_core::PolicyEngine` for VeilGremlin.

use std::path::Path;

use vg_core::{
    Actor, ArtefactHint, Destination, DestinationId, EntityType, HandlingClass, PolicyEngine,
    PolicyError, PolicyLayers,
};

use crate::config::{self, ResolvedPolicy};

/// A policy engine resolved from up to three layered packs
/// (session-overrides-repo-overrides-global).
///
/// Constructed via [`PolicyEngine::load`]. The global layer is required; repo and session
/// layers are optional overlays. Each layer is signature-checked (Phase 1 stub, see
/// [`config::verify_signature`]) and merged before a single validation/resolution pass.
#[derive(Debug, Clone)]
pub struct LayeredPolicyEngine {
    resolved: ResolvedPolicy,
}

impl LayeredPolicyEngine {
    /// Read, signature-check (stub), and parse one layer file into a [`config::RawPack`].
    fn read_layer(path: &Path) -> Result<config::RawPack, PolicyError> {
        let bytes = std::fs::read(path).map_err(|e| load_err(path, "reading", e))?;

        // Signed-pack verification precedes trusting the bytes (interface-contracts.md §6).
        // Phase 1: this always accepts — see verify_signature's doc.
        config::verify_signature(path, &bytes)?;

        let text = std::str::from_utf8(&bytes).map_err(|e| load_err(path, "decoding", e))?;
        serde_json::from_str(text).map_err(|e| load_err(path, "parsing", e))
    }
}

/// Build a [`PolicyError::Load`] naming which layer file and which step failed.
fn load_err(path: &Path, action: &str, e: impl std::fmt::Display) -> PolicyError {
    PolicyError::Load(format!("{action} policy layer {}: {e}", path.display()))
}

impl PolicyEngine for LayeredPolicyEngine {
    fn load(layers: PolicyLayers) -> Result<Self, PolicyError> {
        let mut merged = Self::read_layer(&layers.global)?;
        if let Some(repo) = layers.repo.as_deref() {
            merged = config::merge(merged, Self::read_layer(repo)?);
        }
        if let Some(session) = layers.session.as_deref() {
            merged = config::merge(merged, Self::read_layer(session)?);
        }
        Ok(Self {
            resolved: ResolvedPolicy::from_raw(merged)?,
        })
    }

    fn classify_artefact(&self, hint: &ArtefactHint) -> HandlingClass {
        // First match wins: file extension, then declared language, then MIME type.
        if let Some(path) = hint.path.as_ref() {
            for ext in extension_candidates(path) {
                if let Some(class) = self.resolved.artefact_by_extension.get(&ext) {
                    return *class;
                }
            }
        }
        if let Some(lang) = hint.language_id.as_deref() {
            if let Some(class) = self.resolved.artefact_by_language.get(lang) {
                return *class;
            }
        }
        if let Some(mime) = hint.mime_type.as_deref() {
            if let Some(class) = self.resolved.artefact_by_mime.get(mime) {
                return *class;
            }
        }
        self.resolved.artefact_default
    }

    fn classify_entity(&self, ty: EntityType) -> HandlingClass {
        let key = config::entity_key(&ty);
        self.resolved
            .entity_overrides
            .get(&key)
            .copied()
            .unwrap_or(self.resolved.entity_default)
    }

    fn destination_allows_masked_only(&self, dest: &DestinationId) -> bool {
        // Defence in depth: the two hard-deny destinations must never receive unmasked
        // content, so force masked-only regardless of what a (possibly mis-signed) pack
        // says. `demask_allowed` carries the contract-mandated hard-deny; this mirrors it
        // on the send-side gate.
        if is_hard_deny_id(dest) {
            return true;
        }
        self.resolved
            .destinations
            .get(&dest.0)
            // Fail-safe: an unconfigured destination is treated as masked-only.
            .map(|d| d.masked_only)
            .unwrap_or(true)
    }

    fn demask_allowed(&self, dest: Destination, actor: &Actor) -> bool {
        // SECURITY-LOAD-BEARING (T06 spec item 4 / interface-contracts.md §6): these two
        // destinations are hard-denied *in code*, before consulting the pack — a malicious
        // or misconfigured pack that sets `demask_allowed = true` for them cannot override
        // this. Every other destination is pure configuration plumbing below.
        if matches!(
            dest,
            Destination::RemoteModelPrompt | Destination::ObservabilitySink
        ) {
            return false;
        }

        match self.resolved.destinations.get(&dest.id().0) {
            Some(rule) => {
                if !rule.demask_allowed {
                    return false;
                }
                if rule.demask_roles.is_empty() {
                    true
                } else {
                    actor.roles.iter().any(|r| rule.demask_roles.contains(r))
                }
            }
            // Fail-safe: demask denied for any destination the pack does not mention.
            None => false,
        }
    }

    fn version(&self) -> &str {
        &self.resolved.version
    }

    fn telemetry_enabled(&self) -> bool {
        self.resolved.telemetry_enabled
    }
}

/// True for the [`DestinationId`]s corresponding to the hard-deny destinations. Kept in
/// sync with `Destination::id()` in `vg-core` (`remote-model-prompt`,
/// `observability-sink`).
fn is_hard_deny_id(dest: &DestinationId) -> bool {
    dest.0 == Destination::RemoteModelPrompt.id().0
        || dest.0 == Destination::ObservabilitySink.id().0
}

/// Extension keys to try for `by_extension` lookup, lowercased, most specific first.
///
/// **Why not just `Path::extension()` (T07 review, High fix):** Rust treats a leading dot
/// as part of a dotfile's *name*, so `Path::new(".env").extension()` is `None` and
/// `".env.local"` yields `"local"` — meaning the contract's own canonical Block example
/// (a literal `.env` file) silently fell through to the artefact default and failed
/// OPEN. For a dotfile we therefore also try the first segment after the leading dot
/// (`.env` → `env`, `.env.local` → `local` then `env`), mirroring how `vg-parsers`'
/// env parser already matches these names for exactly the same reason.
fn extension_candidates(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        out.push(ext.to_ascii_lowercase());
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if let Some(rest) = name.strip_prefix('.') {
            if let Some(first) = rest.split('.').next() {
                if !first.is_empty() {
                    let candidate = first.to_ascii_lowercase();
                    if !out.contains(&candidate) {
                        out.push(candidate);
                    }
                }
            }
        }
    }
    out
}
