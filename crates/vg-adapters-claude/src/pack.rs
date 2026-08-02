//! On-disk persistence of a [`MaskedPack`] so a later `vg demask` can reverse it.
//!
//! `vg_core::MaskedPack` is deliberately not `Serialize` (it is a frozen wire type, and
//! adding serde to it and its transitive types would widen its contract surface), so this
//! module owns a small serializable mirror, [`StoredPack`], holding exactly what a demask
//! needs: the masked `text`, the display↔`MappingRef` `bindings` (contract v1.2 — the
//! only thing that lets `rehydrate` locate placeholders without scanning text), and the
//! `Namespace` the pack was minted under (so the demask resolves under the same scope even
//! when run from a different directory). Stats and a timestamp ride along for `vg audit`/
//! `vg diff` readability; they are informational and never used to drive substitution.
//!
//! **No raw values are ever written here** — the same invariant as `MaskedPack` itself: a
//! binding carries a typed display (`EMAIL_001`) and an opaque UUID, never a value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vg_core::{
    MappingRef, MaskStats, MaskedPack, Namespace, OrgId, PlaceholderBinding, RepoId, SessionId,
};

/// Current on-disk schema version for a persisted pack. Bumped if the shape below changes
/// incompatibly; a reader refuses an unknown version rather than silently mis-reading it.
pub const PACK_SCHEMA_VERSION: u32 = 1;

/// A serializable mirror of a [`MaskedPack`] plus the [`Namespace`] needed to demask it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPack {
    pub schema_version: u32,
    pub text: String,
    pub bindings: Vec<StoredBinding>,
    pub namespace: StoredNamespace,
    pub policy_version: String,
    #[serde(default)]
    pub stats: StoredStats,
    /// Unix seconds when the pack was persisted (informational).
    #[serde(default)]
    pub created_at: u64,
}

/// A display↔ref pairing, with the ref as its UUID text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBinding {
    pub display: String,
    pub mapping_ref: String,
}

/// A tagged, serializable [`Namespace`] (`{"kind":"repo","id":"..."}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum StoredNamespace {
    Session(String),
    Repo(String),
    Org(String),
}

/// Informational, redaction-safe stats (counts by entity-type debug name + blocked count).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredStats {
    #[serde(default)]
    pub counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub blocked_artefacts: usize,
}

/// Errors converting or loading a stored pack. `Display`/`Error` are hand-rolled below
/// rather than pulling `thiserror` into this crate (vg-core already owns that dependency;
/// this crate has no other need for it).
#[derive(Debug)]
pub enum PackError {
    Io(std::io::Error),
    Json(serde_json::Error),
    BadMappingRef(String),
    BadNamespace(String),
    UnknownSchema(u32),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackError::Io(e) => write!(f, "pack io error: {e}"),
            PackError::Json(e) => write!(f, "pack json error: {e}"),
            // Do NOT echo the raw field content (T11 cross-model finding): a corrupt/
            // hostile pack can put an arbitrary string — including a real value — in these
            // fields, and this is a redaction tool. Report the fault, not the payload.
            PackError::BadMappingRef(_) => {
                write!(
                    f,
                    "invalid mapping_ref in pack (not a UUID; value withheld)"
                )
            }
            PackError::BadNamespace(_) => {
                write!(
                    f,
                    "invalid namespace in pack (unrecognised; value withheld)"
                )
            }
            PackError::UnknownSchema(v) => write!(
                f,
                "pack schema_version {v} is newer than this build supports ({PACK_SCHEMA_VERSION})"
            ),
        }
    }
}

impl std::error::Error for PackError {}

impl From<std::io::Error> for PackError {
    fn from(e: std::io::Error) -> Self {
        PackError::Io(e)
    }
}

impl From<serde_json::Error> for PackError {
    fn from(e: serde_json::Error) -> Self {
        PackError::Json(e)
    }
}

impl StoredPack {
    /// Builds a stored pack from a masked pack and the namespace it was minted under.
    pub fn from_pack(pack: &MaskedPack, ns: &Namespace) -> Self {
        let bindings = pack
            .bindings
            .iter()
            .map(|b| StoredBinding {
                display: b.display.clone(),
                mapping_ref: b.mapping_ref.0.to_string(),
            })
            .collect();
        // `{ty}` (Display), never `{ty:?}` (Debug) -- Debug on a Custom variant would
        // serialise the raw policy-dictionary class name into this on-disk pack JSON,
        // exactly the leak this repo closed 2026-08-01 (docs/decisions.md). This
        // struct's own doc comment below claims these stats are "redaction-safe";
        // that claim was false for Custom until this fix.
        let counts = pack
            .stats
            .counts
            .0
            .iter()
            .map(|(ty, n)| (ty.to_string(), *n))
            .collect();
        Self {
            schema_version: PACK_SCHEMA_VERSION,
            text: pack.text.clone(),
            bindings,
            namespace: StoredNamespace::from_ns(ns),
            policy_version: pack.policy_version.clone(),
            stats: StoredStats {
                counts,
                blocked_artefacts: pack.stats.blocked_artefacts,
            },
            created_at: now_secs(),
        }
    }

    /// Reconstructs the `MaskedPack` (text + bindings, with `mapping_refs` derived and
    /// `stats` left default — a demask only reads `text` and `bindings`) and its
    /// `Namespace`.
    pub fn into_masked_pack(self) -> Result<(MaskedPack, Namespace), PackError> {
        // `!=`, not `>`: an *unknown* version includes ones that never existed (e.g. 0 from
        // a hand-edited or corrupted pack), not only newer ones (doubt-pass finding).
        if self.schema_version != PACK_SCHEMA_VERSION {
            return Err(PackError::UnknownSchema(self.schema_version));
        }
        let mut bindings = Vec::with_capacity(self.bindings.len());
        let mut mapping_refs = Vec::with_capacity(self.bindings.len());
        for b in self.bindings {
            // A tampered/corrupt pack with an empty display would make
            // `str::replace("")` insert the raw secret at every character boundary of
            // the text during demask (doubt-pass finding) — refuse it here.
            if b.display.is_empty() {
                return Err(PackError::BadMappingRef(
                    "binding with empty display".to_string(),
                ));
            }
            let uuid = Uuid::parse_str(&b.mapping_ref)
                .map_err(|_| PackError::BadMappingRef(b.mapping_ref.clone()))?;
            mapping_refs.push(MappingRef(uuid));
            bindings.push(PlaceholderBinding {
                display: b.display,
                mapping_ref: MappingRef(uuid),
            });
        }
        let ns = self.namespace.into_ns()?;
        let pack = MaskedPack {
            text: self.text,
            mapping_refs,
            bindings,
            stats: MaskStats::default(),
            policy_version: self.policy_version,
        };
        Ok((pack, ns))
    }

    /// Serialises to pretty JSON.
    pub fn to_json(&self) -> Result<String, PackError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Writes the pack to `dir/<uuid>.json`, returning the path written. The caller must
    /// have created `dir`.
    pub fn save_in(&self, dir: &Path) -> Result<PathBuf, PackError> {
        let path = dir.join(format!("{}.json", Uuid::new_v4()));
        std::fs::write(&path, self.to_json()?)?;
        Ok(path)
    }

    /// Loads and parses a stored pack from `path`.
    pub fn load(path: &Path) -> Result<Self, PackError> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

impl StoredNamespace {
    fn from_ns(ns: &Namespace) -> Self {
        match ns {
            Namespace::Session(SessionId(uuid)) => StoredNamespace::Session(uuid.to_string()),
            Namespace::Repo(RepoId(id)) => StoredNamespace::Repo(id.clone()),
            Namespace::Org(OrgId(id)) => StoredNamespace::Org(id.clone()),
        }
    }

    fn into_ns(self) -> Result<Namespace, PackError> {
        Ok(match self {
            StoredNamespace::Session(s) => {
                let uuid = Uuid::parse_str(&s).map_err(|_| PackError::BadNamespace(s.clone()))?;
                Namespace::Session(SessionId(uuid))
            }
            StoredNamespace::Repo(id) => Namespace::Repo(RepoId(id)),
            StoredNamespace::Org(id) => Namespace::Org(OrgId(id)),
        })
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
