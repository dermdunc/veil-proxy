//! Shared types owned by `vg-core`, frozen per
//! `docs/architecture/interface-contracts.md` v1.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::ids::{DetectorId, OrgId, RepoId, SessionId};

/// Classification of a detected entity.
///
/// `Custom` supports policy-dictionary-defined classes (the contract's "extensible via
/// policy dictionaries" note) without requiring a contract-change PR for every new
/// dictionary entry — only genuinely new *fixed* classes need one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EntityType {
    Person,
    Email,
    Phone,
    Address,
    Postcode,
    EmployeeId,
    CustomerId,
    AccountId,
    Iban,
    SortCode,
    InternalIp,
    Hostname,
    ApiKey,
    TraceId,
    Password,
    PrivateKey,
    Secret,
    AccessToken,
    /// A policy-dictionary-defined class, named by the dictionary (e.g.
    /// `"internal-project-codename"`).
    Custom(String),
}

impl std::fmt::Display for EntityType {
    /// The safe tag for rendering an `EntityType` into user-facing or persisted output
    /// (CLI summaries, stored-pack stats, placeholder display tags). `Custom` collapses
    /// to a fixed `"CUSTOM"` tag exactly like every other variant is a fixed tag — the
    /// policy-dictionary class name must never reach rendered text (closing the
    /// custom-entity-label leak, 2026-08-01: `{ty:?}` reached both `vg diff`'s stderr
    /// summary and the stored pack's on-disk stats keys, printing the raw name).
    ///
    /// Prefer `{}` over `{:?}` for `EntityType` everywhere outside code that is certain
    /// its output never leaves the process — `{:?}` (`Debug`) is deliberately left
    /// leaking the name, as the explicit "I know what I'm doing" escape hatch, not the
    /// default a caller reaches for out of habit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self {
            EntityType::Person => "PERSON",
            EntityType::Email => "EMAIL",
            EntityType::Phone => "PHONE",
            EntityType::Address => "ADDRESS",
            EntityType::Postcode => "POSTCODE",
            EntityType::EmployeeId => "EMPLOYEE_ID",
            EntityType::CustomerId => "CUSTOMER_ID",
            EntityType::AccountId => "ACCOUNT_ID",
            EntityType::Iban => "IBAN",
            EntityType::SortCode => "SORT_CODE",
            EntityType::InternalIp => "INTERNAL_IP",
            EntityType::Hostname => "HOSTNAME",
            EntityType::ApiKey => "API_KEY",
            EntityType::TraceId => "TRACE_ID",
            EntityType::Password => "PASSWORD",
            EntityType::PrivateKey => "PRIVATE_KEY",
            EntityType::Secret => "SECRET",
            EntityType::AccessToken => "ACCESS_TOKEN",
            EntityType::Custom(_) => "CUSTOM",
        };
        write!(f, "{tag}")
    }
}

/// What the policy says to do with a class of entity/artefact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlingClass {
    /// Reversible typed placeholder via vault.
    Mask,
    /// One-way; never vault-stored.
    IrreversibleRedact,
    /// Do not send (artefact-level).
    Block,
    /// Non-sensitive.
    Pass,
}

/// Namespace for placeholder stability: the same raw value maps to the same placeholder
/// only within the same namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Namespace {
    Session(SessionId),
    Repo(RepoId),
    Org(OrgId),
}

/// Structural context a `Parser` attaches to a `Span`, letting detectors be
/// field/structure-aware.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    Key,
    Value,
    Field(String),
    StringLiteral,
    Comment,
    Identifier,
    Other(String),
}

/// Byte span + optional structural context from a parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub node_kind: Option<NodeKind>,
}

/// A single detection over an input buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub entity_type: EntityType,
    pub span: Span,
    pub confidence: f32,
    pub detector: DetectorId,
}

/// Opaque handle into the vault; never the raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappingRef(pub Uuid);

/// Binds a display placeholder that `mask` minted (`EMAIL_001`) to the opaque
/// [`MappingRef`] the vault interned it under.
///
/// **Why this exists (contract v1.2, 2026-07-18, Task T09):** demask must locate the
/// placeholders to reverse **exclusively from the pack's own mappings — never by
/// pattern-scanning `.text` for placeholder-shaped substrings**. Raw input that already
/// contains an `EMAIL_001`-shaped string is byte-for-byte indistinguishable from pipeline
/// output, so a text scan cannot tell "a placeholder we minted" from "a coincidental
/// look-alike in the user's data". [`MaskedPack::mapping_refs`] alone can't drive
/// substitution either — a `MappingRef` is an opaque UUID with no display attached.
/// `mask` holds both the display and the ref at intern time, so it records the pairing
/// here and [`crate::rehydrate`] substitutes *only* these displays.
///
/// Carries only a typed display (`EMAIL_001`) and an opaque UUID — never a raw value — so
/// it does not widen [`MaskedPack`]'s "no raw value" invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderBinding {
    /// The minted display string as it appears in [`MaskedPack::text`] (`EMAIL_001`).
    pub display: String,
    /// The vault handle the display resolves through in [`crate::rehydrate`].
    pub mapping_ref: MappingRef,
}

/// Counts of findings by `EntityType`, used for audit/mask stats without exposing
/// values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntityCounts(pub BTreeMap<EntityType, usize>);

/// Summary stats attached to a `MaskedPack`: counts by `EntityType`, blocked artefacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaskStats {
    pub counts: EntityCounts,
    pub blocked_artefacts: usize,
}

/// The only thing serialized toward a model. **Must contain no raw detected value or
/// vault key** — produced correctly by `mask()`'s implementation (Task T07) and checked
/// in tests by [`crate::conformance::assert_masked_pack_excludes_raw_values`].
///
/// This is a testing/convention discipline, not a type-system guarantee: every field
/// here is `pub` with no smart constructor, so nothing stops code from hand-constructing
/// a `MaskedPack` with raw values in `.text` directly, bypassing `mask()` entirely.
/// `MappingRef` being an opaque `Uuid` (never a real key) is what makes "no vault key"
/// true by construction; "no raw detected value" depends entirely on `mask()`'s own
/// correctness and the conformance test's coverage, not on anything this type enforces.
#[derive(Debug, Clone, PartialEq)]
pub struct MaskedPack {
    pub text: String,
    pub mapping_refs: Vec<MappingRef>,
    /// display → `MappingRef` pairing for every placeholder `mask` minted into `text`
    /// (contract v1.2 additive field). Retained alongside `mapping_refs` (a subset — just
    /// the refs, no displays) rather than replacing it, since removing a frozen field
    /// would be a breaking change; `bindings` is the superset [`crate::rehydrate`] needs
    /// to reverse the pack without ever scanning `text` for placeholder-shaped strings.
    /// See [`PlaceholderBinding`].
    pub bindings: Vec<PlaceholderBinding>,
    pub stats: MaskStats,
    pub policy_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::assert_masked_pack_excludes_raw_values;

    #[test]
    fn masked_pack_invariant_helper_flags_a_leaked_raw_value() {
        let leaking = MaskedPack {
            text: "contact jane.doe@example.com for details".to_string(),
            mapping_refs: vec![],
            bindings: vec![],
            stats: MaskStats::default(),
            policy_version: "v1".to_string(),
        };
        let result = std::panic::catch_unwind(|| {
            assert_masked_pack_excludes_raw_values(&leaking, &["jane.doe@example.com"]);
        });
        assert!(
            result.is_err(),
            "helper must panic when a raw value is present in MaskedPack.text"
        );
    }

    #[test]
    fn masked_pack_invariant_helper_passes_on_placeholder_only_text() {
        let masked = MaskedPack {
            text: "contact {{EMAIL_1}} for details".to_string(),
            mapping_refs: vec![MappingRef(Uuid::nil())],
            bindings: vec![PlaceholderBinding {
                display: "{{EMAIL_1}}".to_string(),
                mapping_ref: MappingRef(Uuid::nil()),
            }],
            stats: MaskStats::default(),
            policy_version: "v1".to_string(),
        };
        assert_masked_pack_excludes_raw_values(&masked, &["jane.doe@example.com"]);
    }

    #[test]
    fn entity_type_display_never_carries_the_custom_dictionary_name() {
        // Regression for the custom-entity-label leak (docs/decisions.md, 2026-08-01):
        // `{ty:?}` (Debug) on a Custom variant prints the raw policy-dictionary class
        // name verbatim -- found reachable via `vg diff`'s stderr summary
        // (vg-cli/src/main.rs) and the stored pack's stats keys
        // (vg-adapters-claude/src/pack.rs), both outside the original fix's two sites.
        // `{ty}` (Display) is the safe default every caller should use instead.
        let ty = EntityType::Custom("internal-project-codename".to_string());
        assert_eq!(ty.to_string(), "CUSTOM");
        assert!(!ty.to_string().to_lowercase().contains("codename"));
        // Debug remains available and does still leak -- that's the point: Debug is the
        // explicit "I know what I'm doing, this stays in-process" escape hatch, not the
        // default any caller reaches for by habit.
        assert!(format!("{ty:?}").contains("codename"));
    }

    #[test]
    fn still_flags_fixed_type_display_is_unaffected() {
        assert_eq!(EntityType::Email.to_string(), "EMAIL");
        assert_eq!(EntityType::AccountId.to_string(), "ACCOUNT_ID");
    }
}
