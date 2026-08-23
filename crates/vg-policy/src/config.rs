//! Policy-pack config: the on-disk (serde) shape, 3-layer merge, and resolution into the
//! validated [`ResolvedPolicy`] the engine queries.
//!
//! A policy pack is deserialised into [`RawPack`] (every field optional, so a layer can
//! set only the keys it wants to override). Layers are merged
//! session-overrides-repo-overrides-global at the *raw* level by [`merge`], then the
//! single merged pack is validated and resolved once by [`ResolvedPolicy::from_raw`] —
//! this is where an unknown handling-class string becomes a load error, rather than
//! surfacing lazily on the first `classify_*` call.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use vg_core::{EntityType, HandlingClass, PolicyError};

/// One policy pack as read from disk. Every field is optional/defaulted so a repo or
/// session layer only has to name the keys it overrides, not restate the whole pack.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawPack {
    #[serde(default)]
    pub version: Option<String>,
    /// Phase 1: read but not verified (see [`verify_signature`]). Phase 2 verifies this
    /// against a trusted key over the pack bytes before the pack is trusted.
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub entities: RawEntityRules,
    #[serde(default)]
    pub artefacts: RawArtefactRules,
    #[serde(default)]
    pub destinations: BTreeMap<String, RawDestinationRule>,
    /// Whether opt-in telemetry (`vg_core::telemetry`) is enabled for this pack. Absent
    /// resolves to `false` (fail-safe: ADR-015 ratifies telemetry as opt-in, never
    /// opt-out — a policy pack that doesn't mention it must not silently turn telemetry
    /// on). "opt-in, policy-gated" per `docs/architecture/product-family.md`, which is
    /// why this lives here rather than a separate config surface.
    #[serde(default)]
    pub telemetry_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawEntityRules {
    /// Handling class for any entity type not named in `overrides`.
    #[serde(default)]
    pub default: Option<String>,
    /// Per-entity-type overrides, keyed by the stable string from [`entity_key`].
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawArtefactRules {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub by_extension: BTreeMap<String, String>,
    #[serde(default)]
    pub by_language: BTreeMap<String, String>,
    #[serde(default)]
    pub by_mime: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RawDestinationRule {
    /// Whether the destination accepts only masked content. Absent resolves to `true`
    /// (fail-safe: an unspecified destination is treated as masked-only).
    #[serde(default)]
    pub masked_only: Option<bool>,
    /// Whether demasking toward this destination is permitted at all. Absent resolves to
    /// `false` (fail-safe). Ignored for hard-deny destinations (see the engine).
    #[serde(default)]
    pub demask_allowed: Option<bool>,
    /// If non-empty, the actor must hold at least one of these roles for demask to be
    /// allowed. Empty/absent means no role restriction beyond `demask_allowed`.
    #[serde(default)]
    pub demask_roles: Option<Vec<String>>,
}

/// **PHASE 1 STUB — always accepts.** Real signed-pack verification (checking
/// `pack.signature` against a trusted signing key over the pack bytes, per
/// `interface-contracts.md` §6: "signed-pack verification before load (stub in Phase 1,
/// enforced later)") is deferred to Phase 2.
///
/// Returning `Ok(())` unconditionally is intentional for Phase 1 and **must be replaced**
/// before any untrusted policy pack is loaded — Phase 2 returns
/// [`PolicyError::Verify`] on a bad or missing signature. The signature type is
/// threaded through now (`RawPack::signature`) so adding real verification here does not
/// change the load flow or the on-disk schema.
pub fn verify_signature(_path: &Path, _bytes: &[u8]) -> Result<(), PolicyError> {
    Ok(())
}

/// Merge `over` onto `base`, `over` winning key-by-key (session-over-repo-over-global).
///
/// Scalars (`version`, `signature`, the `default` classes) take `over` when present,
/// else keep `base`. Map entries from `over` replace same-keyed `base` entries; keys only
/// in `base` are kept. Destination rules merge *field by field*, so a repo layer can flip
/// one destination's `demask_allowed` without restating its `masked_only`.
pub fn merge(base: RawPack, over: RawPack) -> RawPack {
    RawPack {
        version: over.version.or(base.version),
        signature: over.signature.or(base.signature),
        entities: RawEntityRules {
            default: over.entities.default.or(base.entities.default),
            overrides: merge_map(base.entities.overrides, over.entities.overrides),
        },
        artefacts: RawArtefactRules {
            default: over.artefacts.default.or(base.artefacts.default),
            by_extension: merge_map(base.artefacts.by_extension, over.artefacts.by_extension),
            by_language: merge_map(base.artefacts.by_language, over.artefacts.by_language),
            by_mime: merge_map(base.artefacts.by_mime, over.artefacts.by_mime),
        },
        destinations: merge_destinations(base.destinations, over.destinations),
        telemetry_enabled: over.telemetry_enabled.or(base.telemetry_enabled),
    }
}

fn merge_map(
    mut base: BTreeMap<String, String>,
    over: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    base.extend(over);
    base
}

fn merge_destinations(
    mut base: BTreeMap<String, RawDestinationRule>,
    over: BTreeMap<String, RawDestinationRule>,
) -> BTreeMap<String, RawDestinationRule> {
    for (key, over_rule) in over {
        let merged = match base.remove(&key) {
            Some(base_rule) => RawDestinationRule {
                masked_only: over_rule.masked_only.or(base_rule.masked_only),
                demask_allowed: over_rule.demask_allowed.or(base_rule.demask_allowed),
                demask_roles: over_rule.demask_roles.or(base_rule.demask_roles),
            },
            None => over_rule,
        };
        base.insert(key, merged);
    }
    base
}

/// A validated, query-ready policy: every handling class parsed, every default resolved.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub version: String,
    pub entity_default: HandlingClass,
    pub entity_overrides: BTreeMap<String, HandlingClass>,
    pub artefact_default: HandlingClass,
    pub artefact_by_extension: BTreeMap<String, HandlingClass>,
    pub artefact_by_language: BTreeMap<String, HandlingClass>,
    pub artefact_by_mime: BTreeMap<String, HandlingClass>,
    pub destinations: BTreeMap<String, DestinationSetting>,
    pub telemetry_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DestinationSetting {
    pub masked_only: bool,
    pub demask_allowed: bool,
    /// Empty means no role restriction; non-empty means the actor must hold one of these.
    pub demask_roles: Vec<String>,
}

impl ResolvedPolicy {
    /// Validate and resolve a merged raw pack. Fails with [`PolicyError::Load`] if any
    /// handling-class string is not one of `mask` / `irreversible-redact` / `block` /
    /// `pass` — a typo in a policy pack is a load-time error, not a silent
    /// misclassification later.
    pub fn from_raw(raw: RawPack) -> Result<Self, PolicyError> {
        let entity_default = match raw.entities.default {
            Some(s) => parse_class(&s)?,
            // Fail-safe: an entity we detected but the policy didn't classify is masked,
            // never passed through unmasked.
            None => HandlingClass::Mask,
        };
        let artefact_default = match raw.artefacts.default {
            Some(s) => parse_class(&s)?,
            // Deliberately `Pass`, not `Mask`/`Block` — and NOT the same fail-safe posture as
            // `entity_default` above, for a real reason (documented after a 2026-07-17
            // cross-model review flagged the asymmetry). Artefact class is a *whole-file*
            // decision: `Block` refuses to send a file at all (e.g. a `.env`), `Pass` lets it
            // through. Defaulting unknown file types to `Block` would refuse everything not
            // explicitly allow-listed and make the tool unusable; defaulting to `Pass` lets
            // them through — but their detected PII entities are STILL masked, because
            // entity-level classification defaults to `Mask` (above) independently of the
            // artefact class. **Hard requirement this leans on, for Task T07 (pipeline):**
            // artefact-`Pass` must mean "send after entity masking," NOT "skip detection/
            // masking for this file." If T07 ever lets an artefact class short-circuit entity
            // scanning, this default becomes a fail-open leak — so it must not.
            None => HandlingClass::Pass,
        };

        let artefact_by_extension = resolve_class_map(raw.artefacts.by_extension, true)?;
        let artefact_by_language = resolve_class_map(raw.artefacts.by_language, false)?;
        let artefact_by_mime = resolve_class_map(raw.artefacts.by_mime, false)?;

        // Phase-1 restriction (T07 review, fail-open fix): the pipeline implements only
        // `pass` and `block` at ARTEFACT scope — a pack saying an artefact class is
        // `mask`/`irreversible-redact` would previously parse fine and then be silently
        // treated as `Pass` by the pipeline, i.e. a policy author's "redact this whole
        // file" declaration failed open. Reject it loudly at load instead; artefact-scope
        // mask/redact semantics are a later-phase feature, not a silent no-op.
        for (scope, class) in std::iter::once(("default", &artefact_default))
            .chain(artefact_by_extension.iter().map(|(k, v)| (k.as_str(), v)))
            .chain(artefact_by_language.iter().map(|(k, v)| (k.as_str(), v)))
            .chain(artefact_by_mime.iter().map(|(k, v)| (k.as_str(), v)))
        {
            if !matches!(class, HandlingClass::Pass | HandlingClass::Block) {
                return Err(PolicyError::Load(format!(
                    "artefact class for {scope:?} is {class:?}, but artefact-scope policy \
                     supports only 'pass' or 'block' in Phase 1 (entity-scope handles \
                     mask/irreversible-redact) — refusing to load rather than silently \
                     treating it as pass"
                )));
            }
        }

        let version = raw
            .version
            .unwrap_or_else(|| "veilgremlin-policy-unversioned".to_string());
        // Validate the version's shape at load (T11 cross-model finding): `version` is
        // config-tainted and gets copied into every `MaskedPack` and onto blocked-hook
        // stderr, so a value accidentally set to a real identifier (a customer email, an
        // internal codename) would be persisted/echoed. Restrict it to an obviously-safe
        // token charset and a sane length so it can never carry free text.
        if version.len() > 64
            || !version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return Err(PolicyError::Load(format!(
                "policy `version` must be <=64 chars of [A-Za-z0-9._-] (got {} chars); it is \
                 persisted into packs and must never carry free text",
                version.len()
            )));
        }

        Ok(Self {
            version,
            entity_default,
            entity_overrides: resolve_class_map(raw.entities.overrides, false)?,
            artefact_default,
            artefact_by_extension,
            artefact_by_language,
            artefact_by_mime,
            destinations: raw
                .destinations
                .into_iter()
                .map(|(k, v)| (k, resolve_destination(v)))
                .collect(),
            telemetry_enabled: raw.telemetry_enabled.unwrap_or(false),
        })
    }
}

/// Resolve a `key -> class-string` map, parsing each class. When `lower_keys` is set the
/// keys are lower-cased (used for file extensions, matched case-insensitively).
fn resolve_class_map(
    raw: BTreeMap<String, String>,
    lower_keys: bool,
) -> Result<BTreeMap<String, HandlingClass>, PolicyError> {
    raw.into_iter()
        .map(|(k, v)| {
            let key = if lower_keys {
                k.to_ascii_lowercase()
            } else {
                k
            };
            Ok((key, parse_class(&v)?))
        })
        .collect()
}

fn resolve_destination(raw: RawDestinationRule) -> DestinationSetting {
    DestinationSetting {
        masked_only: raw.masked_only.unwrap_or(true),
        demask_allowed: raw.demask_allowed.unwrap_or(false),
        demask_roles: raw.demask_roles.unwrap_or_default(),
    }
}

/// Parse a policy-pack handling-class string into the `vg-core` enum.
pub fn parse_class(s: &str) -> Result<HandlingClass, PolicyError> {
    match s {
        "mask" => Ok(HandlingClass::Mask),
        "irreversible-redact" | "redact" => Ok(HandlingClass::IrreversibleRedact),
        "block" => Ok(HandlingClass::Block),
        "pass" => Ok(HandlingClass::Pass),
        other => Err(PolicyError::Load(format!(
            "unknown handling class {other:?} (expected one of: mask, irreversible-redact, block, pass)"
        ))),
    }
}

/// Stable string key a policy dictionary uses for one [`EntityType`]. `Custom(name)` keys
/// on its dictionary name directly. `EntityType` is `#[non_exhaustive]`, so a variant
/// added to `vg-core` later falls back to a lower-cased debug name — it can still be keyed
/// in a pack without a breaking change here.
pub fn entity_key(ty: &EntityType) -> String {
    let s = match ty {
        EntityType::Person => "person",
        EntityType::Email => "email",
        EntityType::Phone => "phone",
        EntityType::Address => "address",
        EntityType::Postcode => "postcode",
        EntityType::EmployeeId => "employee-id",
        EntityType::CustomerId => "customer-id",
        EntityType::AccountId => "account-id",
        EntityType::Iban => "iban",
        EntityType::SortCode => "sort-code",
        EntityType::InternalIp => "internal-ip",
        EntityType::Hostname => "hostname",
        EntityType::ApiKey => "api-key",
        EntityType::TraceId => "trace-id",
        EntityType::Password => "password",
        EntityType::PrivateKey => "private-key",
        EntityType::Secret => "secret",
        EntityType::AccessToken => "access-token",
        EntityType::Custom(name) => return name.clone(),
        other => return format!("{other:?}").to_ascii_lowercase(),
    };
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn merge_prefers_over_layer_per_key_but_keeps_base_only_keys() {
        let base = RawPack {
            version: Some("base".to_string()),
            entities: RawEntityRules {
                default: Some("mask".to_string()),
                overrides: class_map(&[("email", "mask"), ("hostname", "pass")]),
            },
            ..RawPack::default()
        };
        let over = RawPack {
            version: Some("over".to_string()),
            entities: RawEntityRules {
                default: None,
                overrides: class_map(&[("email", "irreversible-redact")]),
            },
            ..RawPack::default()
        };

        let merged = merge(base, over);
        assert_eq!(merged.version.as_deref(), Some("over"));
        // over-layer default absent -> base default retained.
        assert_eq!(merged.entities.default.as_deref(), Some("mask"));
        // email overridden by over; hostname (base-only) kept.
        let overrides = &merged.entities.overrides;
        assert_eq!(
            overrides.get("email"),
            Some(&"irreversible-redact".to_string())
        );
        assert_eq!(overrides.get("hostname"), Some(&"pass".to_string()));
    }

    #[test]
    fn destination_merge_is_field_by_field() {
        let base_rule = RawDestinationRule {
            masked_only: Some(false),
            demask_allowed: Some(false),
            demask_roles: None,
        };
        let over_rule = RawDestinationRule {
            masked_only: None,
            demask_allowed: Some(true),
            demask_roles: Some(vec!["reviewer".to_string()]),
        };
        let mut base_dests = BTreeMap::new();
        base_dests.insert("local-explanation-buffer".to_string(), base_rule);
        let mut over_dests = BTreeMap::new();
        over_dests.insert("local-explanation-buffer".to_string(), over_rule);

        let merged = merge_destinations(base_dests, over_dests);
        let rule = &merged["local-explanation-buffer"];
        // over left masked_only unset -> base's false survives; demask_allowed flipped.
        assert_eq!(rule.masked_only, Some(false));
        assert_eq!(rule.demask_allowed, Some(true));
        assert_eq!(rule.demask_roles, Some(vec!["reviewer".to_string()]));
    }

    #[test]
    fn unknown_handling_class_is_a_load_error() {
        let raw = RawPack {
            entities: RawEntityRules {
                default: None,
                overrides: class_map(&[("email", "encrypt-somehow")]),
            },
            ..RawPack::default()
        };
        let err = ResolvedPolicy::from_raw(raw).expect_err("bad class must fail resolution");
        assert!(
            matches!(err, PolicyError::Load(_)),
            "expected Load error, got {err:?}"
        );
    }

    #[test]
    fn artefact_scope_mask_or_redact_is_a_load_error_not_a_silent_pass() {
        // T07 review (fail-open fix): the pipeline implements only pass|block at artefact
        // scope. A pack declaring an artefact class of mask/irreversible-redact used to
        // parse fine and then be silently treated as Pass — a policy author's "redact
        // this whole file" failing open. It must refuse to load instead.
        let raw = RawPack {
            artefacts: RawArtefactRules {
                by_extension: class_map(&[("sql", "irreversible-redact")]),
                ..RawArtefactRules::default()
            },
            ..RawPack::default()
        };
        let err = ResolvedPolicy::from_raw(raw).expect_err("artefact-scope redact must fail load");
        assert!(
            matches!(err, PolicyError::Load(_)),
            "expected Load error, got {err:?}"
        );
    }

    #[test]
    fn telemetry_enabled_defaults_to_false_when_absent_from_every_layer() {
        // ADR-015: opt-in, never opt-out -- a pack that never mentions telemetry must
        // resolve to disabled, not merely "unspecified."
        let resolved = ResolvedPolicy::from_raw(RawPack::default()).unwrap();
        assert!(!resolved.telemetry_enabled);
    }

    #[test]
    fn telemetry_enabled_true_resolves_when_set() {
        let raw = RawPack {
            telemetry_enabled: Some(true),
            ..RawPack::default()
        };
        let resolved = ResolvedPolicy::from_raw(raw).unwrap();
        assert!(resolved.telemetry_enabled);
    }

    #[test]
    fn telemetry_enabled_merges_over_wins_when_present() {
        let base = RawPack {
            telemetry_enabled: Some(true),
            ..RawPack::default()
        };
        let over = RawPack {
            telemetry_enabled: Some(false),
            ..RawPack::default()
        };
        let merged = merge(base, over);
        assert_eq!(merged.telemetry_enabled, Some(false));
    }

    #[test]
    fn telemetry_enabled_merge_keeps_base_when_over_is_absent() {
        // Distinguishes "over explicitly disables" (previous test) from "over doesn't
        // mention it at all" -- an absent field in a repo/session layer must not
        // silently disable telemetry a stricter global layer turned on.
        let base = RawPack {
            telemetry_enabled: Some(true),
            ..RawPack::default()
        };
        let over = RawPack::default();
        let merged = merge(base, over);
        assert_eq!(merged.telemetry_enabled, Some(true));
    }

    #[test]
    fn entity_key_maps_custom_to_its_dictionary_name() {
        assert_eq!(entity_key(&EntityType::AccessToken), "access-token");
        assert_eq!(
            entity_key(&EntityType::Custom("internal-codename".to_string())),
            "internal-codename"
        );
    }
}
