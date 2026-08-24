//! Bounded, non-raw-capable identifier and token types for the `TelemetryEvent` type
//! system (`docs/architecture/telemetry-receipt-reconciliation-plan.md` §3.2a — the
//! "required deliverable: type inventory"). None of these have a public constructor
//! that accepts an unvalidated `String`: either the representation makes a raw value
//! structurally unrepresentable (UUID, fixed-size byte array, closed enum), or the
//! constructor is fallible and validates a bounded charset.
//!
//! **None of the data types below derive `Debug` or `Hash`.** `Debug` was removed
//! because `docs/architecture/implementation-plan.md` §3.2 explicitly rules out a
//! `Debug` serialisation path. `Hash` was removed separately and later: a fourth
//! adversarial review round proved — by compiling and running an external-crate
//! integration test — that `#[derive(Hash)]` over a private `String`/byte-array field is
//! a *verbatim* recovery channel, not merely a weaker one than `Debug`. `Hash::hash`
//! takes a caller-supplied `H: Hasher`; a `Hasher` that just records the bytes it's
//! given (instead of actually hashing them) recovers the private field byte-for-byte
//! through the ordinary, safe `Hash` trait — no unsafe code, no privacy violation the
//! compiler can see. Removing `Debug` alone left this channel wide open. Nothing in this
//! module or its tests uses these types as a map/set key, so `Hash` cost nothing to
//! remove. Only the `thiserror::Error` types below (`TokenError`, `DeviceRefError`)
//! still derive `Debug` (`Hash` was never on them), because `std::error::Error` requires
//! `Debug` and their fields are compile-time-fixed safe labels, not runtime data — a
//! different case from the value types this rule targets.
//!
//! **A flagged interpretive choice, not silently redefined:**
//! `docs/architecture/implementation-plan.md` §3.2's "zero `String` columns" invariant
//! lists a closed set of sanctioned encodings — enums, integers, booleans, fixed-width
//! hashes — that does not literally include "validated bounded string." The seven
//! `bounded_token!` types below (`VersionToken`, `DetectorSetId`, `ExceptionRuleId`,
//! `TenantId`, `AlertRuleId`, `KeyRef`, `RegistryRef`) are `String`-backed underneath a
//! private field and a fallible, charset-validated constructor — meaningfully bounded,
//! but not literally zero-`String`. This was a deliberate judgment call (caught and
//! confirmed independently by two doubt-driven-development review rounds, not missed):
//! these identifiers are inherently human-legible, variable-content tokens
//! (policy/detector-bundle versions, rule ids) that ops teams need to read; collapsing
//! them to a fixed-width hash would trade real information loss for literal compliance.
//! A stronger fix — hash-based identifiers resolved through a versioned registry at
//! ingest, per the reconciliation plan's own §3.2a language for open external domains —
//! is real future work, not done here.

use thiserror::Error;
use uuid::Uuid;

use crate::traits::ArtefactKind;
use crate::types::EntityType;

/// Correlation identifier for a Bedrock invocation (`linkage.veil_trace_id` /
/// `logical_interaction_id` / `local_trace_id`). UUID-backed rather than ULID-backed: no
/// ULID crate is a dependency of this crate today (`Cargo.toml` has `uuid` only), and
/// adding one is a real, deliberate future decision — not made silently here. The final
/// wire pattern (e.g. a `tr_`-prefixed hex string) is schema-generation's job, a
/// separate, later deliverable.
///
/// **Deliberately does not derive `Ord`/`PartialOrd` (or `Hash`).** A first version of
/// this type derived `Ord`, reasoned (wrongly) that a single `Ord::cmp` call only ever
/// returns an `Ordering` and so couldn't reproduce this module doc's `Hash`-based
/// byte-recovery channel. A doubt-driven-development review round caught the flaw: `Ord`
/// being `pub` lets any external holder of a `TraceId` run ~128 adaptive `<`/`cmp` calls
/// (a binary search) against self-minted probe values to recover the wrapped `Uuid`
/// bit-for-bit — the same class of channel as the `Hash` case, just amortised over many
/// calls instead of one. `telemetry::aggregator::TraceBuffer` still needs a total order to
/// key a `BTreeMap` by trace, so it orders by [`TraceId::ordering_key`] instead — a
/// `pub(crate)` escape hatch that keeps comparison capability inside this crate rather
/// than exposing it on the public type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TraceId(Uuid);

impl From<Uuid> for TraceId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl TraceId {
    /// A `pub(crate)`-only, order-preserving key for keying a `BTreeMap<_, _>` by trace
    /// (`telemetry::aggregator::TraceBuffer`). Not `pub`: see this type's own doc for why
    /// exposing an ordering on `TraceId` itself is a comparison-oracle recovery channel
    /// this module deliberately closes.
    pub(crate) fn ordering_key(&self) -> u128 {
        self.0.as_u128()
    }
}

/// Identity of one telemetry record (`Envelope::record_id`). Mirrors `AuditId(Uuid)`'s
/// precedent in `crate::ids`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecordId(Uuid);

impl From<Uuid> for RecordId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

/// Why a bounded-token constructor rejected its input. Derives `Debug`: required by
/// `std::error::Error` (via `thiserror::Error`), and every field here is a
/// compile-time-fixed variant label or a `usize`/length — never runtime string content
/// — so it doesn't fall under the "no `Debug` serialisation path" rule that governs the
/// value types in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TokenError {
    #[error("token must not be empty")]
    Empty,
    #[error("token exceeds 64 bytes")]
    TooLong,
    #[error("token contains a byte outside the allowed charset for this field")]
    InvalidChar,
}

/// Charset/length bound shared by every human-legible token type below: non-empty, at
/// most 64 bytes, ASCII alphanumeric (upper and lower) plus `._-` and whatever
/// `extra_chars` the caller passes for a field-specific separator.
///
/// The base charset matches `crates/vg-policy/src/config.rs`'s real, already-shipped
/// `version` validator exactly (`c.is_ascii_alphanumeric() || matches!(c, '.' | '-' |
/// '_')`, `len() <= 64`) — an earlier draft of this function was lowercase-only, which a
/// doubt-driven-development review caught: every fixture in this repo happens to be
/// lowercase, but nothing upstream enforces that, and a legitimately uppercase policy
/// version (valid per `vg-policy`'s own rule) would have been silently rejected once
/// `Controls::policy_version` is wired to `PolicyEngine::version()`.
///
/// `extra_chars` exists because a second doubt-driven-development round caught that
/// `DetectorSetId`'s real producer (`crates/vg-core/src/api.rs:465-469`'s
/// `detector_version`, `ids.join("+")`) uses `+` as a separator — a charset shared
/// verbatim across all seven token types would either wrongly reject that real value or
/// wrongly accept `+` in fields (like `VersionToken`) that don't need it. `allow_empty`
/// exists for the same class of reason, found later: `crates/vg-policy/src/config.rs`'s
/// real, shipped `version` validator has no `is_empty()` check at all (only
/// `len() > 64` and charset), so an explicitly-empty `version` string is legal there
/// today — `VersionToken` rejecting empty unconditionally would silently diverge from
/// its own cited precedent. Hand-rolled rather than a `regex` dependency (none exists in
/// this crate).
fn validate_token(s: &str, extra_chars: &str, allow_empty: bool) -> Result<(), TokenError> {
    if s.is_empty() && !allow_empty {
        return Err(TokenError::Empty);
    }
    if s.len() > 64 {
        return Err(TokenError::TooLong);
    }
    if !s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') || extra_chars.contains(c)
    }) {
        return Err(TokenError::InvalidChar);
    }
    Ok(())
}

macro_rules! bounded_token {
    ($name:ident, $doc:expr) => {
        bounded_token!($name, $doc, "", false);
    };
    ($name:ident, $doc:expr, $extra_chars:expr) => {
        bounded_token!($name, $doc, $extra_chars, false);
    };
    ($name:ident, $doc:expr, $extra_chars:expr, $allow_empty:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl TryFrom<&str> for $name {
            type Error = TokenError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                validate_token(s, $extra_chars, $allow_empty)?;
                Ok(Self(s.to_string()))
            }
        }
    };
}

bounded_token!(
    VersionToken,
    "A validated policy-bundle version identifier (`Controls::policy_version`). Allows \
     an empty string — `crates/vg-policy/src/config.rs`'s real, shipped `version` \
     validator has no `is_empty()` check, so an explicitly-empty version is legal \
     upstream today. An earlier draft rejected empty unconditionally, silently \
     diverging from the exact precedent this type's charset otherwise claims to match \
     (caught by a fourth adversarial review round).",
    "",
    true
);
bounded_token!(
    DetectorSetId,
    "A validated detector-bundle version identifier (`Controls::detector_version`). \
     Allows `+` in addition to the shared base charset — matches the real producer's \
     format exactly (`crates/vg-core/src/api.rs`'s `detector_version`: sorted detector \
     ids joined with `+`, e.g. `email+entropy+ip`). An earlier draft used the shared \
     charset unmodified, which would have rejected every real multi-detector scan \
     (caught by doubt-driven-development review). An empty detector list would still \
     produce an empty string, which this type still rejects (`TokenError::Empty`) — \
     deliberately: an empty detector-version on a real scan signals a configuration bug \
     worth surfacing loudly, not a value to silently accept. This charset matches \
     *observed* detector ids, not an enforced bound on them: `DetectorId(pub String)` \
     (`crate::ids`) is itself unconstrained — already named as one of the six \
     raw-capable surfaces in `docs/architecture/implementation-plan.md` §3.1, sequenced \
     to close before this type system, but not yet closed. A future detector id outside \
     this charset would make `detector_version(ctx)`'s output unconvertible here, with \
     no dedicated `TelemetryReject` for that case.",
    "+"
);
bounded_token!(
    ExceptionRuleId,
    "A validated policy-authored exception-rule identifier (`Controls::exceptions`)."
);
bounded_token!(
    TenantId,
    "A validated tenant identifier (`Envelope::tenant_id`). Always `None` in v1 — the \
     ratified Q2 decision targets per-laptop enrolment only \
     (`docs/architecture/telemetry-receipt-reconciliation-plan.md` §4a)."
);
bounded_token!(
    AlertRuleId,
    "A validated policy-authored alert-rule identifier (`Alert::rule`)."
);
bounded_token!(
    KeyRef,
    "A validated opaque signing-key identifier (`Integrity::key_ref`)."
);
bounded_token!(
    RegistryRef,
    "A charset/length-bounded reference (`CallerContext::repository_id` / \
     `workspace_id`) — blocks the *shape* of the concrete leak the reconciliation plan \
     §2.4 names (`github://org/repo`, which fails on `:` and `/`), but does **not** \
     enforce that the value is actually hashed or registry-assigned. A human-legible, \
     non-hashed identifier like `acme-corp-backend-repo` still validates cleanly \
     (caught by doubt-driven-development review — an earlier doc comment here claimed \
     'hashed or registry-assigned' as if the type enforced it). Callers are responsible \
     for actually hashing or resolving through a registry before constructing one; this \
     type only guarantees the wire-safe charset, not the stronger property its name \
     implies."
);

/// Why `DeviceRef::try_from` rejected its input. Derives `Debug` for the same
/// `thiserror`/safe-fields-only reason as `TokenError` above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeviceRefError {
    #[error("device_ref must be exactly 16 bytes, got {0}")]
    WrongLength(usize),
}

/// Enrolment-minted device pseudonym (`Envelope::device_ref`). 16 bytes, matching the
/// reconciliation plan's own envelope sketch pattern exactly (`^dev_[a-f0-9]{32}$` is 32
/// hex characters = 16 bytes). `Envelope::device_ref` stays `None` until
/// `veil-custodian`'s enrolment registry exists (ratified Q1) — this type exists now so
/// the envelope's shape is correct in advance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceRef([u8; 16]);

impl TryFrom<&[u8]> for DeviceRef {
    type Error = DeviceRefError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| DeviceRefError::WrongLength(bytes.len()))?;
        Ok(Self(arr))
    }
}

/// Integer index into a not-yet-built versioned reason dictionary (block reasons, alert
/// rule explanations). The distribution mechanism for that dictionary is explicitly
/// deferred (`telemetry-receipt-reconciliation-plan.md` §5, "the reason-dictionary
/// distribution mechanism... belongs with the policy/detector-pack distribution
/// channel") — this type exists now so callers reach for a code, never a raw string, in
/// the meantime.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReasonCode(u16);

impl From<u16> for ReasonCode {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

/// Closed classification for telemetry, mirroring `EntityType`'s fixed variants but
/// collapsing `EntityType::Custom(_)` to a single `Custom` unit variant — implements the
/// ratified Q6 decision (`docs/decisions.md`, 2026-08-23). Precisely: the custom
/// dictionary *name* is excluded from telemetry entirely and is structurally
/// unrepresentable here (a closed enum, not a bounded string) — the *fact* that some
/// custom-class detection occurred, and its count, still reaches telemetry via this
/// `Custom` tag plus `Detection::count`; only the specific name never transits the wire
/// (tightened wording — a doubt-driven-development review flagged the previous phrasing,
/// "excluded from telemetry entirely," as reasonably misreadable as "no custom-class
/// signal reaches telemetry at all," which overstates the guarantee).
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntityClassId {
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
    /// Any `EntityType::Custom(_)` collapses here — the dictionary name never crosses.
    Custom,
}

impl From<&EntityType> for EntityClassId {
    /// Exhaustive over `EntityType`'s current variants. `EntityType` is
    /// `#[non_exhaustive]` from outside `vg-core`, but this impl lives inside `vg-core`
    /// itself, so the compiler still enforces exhaustiveness here — a future
    /// `EntityType` variant forces a reviewed decision in this match, the same
    /// discipline `TryFrom<&AuditEvent>` applies in `telemetry::mod`.
    fn from(ty: &EntityType) -> Self {
        match ty {
            EntityType::Person => EntityClassId::Person,
            EntityType::Email => EntityClassId::Email,
            EntityType::Phone => EntityClassId::Phone,
            EntityType::Address => EntityClassId::Address,
            EntityType::Postcode => EntityClassId::Postcode,
            EntityType::EmployeeId => EntityClassId::EmployeeId,
            EntityType::CustomerId => EntityClassId::CustomerId,
            EntityType::AccountId => EntityClassId::AccountId,
            EntityType::Iban => EntityClassId::Iban,
            EntityType::SortCode => EntityClassId::SortCode,
            EntityType::InternalIp => EntityClassId::InternalIp,
            EntityType::Hostname => EntityClassId::Hostname,
            EntityType::ApiKey => EntityClassId::ApiKey,
            EntityType::TraceId => EntityClassId::TraceId,
            EntityType::Password => EntityClassId::Password,
            EntityType::PrivateKey => EntityClassId::PrivateKey,
            EntityType::Secret => EntityClassId::Secret,
            EntityType::AccessToken => EntityClassId::AccessToken,
            EntityType::Custom(_) => EntityClassId::Custom,
        }
    }
}

/// Closed classification for telemetry, mirroring `ArtefactKind`'s fixed variants but
/// collapsing `ArtefactKind::SourceCode(String)` to a single `SourceCode` unit
/// variant — same discipline as `EntityClassId::Custom` above, and for the same reason:
/// `ArtefactKind::SourceCode(String)` is itself still one of the six raw-capable
/// surfaces named in `docs/architecture/implementation-plan.md` §3.1 and not yet fixed
/// at its source, so telemetry must not transit the language name until it is. A real
/// bounded language enum (rust/python/js/...) is a follow-up once that surface closes,
/// not built here.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtefactKindId {
    Json,
    Yaml,
    Toml,
    Sql,
    Csv,
    LogLine,
    Diff,
    EnvFile,
    SourceCode,
    PlainText,
    Unknown,
}

impl From<&ArtefactKind> for ArtefactKindId {
    fn from(kind: &ArtefactKind) -> Self {
        match kind {
            ArtefactKind::Json => ArtefactKindId::Json,
            ArtefactKind::Yaml => ArtefactKindId::Yaml,
            ArtefactKind::Toml => ArtefactKindId::Toml,
            ArtefactKind::Sql => ArtefactKindId::Sql,
            ArtefactKind::Csv => ArtefactKindId::Csv,
            ArtefactKind::LogLine => ArtefactKindId::LogLine,
            ArtefactKind::Diff => ArtefactKindId::Diff,
            ArtefactKind::EnvFile => ArtefactKindId::EnvFile,
            ArtefactKind::SourceCode(_) => ArtefactKindId::SourceCode,
            ArtefactKind::PlainText => ArtefactKindId::PlainText,
            ArtefactKind::Unknown => ArtefactKindId::Unknown,
        }
    }
}

/// A pseudonymized actor identity (32 bytes — HMAC-SHA256 output width). **No public
/// constructor** — only `pub(crate) fn from_bytes` for this module's own tests and a
/// future real pseudonymization mechanism to call. Building a throwaway
/// pseudonymization scheme here (e.g. keyed on a locally-generated, unmanaged secret)
/// would just have to be thrown away again once the ratified fix — "keyed HMAC
/// pseudonym, computed locally" (`docs/next-actions.md`'s six-raw-capable-surfaces item)
/// — actually lands; see `telemetry::mod`'s `TryFrom<&AuditEvent>` doc comment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActorPseudonym([u8; 32]);

impl ActorPseudonym {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_token_accepts_a_conforming_value() {
        assert!(VersionToken::try_from("policy-v3.1").is_ok());
    }

    #[test]
    fn version_token_accepts_uppercase_matching_vg_policys_real_validator() {
        // Regression for the doubt-driven-development finding: a lowercase-only
        // charset would silently reject a policy version that vg-policy's own
        // `config.rs` validator (`c.is_ascii_alphanumeric()`) accepts as legitimate.
        assert!(VersionToken::try_from("Veilgremlin-Policy-V1").is_ok());
    }

    #[test]
    fn version_token_accepts_empty_matching_vg_policys_real_validator() {
        // vg-policy's real, shipped validator has no is_empty() check — matching it
        // exactly means VersionToken must accept "" too, not reject it.
        assert!(VersionToken::try_from("").is_ok());
    }

    #[test]
    fn detector_set_id_still_rejects_empty() {
        // Unlike VersionToken, DetectorSetId has no real upstream precedent permitting
        // an empty value — this is a deliberate, reasoned default (an empty
        // detector-version on a real scan signals a configuration bug), not a
        // divergence from a known real validator.
        assert!(DetectorSetId::try_from("") == Err(TokenError::Empty));
    }

    #[test]
    fn version_token_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(VersionToken::try_from(long.as_str()) == Err(TokenError::TooLong));
    }

    #[test]
    fn version_token_rejects_invalid_char() {
        assert!(VersionToken::try_from("jane.doe@example.com") == Err(TokenError::InvalidChar));
        assert!(VersionToken::try_from("has spaces") == Err(TokenError::InvalidChar));
        assert!(VersionToken::try_from("has\nnewline") == Err(TokenError::InvalidChar));
    }

    #[test]
    fn version_token_rejects_plus_but_detector_set_id_accepts_it() {
        // VersionToken doesn't need the `+` separator DetectorSetId's real producer
        // uses — proves the per-type extra_chars parameterisation actually varies by
        // type rather than silently widening every token's charset.
        assert!(VersionToken::try_from("a+b") == Err(TokenError::InvalidChar));
        assert!(DetectorSetId::try_from("email+entropy+ip").is_ok());
    }

    #[test]
    fn device_ref_requires_exactly_16_bytes() {
        assert!(DeviceRef::try_from([0u8; 16].as_slice()).is_ok());
        assert!(DeviceRef::try_from([0u8; 15].as_slice()) == Err(DeviceRefError::WrongLength(15)));
        assert!(DeviceRef::try_from([0u8; 17].as_slice()) == Err(DeviceRefError::WrongLength(17)));
        assert!(DeviceRef::try_from([].as_slice()) == Err(DeviceRefError::WrongLength(0)));
    }

    #[test]
    fn entity_class_id_collapses_custom() {
        let ty = EntityType::Custom("internal-project-codename".to_string());
        let class = EntityClassId::from(&ty);
        // No `format!("{class:?}")` check here (no Debug on EntityClassId, per this
        // module's own rule) — the guarantee is now structural: `EntityClassId::Custom`
        // is a unit variant with no field, so there is no representation, Debug or
        // otherwise, that could carry "internal-project-codename" through it.
        assert!(class == EntityClassId::Custom);
    }

    #[test]
    fn artefact_kind_id_collapses_source_code_language_name() {
        let kind = ArtefactKind::SourceCode("rust".to_string());
        assert!(ArtefactKindId::from(&kind) == ArtefactKindId::SourceCode);
    }

    #[test]
    fn entity_class_id_maps_fixed_variants_through() {
        assert!(EntityClassId::from(&EntityType::Email) == EntityClassId::Email);
        assert!(EntityClassId::from(&EntityType::AccountId) == EntityClassId::AccountId);
    }
}
