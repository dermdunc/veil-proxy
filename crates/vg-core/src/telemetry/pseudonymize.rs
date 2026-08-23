//! Keyed-HMAC actor pseudonymization: turns a real `ActorId` into an opaque
//! [`ActorPseudonym`] for telemetry, per `docs/next-actions.md`'s "`ActorId`
//! pseudonymization (keyed HMAC, computed locally)" item and the ratified per-device,
//! no-cross-device-correlation scope (this session's interview).
//!
//! `vg-core` does not generate, store, or retrieve the key here — same stance as
//! `crate::keying`'s `placeholder_key` (see its doc comment): this crate doesn't own
//! persistent secret storage, so a compiled-in key would make "keyed" a no-op. Callers
//! load an [`ActorPseudonymKey`] via `vg-vault` (its OS-keychain-backed loader) and pass
//! it in.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

use super::ids::ActorPseudonym;
use crate::ids::ActorId;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separates this HMAC's message space from any other keyed construction in this
/// crate (e.g. `crate::keying::placeholder_key`) that might reuse the same key material
/// by caller error — distinct label, so even an accidental key reuse can't produce
/// colliding messages across the two constructions.
const DOMAIN_LABEL: &[u8] = b"veilgremlin-actor-pseudonym-v1";

/// A 32-byte HMAC key for actor pseudonymization. Not vault-related — a distinct
/// secret, per-device. This is *security material*, not a telemetry *value* type, so it
/// follows `Secret`/`PlaceholderKey`'s existing convention (redacting `Debug`,
/// zeroize-on-drop), not `telemetry::`'s "no `Debug` at all" rule for wire-contract data.
/// `PartialEq`/`Eq` (not `Hash` — a security-material key must never derive `Hash`, same
/// reasoning as `telemetry::`'s value types: a custom `Hasher` fed to a derived `Hash`
/// impl can record the raw bytes written to it) exist only so tests can assert two keys
/// are/aren't the same; a derived byte-equality check is not a side channel the way
/// `Hash::hash`'s caller-controlled `Write` sequence is.
///
/// **`from_bytes` is deliberately unrestricted `pub`, not `pub(crate)`-restricted to
/// `vg-vault`'s loader** (a doubt-driven-development finding, not an oversight): this
/// crate's own integration tests (`crates/vg-core/tests/telemetry.rs`) construct
/// `EdgeEvent::try_from_audit_event` end-to-end and, being a separate compiled crate
/// under `cargo test`'s rules, can only reach `pub` items. The real protection this type
/// offers is not "nothing outside this module can construct one" — like
/// `Secret::new(String)` elsewhere in this crate, any caller *can* fabricate one — it is
/// that [`crate::telemetry::EdgeEvent::try_from_audit_event`] and
/// [`pseudonymize_actor`] never generate, store, or retrieve key material themselves;
/// only `vg_vault::load_or_create_actor_pseudonym_key` (the OS-keychain-backed loader)
/// is the legitimate path to a real per-device key in production, and it returns an
/// already-wrapped `ActorPseudonymKey`, not a bare `[u8; 32]`, precisely so production
/// call sites never have a reason to call `from_bytes` themselves.
#[derive(PartialEq, Eq)]
pub struct ActorPseudonymKey([u8; 32]);

impl ActorPseudonymKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for ActorPseudonymKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ActorPseudonymKey")
            .field(&"<redacted>")
            .finish()
    }
}

impl Drop for ActorPseudonymKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Computes `HMAC-SHA256(key, DOMAIN_LABEL || 0x1F || canonicalize(actor.0))`. `0x1F`
/// (ASCII Unit Separator) prevents a naive-concatenation collision between the fixed
/// domain label and the actor string, matching `placeholder_key`'s own separator
/// rationale.
///
/// **Trims, collapses internal whitespace runs, and lowercases `actor.0` before
/// hashing** — a doubt-driven-development finding, checked against real production
/// evidence rather than left as an open question: `crates/vg-cli/src/main.rs`'s `vg
/// demask --actor <STRING>` is a free-typed operator CLI argument with no validation
/// anywhere upstream (`ActorId(actor)` wraps the raw `clap` string directly), so the
/// *same* real actor typing the same identity across two invocations can trivially
/// produce `"jane.doe"` vs. `"Jane.Doe"` vs. `" jane.doe "` vs. `"jane  doe"`. Without
/// normalization those would pseudonymize differently even on the same device with the
/// same key, silently breaking the "same actor, same device -> same pseudonym" property
/// this function exists to provide — not just a cross-device concern. Internal-whitespace
/// collapsing reuses `crate::keying::canonicalize`'s first step
/// (`split_whitespace().join(" ")`) rather than importing that function wholesale: actor
/// identities aren't IBANs/phone numbers with structurally equivalent alternate
/// renderings, so trim + whitespace-collapse + lowercase is the fix sized to the
/// concrete evidence above, not a blanket import of `canonicalize`'s cosmetic-separator
/// stripping (which targets a different problem shape).
///
/// **Two residuals a second, cross-model (Codex) doubt-driven-development round found
/// and this fix deliberately does not chase, recorded rather than silently accepted:**
/// (1) an empty or whitespace-only `ActorId` collapses to the same canonical `""` as
/// every other empty/whitespace-only `ActorId` — accepted because such a value carries
/// no real identity information to begin with (it was already meaningless before this
/// function trims it, not newly made ambiguous by trimming); (2) no Unicode
/// normalization (NFC/NFD) — two byte-distinct-but-visually-identical renderings of an
/// accented name would still pseudonymize differently. No evidence today that any
/// production actor-identity source in this codebase emits non-ASCII or differently
/// normalized text, so pulling in a Unicode-normalization dependency for a currently
/// hypothetical case was judged premature; revisit if a real source (e.g. a non-ASCII
/// OS username) surfaces this in practice.
pub(crate) fn pseudonymize_actor(key: &ActorPseudonymKey, actor: &ActorId) -> ActorPseudonym {
    let canonical = actor
        .0
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut mac =
        HmacSha256::new_from_slice(&key.0).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(DOMAIN_LABEL);
    mac.update(&[0x1F]);
    mac.update(canonical.as_bytes());

    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    ActorPseudonym::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> ActorPseudonymKey {
        ActorPseudonymKey::from_bytes([byte; 32])
    }

    #[test]
    fn pseudonymize_actor_is_deterministic() {
        let k = key(1);
        let actor = ActorId("alice".to_string());
        let a = pseudonymize_actor(&k, &actor);
        let b = pseudonymize_actor(&k, &actor);
        assert!(a == b);
    }

    #[test]
    fn pseudonymize_actor_is_key_sensitive() {
        let actor = ActorId("alice".to_string());
        let a = pseudonymize_actor(&key(1), &actor);
        let b = pseudonymize_actor(&key(2), &actor);
        assert!(a != b);
    }

    #[test]
    fn pseudonymize_actor_is_actor_sensitive() {
        let k = key(1);
        let a = pseudonymize_actor(&k, &ActorId("alice".to_string()));
        let b = pseudonymize_actor(&k, &ActorId("bob".to_string()));
        assert!(a != b);
    }

    #[test]
    fn pseudonymize_actor_has_no_naive_concatenation_collision() {
        // DOMAIN_LABEL is fixed, so the only concatenation surface is
        // DOMAIN_LABEL || 0x1F || actor.0 -- verify two different actor strings that
        // would collide without the separator (impossible here since DOMAIN_LABEL is
        // constant) still can't produce the same message via an actor string that
        // itself contains the separator byte.
        let k = key(1);
        let a = pseudonymize_actor(&k, &ActorId("ab".to_string()));
        let b = pseudonymize_actor(&k, &ActorId("a\u{1f}b".to_string()));
        assert!(a != b);
    }

    #[test]
    fn pseudonymize_actor_is_stable_across_case_and_surrounding_whitespace() {
        // Regression for real production evidence: `vg demask --actor <STRING>`
        // (`crates/vg-cli/src/main.rs`) is a free-typed, unvalidated operator CLI
        // argument, so the same real actor can type "jane.doe", "Jane.Doe", or
        // " jane.doe " across different invocations.
        let k = key(1);
        let canonical = pseudonymize_actor(&k, &ActorId("jane.doe".to_string()));
        let uppercased = pseudonymize_actor(&k, &ActorId("Jane.Doe".to_string()));
        let padded = pseudonymize_actor(&k, &ActorId(" jane.doe ".to_string()));
        assert!(canonical == uppercased);
        assert!(canonical == padded);
    }

    #[test]
    fn pseudonymize_actor_is_stable_across_internal_whitespace_runs() {
        // A second, cross-model doubt-driven-development round found the first fix
        // only handled leading/trailing whitespace, not internal runs (e.g. "jane
        // doe" vs. "jane  doe").
        let k = key(1);
        let single_space = pseudonymize_actor(&k, &ActorId("jane doe".to_string()));
        let double_space = pseudonymize_actor(&k, &ActorId("jane  doe".to_string()));
        let tab_separated = pseudonymize_actor(&k, &ActorId("jane\tdoe".to_string()));
        assert!(single_space == double_space);
        assert!(single_space == tab_separated);
    }

    #[test]
    fn actor_pseudonym_key_debug_never_prints_the_key_bytes() {
        let k = key(0xAB);
        let debug_output = format!("{k:?}");
        assert!(!debug_output.contains("171")); // 0xAB decimal
        assert!(!debug_output.contains("ab"));
        assert!(debug_output.contains("redacted"));
    }
}
