//! OS-keychain wrap for the SQLCipher database encryption key.
//!
//! The 32-byte DB key is never written to disk in plaintext (interface-contracts.md §5:
//! "DB key wrapped by OS keychain, never persisted plaintext"). It lives in the OS secret
//! store — the macOS Keychain (via the `keyring` crate's Security-framework backend on
//! `target_os = "macos"`, the platform this lab targets first). On first open a fresh
//! random key is generated and stored; subsequent opens retrieve it.
//!
//! The key is stored hex-encoded because the keychain APIs traffic in UTF-8 strings, not
//! arbitrary bytes.

use keyring::{Entry, Error as KeyringError};
use zeroize::Zeroizing;

use crate::error::{crypto_err, VaultError};
use crate::random::fill_random;
use vg_core::telemetry::ActorPseudonymKey;

/// Returns the DB encryption key for `(service, account)`, generating and storing a fresh
/// random 32-byte key in the OS keychain the first time (when no entry exists yet).
pub(crate) fn load_or_create_db_key(service: &str, account: &str) -> Result<[u8; 32], VaultError> {
    let entry = Entry::new(service, account)
        .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;

    match entry.get_password() {
        Ok(hex) => decode_key("DB key", &hex),
        Err(KeyringError::NoEntry) => {
            let mut key = [0u8; 32];
            fill_random(&mut key)?;
            entry
                .set_password(&encode_key(&key))
                .map_err(|e| crypto_err(format!("keychain store failed: {e}")))?;
            Ok(key)
        }
        Err(e) => Err(crypto_err(format!("keychain read failed: {e}"))),
    }
}

/// The OS-keychain service name under which the per-device actor-pseudonymization key
/// (`vg_core::telemetry::ActorPseudonymKey`) is stored — a distinct secret from the DB
/// key above, following the same wrap-never-persist-plaintext precedent
/// (`DEFAULT_KEYCHAIN_SERVICE` in `lib.rs`).
const ACTOR_PSEUDONYM_SERVICE: &str = "com.veilgremlin.actor-pseudonym";

/// Fixed, not per-vault-path: one pseudonymization key per device (the ratified scope —
/// "per-device key, no cross-device correlation"), so it must not fragment across a
/// user's multiple local state dirs the way the DB key's path-derived account does.
const ACTOR_PSEUDONYM_ACCOUNT: &str = "default";

/// Test-only escape hatch, mirroring `vg-adapters-claude::VAULT_KEY_ENV`'s seam for the
/// DB key: when set, returns this key directly instead of touching the OS keychain, so
/// a test suite never reads or mutates the real keychain entry. Unlike the DB key's
/// seam (which lives in the caller crate, since `Vault::open`/`open_with_key` already
/// gives callers that choice explicitly), this check lives inside the function itself —
/// there is no equivalent caller-supplied-key constructor for this key yet, so without
/// this the seam would have nowhere to live.
///
/// **Unconditional, no `#[cfg(test)]`/`debug_assertions` gate — a real, unresolved gap,
/// not just a stylistic one** (a second doubt-driven-development round, Codex
/// cross-model, pushed back on treating this as "matched to `VAULT_KEY_ENV`'s own
/// looseness" and therefore acceptable at the same bar): structurally it *can't* be
/// `#[cfg(test)]`-gated, because downstream crates' integration tests and CLI test
/// invocations link this crate *without* its own `cfg(test)` — the same structural
/// constraint `VAULT_KEY_ENV` already lives with. But the consequence here is worse
/// than for the DB key: this key's entire purpose is the ratified "per-device key, no
/// cross-device correlation" property, and if the *same* env value is ever set on two
/// machines (a fleet config baking in a fixed key by accident, a shared `.env` template),
/// that property is silently defeated — not just "the key is weaker," but "the
/// no-correlation guarantee this feature exists to provide is gone," with nothing but
/// the stderr warning below as a signal. No structural fix was found within this
/// crate's existing test-seam architecture (env-var check inside the production
/// function is the same shape every other seam in this codebase uses); this is recorded
/// as an accepted, named residual risk (`docs/decisions.md`), not a solved problem.
const ACTOR_PSEUDONYM_KEY_ENV: &str = "VG_ACTOR_PSEUDONYM_KEY_HEX";

/// Returns this device's actor-pseudonymization key, generating and storing a fresh
/// random 32-byte key in the OS keychain the first time. One key per device (fixed
/// service/account, see [`ACTOR_PSEUDONYM_ACCOUNT`]'s doc comment) — every vault on this
/// device shares it, unlike the DB key which is scoped per vault path.
///
/// Returns the already-wrapped [`ActorPseudonymKey`], not a bare `[u8; 32]` — a
/// doubt-driven-development finding: an unwrapped array has default `Debug` (an
/// incidental `{:?}`/log/`.expect()` at a call site would print the raw key) and is
/// `Copy` (nothing reminds a caller to drop/zeroize their own local copy). Wrapping here,
/// at the point the bytes are produced, keeps that exposure window to this function's
/// own body — this crate's shared `decode_key`/`encode_key` hex-`String` intermediates
/// still exist within that window, a residual this shares with the DB key path and does
/// not newly introduce.
///
/// **Known, inherited create-race, not fixed here:** the check-then-set below
/// (`get_password` -> on `NoEntry`, generate + `set_password`) is not atomic — two
/// processes racing on this device's very first run can each observe `NoEntry`, each
/// generate a *different* key, and each keep using their own after the losing
/// `set_password` is silently overwritten. This race already existed in
/// `load_or_create_db_key`, reused here unchanged; it is a materially bigger deal for
/// *this* key than for the DB key, because every vault on the device is meant to share
/// one fixed `(service, account)` pair (see [`ACTOR_PSEUDONYM_ACCOUNT`]'s doc comment),
/// so any two `vg-*` processes launched near-simultaneously on a fresh device can
/// trigger it — not just two processes racing to open the same vault file. Properly
/// fixing this needs an atomic compare-and-set the OS keychain APIs this crate uses
/// (via the `keyring` crate) do not appear to offer; tracked as a follow-up in
/// `docs/next-actions.md` rather than solved in this change.
pub fn load_or_create_actor_pseudonym_key() -> Result<ActorPseudonymKey, VaultError> {
    if let Ok(hex) = std::env::var(ACTOR_PSEUDONYM_KEY_ENV) {
        eprintln!(
            "veilgremlin: WARNING {ACTOR_PSEUDONYM_KEY_ENV} is set — actor-pseudonymization \
             key taken from the environment, NOT the OS keychain. This is a test seam; if the \
             same value is ever set on two machines, this device's key is no longer unique, \
             silently defeating the 'no cross-device correlation' guarantee. Unset it for real \
             sessions."
        );
        return decode_key("actor-pseudonymization key", &hex).map(ActorPseudonymKey::from_bytes);
    }
    load_or_create_db_key(ACTOR_PSEUDONYM_SERVICE, ACTOR_PSEUDONYM_ACCOUNT)
        .map(ActorPseudonymKey::from_bytes)
}

/// Returns a zeroize-on-drop hex `String` — a doubt-driven-development finding (Codex
/// cross-model): the plaintext hex this crate builds on the way to/from the OS keychain
/// had no zeroize coverage at all; only the final `[u8; 32]`'s callers were ever
/// expected to guard it (and, for the actor-pseudonymization key, now do —
/// `load_or_create_actor_pseudonym_key` wraps into `ActorPseudonymKey` immediately).
fn encode_key(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect())
}

/// Shared by both the DB key and the actor-pseudonymization key — `label` names which
/// one, so a malformed-input error is specific rather than generic (a
/// doubt-driven-development fix: an earlier version said "stored DB key is..."
/// unconditionally, which became actively misleading once this function started
/// decoding the actor-pseudonymization key too; a later pass generalized it to "stored
/// key," accurate but no longer specific enough to be actionable from the error text
/// alone).
fn decode_key(label: &str, hex: &str) -> Result<[u8; 32], VaultError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        decode_hex(hex).ok_or_else(|| crypto_err(format!("stored {label} is not valid hex")))?,
    );
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| crypto_err(format!("stored {label} is not 32 bytes")))?;
    Ok(arr)
}

/// Decodes an even-length lowercase/uppercase hex string, or `None` on any non-hex byte.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hex_round_trips() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        let hex = encode_key(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_key("test key", &hex).unwrap(), key);
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        assert!(decode_key("test key", "abcd").is_err());
    }

    #[test]
    fn decode_key_rejects_non_hex() {
        assert!(decode_key("test key", &"zz".repeat(32)).is_err());
    }

    /// `load_or_create_actor_pseudonym_key`'s env-seam round-trip. Uses real
    /// `std::env::set_var`/`remove_var` (`unsafe` since Rust 1.82: not guaranteed atomic
    /// against a concurrent read on some platforms) — sound here because
    /// `ACTOR_PSEUDONYM_KEY_ENV` is a name unique to this function and no other test in
    /// this crate reads or writes it, so there is no cross-test race in practice despite
    /// `cargo test`'s default parallelism within one binary.
    #[test]
    fn actor_pseudonym_key_env_seam_round_trips() {
        let key = [7u8; 32];
        let hex = encode_key(&key);
        unsafe {
            std::env::set_var(ACTOR_PSEUDONYM_KEY_ENV, &hex);
        }
        let result = load_or_create_actor_pseudonym_key();
        unsafe {
            std::env::remove_var(ACTOR_PSEUDONYM_KEY_ENV);
        }
        assert!(result.unwrap() == ActorPseudonymKey::from_bytes(key));
    }

    #[test]
    fn actor_pseudonym_key_env_seam_rejects_malformed_hex() {
        unsafe {
            std::env::set_var(ACTOR_PSEUDONYM_KEY_ENV, "not-hex");
        }
        let result = load_or_create_actor_pseudonym_key();
        unsafe {
            std::env::remove_var(ACTOR_PSEUDONYM_KEY_ENV);
        }
        assert!(result.is_err());
    }
}
