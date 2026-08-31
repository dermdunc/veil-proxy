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

use crate::certificate::validate_signing_certificate_pem;
use crate::error::{crypto_err, VaultError};
use crate::random::fill_random;
use vg_core::telemetry::{ActorPseudonymKey, DeviceSigningCredential};

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

/// The OS-keychain service names under which a custodian-issued (ADR-S) device telemetry
/// signing credential is stored: the raw P-256 private scalar and its certificate are two
/// separate entries (the existing `load_or_create_db_key`/`decode_key` helpers this file
/// already has are hardwired to a fixed 32-byte secret, which fits the scalar but not a
/// variable-length PEM certificate). One account, `"default"`, per device — same
/// reasoning as [`ACTOR_PSEUDONYM_ACCOUNT`]: this doesn't fragment per vault path.
const DEVICE_SIGNING_KEY_SERVICE: &str = "com.veilgremlin.device-signing-key";
const DEVICE_SIGNING_CERT_SERVICE: &str = "com.veilgremlin.device-signing-cert";
const DEVICE_SIGNING_ACCOUNT: &str = "default";

/// Test-only escape hatch, same shape and same unconditional (not `#[cfg(test)]`-gated)
/// reasoning as [`ACTOR_PSEUDONYM_KEY_ENV`]'s own doc comment. Two env vars, not one: a
/// signing credential is a (key, certificate) pair, and [`load_device_signing_credential`]
/// treats "exactly one of the two is set" as a configuration error rather than silently
/// picking a source per field.
const DEVICE_SIGNING_KEY_ENV: &str = "VG_DEVICE_SIGNING_KEY_HEX";
const DEVICE_SIGNING_CERT_ENV: &str = "VG_DEVICE_SIGNING_CERT_PEM";

/// Loads this device's custodian-issued (ADR-S) telemetry signing credential from the OS
/// keychain. **Load-only, never load-or-create** — unlike every other loader in this
/// file, there is no legitimate "generate one locally" fallback: only `veil-custodian`'s
/// CA can issue a certificate for a signing key, so a missing entry is a typed absence
/// (device not yet enrolled), not a trigger to fabricate one.
///
/// Cross-checks the loaded private key's own public half against the certificate's
/// `SubjectPublicKeyInfo` before returning — catching a keychain left in an inconsistent
/// state (e.g. a certificate re-issued after key rotation without the matching private
/// key entry being updated) here, at load time, rather than as a mysterious signature
/// -verification failure far downstream.
pub fn load_device_signing_credential() -> Result<DeviceSigningCredential, VaultError> {
    let (key_hex, cert_pem) = match (
        std::env::var(DEVICE_SIGNING_KEY_ENV),
        std::env::var(DEVICE_SIGNING_CERT_ENV),
    ) {
        (Ok(key_hex), Ok(cert_pem)) => {
            eprintln!(
                "veilgremlin: WARNING {DEVICE_SIGNING_KEY_ENV}/{DEVICE_SIGNING_CERT_ENV} are \
                 set — device signing credential taken from the environment, NOT the OS \
                 keychain. This is a test seam; unset both for real sessions."
            );
            (Zeroizing::new(key_hex), cert_pem)
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
            let key_entry = Entry::new(DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;
            let cert_entry = Entry::new(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;

            let key_hex = key_entry.get_password().map_err(|e| match e {
                KeyringError::NoEntry => crypto_err(
                    "no device signing key in the OS keychain -- this device has not been \
                     enrolled for telemetry signing (ADR-S); this loader never mints one \
                     itself, only the custodian CA can issue one",
                ),
                e => crypto_err(format!("keychain read failed: {e}")),
            })?;
            let cert_pem = cert_entry.get_password().map_err(|e| match e {
                KeyringError::NoEntry => crypto_err(
                    "device signing key exists in the OS keychain but its certificate does \
                     not -- keychain is in an inconsistent state",
                ),
                e => crypto_err(format!("keychain read failed: {e}")),
            })?;
            (Zeroizing::new(key_hex), cert_pem)
        }
        _ => {
            return Err(crypto_err(format!(
                "{DEVICE_SIGNING_KEY_ENV} and {DEVICE_SIGNING_CERT_ENV} must both be set or \
                 both unset"
            )));
        }
    };

    let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        decode_hex(key_hex.trim())
            .ok_or_else(|| crypto_err("stored device signing key is not valid hex"))?,
    );
    let signing_key = p256::ecdsa::SigningKey::from_slice(&key_bytes).map_err(|e| {
        crypto_err(format!(
            "stored device signing key is not a valid P-256 scalar: {e}"
        ))
    })?;

    let validated = validate_signing_certificate_pem(&cert_pem)?;

    let actual_public_key = signing_key.verifying_key().to_sec1_bytes();
    if actual_public_key.as_ref() != validated.subject_public_key_bytes.as_slice() {
        return Err(crypto_err(
            "device signing key does not match its own certificate's public key -- \
             keychain is in an inconsistent state",
        ));
    }

    Ok(DeviceSigningCredential::from_parts(
        signing_key,
        &validated.der,
        validated.device_ref,
    ))
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
/// `pub(crate)`, not private: `crate::certificate` reuses this to decode the device
/// pseudonym out of a signing certificate's SAN, rather than a second hand-rolled hex
/// decoder in this crate.
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
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

    /// `load_or_create_actor_pseudonym_key`'s env-seam round-trip, plus its malformed-hex
    /// rejection. Both cases live in one test function, not two, and run one after the
    /// other: `cargo test`'s default in-binary parallelism means two separate `#[test]`
    /// functions both mutating the same process-global `ACTOR_PSEUDONYM_KEY_ENV` (via
    /// `std::env::set_var`/`remove_var`, `unsafe` since Rust 1.82) can interleave and read
    /// each other's value — a real, observed flake, not merely a theoretical one; an
    /// earlier version of this suite split the two cases into separate tests under a
    /// comment claiming no cross-test race was possible, which this replaces.
    #[test]
    fn actor_pseudonym_key_env_seam_round_trips_and_rejects_malformed_hex() {
        let key = [7u8; 32];
        let hex = encode_key(&key);
        unsafe {
            std::env::set_var(ACTOR_PSEUDONYM_KEY_ENV, &hex);
        }
        let round_trip_result = load_or_create_actor_pseudonym_key();
        unsafe {
            std::env::remove_var(ACTOR_PSEUDONYM_KEY_ENV);
        }
        assert!(round_trip_result.unwrap() == ActorPseudonymKey::from_bytes(key));

        unsafe {
            std::env::set_var(ACTOR_PSEUDONYM_KEY_ENV, "not-hex");
        }
        let result = load_or_create_actor_pseudonym_key();
        unsafe {
            std::env::remove_var(ACTOR_PSEUDONYM_KEY_ENV);
        }
        assert!(result.is_err());
    }

    /// A real ADR-S-profile certificate whose private key actually matches it —
    /// generated together (`tests/fixtures/README.md` documents the exact `openssl`
    /// commands). Not the vendored `veil-custodian` fixture: that one has no known
    /// private key (it exists only to pin `key_ref`'s derivation).
    const MATCHING_CERT_PEM: &str =
        include_str!("../tests/fixtures/loader_matching_certificate.pem");
    const MATCHING_KEY_HEX: &str =
        "d2fabd5b420e79a77994de5154396484ae1b260dabecb100eae9b01cc2785fd0";
    /// A different, unrelated, but still-valid P-256 scalar — matches no certificate's
    /// public key.
    const MISMATCHED_KEY_HEX: &str =
        "0909090909090909090909090909090909090909090909090909090909090909";

    /// All three env-seam cases for `load_device_signing_credential` in one test
    /// function, not three, for the identical cross-test-race reason
    /// `actor_pseudonym_key_env_seam_round_trips_and_rejects_malformed_hex` documents —
    /// this seam mutates the same two process-global env vars every case below.
    #[test]
    fn device_signing_credential_env_seam_round_trips_and_rejects_mismatches() {
        unsafe {
            std::env::set_var(DEVICE_SIGNING_KEY_ENV, MATCHING_KEY_HEX);
            std::env::set_var(DEVICE_SIGNING_CERT_ENV, MATCHING_CERT_PEM);
        }
        let happy_path = load_device_signing_credential();
        unsafe {
            std::env::remove_var(DEVICE_SIGNING_KEY_ENV);
            std::env::remove_var(DEVICE_SIGNING_CERT_ENV);
        }
        // `key_ref`'s exact derivation is `certificate.rs`'s own test, pinned against the
        // vendored custodian fixture; this test's job is proving the loader wires a real,
        // *matching* credential through end to end, which the public-key cross-check
        // below (implicitly, by the happy path not erroring) and the `device_ref` check
        // together establish.
        let credential = happy_path.unwrap();
        let expected_device_bytes = decode_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let expected_device_ref =
            vg_core::telemetry::DeviceRef::try_from(expected_device_bytes.as_slice()).unwrap();
        assert!(credential.device_ref() == expected_device_ref);

        unsafe {
            std::env::set_var(DEVICE_SIGNING_KEY_ENV, MISMATCHED_KEY_HEX);
            std::env::set_var(DEVICE_SIGNING_CERT_ENV, MATCHING_CERT_PEM);
        }
        let mismatch_result = load_device_signing_credential();
        unsafe {
            std::env::remove_var(DEVICE_SIGNING_KEY_ENV);
            std::env::remove_var(DEVICE_SIGNING_CERT_ENV);
        }
        assert!(mismatch_result.is_err());

        unsafe {
            std::env::set_var(DEVICE_SIGNING_KEY_ENV, MATCHING_KEY_HEX);
        }
        let partial_result = load_device_signing_credential();
        unsafe {
            std::env::remove_var(DEVICE_SIGNING_KEY_ENV);
        }
        assert!(partial_result.is_err());
    }
}
