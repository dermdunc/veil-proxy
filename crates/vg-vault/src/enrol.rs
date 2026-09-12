//! Device-side signing-credential installer (ADR-017, XREPO-009): the missing counterpart to
//! `keychain::load_device_signing_credential`. Formalises the CSR-handoff flow `veil-enrol`'s
//! own accepted design already names (`request-csr` / `install-cert`) into real code.
//!
//! No new network protocol: `request_device_signing_csr` generates a keypair in-process and
//! emits a CSR for the existing out-of-band operator handoff; `install_device_signing_
//! certificate` takes back a certificate file, verifies it, and writes it to the OS keychain.
//!
//! ## Write ordering and crash recovery (ADR-017 §3)
//!
//! All validation (env-seam check, ADR-S profile via `certificate::validate_signing_
//! certificate_pem`, anchor verification via `anchor::verify_issued_by_anchor`) happens
//! *before* any keychain read or write, so a failure never touches the keychain. The existing
//! keychain state is then classified read-only (`classify_existing_state`) and, on every path
//! that will actually write, the pending private key is looked up and cross-checked against
//! the certificate's SPKI **before the first write** -- round-D finding: an earlier draft
//! classified and wrote in the same pass, which let a certificate with no matching (or a
//! mismatched) pending key write the marker and certificate before discovering there was
//! nothing valid to pair them with, permanently degrading a previously-healthy device. Once
//! validated, the write sequence is: marker, then certificate, then key, then delete-pending.
//! A crash between the certificate and key writes is recovered on re-run by comparing the
//! *stored* certificate's DER against the *incoming* one — SPKI equality alone is not enough,
//! since `veil-custodian` deliberately permits repeat issuance from the same CSR/key with a
//! different resulting certificate each time.
//!
//! ## Concurrency (ADR-017 §3, round-B corrected)
//!
//! Every mutating operation is serialized by [`EnrolLock`]: an advisory `flock(2)` on a fixed,
//! **device-global** path — deliberately not under this crate's own state-dir resolution
//! (which is repo-local and CWD-dependent), since the keychain entries this lock protects are
//! device-global. The kernel releases the lock automatically if the holding process exits for
//! any reason, so a crash mid-install can never leave a stale lock blocking the very recovery
//! this module exists to perform.

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::SystemTime;

use der::{DecodePem, Encode};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use vg_core::telemetry::{DeviceRef, KeyRef};
use vg_core::VaultError;

use crate::anchor::verify_issued_by_anchor;
use crate::certificate::validate_signing_certificate_pem;
use crate::csr::{build_signing_csr, generate_signing_key};
use crate::error::{crypto_err, io_err};
use crate::keychain::{
    decode_hex, load_device_signing_credential_from_keychain_only_with_store,
    DEVICE_ENROLLED_SERVICE, DEVICE_SIGNING_ACCOUNT, DEVICE_SIGNING_CERT_SERVICE,
    DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_PENDING_SERVICE,
};
// Only the tests reach through the env-precedence loader (production code here uses the
// keychain-only one -- see the round-D finding in `credential_status_with_store`'s own doc).
#[cfg(test)]
use crate::keychain::load_device_signing_credential_with_store;
use crate::store::{OsKeychain, SecretStore};

/// Test-only escape hatch this module must never be silently shadowed by -- same two env
/// vars `keychain.rs` already checks at load time. Duplicated here (not imported) because
/// `keychain.rs` keeps them private; both modules check the identical pair for the identical
/// reason, and a single source of truth for the *names* (not the check itself) is not worth
/// the coupling.
const DEVICE_SIGNING_KEY_ENV: &str = "VG_DEVICE_SIGNING_KEY_HEX";
const DEVICE_SIGNING_CERT_ENV: &str = "VG_DEVICE_SIGNING_CERT_PEM";

/// Presence, not validity -- `var_os` (round-D correction: `std::env::var(..).is_ok()` treats
/// a *present but non-UTF-8* value as absent, since it returns `Err(NotUnicode(_))`, which
/// would let `install-cert` proceed past this check while the loader's own `std::env::var`
/// call later treats the identical value as a hard configuration error. The seam is "is
/// either variable set at all", not "is it set to valid UTF-8".
fn env_seam_active() -> bool {
    std::env::var_os(DEVICE_SIGNING_KEY_ENV).is_some()
        || std::env::var_os(DEVICE_SIGNING_CERT_ENV).is_some()
}

/// A freshly generated CSR and the fingerprint the out-of-band operator-confirmation flow
/// needs (`veil-enrol`'s CSR handoff mechanism). Carries no private key -- it is already in
/// the OS keychain's pending service by the time this is returned.
pub struct PendingCsr {
    pub csr_pem: String,
    pub spki_fingerprint: String,
}

/// An installed (or about-to-be-reported) signing credential's identifying facts.
///
/// **Implementation-time addition**: `issuer`/`not_before` were not in the original
/// interface-contract draft, added so `vg-cli`'s install summary (ADR-017 §3's command
/// surface, which commits to printing "profile, issuer, device_ref, key_ref, validity
/// window") can report them without a second certificate parse. `issuer` comes from the
/// certificate's own `issuer` field -- obtainable identically whether this is being reported
/// fresh at install time or read back later by `credential_status`, unlike the *anchor's* own
/// subject/fingerprint, which only exist at install time (`--ca-cert` isn't available to
/// `credential_status`) and are deliberately not part of this shared type.
pub struct InstalledSigningCredential {
    pub device_ref: DeviceRef,
    pub key_ref: KeyRef,
    /// The issuing CA's Subject, rendered for display, taken from the certificate's own
    /// `issuer` field (enforced to match the pinned anchor's `subject` at install time,
    /// `anchor::verify_issued_by_anchor`'s issuer-chaining check).
    pub issuer: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// What `install_device_signing_certificate` did.
pub enum InstallOutcome {
    /// A new credential was written (fresh install, or a forced replacement).
    Installed(InstalledSigningCredential),
    /// The exact certificate was already fully installed -- no writes, at most a best-effort
    /// pending-entry cleanup.
    AlreadyInstalled(InstalledSigningCredential),
    /// A crash left the certificate written but not the key (or, for an interrupted `--force`
    /// replacement, the old key still in place) -- completed without needing `--force`.
    RecoveredPartialInstall(InstalledSigningCredential),
}

/// Three independent facts about this device's signing-credential state (ADR-017 §8, twice
/// corrected during review: not one enum's mutually exclusive arms).
pub struct CredentialStatus {
    pub installed: Option<InstalledSigningCredential>,
    pub env_seam_shadowing: bool,
    pub enrolment_marker_present: bool,
}

/// Distinguishable by callers without string-matching -- the same reason `vg-vault`'s own
/// `VaultError` is deliberately frozen at three variants (see that type's doc). `EnrolError`
/// is this module's own, separate error type: not every enrolment failure fits `VaultError`'s
/// three arms, and conflating them would force exactly the string-matching this crate's
/// existing conventions go out of their way to avoid.
///
/// **Implementation-time refinement from the interface-contract's original draft**: a bare
/// `AnchorMismatch` unit variant carried no message, which would have made every anchor
/// rejection reason (wrong CA, tampered signature, wrong algorithm, expired anchor, wrong
/// curve) indistinguishable to a caller. `anchor.rs` does not produce a separately-typed error
/// per rejection reason, so a second, redundant `UnsupportedSignatureAlgorithm` variant could
/// never actually be constructed without string-matching `anchor.rs`'s own message text --
/// exactly the anti-pattern this type exists to avoid. Both are replaced by a single
/// `AnchorMismatch(String)` carrying `anchor.rs`'s own descriptive message.
pub enum EnrolError {
    /// `VG_DEVICE_SIGNING_KEY_HEX`/`_CERT_PEM` is set -- an install would be silently
    /// shadowed at load time (ADR-017 §4).
    EnvSeamActive,
    /// The certificate failed `certificate::validate_signing_certificate_pem`'s ADR-S
    /// profile check.
    Profile(VaultError),
    /// The certificate failed `anchor::verify_issued_by_anchor`'s CA-signature/chaining
    /// verification. Carries that function's own descriptive message.
    AnchorMismatch(String),
    /// No pending private key exists matching the certificate's own SPKI fingerprint.
    NoPendingKey,
    /// A different credential is already installed; `--force` is required to replace it.
    /// `key_present` (round-D addition): whether the stored key entry alongside the
    /// conflicting certificate is actually present -- ADR-017 §6 requires the refusal
    /// message say so explicitly when it is not.
    AlreadyEnrolled {
        key_ref: KeyRef,
        device_ref: DeviceRef,
        key_present: bool,
    },
    /// The keychain is in a state this call will not proceed past without `--force` (e.g. a
    /// key entry with no matching certificate), or a lower-level keychain/lock failure.
    Keychain(VaultError),
}

impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvSeamActive => write!(
                f,
                "{DEVICE_SIGNING_KEY_ENV}/{DEVICE_SIGNING_CERT_ENV} is set -- a keychain \
                 install would be silently shadowed at load time; unset both before \
                 installing"
            ),
            Self::Profile(e) => write!(f, "certificate profile rejected: {e}"),
            Self::AnchorMismatch(msg) => write!(f, "{msg}"),
            Self::NoPendingKey => write!(
                f,
                "no pending private key matches this certificate's public key -- was it \
                 issued for a CSR from this device?"
            ),
            // `KeyRef`/`DeviceRef` deliberately have no `Display`/`Debug` (only `Serialize` --
            // `vg-core`'s own convention for identifier types); the caller has the typed
            // fields directly on this variant and can render them (e.g. via `serde_json`,
            // `vg-cli`'s own established pattern) without this crate taking on that
            // dependency just to format an error message. `key_present` IS a plain `bool`,
            // so this Display can and does report it directly (round-D correction: an
            // earlier draft omitted even this from the message).
            Self::AlreadyEnrolled { key_present, .. } => write!(
                f,
                "a different signing credential is already installed{} -- re-run with that \
                 certificate, or use --force to replace it",
                if *key_present {
                    ""
                } else {
                    " (its private key is missing from the keychain)"
                }
            ),
            Self::Keychain(e) => write!(f, "{e}"),
        }
    }
}

/// Generates a fresh P-256 signing key in-process, stores it in the OS keychain's
/// content-addressed pending service (never to a plaintext file), and returns a CSR for the
/// existing out-of-band operator-confirmation flow.
pub fn request_device_signing_csr() -> Result<PendingCsr, EnrolError> {
    request_device_signing_csr_with_store(&OsKeychain)
}

pub(crate) fn request_device_signing_csr_with_store(
    store: &dyn SecretStore,
) -> Result<PendingCsr, EnrolError> {
    let _lock = EnrolLock::acquire().map_err(EnrolError::Keychain)?;

    if env_seam_active() {
        eprintln!(
            "veilgremlin: WARNING {DEVICE_SIGNING_KEY_ENV}/{DEVICE_SIGNING_CERT_ENV} is set -- \
             a certificate installed for this CSR will be shadowed at load time until both \
             are unset."
        );
    }

    let key = generate_signing_key().map_err(EnrolError::Keychain)?;
    let csr = build_signing_csr(&key).map_err(EnrolError::Keychain)?;
    let key_hex = scalar_hex(&key);
    store
        .set(
            DEVICE_SIGNING_PENDING_SERVICE,
            &csr.spki_fingerprint,
            &key_hex,
        )
        .map_err(EnrolError::Keychain)?;

    Ok(PendingCsr {
        csr_pem: csr.pem,
        spki_fingerprint: csr.spki_fingerprint,
    })
}

/// Discards one pending CSR's private key. The only way to remove an orphaned pending entry
/// short of the OS keychain UI -- a direct consequence of pending storage being
/// content-addressed, which lets multiple outstanding CSRs coexist.
pub fn cancel_pending_csr(spki_fingerprint: &str) -> Result<(), EnrolError> {
    cancel_pending_csr_with_store(&OsKeychain, spki_fingerprint)
}

pub(crate) fn cancel_pending_csr_with_store(
    store: &dyn SecretStore,
    spki_fingerprint: &str,
) -> Result<(), EnrolError> {
    let _lock = EnrolLock::acquire().map_err(EnrolError::Keychain)?;

    // Engineer-panel finding: `SecretStore::delete` is deliberately no-op-safe on entries
    // that don't exist (this crate's other best-effort cleanup callers rely on exactly that),
    // so calling it directly here reported "discarded" even for a fingerprint that was never
    // pending -- e.g. a fat-fingered copy-paste from `request-csr`'s printed output. This
    // command is the one place a caller specifically wants to know "was there really
    // something there", so it checks first and reports `NoPendingKey` if not.
    if store
        .get(DEVICE_SIGNING_PENDING_SERVICE, spki_fingerprint)
        .map_err(EnrolError::Keychain)?
        .is_none()
    {
        return Err(EnrolError::NoPendingKey);
    }

    store
        .delete(DEVICE_SIGNING_PENDING_SERVICE, spki_fingerprint)
        .map_err(EnrolError::Keychain)
}

/// Verifies `cert_pem` against the pinned `ca_cert_pem` and the ADR-S signing profile,
/// matches it to its pending private key by SPKI, and installs it. `--ca-cert` (`ca_cert_pem`)
/// is not optional at the call-site type level either -- there is no variant of this function
/// that skips it.
pub fn install_device_signing_certificate(
    cert_pem: &str,
    ca_cert_pem: &str,
    force: bool,
) -> Result<InstallOutcome, EnrolError> {
    install_device_signing_certificate_with_store(&OsKeychain, cert_pem, ca_cert_pem, force)
}

pub(crate) fn install_device_signing_certificate_with_store(
    store: &dyn SecretStore,
    cert_pem: &str,
    ca_cert_pem: &str,
    force: bool,
) -> Result<InstallOutcome, EnrolError> {
    // Step 0: every check below happens before any keychain access, so a rejection here
    // never touches the keychain.
    if env_seam_active() {
        return Err(EnrolError::EnvSeamActive);
    }

    let validated = validate_signing_certificate_pem(cert_pem).map_err(EnrolError::Profile)?;
    let anchor = verify_issued_by_anchor(&validated.der, ca_cert_pem)
        .map_err(|e| EnrolError::AnchorMismatch(e.to_string()))?;
    let fingerprint = hex_lower(&Sha256::digest(&anchor.leaf_spki_der));

    let installed_info = InstalledSigningCredential {
        device_ref: validated.device_ref,
        key_ref: KeyRef::from_certificate_der(&validated.der),
        issuer: anchor.leaf_issuer.clone(),
        not_before: anchor.leaf_not_before,
        not_after: anchor.leaf_not_after,
    };

    let _lock = EnrolLock::acquire().map_err(EnrolError::Keychain)?;

    let stored_cert_pem = store
        .get(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
        .map_err(EnrolError::Keychain)?;
    let stored_key_hex = store
        .get(DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_ACCOUNT)
        .map_err(EnrolError::Keychain)?;

    // Read-only classification -- no writes yet, on any path, including a `--force` one.
    // (Round-D finding: an earlier draft classified and wrote in the same pass, which let a
    // certificate with no matching pending key -- or a mismatched one -- write the marker
    // and certificate *before* discovering there was nothing valid to pair them with,
    // permanently degrading a previously-healthy device.)
    let recovered = match classify_existing_state(
        stored_cert_pem.as_deref(),
        stored_key_hex.as_deref(),
        &validated,
    ) {
        Classification::AlreadyInstalled => {
            delete_pending_best_effort(store, &fingerprint);
            return Ok(InstallOutcome::AlreadyInstalled(installed_info));
        }
        Classification::Fresh => false,
        // Round-D finding, confirming round-A/round-B's own design: the unified
        // crash-residue condition (stored cert DER matches incoming, stored key absent or
        // not matching its SPKI) recovers WITHOUT requiring `--force`, regardless of
        // whether the mismatch came from a fresh-install crash, an interrupted `--force`
        // replacement (old key, new cert), or the stored key simply being malformed --
        // ADR-017 §6's table does not carve out "malformed" as a separate case.
        Classification::RecoverKey => true,
        Classification::Conflict {
            key_ref,
            device_ref,
            key_present,
        } => {
            if !force {
                return Err(EnrolError::AlreadyEnrolled {
                    key_ref,
                    device_ref,
                    key_present,
                });
            }
            false
        }
        // Round-D finding: a malformed stored certificate (or key-without-cert corruption)
        // used to hard-fail via `?` before `force` was ever consulted, making `--force`
        // unable to repair exactly the states ADR-017 §6 says it should.
        Classification::Corrupt(msg) => {
            if !force {
                return Err(EnrolError::Keychain(crypto_err(msg)));
            }
            false
        }
    };

    // Validate the pending key BEFORE any write, on every path that reaches here (fresh
    // install, recovery, or a forced replacement) -- this is what closes the round-D
    // finding above structurally, not just for the specific case it was found in.
    let pending_hex = store
        .get(DEVICE_SIGNING_PENDING_SERVICE, &fingerprint)
        .map_err(EnrolError::Keychain)?
        .ok_or(EnrolError::NoPendingKey)?;
    if !stored_key_matches_spki(&pending_hex, &validated.subject_public_key_bytes).unwrap_or(false)
    {
        return Err(EnrolError::Keychain(crypto_err(
            "pending private key does not match this certificate's public key -- refusing to \
             install a mismatched credential",
        )));
    }

    store
        .set(
            DEVICE_ENROLLED_SERVICE,
            DEVICE_SIGNING_ACCOUNT,
            &fingerprint,
        )
        .map_err(EnrolError::Keychain)?;
    store
        .set(
            DEVICE_SIGNING_CERT_SERVICE,
            DEVICE_SIGNING_ACCOUNT,
            cert_pem,
        )
        .map_err(EnrolError::Keychain)?;
    store
        .set(
            DEVICE_SIGNING_KEY_SERVICE,
            DEVICE_SIGNING_ACCOUNT,
            &pending_hex,
        )
        .map_err(EnrolError::Keychain)?;
    delete_pending_best_effort(store, &fingerprint);

    Ok(if recovered {
        InstallOutcome::RecoveredPartialInstall(installed_info)
    } else {
        InstallOutcome::Installed(installed_info)
    })
}

/// What's already in the keychain, relative to the certificate being installed -- ADR-017
/// §6's table, as a closed set of outcomes rather than inline branching. Read-only: computing
/// this never touches the keychain.
enum Classification {
    /// Nothing installed yet, no conflicting state.
    Fresh,
    /// The exact certificate (by DER) is already installed with its matching key.
    AlreadyInstalled,
    /// The stored certificate's DER matches the incoming one, but the stored key is absent,
    /// mismatched, or malformed -- ADR-017 §3's unified crash-residue condition.
    RecoverKey,
    /// A different, identifiable certificate occupies the cert slot.
    Conflict {
        key_ref: KeyRef,
        device_ref: DeviceRef,
        key_present: bool,
    },
    /// The keychain is in a state requiring `--force`, but the existing credential could not
    /// be identified (a stored certificate that fails to parse at all, or a key present with
    /// no certificate alongside it). Carries the message to report if `--force` is absent.
    Corrupt(String),
}

fn classify_existing_state(
    stored_cert_pem: Option<&str>,
    stored_key_hex: Option<&str>,
    validated: &crate::certificate::ValidatedSigningCertificate,
) -> Classification {
    let Some(stored_pem) = stored_cert_pem else {
        return match stored_key_hex {
            None => Classification::Fresh,
            // Key present, cert absent -- the loader's existing "inconsistent state" error.
            Some(_) => Classification::Corrupt(
                "device signing key exists in the OS keychain but its certificate does not \
                 -- keychain is in an inconsistent state; --force to overwrite"
                    .to_string(),
            ),
        };
    };

    let Ok(stored_der) = cert_pem_to_der(stored_pem) else {
        return Classification::Corrupt(
            "a certificate is already installed but does not parse as valid DER -- keychain \
             is in an inconsistent state; --force to overwrite"
                .to_string(),
        );
    };

    // Round-B correction: any certificate already present in the cert slot is classified by
    // DER comparison first, regardless of what the key or pending state looks like -- SPKI
    // equality alone cannot distinguish "this is my own crash residue" from "a different,
    // re-issued certificate for the same key," since `veil-custodian` permits the latter.
    if stored_der == validated.der {
        match stored_key_hex {
            None => Classification::RecoverKey,
            Some(key_hex) => {
                if stored_key_matches_spki(key_hex, &validated.subject_public_key_bytes)
                    .unwrap_or(false)
                {
                    Classification::AlreadyInstalled
                } else {
                    Classification::RecoverKey
                }
            }
        }
    } else {
        // A different certificate already occupies the cert slot. Round-B correction: a
        // stored certificate that fails to parse against the ADR-S profile cannot yield a
        // `device_ref` (it comes from the SAN, which requires a successful parse) --
        // classified as `Corrupt` instead, never `Conflict`.
        match validate_signing_certificate_pem(stored_pem) {
            Ok(existing) => Classification::Conflict {
                key_ref: KeyRef::from_certificate_der(&existing.der),
                device_ref: existing.device_ref,
                key_present: stored_key_hex.is_some(),
            },
            Err(_) => Classification::Corrupt(
                "a certificate is already installed but does not parse as a valid ADR-S \
                 signing certificate -- keychain is in an inconsistent state; --force to \
                 overwrite"
                    .to_string(),
            ),
        }
    }
}

fn delete_pending_best_effort(store: &dyn SecretStore, fingerprint: &str) {
    let _ = store.delete(DEVICE_SIGNING_PENDING_SERVICE, fingerprint);
}

/// Returns `Err` if `key_hex` doesn't even parse as a valid P-256 scalar. Every call site
/// against a *stored* value collapses that `Err` to `false` (`.unwrap_or(false)`) rather than
/// propagating it: a stored/pending value that fails to parse is treated identically to
/// "doesn't match" -- corrupt stored key material is exactly the kind of state ADR-017 §6's
/// recovery/`--force` paths exist to overwrite, not a reason to hard-fail before that
/// classification logic runs (round-D finding).
fn stored_key_matches_spki(key_hex: &str, spki_bytes: &[u8]) -> Result<bool, VaultError> {
    let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        decode_hex(key_hex.trim())
            .ok_or_else(|| crypto_err("stored device signing key is not valid hex"))?,
    );
    let signing_key = p256::ecdsa::SigningKey::from_slice(&key_bytes).map_err(|e| {
        crypto_err(format!(
            "stored device signing key is not a valid P-256 scalar: {e}"
        ))
    })?;
    Ok(signing_key.verifying_key().to_sec1_bytes().as_ref() == spki_bytes)
}

fn cert_pem_to_der(pem: &str) -> Result<Vec<u8>, VaultError> {
    let cert = Certificate::from_pem(pem.as_bytes())
        .map_err(|e| crypto_err(format!("malformed stored certificate PEM: {e}")))?;
    cert.to_der().map_err(|e| {
        crypto_err(format!(
            "failed to re-encode stored certificate to DER: {e}"
        ))
    })
}

fn scalar_hex(key: &p256::ecdsa::SigningKey) -> Zeroizing<String> {
    Zeroizing::new(key.to_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reports whether a credential is installed, whether the env seam is shadowing it, and
/// whether the ADR-017 §7 enrolment marker is present -- three independent facts, twice
/// corrected during review (see this module's `CredentialStatus` doc).
pub fn credential_status() -> Result<CredentialStatus, EnrolError> {
    credential_status_with_store(&OsKeychain)
}

pub(crate) fn credential_status_with_store(
    store: &dyn SecretStore,
) -> Result<CredentialStatus, EnrolError> {
    let env_seam_shadowing = env_seam_active();
    let enrolment_marker_present = store
        .get(DEVICE_ENROLLED_SERVICE, DEVICE_SIGNING_ACCOUNT)
        .map_err(EnrolError::Keychain)?
        .is_some();

    // Round-D finding: the combined loader (`load_device_signing_credential_with_store`)
    // prefers the env seam over the keychain, so using it here would report the *env's*
    // identity as "installed" whenever the seam is active -- silently conflating the two
    // independent facts this type exists to keep apart. The keychain-only loader reports
    // what's actually in the keychain regardless of what the env seam currently holds.
    let installed = match load_device_signing_credential_from_keychain_only_with_store(store) {
        Ok(Some(cred)) => {
            // `DeviceSigningCredential` does not itself retain the certificate's validity
            // window -- re-derived here from the stored certificate PEM directly, the same
            // way `anchor.rs` derives it for a certificate being installed.
            let cert_pem = store
                .get(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .map_err(EnrolError::Keychain)?
                .ok_or_else(|| {
                    EnrolError::Keychain(crypto_err(
                        "loader reported an installed credential but the certificate entry is \
                         now missing -- keychain changed concurrently",
                    ))
                })?;
            let cert = Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
                EnrolError::Keychain(crypto_err(format!("malformed stored certificate PEM: {e}")))
            })?;
            let validity = cert.tbs_certificate().validity();
            Some(InstalledSigningCredential {
                device_ref: cred.device_ref(),
                key_ref: cred.key_ref().clone(),
                issuer: cert.tbs_certificate().issuer().to_string(),
                not_before: validity.not_before.to_system_time(),
                not_after: validity.not_after.to_system_time(),
            })
        }
        Ok(None) => None,
        // Round-D finding: this used to collapse to `installed: None` unconditionally,
        // silently swallowing a genuine keychain-read failure or key/certificate mismatch
        // as if the device were simply not enrolled. The one case that legitimately still
        // means "not installed, but say why" is the marker-present/credential-missing `Err`
        // `keychain.rs` returns for an interrupted or since-removed install -- that one is
        // exactly what `enrolment_marker_present` above already reports, so it collapses to
        // `None` here too. Any other error (a malformed stored value, a real keychain access
        // failure) is now propagated as a genuine `Err` from this function instead.
        Err(e) if enrolment_marker_present => {
            let _ = e; // the marker already conveys this case; see comment above
            None
        }
        Err(e) => return Err(EnrolError::Keychain(e)),
    };

    Ok(CredentialStatus {
        installed,
        env_seam_shadowing,
        enrolment_marker_present,
    })
}

/// A single, device-global, advisory `flock(2)` lock serializing every mutating `enrol`
/// command (ADR-017 §3). Two properties are load-bearing, both round-B findings against an
/// earlier draft:
///
/// - **Location**: a fixed path under the current user's home directory --
///   deliberately *not* this crate's own state-dir resolution (`vg-cli`'s `--state-dir`/
///   `VG_STATE_DIR`, repo-local and CWD-dependent), since the keychain entries this lock
///   protects are device-global. A state-dir-scoped lock would let two invocations from
///   different working directories take two different locks and interleave freely against
///   the same keychain entries.
/// - **Semantics**: an advisory lock on an open file descriptor, never a lockfile-existence
///   convention. The kernel releases an advisory lock automatically when the holding process
///   exits for any reason (including a crash), so this can never go stale across the exact
///   crash `install_device_signing_certificate`'s recovery logic exists for. A
///   create-and-check lockfile would instead survive the crash and permanently block every
///   future mutating `enrol` command.
///
/// macOS-only for Phase 1 (ADR-017 §5, §13 limitation 2) -- built on `flock(2)`/`$HOME`,
/// which are POSIX, not gated further here since nothing in this workspace's CI builds this
/// crate on a non-Unix target.
#[cfg(unix)]
struct EnrolLock {
    _file: std::fs::File,
}

#[cfg(unix)]
impl EnrolLock {
    fn acquire() -> Result<Self, VaultError> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| io_err(format!("failed to create {parent:?}: {e}")))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| io_err(format!("failed to open lock file {path:?}: {e}")))?;

        // SAFETY: `file.as_raw_fd()` is a valid, open file descriptor for the duration of
        // this call (the `File` outlives it); `flock` with `LOCK_EX` blocks until this
        // process holds an exclusive advisory lock on it, or returns a real error.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(io_err(format!(
                "failed to acquire enrolment lock: {}",
                io::Error::last_os_error()
            )));
        }

        Ok(Self { _file: file })
    }

    /// `<real home>/Library/Application Support/veilgremlin/enrol.lock` -- device-global,
    /// per-user, independent of any repo's `.veilgremlin/` state directory.
    ///
    /// **Round-D correction: resolved via `getpwuid_r`, never `$HOME`.** An earlier draft
    /// used `std::env::var("HOME")` — but `HOME` is an ordinary process environment variable,
    /// fully controlled by whoever launches the process, not an OS-verified fact about the
    /// user. Two `vg enrol install-cert` invocations launched with `HOME=/tmp/a` and
    /// `HOME=/tmp/b` would resolve to two different lock files while still writing to the
    /// *same* real macOS login keychain, defeating the lock's entire purpose: exactly the
    /// torn-credential race it exists to prevent. `getpwuid_r` asks the OS account database
    /// for the real UID's home directory directly, which an unprivileged process cannot
    /// spoof by setting an environment variable.
    fn path() -> Result<PathBuf, VaultError> {
        let home = real_home_dir()?;
        Ok(home
            .join("Library/Application Support/veilgremlin")
            .join("enrol.lock"))
    }
}

// Dropping `_file` closes the descriptor, which releases the `flock` -- both on an orderly
// drop and, per POSIX, when the process holding it exits for any other reason (including a
// crash the recovery logic above exists to handle). No explicit `Drop` impl needed.

/// Resolves the real, OS-verified home directory of the current effective user via
/// `getpwuid_r(3)` -- deliberately not `$HOME`, which any process can set to anything (see
/// [`EnrolLock::path`]'s own doc for why that matters here).
#[cfg(unix)]
fn real_home_dir() -> Result<PathBuf, VaultError> {
    let uid = unsafe { libc::getuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    // 16 KiB comfortably covers every real-world `passwd` string-table size; `getpwuid_r`
    // reports `ERANGE` rather than overflowing if it doesn't, so this can't silently corrupt
    // memory even if some exotic directory service returns something larger.
    let mut buf = [0i8; 16_384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: `pwd`/`buf`/`result` are all valid, appropriately-sized local buffers for the
    // duration of this call; `getpwuid_r` never retains a pointer to them past return.
    let ret = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if ret != 0 || result.is_null() {
        return Err(io_err(format!(
            "failed to resolve the current user's home directory via getpwuid_r: {}",
            io::Error::from_raw_os_error(ret)
        )));
    }

    // SAFETY: `getpwuid_r` succeeded and populated `pwd.pw_dir` as a NUL-terminated string
    // valid for at least the lifetime of `buf`, which outlives this access.
    let home_cstr = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let home = home_cstr
        .to_str()
        .map_err(|_| io_err("current user's home directory path is not valid UTF-8"))?;
    Ok(PathBuf::from(home))
}

/// Non-Unix stub (ADR-017 §5/§13 limitation 2: the writer is macOS-only for Phase 1; nothing
/// in this workspace's CI builds `vg-vault` on a non-Unix target, but the crate itself must
/// still *compile* there, since the existing OS-keychain *loader* already supports Windows).
/// Refuses outright rather than silently skipping serialization.
#[cfg(not(unix))]
struct EnrolLock;

#[cfg(not(unix))]
impl EnrolLock {
    fn acquire() -> Result<Self, VaultError> {
        Err(io_err(
            "vg enrol's device-signing-credential writer is not supported on this platform \
             (ADR-017: macOS-only for Phase 1)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fakes::{FailAfterNWrites, InMemoryStore};

    // Reuses the same real, vendored ADR-S certificate/CA fixtures as `certificate.rs` and
    // `anchor.rs`'s own tests, rather than a fourth copy: a self-signed local CA, two leaves
    // it issued (LEAF_A / LEAF_B), and each leaf's matching private key (generated together
    // for this test module).
    const CA_PEM: &str = include_str!("../tests/fixtures/enrol_ca.pem");
    const LEAF_A_PEM: &str = include_str!("../tests/fixtures/enrol_leaf_a.pem");
    const LEAF_A_KEY_HEX: &str = include_str!("../tests/fixtures/enrol_leaf_a_key_hex.txt");
    /// The identical CSR (same key, same SPKI) as `LEAF_A_PEM`, signed a second time --
    /// reproducing `veil-custodian`'s real repeat-issuance behavior. Different DER, same
    /// SPKI: the exact case round-A's central finding is about (SPKI equality is not
    /// certificate identity).
    const LEAF_A_REISSUED_PEM: &str = include_str!("../tests/fixtures/enrol_leaf_a_reissued.pem");
    const LEAF_B_PEM: &str = include_str!("../tests/fixtures/enrol_leaf_b.pem");
    const LEAF_B_KEY_HEX: &str = include_str!("../tests/fixtures/enrol_leaf_b_key_hex.txt");

    /// Serializes every test in this module against each other *and* against `keychain.rs`'s
    /// own `VG_DEVICE_SIGNING_*` env-seam tests, via the crate-wide
    /// `crate::test_support::device_signing_env_lock`. `install_is_refused_when_the_env_seam_
    /// is_active` mutates those real process-global env vars, which every other test's
    /// `env_seam_active()` check also reads; a per-module-only lock was not enough (confirmed
    /// by an actual flaky failure across module boundaries during initial implementation
    /// against the full `cargo test -p vg-vault` run, not merely reasoned about) --
    /// `keychain::tests::device_signing_credential_env_seam_round_trips_and_rejects_mismatches`
    /// mutates the identical pair and previously held no lock at all.
    fn serialize_tests() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::device_signing_env_lock()
    }

    fn spki_fingerprint_of(cert_pem: &str) -> String {
        let validated = validate_signing_certificate_pem(cert_pem).unwrap();
        let anchor = verify_issued_by_anchor(&validated.der, CA_PEM).unwrap();
        hex_lower(&Sha256::digest(&anchor.leaf_spki_der))
    }

    fn store_with_pending(cert_pem: &str, key_hex: &str) -> InMemoryStore {
        let store = InMemoryStore::default();
        let fp = spki_fingerprint_of(cert_pem);
        store
            .set(DEVICE_SIGNING_PENDING_SERVICE, &fp, key_hex.trim())
            .unwrap();
        store
    }

    /// Engineer-panel finding, verified live against the built binary: `cancel_pending_csr`
    /// used to report success unconditionally, since `SecretStore::delete` is deliberately a
    /// no-op on an absent entry (correct for this crate's other best-effort cleanup callers,
    /// wrong for a command whose entire job is confirming a specific cancellation happened).
    #[test]
    fn cancel_csr_reports_no_pending_key_for_an_unknown_fingerprint() {
        let _guard = serialize_tests();
        let store = InMemoryStore::default();
        let err = cancel_pending_csr_with_store(
            &store,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("cancelling a fingerprint that was never pending must not report success");
        assert!(matches!(err, EnrolError::NoPendingKey));
    }

    #[test]
    fn cancel_csr_actually_removes_a_real_pending_entry() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        let fp = spki_fingerprint_of(LEAF_A_PEM);

        cancel_pending_csr_with_store(&store, &fp)
            .ok()
            .expect("cancelling a real pending entry must succeed");
        assert!(
            store
                .get(DEVICE_SIGNING_PENDING_SERVICE, &fp)
                .unwrap()
                .is_none(),
            "the pending entry must actually be gone"
        );

        // Cancelling it again must now report NoPendingKey, not a second false success.
        let err = cancel_pending_csr_with_store(&store, &fp)
            .expect_err("cancelling an already-cancelled fingerprint must not report success");
        assert!(matches!(err, EnrolError::NoPendingKey));
    }

    #[test]
    fn fresh_install_succeeds_and_loads_back_through_the_migrated_loader() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);

        let outcome =
            install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
                .ok()
                .expect("fresh install must succeed");
        assert!(matches!(outcome, InstallOutcome::Installed(_)));

        // Pending entry consumed.
        let fp = spki_fingerprint_of(LEAF_A_PEM);
        assert!(store
            .get(DEVICE_SIGNING_PENDING_SERVICE, &fp)
            .unwrap()
            .is_none());

        // Install→load round trip through the *migrated* loader branch -- the test that
        // justifies that migration.
        let loaded = load_device_signing_credential_with_store(&store).unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn install_without_a_pending_key_is_refused_and_touches_nothing() {
        let _guard = serialize_tests();
        let store = InMemoryStore::default();
        let err = install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .err()
            .expect("must refuse with no pending key");
        assert!(matches!(err, EnrolError::NoPendingKey));

        // Round-D finding: an earlier draft validated the pending key only *after* writing
        // the marker and certificate, so a certificate with no matching pending key still
        // left the keychain in a marker+cert-only state indistinguishable from a genuine
        // crash residue. Nothing here has a pending key at all, so nothing may be written.
        assert!(
            store
                .get(DEVICE_ENROLLED_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .unwrap()
                .is_none(),
            "a rejected install must not write the enrolment marker"
        );
        assert!(
            store
                .get(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .unwrap()
                .is_none(),
            "a rejected install must not write the certificate"
        );
        assert!(
            store
                .get(DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .unwrap()
                .is_none(),
            "a rejected install must not write the key"
        );
    }

    /// Round-D finding: a certificate genuinely already installed and working must not be
    /// damaged by a *second*, unrelated certificate arriving under `--force` with no matching
    /// pending key -- `--force` overrides the "different credential" refusal, but must not
    /// also bypass "there is no real pending key to install", and a rejected install (for
    /// whatever reason) must leave a previously-healthy credential fully intact.
    #[test]
    fn forcing_an_unrelated_certificate_with_no_pending_key_does_not_disturb_a_working_credential()
    {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .expect("fresh install of LEAF_A must succeed");
        let cert_before = store
            .get(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
            .unwrap();
        let key_before = store
            .get(DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_ACCOUNT)
            .unwrap();

        // LEAF_B, --force, but no pending key was ever requested for it on this keychain --
        // must still refuse (a NoPendingKey error, not a successful forced overwrite) and
        // must not touch LEAF_A's credential in the process.
        let err = install_device_signing_certificate_with_store(&store, LEAF_B_PEM, CA_PEM, true)
            .err()
            .expect("must refuse: no pending key for LEAF_B, even under --force");
        assert!(matches!(err, EnrolError::NoPendingKey));

        assert_eq!(
            store
                .get(DEVICE_SIGNING_CERT_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .unwrap(),
            cert_before,
            "LEAF_A's certificate must be untouched by LEAF_B's rejected forced install"
        );
        assert_eq!(
            store
                .get(DEVICE_SIGNING_KEY_SERVICE, DEVICE_SIGNING_ACCOUNT)
                .unwrap(),
            key_before,
            "LEAF_A's key must be untouched by LEAF_B's rejected forced install"
        );
    }

    #[test]
    fn install_is_refused_when_the_env_seam_is_active() {
        let _guard = serialize_tests();
        // Process-global env mutation, scoped to this single test's body -- matching
        // `keychain.rs`'s own env-seam test convention of isolating each such test into one
        // function to avoid a cross-test race.
        unsafe {
            std::env::set_var(DEVICE_SIGNING_KEY_ENV, "irrelevant");
        }
        let store = InMemoryStore::default();
        let result =
            install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false);
        unsafe {
            std::env::remove_var(DEVICE_SIGNING_KEY_ENV);
        }
        assert!(matches!(result, Err(EnrolError::EnvSeamActive)));
    }

    #[test]
    fn reinstalling_the_identical_certificate_is_a_noop() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .unwrap();

        // Re-run with the exact same certificate: no pending entry exists anymore, but that
        // must not matter -- this is the AlreadyInstalled path, not a fresh install.
        let outcome =
            install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
                .ok()
                .expect("re-installing the identical certificate must succeed as a no-op");
        assert!(matches!(outcome, InstallOutcome::AlreadyInstalled(_)));
    }

    /// Round-A's central finding, tested against the *actual* scenario it names: `LEAF_A` and
    /// `LEAF_A_REISSUED` share one SPKI (the identical CSR, signed twice) but have different
    /// DER, reproducing `veil-custodian`'s real repeat-issuance behavior. Round-D confirmed
    /// the original version of this test used two *different keys* (`LEAF_A`/`LEAF_B`) and so
    /// never actually exercised the same-SPKI case at all.
    #[test]
    fn a_reissued_certificate_for_the_same_key_is_not_already_installed() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .unwrap();

        // The re-issued certificate arrives -- same key, same SPKI, different DER. No
        // pending entry exists for it under its own fingerprint (it's the same key as
        // LEAF_A, whose pending entry was already consumed), so this must refuse.
        let err = install_device_signing_certificate_with_store(
            &store,
            LEAF_A_REISSUED_PEM,
            CA_PEM,
            false,
        )
        .err()
        .expect("a re-issued certificate for the same key must not be AlreadyInstalled");
        assert!(
            matches!(err, EnrolError::AlreadyEnrolled { .. }),
            "must be classified as a conflicting (different DER) credential, not accepted \
             as already-installed just because the SPKI matches"
        );
    }

    #[test]
    fn a_different_certificate_for_a_different_key_is_refused_without_force_and_replaced_with_it() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .unwrap();

        // LEAF_B arrives on the same keychain (a different certificate, a different key)
        // without --force.
        let fp_b = spki_fingerprint_of(LEAF_B_PEM);
        store
            .set(DEVICE_SIGNING_PENDING_SERVICE, &fp_b, LEAF_B_KEY_HEX.trim())
            .unwrap();

        let err = install_device_signing_certificate_with_store(&store, LEAF_B_PEM, CA_PEM, false)
            .err()
            .expect("a different certificate must be refused without --force");
        assert!(matches!(err, EnrolError::AlreadyEnrolled { .. }));

        // --force replaces it.
        let outcome =
            install_device_signing_certificate_with_store(&store, LEAF_B_PEM, CA_PEM, true)
                .ok()
                .expect("--force must allow replacement");
        assert!(matches!(outcome, InstallOutcome::Installed(_)));
    }

    #[test]
    fn crash_after_the_certificate_write_recovers_without_force() {
        let _guard = serialize_tests();
        // FailAfterNWrites(2): the marker write and the cert write are allowed, then the key
        // write fails -- simulating a crash after the cert lands but before the key does.
        let inner = InMemoryStore::default();
        let fp = spki_fingerprint_of(LEAF_A_PEM);
        inner
            .set(DEVICE_SIGNING_PENDING_SERVICE, &fp, LEAF_A_KEY_HEX.trim())
            .unwrap();
        let crashing = FailAfterNWrites::new(&inner, 2);

        let result =
            install_device_signing_certificate_with_store(&crashing, LEAF_A_PEM, CA_PEM, false);
        assert!(
            result.is_err(),
            "the simulated crash must actually interrupt the install"
        );

        // The loader must see this as observable (marker present, key absent), not silently
        // "not enrolled" -- ADR-017 §7.
        let loaded = load_device_signing_credential_with_store(&inner);
        assert!(
            loaded.is_err(),
            "marker-present/key-absent must be a named Err, not Ok(None)"
        );

        // Re-run against the real (non-crashing) store recovers without --force.
        let outcome =
            install_device_signing_certificate_with_store(&inner, LEAF_A_PEM, CA_PEM, false)
                .ok()
                .expect("recovery must not require --force");
        assert!(matches!(
            outcome,
            InstallOutcome::RecoveredPartialInstall(_)
        ));
    }

    /// The regression test for round-C/round-D's most severe finding: an earlier draft
    /// required a *second* `--force` to recover from a crash that happened *during* a
    /// `--force` replacement, directly contradicting ADR-017 §6's own table (this exact
    /// state -- "stored cert DER matches incoming, stored key absent or not matching" --
    /// is supposed to auto-recover without `--force`, covering interrupted replacements as
    /// well as fresh-install crashes).
    #[test]
    fn crash_mid_force_replacement_recovers_without_a_second_force() {
        let _guard = serialize_tests();
        // LEAF_A installed and working.
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .expect("fresh install of LEAF_A must succeed");

        // A --force replacement to LEAF_B begins and crashes after the certificate write but
        // before the key write: simulated by installing LEAF_B's *certificate* directly,
        // leaving LEAF_A's *key* still in place underneath it -- exactly the residue an
        // interrupted `--force` replacement leaves.
        let fp_b = spki_fingerprint_of(LEAF_B_PEM);
        store
            .set(DEVICE_SIGNING_PENDING_SERVICE, &fp_b, LEAF_B_KEY_HEX.trim())
            .unwrap();
        store
            .set(DEVICE_ENROLLED_SERVICE, DEVICE_SIGNING_ACCOUNT, &fp_b)
            .unwrap();
        store
            .set(
                DEVICE_SIGNING_CERT_SERVICE,
                DEVICE_SIGNING_ACCOUNT,
                LEAF_B_PEM,
            )
            .unwrap();
        // (LEAF_A's key, from the earlier install, is still sitting under
        // DEVICE_SIGNING_KEY_SERVICE -- never overwritten, simulating the crash.)

        // Re-run install-cert for LEAF_B *without* --force: must auto-recover, not demand a
        // second --force just to finish what an already-authorized --force started.
        let outcome =
            install_device_signing_certificate_with_store(&store, LEAF_B_PEM, CA_PEM, false)
                .ok()
                .expect("an interrupted --force replacement must recover without a second --force");
        assert!(matches!(
            outcome,
            InstallOutcome::RecoveredPartialInstall(_)
        ));

        // The recovered key must actually be LEAF_B's, not LEAF_A's stale one left behind.
        let loaded = load_device_signing_credential_with_store(&store)
            .unwrap()
            .expect("a credential must now load cleanly");
        assert!(
            *loaded.key_ref()
                == KeyRef::from_certificate_der(
                    &validate_signing_certificate_pem(LEAF_B_PEM).unwrap().der
                )
        );
    }

    /// Round-D finding: a stored certificate that doesn't even parse as valid DER used to
    /// hard-fail unconditionally via `?`, before `--force` was ever consulted -- making
    /// `--force` unable to repair exactly the corruption state ADR-017 §6 says it should.
    #[test]
    fn a_malformed_stored_certificate_can_be_overwritten_with_force_but_not_without_it() {
        let _guard = serialize_tests();
        let store = InMemoryStore::default();
        store
            .set(
                DEVICE_SIGNING_CERT_SERVICE,
                DEVICE_SIGNING_ACCOUNT,
                "-----BEGIN CERTIFICATE-----\nnot actually a certificate\n-----END CERTIFICATE-----\n",
            )
            .unwrap();
        let fp = spki_fingerprint_of(LEAF_A_PEM);
        store
            .set(DEVICE_SIGNING_PENDING_SERVICE, &fp, LEAF_A_KEY_HEX.trim())
            .unwrap();

        let err = install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .err()
            .expect("a malformed stored certificate must refuse without --force");
        assert!(matches!(err, EnrolError::Keychain(_)));

        let outcome =
            install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, true)
                .ok()
                .expect("--force must overwrite a malformed stored certificate");
        assert!(matches!(outcome, InstallOutcome::Installed(_)));
    }

    #[test]
    fn status_reports_all_three_facts_independently() {
        let _guard = serialize_tests();
        let store = store_with_pending(LEAF_A_PEM, LEAF_A_KEY_HEX);
        install_device_signing_certificate_with_store(&store, LEAF_A_PEM, CA_PEM, false)
            .ok()
            .unwrap();

        let status = credential_status_with_store(&store).ok().unwrap();
        assert!(status.installed.is_some());
        assert!(!status.env_seam_shadowing);
        assert!(status.enrolment_marker_present);
    }
}
