//! Pinned-CA trust-anchor verification (ADR-017, XREPO-009).
//!
//! `certificate.rs`'s own module doc has always said, correctly, that it does not verify a
//! certificate's CA signature -- "that trust decision belongs to `veil-custodian`, the
//! issuer; a certificate reaching this loader already came from the local, already-trusted OS
//! keychain, not an untrusted network peer." `install_device_signing_certificate` (`enrol.rs`)
//! is exactly the thing that breaks that premise: it accepts a certificate handed over an
//! out-of-band channel, before it has ever touched the keychain. This module is what makes
//! that premise hold again at the one point it stops being automatic.
//!
//! `x509-cert 0.3` has no certificate-verification API of its own, with or without its
//! `signature` feature (that feature exists only to support `builder`, this crate's
//! `Cargo.toml` explains why both stay off) -- so verification here is not a stopgap for a
//! library feature that doesn't exist, it is the only implementation. Exactly one algorithm
//! is supported: `ecdsa-with-SHA256` over a P-256 anchor key -- the one `veil-custodian`'s CA
//! actually signs with today (`rcgen::KeyPair::generate()`'s default). `veil-custodian` does
//! not itself restrict a *provisioned* production CA to that algorithm, so a mismatched
//! anchor/leaf pair is refused, not silently accepted -- ADR-017 §13 records this as an
//! explicit closure limitation, not assumed away.

use std::time::SystemTime;

use der::asn1::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::error::{crypto_err, VaultError};

/// `ecdsa-with-SHA256` (RFC 5758) -- see `csr.rs`'s identical constant for why this is not
/// shared across modules that check different structures for different reasons.
const ECDSA_WITH_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `id-ecPublicKey` (RFC 5480) -- see `certificate.rs`'s identical constant.
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` / NIST P-256 (RFC 5480) -- see `certificate.rs`'s identical constant.
const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// What a successful anchor verification yields: the leaf's issuer identity and validity
/// window (so the caller can warn on an already-expired-or-expiring credential and report an
/// install summary without a second certificate parse) and the leaf's own SPKI DER (so the
/// caller can compute the fingerprint that selects its matching pending private key).
pub(crate) struct AnchorVerification {
    /// The leaf's own `issuer` field, rendered for display -- enforced below to match the
    /// anchor's own `subject`, so this is the anchor's identity, taken from the certificate
    /// being installed rather than the anchor file. `enrol.rs`'s `InstalledSigningCredential`
    /// reports this same value, obtainable identically whether reported fresh at install time
    /// or read back later by `credential_status` (unlike an anchor-file-only fact, e.g. the
    /// anchor's own DER fingerprint, which only exists at install time and is not threaded
    /// through this module's return value since nothing currently consumes it).
    pub(crate) leaf_issuer: String,
    pub(crate) leaf_not_before: SystemTime,
    pub(crate) leaf_not_after: SystemTime,
    /// The leaf's own DER-encoded `SubjectPublicKeyInfo` -- re-exposed here so `enrol.rs`
    /// doesn't need a second certificate parse just to compute the SPKI fingerprint that
    /// selects the matching pending private key (`csr.rs`'s fingerprint is over these exact
    /// bytes).
    pub(crate) leaf_spki_der: Vec<u8>,
}

/// Verifies that `leaf_der` (a DER-encoded certificate, typically `ValidatedSigningCertificate
/// ::der` from `certificate.rs`) was issued by `anchor_pem` (a pinned CA certificate PEM):
/// issuer-name chaining, then a real ECDSA signature check, both restricted to exactly
/// `ecdsa-with-SHA256` over a P-256 anchor key. Does not check the leaf's own ADR-S profile
/// (`certificate.rs` already does that, separately) or revocation (custodian's ADR-P problem).
pub(crate) fn verify_issued_by_anchor(
    leaf_der: &[u8],
    anchor_pem: &str,
) -> Result<AnchorVerification, VaultError> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| crypto_err(format!("malformed leaf certificate DER: {e}")))?;
    let anchor = Certificate::from_pem(anchor_pem.as_bytes())
        .map_err(|e| crypto_err(format!("malformed CA anchor certificate PEM: {e}")))?;

    let anchor_tbs = anchor.tbs_certificate();

    // Anchor sanity, checked before any cryptographic work: a non-CA or wrong-purpose anchor
    // file is an operator error (wrong file handed to --ca-cert), and deserves a message that
    // says so rather than a generic "signature does not verify".
    let anchor_is_ca = anchor_tbs
        .get_extension::<BasicConstraints>()
        .map_err(|e| crypto_err(format!("malformed anchor BasicConstraints: {e}")))?
        .is_some_and(|(_, bc)| bc.ca);
    if !anchor_is_ca {
        return Err(crypto_err(
            "--ca-cert does not have BasicConstraints CA:TRUE -- this is not a CA certificate",
        ));
    }
    if let Some((_, key_usage)) = anchor_tbs
        .get_extension::<KeyUsage>()
        .map_err(|e| crypto_err(format!("malformed anchor KeyUsage: {e}")))?
    {
        if !key_usage.0.contains(KeyUsages::KeyCertSign) {
            return Err(crypto_err(
                "--ca-cert's KeyUsage does not include keyCertSign -- this CA certificate is \
                 not authorised to sign other certificates",
            ));
        }
    }
    let anchor_spki = anchor_tbs.subject_public_key_info();
    if anchor_spki.algorithm.oid != EC_PUBLIC_KEY_OID {
        return Err(crypto_err(
            "--ca-cert's public key algorithm is not id-ecPublicKey -- only a P-256 CA is \
             supported (ADR-017 §13 limitation 5)",
        ));
    }
    let anchor_curve_oid: ObjectIdentifier = anchor_spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| crypto_err("--ca-cert's public key has no EC curve parameter"))?
        .decode_as()
        .map_err(|e| crypto_err(format!("--ca-cert's EC curve parameter is malformed: {e}")))?;
    if anchor_curve_oid != PRIME256V1_OID {
        return Err(crypto_err(
            "--ca-cert's public key curve is not P-256 -- only a P-256 CA is supported \
             (ADR-017 §13 limitation 5)",
        ));
    }

    // Issuer-name chaining, checked before the signature: converts the overwhelmingly common
    // "wrong anchor file" mistake into an actionable message instead of an opaque signature
    // failure.
    if leaf.tbs_certificate().issuer() != anchor_tbs.subject() {
        return Err(crypto_err(
            "certificate's issuer does not match --ca-cert's subject -- this does not look \
             like the CA that issued this certificate",
        ));
    }

    // Algorithm gate: exactly ecdsa-with-SHA256, refused otherwise rather than accepted
    // permissively (ADR-017 §13 limitation 5 -- veil-custodian does not itself restrict a
    // provisioned production CA to this algorithm).
    let leaf_sig_alg = leaf.signature_algorithm();
    if leaf_sig_alg.oid != ECDSA_WITH_SHA256_OID || leaf_sig_alg.parameters.is_some() {
        return Err(crypto_err(format!(
            "certificate signature algorithm is {} with parameters {:?}, not exactly \
             ecdsa-with-SHA256 with absent parameters -- only that one algorithm is supported",
            leaf_sig_alg.oid, leaf_sig_alg.parameters,
        )));
    }

    // The signature itself: verify the leaf's TBS DER against the anchor's public key. Sound
    // for a conformant (DER, not merely BER) certificate -- the same canonicality argument
    // `certificate.rs` already relies on for its own re-encoding check.
    let tbs_der = leaf
        .tbs_certificate()
        .to_der()
        .map_err(|e| crypto_err(format!("failed to re-encode certificate TBS to DER: {e}")))?;
    let anchor_key = VerifyingKey::from_sec1_bytes(anchor_spki.subject_public_key.raw_bytes())
        .map_err(|e| {
            crypto_err(format!(
                "--ca-cert's public key is not a valid P-256 point: {e}"
            ))
        })?;
    let leaf_signature = DerSignature::try_from(leaf.signature().raw_bytes()).map_err(|e| {
        crypto_err(format!(
            "certificate signature is not a valid DER ECDSA signature: {e}"
        ))
    })?;
    anchor_key.verify(&tbs_der, &leaf_signature).map_err(|_| {
        crypto_err(
            "certificate signature does not verify against --ca-cert -- this certificate \
                 was not issued by this CA",
        )
    })?;

    let validity = leaf.tbs_certificate().validity();
    let leaf_spki_der = leaf
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| crypto_err(format!("failed to re-encode leaf SPKI to DER: {e}")))?;
    Ok(AnchorVerification {
        leaf_issuer: leaf.tbs_certificate().issuer().to_string(),
        leaf_not_before: validity.not_before.to_system_time(),
        leaf_not_after: validity.not_after.to_system_time(),
        leaf_spki_der,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR_PEM: &str = include_str!("../tests/fixtures/anchor_ca.pem");
    const LEAF_ISSUED_BY_ANCHOR_PEM: &str = include_str!("../tests/fixtures/anchor_leaf.pem");
    const LEAF_ISSUED_BY_OTHER_CA_PEM: &str =
        include_str!("../tests/fixtures/anchor_leaf_wrong_ca.pem");
    const LEAF_TAMPERED_TBS_PEM: &str = include_str!("../tests/fixtures/anchor_leaf_tampered.pem");
    const LEAF_RSA_SIGNED_PEM: &str = include_str!("../tests/fixtures/anchor_leaf_rsa_signed.pem");
    const LEAF_WRONG_ISSUER_NAME_PEM: &str =
        include_str!("../tests/fixtures/anchor_leaf_wrong_issuer_name.pem");
    const NON_CA_ANCHOR_PEM: &str = include_str!("../tests/fixtures/anchor_non_ca.pem");

    fn leaf_der(pem: &str) -> Vec<u8> {
        Certificate::from_pem(pem.as_bytes())
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn accepts_a_leaf_genuinely_issued_by_the_anchor() {
        let result = verify_issued_by_anchor(&leaf_der(LEAF_ISSUED_BY_ANCHOR_PEM), ANCHOR_PEM);
        assert!(result.is_ok(), "{:?}", result.err().map(|e| e.to_string()));
    }

    #[test]
    fn rejects_a_leaf_issued_by_a_different_ca() {
        let err = verify_issued_by_anchor(&leaf_der(LEAF_ISSUED_BY_OTHER_CA_PEM), ANCHOR_PEM)
            .err()
            .expect("expected verify_issued_by_anchor to reject, it accepted");
        assert!(format!("{err}").contains("issuer"));
    }

    #[test]
    fn rejects_a_tampered_tbs_as_a_signature_failure_not_a_parse_failure() {
        let err = verify_issued_by_anchor(&leaf_der(LEAF_TAMPERED_TBS_PEM), ANCHOR_PEM)
            .err()
            .expect("expected verify_issued_by_anchor to reject, it accepted");
        assert!(format!("{err}").contains("does not verify"));
    }

    #[test]
    fn rejects_a_non_ecdsa_sha256_signature_algorithm() {
        let err = verify_issued_by_anchor(&leaf_der(LEAF_RSA_SIGNED_PEM), ANCHOR_PEM)
            .err()
            .expect("expected verify_issued_by_anchor to reject, it accepted");
        assert!(format!("{err}").contains("ecdsa-with-SHA256"));
    }

    #[test]
    fn rejects_an_issuer_subject_name_mismatch() {
        let err = verify_issued_by_anchor(&leaf_der(LEAF_WRONG_ISSUER_NAME_PEM), ANCHOR_PEM)
            .err()
            .expect("expected verify_issued_by_anchor to reject, it accepted");
        assert!(format!("{err}").contains("issuer"));
    }

    #[test]
    fn rejects_a_non_ca_anchor() {
        let err = verify_issued_by_anchor(&leaf_der(LEAF_ISSUED_BY_ANCHOR_PEM), NON_CA_ANCHOR_PEM)
            .err()
            .expect("expected verify_issued_by_anchor to reject, it accepted");
        assert!(format!("{err}").contains("CA:TRUE"));
    }
}
