//! ADR-S (`veil-custodian`'s per-device telemetry signing-key issuance) certificate
//! profile validation, plus the two identifiers a validated certificate yields:
//! [`vg_core::telemetry::KeyRef`] (derived from the certificate's own DER) and
//! [`vg_core::telemetry::DeviceRef`] (extracted from its Subject Alternative Name).
//!
//! **What this module checks, and why.** ADR-S's whole two-certificate design exists so
//! a compromised telemetry-signing key can never be presented as an mTLS client
//! credential (or vice versa) — a property that only holds if this crate actually
//! verifies the certificate it loads carries the *signing* profile, not the mTLS one.
//! Concretely: Key Usage is `digitalSignature` **only** (no `keyEncipherment`, which the
//! mTLS profile carries); Extended Key Usage is **exactly** the one project-local
//! placeholder OID `1.3.6.1.4.1.55555.1.1.1` ADR-S pins (`55555` is not a real IANA
//! Private Enterprise Number — a marked placeholder, not a mistake); the certificate
//! must **never** carry the `id-kp-clientAuth` EKU the mTLS profile is amended to gain —
//! checked as its own explicit, separately-erroring condition, not merely implied by the
//! exact-match check above it, so a certificate carrying both the correct OID *and*
//! `clientAuth` fails with an unambiguous reason; `BasicConstraints.cA` must be `FALSE`
//! (an end-entity certificate, never a CA) — `veil-custodian`'s own
//! `key-ref-golden.json` fixture comment names `CA:TRUE` as a defect its own adversarial
//! review caught and fixed, so this is part of "the ADR-S profile" by the custodian's
//! own definition, not an addition invented here (a doubt-driven-development review
//! round on this module caught its absence); and the public key itself must actually be
//! `id-ecPublicKey` on the `prime256v1` (P-256) curve — checked from the certificate's
//! own `SubjectPublicKeyInfo.algorithm`, not merely assumed from the raw point bytes'
//! length, which a wrong-algorithm key could coincidentally match (same review round).
//!
//! **What this module does not check.** It does not verify the certificate's own CA
//! signature — that trust decision belongs to `veil-custodian`, the issuer; a
//! certificate reaching this loader already came from the local, already-trusted OS
//! keychain (`keychain::load_device_signing_credential`), not an untrusted network peer.
//! It does not parse or validate `not_before`/`not_after` — expiry is the custodian's
//! revocation/CRL problem (ADR-P), not this crate's.

use der::asn1::ObjectIdentifier;
use der::{DecodePem, Encode};
use vg_core::telemetry::{DeviceRef, DeviceRefError};
use vg_core::VaultError;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::Certificate;

use crate::error::crypto_err;
use crate::keychain::decode_hex;

/// ADR-S's placeholder EKU OID for the telemetry signing profile
/// (`docs/decisions.md`'s ADR-S row, `veil-custodian`) — pinned now, not deferred, and
/// must not change once any non-dev certificate has been issued (tracked as a risk,
/// `docs/risks.md`).
const ADR_S_SIGNING_EKU_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.1.1");

/// RFC 5280's `id-kp-clientAuth` — the mTLS profile's EKU (ADR-S also amends that
/// profile to gain this). The signing profile must never carry it.
const CLIENT_AUTH_EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// `id-ecPublicKey` (RFC 5480) — the only public-key algorithm ADR-S's signing profile
/// permits (the custodian's own CSR validation already rejects any other at issuance;
/// this is the equivalent check on the consumption side, not merely inherited from it).
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// `prime256v1` / NIST P-256 (RFC 5480) — the only curve ADR-S permits.
const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The SAN URI prefix a device's signing certificate carries (ADR-S: identical
/// convention to the existing ADR-A mTLS cert's SAN). The `dev_`-prefixed suffix is
/// `veil-custodian`'s own wire form for a pseudonym (ADR-G); this crate strips the
/// prefix before handing the raw 16 bytes to [`DeviceRef`], which — on the veilgremlin
/// side — serializes bare, with no prefix (ADR-G's own corrected wire-format note).
const DEVICE_SAN_URI_PREFIX: &str = "urn:veil:device:dev_";

/// A certificate that has passed every ADR-S signing-profile check, plus the identifiers
/// and raw key material it yields.
pub struct ValidatedSigningCertificate {
    pub device_ref: DeviceRef,
    /// The certificate's own DER encoding. No separate `key_ref` field exists on this
    /// struct — `KeyRef::from_certificate_der(&der)` is the single derivation path
    /// (called by `DeviceSigningCredential::from_parts` when the keychain loader
    /// constructs a real credential, and directly by this module's own test against the
    /// vendored fixture); carrying a second, independently-computed copy here would be
    /// redundant surface, not a stronger guarantee.
    pub der: Vec<u8>,
    /// The certificate's own `SubjectPublicKeyInfo.subject_public_key`, raw SEC1 bytes
    /// (uncompressed, per the custodian's own encoding). This module has no private key
    /// to check against, so it does not compare this itself — the keychain loader does,
    /// against the *loaded* private key's own public half, to catch a keychain in an
    /// inconsistent state (a signing key that doesn't match its own stored certificate)
    /// before ever handing out a [`crate::certificate`]-validated but silently-wrong
    /// credential.
    pub subject_public_key_bytes: Vec<u8>,
}

/// Parses `pem` and validates it against ADR-S's telemetry signing certificate profile.
/// See this module's own doc for exactly what is and isn't checked.
pub fn validate_signing_certificate_pem(
    pem: &str,
) -> Result<ValidatedSigningCertificate, VaultError> {
    let cert = Certificate::from_pem(pem.as_bytes())
        .map_err(|e| crypto_err(format!("malformed signing certificate PEM: {e}")))?;

    // DER is canonical: re-encoding a structure this crate's own parser just decoded
    // from DER reproduces the identical bytes. This is what `KeyRef::from_certificate_der`
    // hashes, and what the vendored `tests/fixtures/custodian/key-ref-golden.json` pins
    // against — a divergence here would fail that cross-repo assertion loudly, not
    // silently.
    let der = cert
        .to_der()
        .map_err(|e| crypto_err(format!("failed to re-encode certificate to DER: {e}")))?;

    let tbs = cert.tbs_certificate();

    let (_, key_usage) = tbs
        .get_extension::<KeyUsage>()
        .map_err(|e| crypto_err(format!("malformed KeyUsage extension: {e}")))?
        .ok_or_else(|| {
            crypto_err("signing certificate is missing the required KeyUsage extension")
        })?;
    if key_usage.0 != KeyUsages::DigitalSignature {
        return Err(crypto_err(
            "signing certificate KeyUsage must be exactly digitalSignature -- ADR-S's \
             signing profile is DigitalSignature-only, unlike the mTLS profile's \
             DigitalSignature + KeyEncipherment",
        ));
    }

    // `BasicConstraints` is optional per RFC 5280 (`cA` defaults to `false` when the
    // extension is absent entirely) -- unlike KeyUsage/ExtendedKeyUsage/SubjectAltName
    // above, a missing extension here is compliant, not an error.
    if let Some((_, basic_constraints)) = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|e| crypto_err(format!("malformed BasicConstraints extension: {e}")))?
    {
        if basic_constraints.ca {
            return Err(crypto_err(
                "signing certificate has BasicConstraints CA:TRUE -- ADR-S's signing \
                 profile is an end-entity certificate (CA:FALSE); a CA-flagged \
                 certificate must never be accepted as a device signing credential",
            ));
        }
    }

    let (_, eku) = tbs
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|e| crypto_err(format!("malformed ExtendedKeyUsage extension: {e}")))?
        .ok_or_else(|| {
            crypto_err("signing certificate is missing the required ExtendedKeyUsage extension")
        })?;
    if eku.0.contains(&CLIENT_AUTH_EKU_OID) {
        return Err(crypto_err(
            "signing certificate carries the ClientAuth EKU -- ADR-S requires the \
             signing profile never carry it, so an mTLS client certificate can never be \
             presented as a telemetry signing credential",
        ));
    }
    if eku.0 != [ADR_S_SIGNING_EKU_OID] {
        return Err(crypto_err(format!(
            "signing certificate ExtendedKeyUsage must be exactly the ADR-S placeholder \
             OID ({ADR_S_SIGNING_EKU_OID}) and no other"
        )));
    }

    let (_, san) = tbs
        .get_extension::<SubjectAltName>()
        .map_err(|e| crypto_err(format!("malformed SubjectAltName extension: {e}")))?
        .ok_or_else(|| {
            crypto_err("signing certificate is missing the required SubjectAltName extension")
        })?;
    let device_ref = device_ref_from_san(&san.0)?;

    // The public-key/certificate cross-check in `keychain::load_device_signing_credential`
    // compares raw point bytes, which says nothing about what *algorithm* those bytes are
    // claimed to encode -- a certificate whose `SubjectPublicKeyInfo` names a different
    // algorithm but happens to carry the same-length bytes would otherwise pass that
    // check undetected. Verifying the algorithm and curve here, from the certificate's
    // own typed `AlgorithmIdentifier`, closes that gap at the source.
    let spki = tbs.subject_public_key_info();
    if spki.algorithm.oid != EC_PUBLIC_KEY_OID {
        return Err(crypto_err(
            "signing certificate public key algorithm is not id-ecPublicKey -- ADR-S \
             requires an EC key, not this certificate's declared algorithm",
        ));
    }
    let curve_oid: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| crypto_err("signing certificate public key has no EC curve parameter"))?
        .decode_as()
        .map_err(|e| {
            crypto_err(format!(
                "signing certificate EC curve parameter is malformed: {e}"
            ))
        })?;
    if curve_oid != PRIME256V1_OID {
        return Err(crypto_err(
            "signing certificate public key curve is not P-256 -- ADR-S's signing \
             profile requires prime256v1, matching the custodian's own CSR validation",
        ));
    }

    let subject_public_key_bytes = spki.subject_public_key.raw_bytes().to_vec();

    Ok(ValidatedSigningCertificate {
        device_ref,
        der,
        subject_public_key_bytes,
    })
}

fn device_ref_from_san(names: &[GeneralName]) -> Result<DeviceRef, VaultError> {
    let uri = names
        .iter()
        .find_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .ok_or_else(|| crypto_err("signing certificate SAN has no URI entry"))?;

    let suffix = uri.strip_prefix(DEVICE_SAN_URI_PREFIX).ok_or_else(|| {
        crypto_err(format!(
            "signing certificate SAN URI does not match the expected \
             urn:veil:device:dev_<32hex> shape: {uri}"
        ))
    })?;

    let bytes = decode_hex(suffix)
        .ok_or_else(|| crypto_err("signing certificate SAN device pseudonym is not valid hex"))?;

    DeviceRef::try_from(bytes.as_slice()).map_err(|e: DeviceRefError| {
        crypto_err(format!(
            "signing certificate SAN device pseudonym has the wrong length: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vg_core::telemetry::KeyRef;

    /// Vendored from `veil-custodian` (`docs/api/fixtures/signing-keys/`, see
    /// `crates/vg-core/tests/fixtures/custodian/FIXTURES_SOURCE`) — the real ADR-S
    /// signing-profile certificate the custodian regenerated specifically to match this
    /// profile.
    const FIXED_CERTIFICATE_PEM: &str =
        include_str!("../../vg-core/tests/fixtures/custodian/fixed-certificate.pem");
    const WRONG_KEY_USAGE_PEM: &str = include_str!("../tests/fixtures/wrong_key_usage.pem");
    const WRONG_EKU_PEM: &str = include_str!("../tests/fixtures/wrong_eku.pem");
    const CLIENT_AUTH_PRESENT_PEM: &str = include_str!("../tests/fixtures/client_auth_present.pem");
    const CA_TRUE_PEM: &str = include_str!("../tests/fixtures/ca_true.pem");
    const WRONG_CURVE_PEM: &str = include_str!("../tests/fixtures/wrong_curve.pem");

    /// `ValidatedSigningCertificate` deliberately has no `Debug` (it carries a raw DER
    /// blob, and this crate's convention is not to derive `Debug` on certificate/key
    /// material by default) — `Result::unwrap_err` requires it on the `Ok` side, so the
    /// three rejection tests below extract the error this way instead.
    fn expect_reject(result: Result<ValidatedSigningCertificate, VaultError>) -> VaultError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected validate_signing_certificate_pem to reject, it accepted"),
        }
    }

    /// Cross-repo assertion: the vendored ADR-S certificate must yield exactly the
    /// `key_ref` `veil-custodian`'s `docs/api/fixtures/signing-keys/key-ref-golden.json`
    /// pins (`sk_90875e5a4a9d72cfcffc23c73f3038c4aea76af0`), and the `device_ref` its own
    /// SAN actually carries (`dev_9c1e7a44b3d24f1a8e6c2b0f5a7d3c11`, ADR-S's own OpenAPI
    /// example pseudonym).
    #[test]
    fn validate_signing_certificate_pem_accepts_the_vendored_adr_s_certificate() {
        let validated = validate_signing_certificate_pem(FIXED_CERTIFICATE_PEM).unwrap();

        let expected_key_ref =
            KeyRef::try_from("sk_90875e5a4a9d72cfcffc23c73f3038c4aea76af0").unwrap();
        assert!(KeyRef::from_certificate_der(&validated.der) == expected_key_ref);

        let expected_device_bytes = decode_hex("9c1e7a44b3d24f1a8e6c2b0f5a7d3c11").unwrap();
        let expected_device_ref = DeviceRef::try_from(expected_device_bytes.as_slice()).unwrap();
        assert!(validated.device_ref == expected_device_ref);
    }

    #[test]
    fn validate_signing_certificate_pem_rejects_the_mtls_key_usage_profile() {
        let err = expect_reject(validate_signing_certificate_pem(WRONG_KEY_USAGE_PEM));
        assert!(format!("{err}").contains("digitalSignature"));
    }

    #[test]
    fn validate_signing_certificate_pem_rejects_a_non_adr_s_eku() {
        let err = expect_reject(validate_signing_certificate_pem(WRONG_EKU_PEM));
        assert!(format!("{err}").contains("ADR-S placeholder"));
    }

    /// The dedicated check, not just the generic exact-match one: a certificate
    /// carrying *both* the correct ADR-S OID *and* `ClientAuth` must fail with a message
    /// naming `ClientAuth` specifically — this is the property ADR-S's two-certificate
    /// design exists to guarantee.
    #[test]
    fn validate_signing_certificate_pem_rejects_client_auth_even_alongside_the_correct_eku() {
        let err = expect_reject(validate_signing_certificate_pem(CLIENT_AUTH_PRESENT_PEM));
        assert!(format!("{err}").contains("ClientAuth"));
    }

    /// A doubt-driven-development finding: an earlier version of this module never
    /// checked `BasicConstraints` at all, and every fixture in this directory happened
    /// to be `CA:TRUE` (openssl's default when `basicConstraints` isn't set explicitly)
    /// without anyone noticing — the vendored `veil-custodian` fixture's own
    /// `key-ref-golden.json` names `CA:TRUE` as exactly this class of defect, caught and
    /// fixed by that repo's own adversarial review.
    #[test]
    fn validate_signing_certificate_pem_rejects_a_ca_certificate() {
        let err = expect_reject(validate_signing_certificate_pem(CA_TRUE_PEM));
        assert!(format!("{err}").contains("CA:TRUE"));
    }

    /// A doubt-driven-development finding: the public-key/certificate cross-check in
    /// `keychain::load_device_signing_credential` compares raw point bytes only, which
    /// says nothing about the *algorithm* those bytes claim to encode. This certificate
    /// is otherwise-fully-compliant (correct KU/EKU/CA/SAN) but its key is P-384, not
    /// P-256 — proving the dedicated curve check catches what the raw-byte comparison
    /// alone cannot.
    #[test]
    fn validate_signing_certificate_pem_rejects_a_non_p256_curve() {
        let err = expect_reject(validate_signing_certificate_pem(WRONG_CURVE_PEM));
        assert!(format!("{err}").contains("P-256"));
    }
}
