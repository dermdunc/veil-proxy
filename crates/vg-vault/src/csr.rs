//! PKCS#10 certificate-signing-request construction for the device telemetry signing
//! credential (ADR-017, XREPO-009).
//!
//! Deliberately does not use `x509-cert`'s `builder` feature (`RequestBuilder`) -- this
//! crate's `Cargo.toml` explains why (its `finalize` unconditionally inserts an
//! `extensionRequest` attribute, diverging from the empty-`Attributes` CSR shape
//! `veil-enrol`/`veil-custodian` are actually proven against, and it pulls an unused `sha1`
//! dependency). `CertReq`/`CertReqInfo` are hand-assembled instead -- these are not
//! feature-gated (only the `builder` submodule is), so this reuses upstream's typed ASN.1
//! encoders rather than reimplementing one.

use der::asn1::ObjectIdentifier;
use der::pem::LineEnding;
use der::{Encode, EncodePem};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, Version};
use x509_cert::spki::SignatureBitStringEncoding;
use x509_cert::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::error::{crypto_err, VaultError};
use crate::random::fill_random;

/// `ecdsa-with-SHA256` (RFC 5758) -- the exact algorithm `veil-custodian`'s CA requires of a
/// CSR's own self-signature (`veil-custodian/src/ca/mod.rs:601`). Not shared with
/// `certificate.rs`'s own OID constants: that module checks a *certificate's* declared
/// algorithm on load, a different structure checked for a different reason, and this crate's
/// convention is not to couple unrelated checks through one shared constant.
const ECDSA_WITH_SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The placeholder CSR subject. `veil-custodian`'s CA overwrites Subject/SAN/KeyUsage/
/// ExtendedKeyUsage/the CA bit unconditionally at signing time
/// (`veil-custodian/src/ca/mod.rs:316-328`), so nothing meaningful can be requested here.
const PLACEHOLDER_SUBJECT: &str = "CN=placeholder";

/// A freshly generated CSR, plus the identifier the out-of-band operator-confirmation flow
/// (`veil-enrol`'s CSR handoff mechanism) needs. Carries no private key -- the caller (
/// `enrol.rs`) holds that separately and stores it in the OS keychain's pending service.
pub(crate) struct SigningCsr {
    /// PKCS#10 `CERTIFICATE REQUEST` PEM.
    pub(crate) pem: String,
    /// SHA-256 of the DER-encoded `SubjectPublicKeyInfo`, lowercase hex -- byte-identical to
    /// `veil-enrol`'s own `csr_public_key_fingerprint` (`veil-enrol/src/csr.rs:81-87`, which
    /// hashes the *whole* SPKI SEQUENCE including its `AlgorithmIdentifier`, not just the raw
    /// EC point) and to `openssl req -in device.csr -pubkey -noout | openssl pkey -pubin
    /// -outform DER | sha256sum`.
    pub(crate) spki_fingerprint: String,
}

/// Generates a fresh P-256 signing key. The caller is responsible for storing it -- never to
/// a plaintext file (see `enrol.rs`, which writes it to the OS keychain's pending service).
pub(crate) fn generate_signing_key() -> Result<SigningKey, VaultError> {
    // Retrying on an out-of-range scalar (astronomically unlikely for P-256, ~2^-128) rather
    // than introducing a `rand_core`-based RNG dependency `SigningKey::random` would need --
    // this crate's own `fill_random` (OS CSPRNG via `getrandom`) is the existing,
    // already-audited entropy source every other secret in this crate uses.
    for _ in 0..8 {
        let mut scalar = [0u8; 32];
        fill_random(&mut scalar)?;
        if let Ok(key) = SigningKey::from_slice(&scalar) {
            return Ok(key);
        }
    }
    Err(crypto_err(
        "failed to generate a valid P-256 scalar after 8 attempts",
    ))
}

/// Builds a CSR for `key`, matching custodian's and `veil-enrol`'s exact expectations: P-256
/// SPKI, an empty attribute set (no `extensionRequest` -- custodian ignores CSR-requested
/// extensions and server-forces the SAN, `veil-custodian/src/ca/mod.rs:237-243`, proven by its
/// own `signing_key_csr_via_extension_request_cannot_smuggle_a_different_san` test), and an
/// `ecdsa-with-SHA256` outer self-signature (`veil-custodian/src/ca/mod.rs:601`, curve-checked
/// on raw CSR bytes before `rcgen` ever sees them, `:573`).
pub(crate) fn build_signing_csr(key: &SigningKey) -> Result<SigningCsr, VaultError> {
    let verifying_key = key.verifying_key();

    let public_key = SubjectPublicKeyInfo::from_key(verifying_key)
        .map_err(|e| crypto_err(format!("failed to encode CSR public key: {e}")))?;
    let spki_der = public_key
        .to_der()
        .map_err(|e| crypto_err(format!("failed to DER-encode CSR public key: {e}")))?;
    let spki_fingerprint = hex_lower(&Sha256::digest(&spki_der));

    let subject: Name = PLACEHOLDER_SUBJECT
        .parse()
        .map_err(|e| crypto_err(format!("failed to build CSR subject: {e}")))?;

    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes: Attributes::default(),
    };
    let info_der = info
        .to_der()
        .map_err(|e| crypto_err(format!("failed to DER-encode CSR info: {e}")))?;

    let signature: DerSignature = key
        .try_sign(&info_der)
        .map_err(|e| crypto_err(format!("failed to sign CSR: {e}")))?;
    let signature_bits = signature
        .to_bitstring()
        .map_err(|e| crypto_err(format!("failed to encode CSR signature: {e}")))?;

    let csr = CertReq {
        info,
        algorithm: AlgorithmIdentifier {
            oid: ECDSA_WITH_SHA256_OID,
            parameters: None,
        },
        signature: signature_bits,
    };

    let pem = csr
        .to_pem(LineEnding::LF)
        .map_err(|e| crypto_err(format!("failed to PEM-encode CSR: {e}")))?;

    Ok(SigningCsr {
        pem,
        spki_fingerprint,
    })
}

/// Shared by `certificate.rs`'s own DER-SPKI-based derivations would be redundant here --
/// this is a plain hex formatter, not the `pub(crate)` hex *decoder* `keychain.rs` already
/// exposes for the opposite direction (decoding a stored/typed hex string back to bytes).
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::request::CertReq as ParsedCertReq;

    const FIXED_SCALAR: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x46, 0x8a, 0xce, 0x13, 0x57, 0x9b,
        0xdf, 0x24,
    ];

    fn fixed_key() -> SigningKey {
        SigningKey::from_slice(&FIXED_SCALAR).expect("fixed scalar is a valid P-256 key")
    }

    #[test]
    fn builds_a_p256_csr_with_empty_attributes_and_ecdsa_sha256_self_signature() {
        let key = fixed_key();
        let csr = build_signing_csr(&key).unwrap();

        let parsed = der::pem::decode_vec(csr.pem.as_bytes())
            .map(|(_, der)| ParsedCertReq::try_from(der.as_slice()).unwrap())
            .unwrap();

        assert!(parsed.info.attributes.is_empty(), "CSR must carry no extensionRequest attribute -- a RequestBuilder-produced CSR always would");
        assert!(parsed.algorithm.oid == ECDSA_WITH_SHA256_OID);
        assert!(parsed.algorithm.parameters.is_none());

        // Self-signature verifies against the CSR's own embedded public key -- proving this
        // module produces something custodian's own preflight would actually accept, not
        // merely something that parses.
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::VerifyingKey;
        let info_der = parsed.info.to_der().unwrap();
        let sig = DerSignature::try_from(parsed.signature.raw_bytes()).unwrap();
        let vk =
            VerifyingKey::from_sec1_bytes(parsed.info.public_key.subject_public_key.raw_bytes())
                .unwrap();
        vk.verify(&info_der, &sig)
            .expect("CSR self-signature must verify");
    }

    #[test]
    fn fingerprint_matches_a_direct_sha256_of_the_der_spki() {
        let key = fixed_key();
        let csr = build_signing_csr(&key).unwrap();

        let spki_der = SubjectPublicKeyInfo::from_key(key.verifying_key())
            .unwrap()
            .to_der()
            .unwrap();
        let expected = hex_lower(&Sha256::digest(&spki_der));

        assert!(csr.spki_fingerprint == expected);
        assert!(csr.spki_fingerprint.len() == 64);
        assert!(csr
            .spki_fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint_differs_for_a_different_key() {
        let a = build_signing_csr(&fixed_key()).unwrap();
        let b = build_signing_csr(&generate_signing_key().unwrap()).unwrap();
        assert!(a.spki_fingerprint != b.spki_fingerprint);
    }

    /// ECDSA-with-SHA256 signing is deterministic (RFC 6979), so a fixed key must always
    /// produce byte-identical CSR PEM. **Round-D finding: an earlier version of this test
    /// called `build_signing_csr` twice and compared the two outputs to each other** -- since
    /// both calls run the identical current code, this can never fail regardless of what
    /// "silent encoding drift on a future dependency bump" (the stated purpose) would
    /// actually mean: it would only catch *non-determinism*, not drift. This version instead
    /// pins one specific, previously-generated PEM as a literal and compares against that --
    /// a real dependency-version bump that changed the encoding would now actually fail this
    /// test. (Regenerate the literal deliberately, not silently, if a dependency upgrade ever
    /// legitimately changes the encoding -- e.g. a new `x509-cert` version changing DER
    /// canonicalisation -- and say so in the commit that updates it.)
    #[test]
    fn csr_bytes_match_a_pinned_golden_value_for_a_fixed_key() {
        const GOLDEN_PEM: &str = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIHPMHgCAQAwFjEUMBIGA1UEAwwLcGxhY2Vob2xkZXIwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAAT2XCeLKoSMt1sQBELWPclfmYWVl/e3PKoJ1zhddw+Wnm7C3EQy\n\
jA/LiSO9bah1ycjNkBQD3n3ih2hG9Pfj8YRmoAAwCgYIKoZIzj0EAwIDRwAwRAIg\n\
R8gwgqaFuAkT5SC1Leh+wLLCT6evlqIcs0/OTKkE/HICIEVylf9zSjQLj3g+lLCa\n\
9N7KWePxo8Yk6sTH9Kw+NKD5\n\
-----END CERTIFICATE REQUEST-----\n";

        let csr = build_signing_csr(&fixed_key()).unwrap();
        assert!(
            csr.pem == GOLDEN_PEM,
            "CSR encoding changed for a fixed key -- if this is an intentional dependency \
             upgrade, regenerate GOLDEN_PEM deliberately and say so in the commit; got:\n{}",
            csr.pem
        );
    }

    /// **Cross-repo contract test (ADR-017 §3/§15): the fingerprint must match `veil-enrol`'s
    /// own algorithm byte-for-byte, verified against a real vendored `veil-enrol` fixture and
    /// an independent `openssl` computation -- not merely against this crate's own code
    /// computing the same thing twice.** Round-D finding: an earlier version of this test
    /// only recomputed the fingerprint locally from freshly-built SPKI bytes and compared
    /// that to `build_signing_csr`'s own output -- both sides used the identical encoding
    /// path, so it could never detect this crate's fingerprint convention silently
    /// diverging from `veil-enrol`'s.
    ///
    /// `VENDORED_VEIL_ENROL_CSR` is `veil-enrol/src/csr.rs`'s own `VALID_P256_CSR` test
    /// constant, copied verbatim (not regenerated) -- a real CSR that repo's own test suite
    /// asserts `validate_p256_signing_csr` accepts. `EXPECTED_FINGERPRINT` was computed
    /// independently via the exact `openssl` recipe `veil-enrol/docs/architecture.md`'s CSR
    /// handoff mechanism documents an operator running:
    /// `openssl req -in device.csr -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`.
    #[test]
    fn fingerprint_matches_a_vendored_veil_enrol_csr_and_an_independent_openssl_computation() {
        const VENDORED_VEIL_ENROL_CSR: &str =
            include_str!("../tests/fixtures/vendored_veil_enrol_csr.pem");
        const EXPECTED_FINGERPRINT: &str =
            "6ce585f48b65156c0e06bb2ff135774dda1bcd23f1332f7743d2defca0d9c1d7";

        let (_, der) = der::pem::decode_vec(VENDORED_VEIL_ENROL_CSR.as_bytes()).unwrap();
        let parsed = ParsedCertReq::try_from(der.as_slice()).unwrap();
        let spki_der = parsed.info.public_key.to_der().unwrap();
        let actual = hex_lower(&Sha256::digest(&spki_der));

        assert!(
            actual == EXPECTED_FINGERPRINT,
            "this crate's fingerprint convention has diverged from veil-enrol's own \
             csr_public_key_fingerprint -- got {actual}, expected {EXPECTED_FINGERPRINT}"
        );
    }
}
