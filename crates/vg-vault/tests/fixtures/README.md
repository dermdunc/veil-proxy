# Test fixtures for ADR-S certificate profile validation and the keychain loader

`wrong_key_usage.pem` / `wrong_eku.pem` / `client_auth_present.pem` / `ca_true.pem` /
`wrong_curve.pem` are used by `src/certificate.rs`'s own `#[cfg(test)]` module to prove
`validate_signing_certificate_pem` actually rejects a certificate that isn't the ADR-S
signing profile — not just that it accepts one that is (that positive case is already
covered by the vendored `crates/vg-core/tests/fixtures/custodian/fixed-certificate.pem`).
`ca_true.pem` and `wrong_curve.pem` were added in a doubt-driven-development review round
alongside the CA:FALSE and P-256-curve checks they exercise (see `certificate.rs`'s own
module doc for why both checks exist).

`loader_matching_certificate.pem` is used by `src/keychain.rs`'s
`device_signing_credential_env_seam_*` test — a real ADR-S-profile certificate whose
private key (hex, inline in that test, not checked in as its own file since only the test
needs it) actually matches it, to exercise `load_device_signing_credential`'s
public-key/certificate cross-check end to end, both when it should pass and when a
mismatched key is substituted.

All three share one P-256 keypair (irrelevant to what's under test — only the
certificate's own extensions are). Self-signed: this module never checks a certificate's
CA signature (see its own module doc for why), so a real custodian-issued chain isn't
needed to exercise these checks.

Regenerated with:

```
openssl ecparam -name prime256v1 -genkey -noout -out test_key.pem

# wrong_key_usage.pem — the mTLS profile's KU (DigitalSignature + KeyEncipherment),
# not the signing profile's (DigitalSignature only)
openssl req -new -x509 -key test_key.pem -days 3650 \
  -subj "/CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1" \
  -addext "subjectAltName=URI:urn:veil:device:dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -out wrong_key_usage.pem

# wrong_eku.pem — serverAuth instead of the ADR-S placeholder OID
openssl req -new -x509 -key test_key.pem -days 3650 \
  -subj "/CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=URI:urn:veil:device:dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -out wrong_eku.pem

# client_auth_present.pem — the correct ADR-S OID, but ClientAuth also present
openssl req -new -x509 -key test_key.pem -days 3650 \
  -subj "/CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1,clientAuth" \
  -addext "subjectAltName=URI:urn:veil:device:dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -out client_auth_present.pem

# ca_true.pem — otherwise the correct signing profile, but CA:TRUE
openssl req -new -x509 -key test_key.pem -days 3650 \
  -subj "/CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1" \
  -addext "subjectAltName=URI:urn:veil:device:dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -out ca_true.pem

# wrong_curve.pem — otherwise the correct signing profile, but P-384 instead of P-256
openssl ecparam -name secp384r1 -genkey -noout -out wrong_curve_key.pem
openssl req -new -x509 -key wrong_curve_key.pem -days 3650 \
  -subj "/CN=dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1" \
  -addext "subjectAltName=URI:urn:veil:device:dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  -out wrong_curve.pem
```

`basicConstraints=critical,CA:FALSE` is explicit everywhere except `ca_true.pem` (added
in a doubt-driven-development review round — an earlier version of these fixtures
omitted it, so `openssl req -x509`'s default of `CA:TRUE` slipped through unnoticed until
`certificate.rs` gained its own CA:FALSE check, at which point
`wrong_eku.pem`/`client_auth_present.pem` started failing for the wrong reason. The
vendored `veil-custodian` fixture's own `key-ref-golden.json` comment names `CA:TRUE` as
a defect that repo's adversarial review caught and fixed — matching that precedent here,
not inventing a new requirement).

`test_key.pem` itself is not checked in — none of the three tests needs the private key,
only the certificate.

`loader_matching_certificate.pem` was generated the same way, with its own fresh keypair:

```
openssl ecparam -name prime256v1 -genkey -noout -out loader_test_key.pem
openssl req -new -x509 -key loader_test_key.pem -days 3650 \
  -subj "/CN=dev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1" \
  -addext "subjectAltName=URI:urn:veil:device:dev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  -out loader_matching_certificate.pem

# Raw 32-byte P-256 scalar, hex, inlined directly in keychain.rs's test:
openssl ec -in loader_test_key.pem -noout -text \
  | sed -n '/priv:/,/pub:/p' | grep -v 'priv:\|pub:' | tr -d ' :\n'
```
