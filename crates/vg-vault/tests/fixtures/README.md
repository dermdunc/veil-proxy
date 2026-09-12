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

## `anchor_*.pem` — `src/anchor.rs`'s trust-anchor verification tests (ADR-017, XREPO-009)

Unlike the fixtures above, these are **not** self-signed -- `anchor.rs` exists specifically to
verify a leaf certificate's CA signature, so its tests need a real two-certificate chain.

```
# The anchor: a real CA, P-256, CN="Test Root CA"
openssl ecparam -name prime256v1 -genkey -noout -out anchor_ca_key.pem
openssl req -new -x509 -key anchor_ca_key.pem -days 3650 \
  -subj "/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -sha256 -out anchor_ca.pem

# anchor_leaf.pem — a leaf genuinely issued by the anchor above
openssl ecparam -name prime256v1 -genkey -noout -out anchor_leaf_key.pem
openssl req -new -key anchor_leaf_key.pem -subj "/CN=leaf" -out anchor_leaf.csr
openssl x509 -req -in anchor_leaf.csr -CA anchor_ca.pem -CAkey anchor_ca_key.pem \
  -CAcreateserial -days 365 -sha256 -out anchor_leaf.pem

# anchor_leaf_wrong_ca.pem / anchor_leaf_wrong_issuer_name.pem (same file, two names for two
# tests) — the identical leaf CSR, signed by a differently-named CA instead
openssl ecparam -name prime256v1 -genkey -noout -out other_ca_key.pem
openssl req -new -x509 -key other_ca_key.pem -days 3650 \
  -subj "/CN=Unrelated CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -sha256 -out other_ca.pem
openssl x509 -req -in anchor_leaf.csr -CA other_ca.pem -CAkey other_ca_key.pem \
  -CAcreateserial -days 365 -sha256 -out anchor_leaf_wrong_ca.pem
cp anchor_leaf_wrong_ca.pem anchor_leaf_wrong_issuer_name.pem

# anchor_leaf_rsa_signed.pem — an RSA CA whose SUBJECT NAME COLLIDES with the real anchor's
# ("CN=Test Root CA") but signs with RSA, isolating the algorithm-gate check (§`anchor.rs`)
# from the issuer-name-chaining check: this leaf passes name-chaining against the real
# `anchor_ca.pem`, then must be rejected for its signature algorithm specifically.
openssl genrsa -out rsa_ca_key.pem 2048
openssl req -new -x509 -key rsa_ca_key.pem -days 3650 \
  -subj "/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -sha256 -out rsa_ca_name_collision.pem
openssl x509 -req -in anchor_leaf.csr -CA rsa_ca_name_collision.pem -CAkey rsa_ca_key.pem \
  -CAcreateserial -days 365 -sha256 -out anchor_leaf_rsa_signed.pem

# anchor_non_ca.pem — a self-signed, CA:FALSE certificate, used as a deliberately-wrong
# `--ca-cert` to prove the anchor-sanity check runs before any leaf/anchor relationship check
openssl ecparam -name prime256v1 -genkey -noout -out non_ca_key.pem
openssl req -new -x509 -key non_ca_key.pem -days 3650 \
  -subj "/CN=Not A CA" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -sha256 -out anchor_non_ca.pem

# anchor_leaf_tampered.pem — anchor_leaf.pem with one byte flipped inside its TBSCertificate
# (offset 20, well within the version/serial-number region, far from the outer
# AlgorithmIdentifier/signature BIT STRING). Issuer/subject/algorithm all still parse
# correctly; only the signature fails -- proving `anchor.rs` reports this as a *signature*
# failure, not a parse failure (the same empirical-confirmation discipline
# `veil-enrol/src/csr.rs`'s own tests use). Not reproducible with a single openssl
# invocation -- generated with a short Python script that base64-decodes the PEM, flips
# `der[20] ^= 0xFF`, and re-encodes; verified afterward with
# `openssl verify -CAfile anchor_ca.pem anchor_leaf_tampered.pem` failing with exactly
# "certificate signature failure", not a parse error.
```

None of the six private keys generated above are checked in — no test needs them; only the
certificates (and the original `anchor_leaf.csr`, also not checked in, reused across three of
the fixtures above so they share one leaf keypair/identity and differ only in *who signed
them*).

## `enrol_*` — `src/enrol.rs`'s install state-machine tests (ADR-017, XREPO-009)

A real CA plus two *ADR-S-profile* leaves it issued (unlike `anchor_*.pem` above, these must
pass both `certificate.rs`'s profile check and `anchor.rs`'s CA verification, since `enrol.rs`
runs both). Each leaf's own private key is checked in as a raw hex scalar — `enrol.rs`'s tests
need to install a *specific* known key, not merely a certificate.

```
openssl ecparam -name prime256v1 -genkey -noout -out enrol_ca_key.pem
openssl req -new -x509 -key enrol_ca_key.pem -days 3650 \
  -subj "/CN=Enrol Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -sha256 -out enrol_ca.pem

# One extension file per device pseudonym (openssl req -x509's -addext can't be combined
# with -req/-CA the way the anchor_*.pem fixtures above didn't need ADR-S extensions at all)
cat > leaf_a.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=1.3.6.1.4.1.55555.1.1.1
subjectAltName=URI:urn:veil:device:dev_cccccccccccccccccccccccccccccccc
EOF
# leaf_b.ext identical, with dev_dddd...dddd instead

openssl ecparam -name prime256v1 -genkey -noout -out leaf_a_key.pem
openssl req -new -key leaf_a_key.pem -subj "/CN=dev_cccccccccccccccccccccccccccccccc" -out leaf_a.csr
openssl x509 -req -in leaf_a.csr -CA enrol_ca.pem -CAkey enrol_ca_key.pem -CAcreateserial \
  -days 365 -sha256 -extfile leaf_a.ext -out enrol_leaf_a.pem

# enrol_leaf_a_reissued.pem — the SAME CSR (same key, same SPKI) signed a SECOND time, giving
# a certificate with a different serial/DER but an identical public key -- reproducing
# `veil-custodian`'s actual repeat-issuance behavior (`src/ca/mod.rs:1608-1646`), which is
# exactly the case `enrol.rs`'s DER-vs-SPKI classification (ADR-017 §3/§6) exists to get
# right: SPKI equality is not certificate identity. A `sleep 1` between the two signings
# ensures a different `notBefore` as well as serial, so the two DERs differ for more than one
# reason.
sleep 1
openssl x509 -req -in leaf_a.csr -CA enrol_ca.pem -CAkey enrol_ca_key.pem -CAcreateserial \
  -days 365 -sha256 -extfile leaf_a.ext -out enrol_leaf_a_reissued.pem

# leaf_b generated identically, with its own key/CSR/leaf_b.ext -- a genuinely different key,
# for the "different certificate, different key entirely" scenarios.

openssl ec -in leaf_a_key.pem -noout -text \
  | sed -n '/priv:/,/pub:/p' | grep -v 'priv:\|pub:' | tr -d ' :\n' > enrol_leaf_a_key_hex.txt
# enrol_leaf_b_key_hex.txt generated identically from leaf_b_key.pem
```

Verified afterward: `openssl verify -CAfile enrol_ca.pem enrol_leaf_a.pem` / `_a_reissued.pem`
/ `_b.pem`, all `OK`; `diff <(openssl x509 -in enrol_leaf_a.pem -pubkey -noout) <(openssl x509
-in enrol_leaf_a_reissued.pem -pubkey -noout)` empty (same SPKI); `cmp enrol_leaf_a.pem
enrol_leaf_a_reissued.pem` reports a difference (different DER). Neither CA key nor any leaf's
PEM private key is checked in — only `enrol_ca.pem`, the three leaf certificates, and the two
raw hex scalars (`enrol_leaf_a_reissued.pem` shares `enrol_leaf_a_key_hex.txt`'s key).

## `vendored_veil_enrol_csr.pem` — `src/csr.rs`'s cross-repo fingerprint contract test

`veil-enrol/src/csr.rs`'s own `VALID_P256_CSR` test constant, copied verbatim (not
regenerated) — a real CSR that repo's own test suite (`accepts_a_real_p256_csr`) asserts
`validate_p256_signing_csr` accepts. Used to prove `vg-vault`'s SPKI-fingerprint convention
matches `veil-enrol`'s `csr_public_key_fingerprint` byte-for-byte, against a real fixture from
that repo rather than only this crate's own code computing the same thing twice.

The expected fingerprint pinned in the test was computed independently via the exact `openssl`
recipe `veil-enrol/docs/architecture.md`'s CSR handoff mechanism documents an operator running:

```
openssl req -in vendored_veil_enrol_csr.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER | sha256sum
# 6ce585f48b65156c0e06bb2ff135774dda1bcd23f1332f7743d2defca0d9c1d7
```
