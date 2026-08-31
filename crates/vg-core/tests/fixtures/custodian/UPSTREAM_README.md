# Signing-key contract fixtures (ADR-S)

Two kinds of fixture here, deliberately not the same kind of fixture:

## Shape fixtures

`issue-happy-path.json`, `issue-revoked-device.json`, `issue-bad-curve-csr.json`,
`lookup-happy-path.json`, `lookup-unknown-key-ref.json` — these assert **field names,
JSON types, enum tokens, and format regexes**, not byte-for-byte equality. Responses
carry certificate PEM, DER-derived fingerprints, and real timestamps
(`OffsetDateTime::now_utc()` in `src/ca/mod.rs`), so exact bytes are not reproducible
without an injectable clock this milestone does not build. Custodian's own handler
tests assert its real responses satisfy these shapes; a consuming repo vendors these
same files verbatim and asserts its own parsing/deserialization against them.

`veilgremlin` should vendor this whole directory into
`crates/vg-core/tests/fixtures/custodian/`, with a `FIXTURES_SOURCE` file pinning the
commit hash of this repo the fixtures were vendored from.

## Deterministic golden vector

`fixed-certificate.pem` is a real, checked-in P-256 self-signed certificate (fixed
bytes; regenerated once on 2026-08-30 during ADR-S's own adversarial review to
actually match the certificate profile ADR-S defines — `CA:FALSE`, Key Usage
`digitalSignature` only, Extended Key Usage the ADR-S placeholder OID
`1.3.6.1.4.1.55555.1.1.1` — the first version was `CA:TRUE` with no EKU at all, close
enough for the byte-exact hash test below but a bad template for anyone who copied it
as a real example). `key-ref-golden.json` records the value this ADR's `key_ref`
derivation (`sk_` + first 40 lowercase hex chars of SHA-256 over the certificate's DER
encoding) produces for that exact certificate. Unlike the shape fixtures, this **is** a
byte-for-byte assertion: both this repo and any consumer can independently compute
SHA-256 over the same fixed DER bytes and must arrive at the identical `key_ref`,
`sk_90875e5a4a9d72cfcffc23c73f3038c4aea76af0`. A mismatch here means the two repos'
derivation logic has diverged, not that a clock or serial number differs.

To regenerate the raw DER for verification: `openssl x509 -in fixed-certificate.pem
-outform der | openssl dgst -sha256 -r`. The first 40 hex characters of that digest,
prefixed `sk_`, must equal the value in `key-ref-golden.json`.

## Explicit scope correction from the original plan

The plan that produced this ADR also called for a second deterministic golden
vector — the ECDSA signing *preimage* (the canonical JSON of a telemetry envelope
with `signature: ""`), mirroring `veilgremlin`'s existing `edge_event_v1_golden.json`
pattern. That vector belongs to `veilgremlin`'s own envelope-canonicalisation code
(`crates/vg-core/src/telemetry/envelope.rs`), not to this API's contract — this repo
has no opinion on telemetry envelope shape, only on certificate issuance. It is
correctly a `veilgremlin`-side artifact, to be produced in that repo's own session
consuming this ADR, not fabricated here without access to the actual canonicalisation
code. Noted here so the omission reads as a deliberate scope correction, not a
dropped task.
