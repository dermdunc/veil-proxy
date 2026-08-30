//! Builds and HMAC-signs a `veil.edge_event.v1` wire record.
//!
//! **Wire shape.** The signed record is a JSON object with exactly two top-level keys:
//!
//! ```text
//! {
//!   "envelope": { ...Envelope's own Serialize impl, telemetry::envelope... },
//!   "edge_event": { ...EdgeEvent's own Serialize impl, telemetry::edge_event... }
//! }
//! ```
//!
//! `envelope.schema_version` is always the literal string `"veil.edge_event.v1"` for a
//! record built here (this module always constructs an `Envelope` with
//! `SchemaVersion::EdgeEventV1`); `envelope.integrity.algorithm` is always
//! `"HMAC_SHA_256"`, since [`sign_edge_event_record`] is the only production path that
//! builds a signed record and it only ever produces an HMAC. See `telemetry::envelope`
//! and `telemetry::edge_event` for the full field-by-field shape of each nested object.
//!
//! **Signing procedure**, mirroring how a verifier must check a received record:
//! 1. Build the record with `integrity.signature` set to an empty byte string (which
//!    serializes as `""`) — the field is present, not omitted, during MAC computation.
//! 2. Render that record as canonical JSON (`telemetry::canonical`).
//! 3. `signature = hex(HMAC-SHA256(key, canonical_json_bytes))`.
//! 4. Rebuild the record with the real `signature` in place, and re-render — *this*
//!    final canonical JSON is what actually goes on the wire.
//!
//! A verifier reverses this exactly: parse the record, read out `integrity.signature`,
//! replace it with `""` in place, re-canonicalize, recompute the HMAC with the same key,
//! and compare (constant-time) against the signature it read out.
//!
//! **Key sourcing**: `VEIL_RECEIPT_KEY`, a hex-encoded string of at least 32 bytes,
//! read via [`load_receipt_signing_key_from_env`]. `vg-vault`'s
//! `load_or_create_actor_pseudonym_key` (OS-keychain-backed) is the ratified precedent
//! for how a *real* per-device key should eventually be sourced — wiring the receipt
//! signing key through that same path is real, deliberately out-of-scope follow-up work
//! for this session, not a nonobvious gap: an env var is an accepted, documented scope
//! cut for now.
//!
//! TODO(follow-up): source the receipt signing key from the OS keychain via a
//! `vg-vault`-style loader, the same way `ActorPseudonymKey` is meant to be, instead of
//! `VEIL_RECEIPT_KEY`.

use hmac::{Hmac, Mac};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use super::canonical::{to_canonical_json, CanonicalizeError};
use super::edge_event::EdgeEvent;
use super::envelope::{Envelope, EnvelopeInvariantError, Integrity, SchemaVersion, SigningAlgorithm};
use super::ids::{DeviceRef, KeyRef, RecordId, TenantId};

type HmacSha256 = Hmac<Sha256>;

/// Minimum accepted key length, in bytes — 32 bytes (256 bits), matching HMAC-SHA256's
/// own output width and this crate's other keyed constructions
/// (`telemetry::pseudonymize::ActorPseudonymKey`).
pub const MIN_SIGNING_KEY_LEN: usize = 32;

/// The env var `load_receipt_signing_key_from_env` reads: a hex-encoded string of at
/// least [`MIN_SIGNING_KEY_LEN`] bytes.
pub const VEIL_RECEIPT_KEY_ENV_VAR: &str = "VEIL_RECEIPT_KEY";

/// A signing key for [`sign_edge_event_record`]. Security material, not a telemetry
/// *value* type — follows `ActorPseudonymKey`'s existing convention
/// (`telemetry::pseudonymize`) exactly: redacted `Debug`, zeroize-on-drop, no `Hash` (a
/// custom `Hasher` fed to a derived `Hash` impl would recover the raw bytes verbatim —
/// same reasoning as that type's own doc comment).
#[derive(PartialEq, Eq)]
pub struct ReceiptSigningKey(Vec<u8>);

impl ReceiptSigningKey {
    /// Enforces the [`MIN_SIGNING_KEY_LEN`] floor — never accepts a short key silently.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SigningError> {
        if bytes.len() < MIN_SIGNING_KEY_LEN {
            return Err(SigningError::KeyTooShort {
                min: MIN_SIGNING_KEY_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for ReceiptSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReceiptSigningKey")
            .field(&"<redacted>")
            .finish()
    }
}

impl Drop for ReceiptSigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Reads [`VEIL_RECEIPT_KEY_ENV_VAR`] from the process environment and parses it. Thin
/// wrapper around [`parse_receipt_signing_key`] so the parsing logic itself is testable
/// without mutating real process environment state (env var mutation across parallel
/// `cargo test` threads is a real flakiness source this crate avoids elsewhere too).
pub fn load_receipt_signing_key_from_env() -> Result<ReceiptSigningKey, SigningError> {
    let raw = match std::env::var(VEIL_RECEIPT_KEY_ENV_VAR) {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(SigningError::KeyEnvVarNotUnicode);
        }
    };
    parse_receipt_signing_key(raw)
}

/// The testable core of [`load_receipt_signing_key_from_env`]: given the raw env var
/// value (or `None` if unset), hex-decodes and length-checks it.
///
/// `pub(super)`, not private: `telemetry::emitter`'s own env-gating logic needs to parse
/// an already-read `VEIL_RECEIPT_KEY` value without re-reading the process environment
/// itself (the same parallel-`cargo test` flakiness reason this function was split out
/// from [`load_receipt_signing_key_from_env`] in the first place) -- kept `pub(super)`
/// rather than `pub` so no crate outside `vg-core` can call it directly, only siblings
/// inside `telemetry`.
pub(super) fn parse_receipt_signing_key(raw: Option<String>) -> Result<ReceiptSigningKey, SigningError> {
    let raw = raw.ok_or(SigningError::KeyEnvVarMissing)?;
    let bytes = super::hexutil::decode(raw.trim()).map_err(|_| SigningError::KeyNotHex)?;
    ReceiptSigningKey::from_bytes(bytes)
}

/// Why signing failed. Never panics, never emits an unsigned record silently — every
/// failure mode is a named, typed variant.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("{VEIL_RECEIPT_KEY_ENV_VAR} environment variable is not set")]
    KeyEnvVarMissing,
    #[error("{VEIL_RECEIPT_KEY_ENV_VAR} environment variable is not valid UTF-8")]
    KeyEnvVarNotUnicode,
    #[error("{VEIL_RECEIPT_KEY_ENV_VAR} is not a valid hex string")]
    KeyNotHex,
    #[error("signing key must be at least {min} bytes, got {got}")]
    KeyTooShort { min: usize, got: usize },
    #[error("envelope construction failed while signing: {0}")]
    Envelope(#[from] EnvelopeInvariantError),
    #[error("failed to canonicalize record for signing: {0}")]
    Canonicalize(#[from] CanonicalizeError),
}

/// Everything needed to build and sign one `veil.edge_event.v1` wire record, gathered
/// into one struct rather than a long parameter list: [`sign_edge_event_record`] needs
/// to construct an [`Envelope`] twice internally (once with a placeholder signature to
/// compute the MAC over, once with the real one), and a struct avoids two long argument
/// lists that must stay in lockstep (mirrors `Envelope::new`'s own
/// `#[allow(clippy::too_many_arguments)]` precedent, but for a call site invoked twice).
pub struct EdgeEventRecordInput {
    pub contract_revision: u32,
    pub record_id: RecordId,
    pub issued_at_us: u64,
    pub device_ref: Option<DeviceRef>,
    pub tenant_id: Option<TenantId>,
    pub sequence: u64,
    pub valid_until_us: u64,
    /// Caller-supplied — this session's scope is signing `integrity.signature`, not
    /// defining what `payload_sha256` covers or how it's computed (see
    /// `telemetry::envelope`'s own doc on that field being reserved for once real
    /// signing exists more broadly). Serialized verbatim as lowercase hex.
    pub payload_sha256: [u8; 32],
    pub nonce: [u8; 16],
    pub key_ref: Option<KeyRef>,
    pub edge_event: EdgeEvent,
}

/// The result of a successful [`sign_edge_event_record`] call.
pub struct SignedEdgeEventRecord {
    pub envelope: Envelope,
    pub edge_event: EdgeEvent,
    /// The exact canonical JSON string for the *signed* record (real `integrity.signature`
    /// embedded) — what actually goes on the wire.
    pub canonical_json: String,
    /// The same signature also available standalone, lowercase hex.
    pub signature_hex: String,
}

/// Combines an [`Envelope`] and an [`EdgeEvent`] into the two-key wire object described
/// in this module's doc comment. A thin `Serialize` wrapper only — reaches no private
/// field of either type, since both already implement `Serialize` themselves
/// (`telemetry::envelope`, `telemetry::edge_event`).
struct EdgeEventWireRecord<'a> {
    envelope: &'a Envelope,
    edge_event: &'a EdgeEvent,
}

impl Serialize for EdgeEventWireRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("EdgeEventWireRecord", 2)?;
        state.serialize_field("envelope", self.envelope)?;
        state.serialize_field("edge_event", self.edge_event)?;
        state.end()
    }
}

/// Builds and HMAC-SHA256-signs one `veil.edge_event.v1` record — see this module's own
/// doc comment for the exact wire shape and signing procedure.
pub fn sign_edge_event_record(
    input: EdgeEventRecordInput,
    key: &ReceiptSigningKey,
) -> Result<SignedEdgeEventRecord, SigningError> {
    let placeholder_integrity = Integrity::new(
        input.payload_sha256,
        input.nonce,
        SigningAlgorithm::HmacSha256,
        input.key_ref.clone(),
        Vec::new(),
    );
    let envelope_unsigned = Envelope::new(
        SchemaVersion::EdgeEventV1,
        input.contract_revision,
        input.record_id,
        input.issued_at_us,
        input.device_ref,
        input.tenant_id.clone(),
        input.sequence,
        input.valid_until_us,
        placeholder_integrity,
    )?;
    let canonical_unsigned = to_canonical_json(&EdgeEventWireRecord {
        envelope: &envelope_unsigned,
        edge_event: &input.edge_event,
    })?;

    let mac_bytes = compute_hmac(key, canonical_unsigned.as_bytes());
    let signature_hex = super::hexutil::encode(&mac_bytes);

    let final_integrity = Integrity::new(
        input.payload_sha256,
        input.nonce,
        SigningAlgorithm::HmacSha256,
        input.key_ref,
        mac_bytes.to_vec(),
    );
    let envelope_signed = Envelope::new(
        SchemaVersion::EdgeEventV1,
        input.contract_revision,
        input.record_id,
        input.issued_at_us,
        input.device_ref,
        input.tenant_id,
        input.sequence,
        input.valid_until_us,
        final_integrity,
    )?;
    let canonical_signed = to_canonical_json(&EdgeEventWireRecord {
        envelope: &envelope_signed,
        edge_event: &input.edge_event,
    })?;

    Ok(SignedEdgeEventRecord {
        envelope: envelope_signed,
        edge_event: input.edge_event,
        canonical_json: canonical_signed,
        signature_hex,
    })
}

fn compute_hmac(key: &ReceiptSigningKey, message: &[u8]) -> [u8; 32] {
    // `.expect(...)`: HMAC-SHA256 accepts a key of any length by construction (RFC
    // 2104) -- same justification `telemetry::pseudonymize::pseudonymize_actor` already
    // relies on for the identical call shape. `ReceiptSigningKey::from_bytes`'s own
    // `MIN_SIGNING_KEY_LEN` floor is a policy choice on top of that, not a requirement
    // `HmacSha256::new_from_slice` itself imposes.
    let mut mac =
        HmacSha256::new_from_slice(&key.0).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Destination;
    use crate::telemetry::ids::{ActorPseudonym, VersionToken};
    use uuid::Uuid;

    fn sample_input(edge_event: EdgeEvent) -> EdgeEventRecordInput {
        EdgeEventRecordInput {
            contract_revision: 1,
            record_id: RecordId::from(Uuid::nil()),
            issued_at_us: 1_700_000_000_000_000,
            device_ref: None,
            tenant_id: None,
            sequence: 0,
            valid_until_us: 1_700_000_300_000_000,
            payload_sha256: [0u8; 32],
            nonce: [0u8; 16],
            key_ref: None,
            edge_event,
        }
    }

    fn sample_key() -> ReceiptSigningKey {
        ReceiptSigningKey::from_bytes(vec![7u8; 32]).unwrap()
    }

    #[test]
    fn from_bytes_rejects_a_key_shorter_than_the_minimum() {
        let result = ReceiptSigningKey::from_bytes(vec![0u8; 31]);
        assert!(matches!(
            result,
            Err(SigningError::KeyTooShort { min: 32, got: 31 })
        ));
    }

    #[test]
    fn from_bytes_accepts_exactly_the_minimum() {
        assert!(ReceiptSigningKey::from_bytes(vec![0u8; 32]).is_ok());
    }

    #[test]
    fn debug_never_prints_the_key_bytes() {
        let k = ReceiptSigningKey::from_bytes(vec![0xABu8; 32]).unwrap();
        let debug_output = format!("{k:?}");
        assert!(!debug_output.contains("171")); // 0xAB decimal
        assert!(!debug_output.to_lowercase().contains(&"ab".repeat(32)));
        assert!(debug_output.contains("redacted"));
    }

    #[test]
    fn parse_receipt_signing_key_rejects_a_missing_value() {
        assert!(matches!(
            parse_receipt_signing_key(None),
            Err(SigningError::KeyEnvVarMissing)
        ));
    }

    #[test]
    fn parse_receipt_signing_key_rejects_non_hex() {
        assert!(matches!(
            parse_receipt_signing_key(Some("not-hex-zz".to_string())),
            Err(SigningError::KeyNotHex)
        ));
    }

    #[test]
    fn parse_receipt_signing_key_rejects_a_short_key() {
        // 30 hex chars = 15 bytes, below the 32-byte floor.
        let short = "00".repeat(15);
        assert!(matches!(
            parse_receipt_signing_key(Some(short)),
            Err(SigningError::KeyTooShort { min: 32, got: 15 })
        ));
    }

    #[test]
    fn parse_receipt_signing_key_accepts_a_valid_hex_key() {
        let valid = "ab".repeat(32);
        assert!(parse_receipt_signing_key(Some(valid)).is_ok());
    }

    #[test]
    fn sign_edge_event_record_produces_a_signature_that_verifies_by_recomputation() {
        let event = EdgeEvent::new_demask_decision(
            Destination::RemoteModelPrompt,
            ActorPseudonym::from_bytes([1u8; 32]),
            true,
            VersionToken::try_from("policy-v1").unwrap(),
        );
        let signed = sign_edge_event_record(sample_input(event), &sample_key()).unwrap();

        // Reproduce the verifier's side: parse the canonical JSON, strip the signature,
        // re-canonicalize, recompute, compare.
        let mut value: serde_json::Value = serde_json::from_str(&signed.canonical_json).unwrap();
        let original_signature = value["envelope"]["integrity"]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(original_signature, signed.signature_hex);
        value["envelope"]["integrity"]["signature"] = serde_json::json!("");
        let re_canonicalized = to_canonical_json(&value).unwrap();

        let recomputed = compute_hmac(&sample_key(), re_canonicalized.as_bytes());
        assert_eq!(super::super::hexutil::encode(&recomputed), original_signature);
    }

    #[test]
    fn sign_edge_event_record_is_deterministic_for_identical_input() {
        let event = || {
            EdgeEvent::new_demask_request(
                Destination::RemoteModelPrompt,
                ActorPseudonym::from_bytes([2u8; 32]),
            )
        };
        let a = sign_edge_event_record(sample_input(event()), &sample_key()).unwrap();
        let b = sign_edge_event_record(sample_input(event()), &sample_key()).unwrap();
        assert_eq!(a.canonical_json, b.canonical_json);
        assert_eq!(a.signature_hex, b.signature_hex);
    }

    #[test]
    fn sign_edge_event_record_signature_changes_with_the_key() {
        let event = || EdgeEvent::new_blocked_attempt(
            crate::telemetry::ids::ArtefactKindId::EnvFile,
            crate::telemetry::ids::ReasonCode::from(1),
        );
        let key_a = ReceiptSigningKey::from_bytes(vec![1u8; 32]).unwrap();
        let key_b = ReceiptSigningKey::from_bytes(vec![2u8; 32]).unwrap();
        let a = sign_edge_event_record(sample_input(event()), &key_a).unwrap();
        let b = sign_edge_event_record(sample_input(event()), &key_b).unwrap();
        assert_ne!(a.signature_hex, b.signature_hex);
    }
}
