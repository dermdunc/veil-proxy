//! [`Envelope`] — the fields every telemetry record carries regardless of payload kind,
//! plus [`Integrity`], the signing block. Per
//! `docs/architecture/telemetry-receipt-reconciliation-plan.md` §3.2: deliberately no
//! `lane` field — the record kind (`Receipt`/`Alert`/`EdgeEvent`, see `telemetry::mod`'s
//! `TelemetryEvent` enum) already implies the delivery lane; a separate flag would let
//! one lane's payload drift toward the other's shape, which is exactly the collapse the
//! ratified design forbids.
//!
//! No `Debug` derives here (`docs/architecture/implementation-plan.md:137`) — see
//! `telemetry::ids`'s module doc for why.

use thiserror::Error;

use super::ids::{DeviceRef, KeyRef, RecordId, TenantId};

/// Which payload kind an envelope wraps, mirrored on the wire as the generated schema's
/// `schema_version` const. Redundant with `TelemetryEvent`'s own variant tag in-memory
/// today, since no wire serialization exists yet (`telemetry::mod`'s module doc) — kept
/// because the eventual generated JSON Schema needs a concrete const per contract-shape
/// change (reconciliation plan §3.4), and `Integrity::payload_sha256` must cover it once
/// real signing exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SchemaVersion {
    ReceiptV2,
    AlertV1,
    EdgeEventV1,
}

/// Why `Envelope::new` rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EnvelopeInvariantError {
    #[error("valid_until_us ({valid_until_us}) must be after issued_at_us ({issued_at_us})")]
    ValidUntilNotAfterIssuedAt {
        issued_at_us: u64,
        valid_until_us: u64,
    },
    /// A fourth adversarial review round found the freshness check enforced only the
    /// harmless direction (`valid_until_us` in the past) and left the dangerous one —
    /// `valid_until_us` arbitrarily far in the future, an effectively unbounded replay
    /// window — completely open, defeating the ratified Q3 "short, fixed 5-minute
    /// window" this field exists to carry.
    #[error(
        "valid_until_us - issued_at_us ({window_us}us) exceeds the maximum allowed \
         window ({max_window_us}us)"
    )]
    WindowTooWide { window_us: u64, max_window_us: u64 },
}

/// Generous upper bound on `valid_until_us - issued_at_us`: 30 minutes. Not the ratified
/// Q3 window itself (a "short, fixed 5 minutes") — enforcing that exact figure is the
/// ingest/consumer's job per the ratified design (`envelope.rs`'s own `Envelope::new`
/// doc), not this constructor's. This is a sanity ceiling with slack, catching the
/// unbounded case (`u64::MAX`) and gross misconfiguration without hard-coding a policy
/// value this type doesn't own.
const MAX_VALIDITY_WINDOW_US: u64 = 30 * 60 * 1_000_000;

/// Fields carried by every telemetry record, independent of payload kind. All fields
/// private; constructed only via `pub(crate) fn new`, used by `TelemetryEvent`'s own
/// (currently all-rejecting) conversion path and this module's tests.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    schema_version: SchemaVersion,
    contract_revision: u32,
    record_id: RecordId,
    /// Epoch microseconds. `vg-core` has no timestamp source of its own (no
    /// `chrono`/`time` dependency) — the caller supplies this; `vg-core` never reads
    /// the clock itself.
    issued_at_us: u64,
    /// `None` until `veil-custodian`'s enrolment registry exists (ratified Q1).
    device_ref: Option<DeviceRef>,
    /// Always `None` in v1 — ratified Q2 targets per-laptop enrolment only.
    tenant_id: Option<TenantId>,
    /// Monotonic per device, replay defence.
    sequence: u64,
    /// Epoch microseconds — explicit freshness window (ratified Q3: a short, fixed
    /// 5-minute replay window for both lanes).
    valid_until_us: u64,
    integrity: Integrity,
}

impl Envelope {
    /// Two checks on `valid_until_us` relative to `issued_at_us`:
    /// - Must be strictly after it (a second review round found this direction
    ///   unchecked — the ratified Q3 replay window was only documented).
    /// - Must not exceed [`MAX_VALIDITY_WINDOW_US`] beyond it (a fourth review round
    ///   found the first check alone left the dangerous direction — an arbitrarily wide
    ///   or unbounded window — completely open; `valid_until_us <= issued_at_us` catches
    ///   nothing that direction).
    ///
    /// Neither check hard-codes the ratified Q3 figure itself ("a short, fixed 5
    /// minutes"); enforcing that precise window is the ingest/consumer's job per the
    /// ratified design, not this constructor's.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        schema_version: SchemaVersion,
        contract_revision: u32,
        record_id: RecordId,
        issued_at_us: u64,
        device_ref: Option<DeviceRef>,
        tenant_id: Option<TenantId>,
        sequence: u64,
        valid_until_us: u64,
        integrity: Integrity,
    ) -> Result<Self, EnvelopeInvariantError> {
        if valid_until_us <= issued_at_us {
            return Err(EnvelopeInvariantError::ValidUntilNotAfterIssuedAt {
                issued_at_us,
                valid_until_us,
            });
        }
        let window_us = valid_until_us - issued_at_us;
        if window_us > MAX_VALIDITY_WINDOW_US {
            return Err(EnvelopeInvariantError::WindowTooWide {
                window_us,
                max_window_us: MAX_VALIDITY_WINDOW_US,
            });
        }
        Ok(Self {
            schema_version,
            contract_revision,
            record_id,
            issued_at_us,
            device_ref,
            tenant_id,
            sequence,
            valid_until_us,
            integrity,
        })
    }

    /// Read back which payload kind this envelope was stamped for — used by
    /// `TelemetryEvent`'s per-kind constructors to reject a mismatched pairing (a
    /// fourth adversarial review round found nothing coupled `Envelope::schema_version`
    /// to the `TelemetryEvent` variant it accompanies, despite this module's own stated
    /// design rationale against exactly that kind of drift).
    pub(crate) fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }
}

/// Signing algorithm, closed enum — matches `veil-observatory`'s existing
/// `veil.receipt.v1.schema.json` `integrity.algorithm` enum
/// (`ECDSA_SHA_256`/`HMAC_SHA_256`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    EcdsaSha256,
    HmacSha256,
}

/// The signing block (ratified Q3: custodian-issued device key, minted at enrolment;
/// short fixed 5-minute replay window carried on `Envelope::valid_until_us` rather than
/// here). All fields fixed-width or closed except `signature`, whose length genuinely
/// varies between ECDSA and HMAC.
#[derive(Clone, PartialEq, Eq)]
pub struct Integrity {
    payload_sha256: [u8; 32],
    nonce: [u8; 16],
    algorithm: SigningAlgorithm,
    key_ref: Option<KeyRef>,
    signature: Vec<u8>,
}

impl Integrity {
    pub(crate) fn new(
        payload_sha256: [u8; 32],
        nonce: [u8; 16],
        algorithm: SigningAlgorithm,
        key_ref: Option<KeyRef>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            payload_sha256,
            nonce,
            algorithm,
            key_ref,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::ids::RecordId;
    use uuid::Uuid;

    fn sample_integrity() -> Integrity {
        Integrity::new(
            [0u8; 32],
            [0u8; 16],
            SigningAlgorithm::HmacSha256,
            None,
            vec![0u8; 32],
        )
    }

    #[test]
    fn envelope_constructs_with_all_fields_private() {
        let env = Envelope::new(
            SchemaVersion::ReceiptV2,
            1,
            RecordId::from(Uuid::nil()),
            0,
            None,
            None,
            0,
            300_000_000, // +5 minutes, matching the ratified Q3 replay window
            sample_integrity(),
        )
        .unwrap();
        // Only `schema_version()` is readable back (`pub(crate)`, used by
        // `TelemetryEvent`'s per-kind constructors); everything else has no accessor
        // and no Debug. This proves construction, PartialEq, and the one accessor work
        // end-to-end for a fully-populated envelope.
        assert!(env == env.clone());
        assert!(env.schema_version() == SchemaVersion::ReceiptV2);
    }

    #[test]
    fn envelope_rejects_a_validity_window_wider_than_the_sanity_ceiling() {
        let result = Envelope::new(
            SchemaVersion::ReceiptV2,
            1,
            RecordId::from(Uuid::nil()),
            0,
            None,
            None,
            0,
            u64::MAX, // an effectively unbounded replay window
            sample_integrity(),
        );
        assert!(matches!(
            result,
            Err(EnvelopeInvariantError::WindowTooWide { .. })
        ));
    }

    #[test]
    fn envelope_rejects_valid_until_at_or_before_issued_at() {
        let at_issued = Envelope::new(
            SchemaVersion::ReceiptV2,
            1,
            RecordId::from(Uuid::nil()),
            1_000,
            None,
            None,
            0,
            1_000,
            sample_integrity(),
        );
        assert!(
            at_issued
                == Err(EnvelopeInvariantError::ValidUntilNotAfterIssuedAt {
                    issued_at_us: 1_000,
                    valid_until_us: 1_000,
                })
        );

        let before_issued = Envelope::new(
            SchemaVersion::ReceiptV2,
            1,
            RecordId::from(Uuid::nil()),
            1_000,
            None,
            None,
            0,
            999,
            sample_integrity(),
        );
        assert!(before_issued.is_err());
    }
}
