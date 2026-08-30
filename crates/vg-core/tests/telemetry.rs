//! Integration tests for `vg_core::telemetry`. Mirrors the idiom in
//! `crates/vg-audit/tests/sink.rs` (`one_of_each_variant` + adversarial-input tables),
//! adapted to this crate's own `AuditEvent` — `vg-core` does not depend on `vg-audit`.
//!
//! No `format!("{:?}", ...)` anywhere in this file: `telemetry`'s data types
//! deliberately don't derive `Debug` (`docs/architecture/implementation-plan.md:137`,
//! see `vg_core::telemetry`'s module doc) — comparisons here use `assert!(a == b)`
//! rather than `assert_eq!`/`assert_ne!` wherever the compared type lacks `Debug`
//! (`assert_eq!`/`assert_ne!` require it even on the passing path, for their failure
//! message). `TelemetryReject` and the `*Error` types keep `Debug` (required by
//! `thiserror`/`std::error::Error`, and safe — every field is a static label), so
//! `assert_eq!`/`assert_ne!` remain used for those.

use uuid::Uuid;
use vg_core::telemetry::{
    sign_edge_event_record, ActorPseudonymKey, AlertRuleId, ArtefactKindId, DetectorSetId,
    DeviceRef, DeviceRefError, EdgeEvent, EdgeEventRecordInput, EntityClassId, ExceptionRuleId,
    KeyRef, ReceiptSigningKey, RecordId, RegistryRef, TelemetryEvent, TelemetryReject, TenantId,
    VersionToken,
};
use vg_core::{
    conformance::assert_telemetry_token_rejects_raw_value, ActorId, ArtefactKind, AuditEvent,
    Destination, EntityCounts, EntityType, HandlingClass, MappingRef,
};

/// Extracts the `Err` side of a `TryFrom<&AuditEvent>` result without requiring the
/// `Ok` type (`TelemetryEvent`) to implement `Debug` — `Result::unwrap_err` requires it
/// anyway (for its own unreachable-panic message), and `TelemetryEvent` deliberately
/// doesn't implement `Debug` (`docs/architecture/implementation-plan.md:137`).
fn expect_reject(result: Result<TelemetryEvent, TelemetryReject>) -> TelemetryReject {
    match result {
        Err(reject) => reject,
        Ok(_) => panic!("expected TryFrom<&AuditEvent> to reject, it succeeded"),
    }
}

/// One instance of each of `AuditEvent`'s six variants, deliberately loaded with the
/// same kind of data-bearing corners `vg-audit/tests/sink.rs:27-58`'s
/// `one_of_each_variant` uses: `EntityType::Custom`, `ArtefactKind::SourceCode`, a
/// hard-deny `Destination`.
fn one_of_each_audit_variant() -> Vec<AuditEvent> {
    let mut counts = EntityCounts::default();
    counts.0.insert(
        EntityType::Custom("internal-project-codename".to_string()),
        1,
    );

    vec![
        AuditEvent::Scan {
            counts,
            detector_version: "detectors-v1".to_string(),
            latency_us: 1_200,
        },
        AuditEvent::PolicyDecision {
            artefact: ArtefactKind::SourceCode("rust".to_string()),
            class: HandlingClass::Mask,
            policy_version: "policy-v1".to_string(),
        },
        AuditEvent::MappingCreated {
            mapping_ref: MappingRef(Uuid::nil()),
            entity_type: EntityType::Email,
        },
        AuditEvent::Block {
            artefact: ArtefactKind::EnvFile,
            reason: "policy rule prod-secrets-001".to_string(),
        },
        AuditEvent::DemaskRequest {
            dest: Destination::RemoteModelPrompt,
            actor: ActorId("jane.doe".to_string()),
        },
        AuditEvent::DemaskDecision {
            dest: Destination::ObservabilitySink,
            actor: ActorId("jane.doe".to_string()),
            allowed: false,
            policy_version: "policy-v1".to_string(),
        },
    ]
}

/// Locks in the reject table from `telemetry::mod`'s `TryFrom<&AuditEvent>` — every
/// current `AuditEvent` variant rejects, with a *specific* reason, not just "is an
/// error". This is what forces a deliberate test update (not a silent pass) the moment
/// any arm changes to `Ok` once the aggregator or actor pseudonymization lands.
#[test]
fn all_audit_variants_currently_reject_with_the_expected_reason() {
    let events = one_of_each_audit_variant();
    let expected: Vec<TelemetryReject> = vec![
        TelemetryReject::RequiresAggregation { variant: "Scan" },
        TelemetryReject::RequiresAggregation {
            variant: "PolicyDecision",
        },
        TelemetryReject::DeferredByDefault {
            variant: "MappingCreated",
            decision_ref: "Q8",
        },
        // The fixture's Block reason ("policy rule prod-secrets-001", below) is
        // deliberately unrecognized by `telemetry::block_reason`'s registry, so this
        // arm's own reason-classification check (added as a doubt-driven-development
        // fix -- see `mod.rs`'s `Block` arm) reports `UnrecognizedReason`, not
        // `RequiresEnvelopeConstruction`. The latter is only ever returned for a
        // *recognized* reason -- see
        // `edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose`
        // below for that case.
        TelemetryReject::UnrecognizedReason {
            variant: "Block",
            field: "reason",
            reason: "no registered BlockReason matched this AuditEvent::Block.reason string",
        },
        TelemetryReject::RequiresActorPseudonymization {
            variant: "DemaskRequest",
        },
        TelemetryReject::RequiresActorPseudonymization {
            variant: "DemaskDecision",
        },
    ];

    assert_eq!(
        events.len(),
        expected.len(),
        "test table itself is out of sync"
    );

    for (index, (event, want)) in events.iter().zip(expected.iter()).enumerate() {
        let got = TelemetryEvent::try_from(event);
        // Not `{event:?}` in the failure message: this fixture deliberately loads
        // `EntityType::Custom("internal-project-codename")` and `ActorId("jane.doe")`
        // (see `one_of_each_audit_variant` above) to exercise the leak paths those
        // types are designed to close — printing `AuditEvent`'s `Debug` here would
        // render them into CI logs on a test failure, contradicting this file's own
        // header and the project's stated `EntityType` convention
        // (`crates/vg-core/src/types.rs`: "`{:?}` is deliberately left leaking the
        // name"). A fourth adversarial review round caught this. Report the index
        // instead.
        assert_eq!(
            got.as_ref().err(),
            Some(want),
            "unexpected conversion outcome for events[{index}]"
        );
    }
}

/// Negative control, strengthened after doubt-driven-development review flagged the
/// original version as trivially true (any two distinct enum *variants* are unequal by
/// construction, regardless of whether their underlying reasons are meaningfully
/// related). This version checks both directions: `Scan` and `PolicyDecision` share the
/// same rejection *category* (`RequiresAggregation`) — checked with `matches!`, not
/// equality, since each also carries a distinct `variant: &'static str` (the source
/// `AuditEvent` variant name) that makes literal equality impossible even within the
/// same category — while `Scan` and `MappingCreated` are genuinely different categories
/// and must not match. Together these prove the categorisation groups correctly, not
/// just that variants differ.
#[test]
fn the_reject_categories_group_correctly() {
    let scan = AuditEvent::Scan {
        counts: EntityCounts::default(),
        detector_version: "detectors-v1".to_string(),
        latency_us: 0,
    };
    let policy_decision = AuditEvent::PolicyDecision {
        artefact: ArtefactKind::EnvFile,
        class: HandlingClass::Mask,
        policy_version: "policy-v1".to_string(),
    };
    let mapping = AuditEvent::MappingCreated {
        mapping_ref: MappingRef(Uuid::nil()),
        entity_type: EntityType::Email,
    };

    // Not `.unwrap_err()`: `Result::unwrap_err` requires the *Ok* type to implement
    // `Debug` too (for its own unreachable-panic message), and `TelemetryEvent`
    // deliberately doesn't (`docs/architecture/implementation-plan.md:137`) —
    // `expect_reject` (defined above) extracts the `Err` side without that bound.
    let scan_reject = expect_reject(TelemetryEvent::try_from(&scan));
    let policy_decision_reject = expect_reject(TelemetryEvent::try_from(&policy_decision));
    let mapping_reject = expect_reject(TelemetryEvent::try_from(&mapping));

    assert!(
        matches!(scan_reject, TelemetryReject::RequiresAggregation { .. }),
        "Scan should require aggregation, got {scan_reject:?}"
    );
    assert!(
        matches!(
            policy_decision_reject,
            TelemetryReject::RequiresAggregation { .. }
        ),
        "PolicyDecision should require aggregation, got {policy_decision_reject:?}"
    );
    assert_ne!(
        scan_reject, mapping_reject,
        "Scan and MappingCreated reject for genuinely different, distinguishable reasons"
    );
}

#[test]
fn token_constructors_reject_adversarial_input() {
    let adversarial = [
        "",
        "jane.doe@example.com",
        "has spaces",
        "has\nnewline",
        "has\ttab",
        "ÜNICODE",
        &"a".repeat(65),
    ];
    // `VersionToken` is checked separately, without `""`: a fourth adversarial review
    // round found it legitimately accepts an empty string, matching
    // `vg-policy/src/config.rs`'s real, shipped validator exactly (no `is_empty()`
    // check there either) — including it in the shared corpus would assert a rejection
    // that's no longer correct.
    let adversarial_non_empty = [
        "jane.doe@example.com",
        "has spaces",
        "has\nnewline",
        "has\ttab",
        "ÜNICODE",
        &"a".repeat(65),
    ];

    // Wrapped in closures, not passed as bare `T::try_from` function items: rustc's
    // trait solver doesn't reliably generalise the HRTB `for<'a> Fn(&'a str) -> ...`
    // bound the helper requires when `TryFrom`'s associated `Error` type is in play —
    // a closure gets its signature inferred fresh at each call site instead.
    assert_telemetry_token_rejects_raw_value(|s| VersionToken::try_from(s), &adversarial_non_empty);
    assert_telemetry_token_rejects_raw_value(|s| DetectorSetId::try_from(s), &adversarial);
    assert_telemetry_token_rejects_raw_value(|s| ExceptionRuleId::try_from(s), &adversarial);
    assert_telemetry_token_rejects_raw_value(|s| TenantId::try_from(s), &adversarial);
    assert_telemetry_token_rejects_raw_value(|s| AlertRuleId::try_from(s), &adversarial);
    // `KeyRef`/`RegistryRef` were missing from this table entirely — a second
    // doubt-driven-development round found two of the seven bounded-token types had no
    // adversarial-input coverage at all.
    assert_telemetry_token_rejects_raw_value(|s| KeyRef::try_from(s), &adversarial);
    assert_telemetry_token_rejects_raw_value(|s| RegistryRef::try_from(s), &adversarial);
}

/// Negative control for the helper above: proves it actually distinguishes conforming
/// from non-conforming input, not just that every input happens to fail.
#[test]
fn token_constructors_accept_conforming_input() {
    assert!(VersionToken::try_from("policy-v3.1").is_ok());
    assert!(DetectorSetId::try_from("detectors-2026.08").is_ok());
    assert!(ExceptionRuleId::try_from("exception-rule-001").is_ok());
    assert!(TenantId::try_from("org-123").is_ok());
    assert!(AlertRuleId::try_from("secret-in-prompt").is_ok());
    assert!(KeyRef::try_from("device-key-001").is_ok());
    assert!(RegistryRef::try_from("acme-corp-backend").is_ok());
}

#[test]
fn detector_set_id_accepts_the_real_multi_detector_join_format() {
    // `crates/vg-core/src/api.rs`'s `detector_version` joins sorted detector ids with
    // `+` (e.g. `email+entropy+ip`) — a second doubt-driven-development round found the
    // shared token charset rejected `+`, which would have made every real multi-detector
    // scan's `detector_version` unconvertible once `Controls::detector_version` is wired
    // up.
    assert!(DetectorSetId::try_from("email+entropy+ip").is_ok());
    assert!(DetectorSetId::try_from("email").is_ok());
    // `VersionToken` doesn't need `+` and should still reject it — proves the
    // per-type charset actually varies, not a blanket widening of every token type.
    assert!(VersionToken::try_from("a+b").is_err());
}

#[test]
fn device_ref_rejects_wrong_length() {
    assert!(DeviceRef::try_from([0u8; 16].as_slice()).is_ok());
    for len in [0usize, 1, 8, 15, 17, 32] {
        assert!(
            DeviceRef::try_from(vec![0u8; len].as_slice()) == Err(DeviceRefError::WrongLength(len))
        );
    }
}

#[test]
fn entity_class_id_collapses_custom_dictionary_names() {
    let ty = EntityType::Custom("acme-project-titan-codenames".to_string());
    let class = EntityClassId::from(&ty);
    // No `format!("{class:?}")` check (no Debug on `EntityClassId`, per this crate's
    // own rule) — the guarantee is structural: `Custom` is a unit variant, so there is
    // no representation, Debug or otherwise, that could carry the dictionary name.
    assert!(class == EntityClassId::Custom);
}

#[test]
fn artefact_kind_id_collapses_source_code_language_names() {
    let kind = ArtefactKind::SourceCode("python".to_string());
    let class = ArtefactKindId::from(&kind);
    assert!(class == ArtefactKindId::SourceCode);
}

// -- EdgeEvent::try_from_audit_event --

/// `EdgeEvent::try_from_audit_event` is a second conversion entry point (has an actor
/// key, `TryFrom<&AuditEvent>` never does), but must reject every variant it cannot
/// itself resolve for exactly the same reason `TryFrom<&AuditEvent>` already does — a
/// direct consistency check between the two entry points, not just independent coverage
/// of each.
///
/// `Block` is excluded from this generic loop, not because the two entry points always
/// disagree on it (for `one_of_each_audit_variant`'s specific unrecognized-reason
/// fixture, they actually still match — both now report `UnrecognizedReason`), but
/// because they diverge for a *recognized* reason specifically (`try_from_audit_event`
/// resolves it for real; the frozen `TryFrom` still can't, for an unrelated reason —
/// envelope construction), and coupling this generic loop to which case the shared
/// fixture happens to exercise would be fragile. See
/// `edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose`
/// below for the recognized-reason divergence stated explicitly, and
/// `edge_event_block_rejects_an_unrecognized_reason_string` for the unrecognized case
/// (where the two entry points do, in fact, still agree).
#[test]
fn edge_event_matches_try_from_reject_reasons_for_variants_it_cannot_resolve() {
    let key = ActorPseudonymKey::from_bytes([9u8; 32]);
    for event in one_of_each_audit_variant() {
        if matches!(
            event,
            AuditEvent::DemaskRequest { .. }
                | AuditEvent::DemaskDecision { .. }
                | AuditEvent::Block { .. }
        ) {
            continue;
        }
        let want = expect_reject(TelemetryEvent::try_from(&event));
        let got = match EdgeEvent::try_from_audit_event(&event, &key) {
            Err(reject) => reject,
            Ok(_) => panic!(
                "expected EdgeEvent::try_from_audit_event to reject Scan/PolicyDecision/MappingCreated"
            ),
        };
        assert_eq!(got, want);
    }
}

/// The asymmetry the test above deliberately carves out, stated explicitly rather than
/// left implicit: `try_from_audit_event` resolves a *recognized* `Block` reason to
/// `Ok`, while the frozen, keyless `TryFrom<&AuditEvent>` rejects the identical event —
/// not because the two disagree about the reason dictionary, but because the frozen
/// path additionally needs `Envelope`/`Integrity` construction (still custodian-blocked)
/// that this narrower entry point doesn't attempt to provide either. Both facts true at
/// once, on the same input.
#[test]
fn edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose() {
    let key = ActorPseudonymKey::from_bytes([9u8; 32]);
    let event = AuditEvent::Block {
        artefact: ArtefactKind::EnvFile,
        // Mirrors `BlockReason::ARTEFACT_POLICY_BLOCK_TEXT` (`telemetry::block_reason`,
        // `pub(crate)` — not reachable from this integration-test crate). Duplicating
        // the literal here is an accepted, low-risk trade-off: a drift between the two
        // would make this specific test fail loudly (`try_from_audit_event` no longer
        // `Ok`), not silently pass with the wrong behavior, and adding a `pub` test-only
        // accessor just for this one assertion was judged not worth expanding the
        // public API surface for.
        reason: "artefact class is Block in resolved policy".to_string(),
    };

    assert!(EdgeEvent::try_from_audit_event(&event, &key).is_ok());
    assert_eq!(
        expect_reject(TelemetryEvent::try_from(&event)),
        TelemetryReject::RequiresEnvelopeConstruction { variant: "Block" }
    );
}

#[test]
fn edge_event_resolves_demask_request_given_an_actor_key() {
    let key = ActorPseudonymKey::from_bytes([1u8; 32]);
    let event = AuditEvent::DemaskRequest {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId("jane.doe".to_string()),
    };
    assert!(EdgeEvent::try_from_audit_event(&event, &key).is_ok());
}

#[test]
fn edge_event_resolves_demask_decision_given_an_actor_key_and_valid_policy_version() {
    let key = ActorPseudonymKey::from_bytes([1u8; 32]);
    let event = AuditEvent::DemaskDecision {
        dest: Destination::ObservabilitySink,
        actor: ActorId("jane.doe".to_string()),
        allowed: true,
        policy_version: "policy-v1".to_string(),
    };
    assert!(EdgeEvent::try_from_audit_event(&event, &key).is_ok());
}

#[test]
fn edge_event_demask_request_pseudonym_is_deterministic_for_the_same_key_and_actor() {
    let key = ActorPseudonymKey::from_bytes([1u8; 32]);
    let event = AuditEvent::DemaskRequest {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId("jane.doe".to_string()),
    };
    let a = EdgeEvent::try_from_audit_event(&event, &key).unwrap();
    let b = EdgeEvent::try_from_audit_event(&event, &key).unwrap();
    assert!(a == b);
}

#[test]
fn edge_event_demask_request_pseudonym_differs_for_a_different_key() {
    let event = AuditEvent::DemaskRequest {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId("jane.doe".to_string()),
    };
    let a =
        EdgeEvent::try_from_audit_event(&event, &ActorPseudonymKey::from_bytes([1u8; 32])).unwrap();
    let b =
        EdgeEvent::try_from_audit_event(&event, &ActorPseudonymKey::from_bytes([2u8; 32])).unwrap();
    assert!(a != b);
}

/// `DemaskDecision`'s `policy_version: String -> VersionToken` failure is a distinct,
/// actor-key-independent reject reason — a valid actor key does not fix it.
#[test]
fn edge_event_demask_decision_rejects_an_invalid_policy_version_even_with_a_valid_key() {
    let key = ActorPseudonymKey::from_bytes([1u8; 32]);
    let event = AuditEvent::DemaskDecision {
        dest: Destination::ObservabilitySink,
        actor: ActorId("jane.doe".to_string()),
        allowed: true,
        policy_version: "has spaces".to_string(),
    };
    let got = match EdgeEvent::try_from_audit_event(&event, &key) {
        Err(reject) => reject,
        Ok(_) => panic!("expected rejection for an invalid policy_version"),
    };
    assert_eq!(
        got,
        TelemetryReject::InvalidField {
            variant: "DemaskDecision",
            field: "policy_version",
            reason: "not a valid VersionToken",
        }
    );
}

/// `Block.reason` values outside the code-defined registry (`telemetry::block_reason`)
/// reject with `UnrecognizedReason`, not a silent default or a panic — including the
/// empty string and a near-miss of the one recognized text (this fixture's own
/// `one_of_each_audit_variant` deliberately uses a *different*, unrecognized reason —
/// "policy rule prod-secrets-001" — precisely so this file's other tests exercise the
/// honest-reject path by default, not the newly-added success path).
#[test]
fn edge_event_block_rejects_an_unrecognized_reason_string() {
    let key = ActorPseudonymKey::from_bytes([9u8; 32]);
    for reason in [
        "policy rule prod-secrets-001",
        "",
        "artefact class is Block in resolved Policy", // capitalization differs
    ] {
        let event = AuditEvent::Block {
            artefact: ArtefactKind::EnvFile,
            reason: reason.to_string(),
        };
        let got = match EdgeEvent::try_from_audit_event(&event, &key) {
            Err(reject) => reject,
            Ok(_) => panic!("expected {reason:?} to be rejected as unrecognized"),
        };
        assert_eq!(
            got,
            TelemetryReject::UnrecognizedReason {
                variant: "Block",
                field: "reason",
                reason: "no registered BlockReason matched this AuditEvent::Block.reason string",
            }
        );
        // For an *unrecognized* reason specifically, the two entry points agree (both
        // report `UnrecognizedReason`) -- they only diverge for a recognized one (see
        // `edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose`).
        // Backs up the claim in this test's own module-level consistency-check doc
        // comment above, rather than leaving it asserted only in prose.
        assert_eq!(expect_reject(TelemetryEvent::try_from(&event)), got);
    }
}

// -- Wire serialization / canonical JSON / HMAC signing --

/// Cross-language contract test: reconstructs the exact `veil.edge_event.v1` record
/// pinned in `tests/fixtures/edge_event_v1_golden.json` via the *production* path
/// (`AuditEvent` -> `EdgeEvent::try_from_audit_event` -> `sign_edge_event_record`) and
/// asserts byte-exact equality against the fixture's `canonical_json` and
/// `signature_hex`. A downstream Python verifier (`veil-observatory`, a separate
/// private repo) pins against this same fixture — any future change to field names,
/// canonicalization, or signing here that doesn't also update the fixture (deliberately,
/// with the cross-repo consequences considered) must fail this test loudly, not pass
/// silently.
///
/// The concrete input values below must match `tests/fixtures/edge_event_v1_golden.json`'s
/// own `input` object exactly -- reviewed and edited together, not derived from each
/// other automatically (deliberately not parsed back out of the fixture file: a bug that
/// corrupted both the fixture and this test's input construction identically would
/// otherwise still pass).
#[test]
fn edge_event_v1_golden_vector_matches_the_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/edge_event_v1_golden.json")).unwrap();

    // input.actor_pseudonym_key_hex = "09" * 32
    let actor_key = ActorPseudonymKey::from_bytes([0x09u8; 32]);
    // input.audit_event
    let event = AuditEvent::DemaskDecision {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId("jane.doe".to_string()),
        allowed: true,
        policy_version: "policy-v1".to_string(),
    };
    let edge_event = EdgeEvent::try_from_audit_event(&event, &actor_key).unwrap();

    // input.signing_key_hex = 01 02 ... 20 (32 sequential bytes)
    let signing_key = ReceiptSigningKey::from_bytes((1u8..=32u8).collect()).unwrap();
    // input.record_id
    let record_id =
        RecordId::from(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap());
    // input.nonce_hex = 01 02 ... 10 (16 sequential bytes)
    let nonce: [u8; 16] = (1u8..=16u8).collect::<Vec<_>>().try_into().unwrap();

    let input = EdgeEventRecordInput {
        contract_revision: 1, // input.contract_revision
        record_id,
        issued_at_us: 1_700_000_000_000_000, // input.issued_at_us
        device_ref: None,                    // input.device_ref
        tenant_id: None,                     // input.tenant_id
        sequence: 0,                         // input.sequence
        valid_until_us: 1_700_000_300_000_000, // input.valid_until_us
        payload_sha256: [0u8; 32],           // input.payload_sha256_hex = "00" * 32
        nonce,
        key_ref: None, // input.key_ref
        edge_event,
    };

    let signed = sign_edge_event_record(input, &signing_key).unwrap();

    assert_eq!(
        signed.canonical_json,
        fixture["canonical_json"].as_str().unwrap(),
        "canonical JSON drifted from the pinned golden vector"
    );
    assert_eq!(
        signed.signature_hex,
        fixture["signature_hex"].as_str().unwrap(),
        "HMAC signature drifted from the pinned golden vector"
    );
    // The signature is also embedded in the canonical JSON -- both must agree.
    assert!(signed.canonical_json.contains(&signed.signature_hex));
}

/// Hard-gate regression: every raw, free-text-shaped value this session's whole input
/// surface can carry (an operator-typed actor identity that could itself be
/// hostname/PII-shaped, and a parser-detected source-code language name) must never
/// appear verbatim in the serialized wire record -- only its pseudonymized/classified/
/// collapsed form may. `EdgeEvent`'s actual input surface has exactly two raw-string
/// vectors (`ActorId`, `ArtefactKind::SourceCode`'s language name) plus one more that
/// collapses to an integer before it can ever reach this struct at all
/// (`AuditEvent::Block.reason`, classified by `telemetry::block_reason` inside
/// `try_from_audit_event` -- there is no field left on `BlockedAttemptPayload` capable
/// of holding the original string, so it isn't re-tested here beyond the coverage
/// `blocked_attempt_serializes_the_reason_as_an_integer_never_the_original_string`
/// (`telemetry::edge_event`'s own tests) already gives it). `EdgeEvent` has no
/// "detected PII value" field of its own (that belongs to `Receipt`/`Detection`, out of
/// this session's scope) -- the marker below stands in for that category via the one
/// vector that actually exists, an actor identity that happens to look like PII.
#[test]
fn edge_event_serialization_never_leaks_raw_forbidden_values() {
    const FORBIDDEN_USERNAME: &str = "jane-q-doe-raw-username-marker-9f3a";
    const FORBIDDEN_PII_LIKE_ACTOR: &str = "4111-1111-1111-1111-raw-pii-marker-2b7c";
    const FORBIDDEN_HOSTNAME: &str = "corp-laptop-0043-raw-hostname-marker-c81e";

    let actor_key = ActorPseudonymKey::from_bytes([9u8; 32]);
    let signing_key = ReceiptSigningKey::from_bytes(vec![7u8; 32]).unwrap();

    let demask_request = AuditEvent::DemaskRequest {
        dest: Destination::RemoteModelPrompt,
        actor: ActorId(FORBIDDEN_USERNAME.to_string()),
    };
    let demask_decision = AuditEvent::DemaskDecision {
        dest: Destination::ObservabilitySink,
        actor: ActorId(FORBIDDEN_PII_LIKE_ACTOR.to_string()),
        allowed: true,
        policy_version: "policy-v1".to_string(),
    };
    let block = AuditEvent::Block {
        artefact: ArtefactKind::SourceCode(FORBIDDEN_HOSTNAME.to_string()),
        // Mirrors `BlockReason::ARTEFACT_POLICY_BLOCK_TEXT`, `pub(crate)` and not
        // reachable from this integration-test crate -- see
        // `edge_event_block_reason_dictionary_diverges_from_the_frozen_try_from_on_purpose`
        // above for the same accepted duplication trade-off.
        reason: "artefact class is Block in resolved policy".to_string(),
    };

    let edge_events = vec![
        EdgeEvent::try_from_audit_event(&demask_request, &actor_key).unwrap(),
        EdgeEvent::try_from_audit_event(&demask_decision, &actor_key).unwrap(),
        EdgeEvent::try_from_audit_event(&block, &actor_key).unwrap(),
    ];

    for (i, edge_event) in edge_events.into_iter().enumerate() {
        let input = EdgeEventRecordInput {
            contract_revision: 1,
            record_id: RecordId::from(Uuid::nil()),
            issued_at_us: 1_700_000_000_000_000,
            device_ref: None,
            tenant_id: None,
            sequence: i as u64,
            valid_until_us: 1_700_000_300_000_000,
            payload_sha256: [0u8; 32],
            nonce: [0u8; 16],
            key_ref: None,
            edge_event,
        };
        let signed = sign_edge_event_record(input, &signing_key).unwrap();

        assert!(
            !signed.canonical_json.contains(FORBIDDEN_USERNAME),
            "events[{i}]: raw username leaked into the wire record"
        );
        assert!(
            !signed.canonical_json.contains(FORBIDDEN_PII_LIKE_ACTOR),
            "events[{i}]: PII-shaped raw actor identity leaked into the wire record"
        );
        assert!(
            !signed.canonical_json.contains(FORBIDDEN_HOSTNAME),
            "events[{i}]: raw hostname-shaped source-code language name leaked into the \
             wire record"
        );
        assert!(
            !signed.canonical_json.contains("artefact class is Block"),
            "events[{i}]: Block's original free-text reason leaked into the wire record \
             instead of its classified ReasonCode"
        );
    }
}

/// Negative control for the leak-regression test above: proves it can actually detect a
/// leak, not just that these three inputs happen not to trigger one. Constructs a
/// deliberately non-conforming payload (bypassing the normal `EdgeEvent` constructors
/// entirely, which is the whole point of this crate's `pub(crate)`-only construction —
/// simulated here by asserting directly against a hand-built JSON value instead) and
/// confirms the same substring check would fail if the marker really were present.
#[test]
fn leak_regression_helper_actually_detects_a_planted_marker() {
    let planted = serde_json::json!({"actor": "jane-q-doe-raw-username-marker-9f3a"});
    let rendered = serde_json::to_string(&planted).unwrap();
    assert!(rendered.contains("jane-q-doe-raw-username-marker-9f3a"));
}
