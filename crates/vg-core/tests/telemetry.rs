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
    AlertRuleId, ArtefactKindId, DetectorSetId, DeviceRef, DeviceRefError, EntityClassId,
    ExceptionRuleId, KeyRef, RegistryRef, TelemetryEvent, TelemetryReject, TenantId, VersionToken,
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
        TelemetryReject::RequiresReasonDictionary { variant: "Block" },
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
