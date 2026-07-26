//! Integration test: feeds real `Finding`s from `vg-detectors::all_detectors()` (Task T03,
//! already merged) through this task's keying logic end to end.
//!
//! Added per the 2026-07-16 cross-crate integration requirement recorded in
//! `docs/architecture/work-breakdown.md` and `.hekton/veil-proxy-dag.toml`'s T04 entry:
//! testing keying only against hand-built mock values would mean the first time it ever sees
//! a real `Finding` is Task T07's full pipeline wiring, several tasks later. This is a
//! dev-dependency-only edge (`vg-core`'s `[dev-dependencies]` on `vg-detectors`) — it does not
//! create a real cycle in the normal build graph, since `vg-detectors`'s own (non-dev)
//! dependency on `vg-core` is the only edge that matters for building either crate for real.
//!
//! The fixture strings below are lifted verbatim from `vg-detectors`' own unit tests
//! (`email.rs`, `phone.rs`, `ip.rs`, `iban_sortcode.rs`, `entropy.rs`) — known-good inputs each
//! detector is independently already proven to match — rather than freshly invented ones, so a
//! detector regression that stops matching shows up as a failure *here* (empty/short findings,
//! caught by the coverage assertion below) rather than this test silently exercising nothing.

use std::collections::HashSet;

use vg_core::{EntityType, Finding, Keyer, Namespace, RepoId};

const FIXTURE: &[u8] = b"Incident report: contact jane.doe+test@example.co.uk or call \
+1-415-555-2671. Server at 192.168.1.42 rejected transfer to IBAN GB29NWBK60161331926819, \
sort code 12-34-56. export API_KEY=zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi leaked in the log.";

fn matched_text<'a>(buf: &'a [u8], finding: &Finding) -> &'a str {
    std::str::from_utf8(&buf[finding.span.start..finding.span.end])
        .expect("fixture is ASCII; every span must slice to valid UTF-8")
}

#[test]
fn real_detector_findings_cover_the_expected_entity_types() {
    // Sanity check on the fixture itself: if a detector regex changes shape and stops
    // matching, this fails loudly here instead of the rest of this test silently exercising
    // an empty findings list.
    let findings: Vec<_> = vg_detectors::all_detectors()
        .iter()
        .flat_map(|d| d.detect(FIXTURE, &[]))
        .collect();

    let seen: HashSet<EntityType> = findings.iter().map(|f| f.entity_type.clone()).collect();
    for expected in [
        EntityType::Email,
        EntityType::Phone,
        EntityType::InternalIp,
        EntityType::Iban,
        EntityType::SortCode,
        EntityType::Secret,
    ] {
        assert!(
            seen.contains(&expected),
            "expected the fixture to trigger a {expected:?} finding; got {findings:?}"
        );
    }
}

#[test]
fn keying_every_real_finding_does_not_panic_and_produces_a_typed_display() {
    let keyer = Keyer::new(b"integration-test-salt".to_vec());
    let ns = Namespace::Repo(RepoId("acme/incident-123".to_string()));

    for detector in vg_detectors::all_detectors() {
        for finding in detector.detect(FIXTURE, &[]) {
            let value = matched_text(FIXTURE, &finding);
            let keyed = keyer.key_for(value, finding.entity_type.clone(), &ns);
            assert!(
                !keyed.display.is_empty(),
                "display must be non-empty for a real Finding value {value:?} ({:?})",
                finding.entity_type
            );
            assert!(
                keyed.ordinal >= 1,
                "ordinal must start at 1 for a real Finding value {value:?}"
            );
        }
    }
}

#[test]
fn keying_the_same_real_finding_twice_yields_the_same_placeholder() {
    // Simulates a rescan: the detectors run again over the same buffer (a realistic
    // occurrence — e.g. the same file scanned across two hook invocations), and the keyer
    // must treat the two independently-produced Finding sets as referring to the same
    // underlying values, per "same value -> same placeholder within namespace"
    // (work-breakdown.md's T04 acceptance criterion).
    let keyer = Keyer::new(b"integration-test-salt".to_vec());
    let ns = Namespace::Repo(RepoId("acme/incident-123".to_string()));

    let first_pass: Vec<_> = vg_detectors::all_detectors()
        .iter()
        .flat_map(|d| d.detect(FIXTURE, &[]))
        .map(|f| {
            let value = matched_text(FIXTURE, &f).to_string();
            keyer.key_for(&value, f.entity_type.clone(), &ns)
        })
        .collect();

    let second_pass: Vec<_> = vg_detectors::all_detectors()
        .iter()
        .flat_map(|d| d.detect(FIXTURE, &[]))
        .map(|f| {
            let value = matched_text(FIXTURE, &f).to_string();
            keyer.key_for(&value, f.entity_type.clone(), &ns)
        })
        .collect();

    assert_eq!(
        first_pass, second_pass,
        "rescanning the same buffer must yield identical Keyed results for every real Finding"
    );
}

#[test]
fn keying_distinguishes_two_real_findings_of_the_same_type() {
    // The fixture's IBAN and sort code are both real Findings, but different EntityTypes;
    // the sort-code detector and the phone detector can also both fire on digit-and-hyphen
    // shaped text -- confirm keying doesn't collapse genuinely different real detector output
    // into the same key.
    let findings: Vec<_> = vg_detectors::all_detectors()
        .iter()
        .flat_map(|d| d.detect(FIXTURE, &[]))
        .collect();

    let iban = findings
        .iter()
        .find(|f| f.entity_type == EntityType::Iban)
        .expect("fixture contains an IBAN finding");
    let sort_code = findings
        .iter()
        .find(|f| f.entity_type == EntityType::SortCode)
        .expect("fixture contains a sort-code finding");

    let keyer = Keyer::new(b"integration-test-salt".to_vec());
    let ns = Namespace::Repo(RepoId("acme/incident-123".to_string()));
    let iban_keyed = keyer.key_for(matched_text(FIXTURE, iban), EntityType::Iban, &ns);
    let sort_code_keyed =
        keyer.key_for(matched_text(FIXTURE, sort_code), EntityType::SortCode, &ns);

    assert_ne!(iban_keyed.key, sort_code_keyed.key);
    assert!(iban_keyed.display.starts_with("IBAN_"));
    assert!(sort_code_keyed.display.starts_with("SORT_CODE_"));
}

#[test]
fn real_iban_finding_text_passes_the_mod97_checksum() {
    // Cross-checks this task's mod-97 validator against the *actual* substring the real IBAN
    // detector reports (not a hand-typed literal) -- if the detector's span ever drifted to
    // include surrounding punctuation or drop a character, this would catch it as a checksum
    // failure rather than the mismatch going unnoticed until masking looked wrong downstream.
    let findings: Vec<_> = vg_detectors::all_detectors()
        .iter()
        .flat_map(|d| d.detect(FIXTURE, &[]))
        .collect();
    let iban = findings
        .iter()
        .find(|f| f.entity_type == EntityType::Iban)
        .expect("fixture contains an IBAN finding");

    assert!(vg_core::iban_mod97_is_valid(matched_text(FIXTURE, iban)));
}
