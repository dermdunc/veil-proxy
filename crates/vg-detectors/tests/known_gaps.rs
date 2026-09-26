//! Known detection gaps, pinned as tests (veil-proxy#86 finding 4, `RISK-0015`).
//!
//! Every detector here matches contiguous tokens. Tool output that prints one character per
//! cell (`od -c`, `fold -w1`) or hex-encodes bytes (`xxd`, `od -x`) splits a sensitive value
//! into pieces no detector recognizes, so it reaches the model raw. A real Claude Code session
//! through vg-proxy hit this: after an `Edit` failed, the model ran `od -c` on the file, read
//! the IBAN out of the dump, and re-emitted it whole.
//!
//! These tests assert the **current** behaviour, which is "not detected". They exist so the gap
//! is visible and measured, not silently assumed away. If a mitigation lands (a normalising
//! pre-pass over `tool_result` content, say), flip each assertion to "detected" and update
//! `RISK-0015` in `docs/risks.md`.

use vg_core::EntityType;
use vg_detectors::all_detectors;

/// Whether any detector reports `entity` anywhere in `buf`. Entity-specific on purpose: the hex
/// groups in an `xxd` dump already trip the phone detector (`6540 6578`), a false positive
/// that says nothing about whether the email inside was caught.
fn detected_as(buf: &str, entity: EntityType) -> bool {
    all_detectors().iter().any(|d| {
        d.detect(buf.as_bytes(), &[])
            .iter()
            .any(|f| f.entity_type == entity)
    })
}

#[test]
fn sanity_the_same_values_are_detected_when_contiguous() {
    assert!(detected_as(
        "pay to GB33BUKB20201555555555 within 30 days",
        EntityType::Iban
    ));
    assert!(detected_as("mail jane.doe@example.com", EntityType::Email));
}

#[test]
fn known_gap_od_c_output_of_an_iban_is_not_detected() {
    // The exact dump from the veil-proxy#86 spike (a published example IBAN, synthetic).
    let od = "0001240    e   n   c   e   }       t   o       G   B   3   3   B   U   K\n\
              0001260    B   2   0   2   0   1   5   5   5   5   5   5   5   5   5\n";
    assert!(
        !detected_as(od, EntityType::Iban),
        "known gap closed? update RISK-0015 and this test"
    );
}

#[test]
fn known_gap_xxd_output_of_an_email_is_not_detected() {
    // `printf 'mail jane.doe@example.com\n' | xxd`
    let xxd = "00000000: 6d61 696c 206a 616e 652e 646f 6540 6578  mail jane.doe@ex\n\
               00000010: 616d 706c 652e 636f 6d0a                 ample.com.\n";
    assert!(
        !detected_as(xxd, EntityType::Email),
        "known gap closed? update RISK-0015 and this test"
    );
}

#[test]
fn known_gap_fold_w1_output_of_an_email_is_not_detected() {
    // `echo jane.doe@example.com | fold -w1`
    let folded: String = "jane.doe@example.com"
        .chars()
        .map(|c| format!("{c}\n"))
        .collect();
    assert!(
        !detected_as(&folded, EntityType::Email),
        "known gap closed? update RISK-0015 and this test"
    );
}
