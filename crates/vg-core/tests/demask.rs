//! Integration tests for the wired `vg_core::rehydrate` (contract v1.2, Task T09).
//!
//! Like `tests/pipeline.rs`, these compose the **real** Wave B crates (a temp-keyed
//! `vg_vault::Vault`, the default `vg_policy` fixture, a temp `vg_audit::JsonlAuditSink`)
//! through `vg-core`'s own trait objects — exactly as the `vg demask` CLI does. They
//! exercise the three things the frozen unit tests could not once `rehydrate` gained a
//! vault handle: the hard-deny gate, the configurable policy gate, and pack-driven
//! substitution that never scans text for placeholder-shaped strings.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use vg_audit::JsonlAuditSink;
use vg_core::{
    mask, rehydrate, Actor, ActorId, ArtefactHint, Context, Destination, Detector, Input,
    MaskedPack, Namespace, Parser, Policy, PolicyEngine, PolicyLayers, RepoId,
};
use vg_detectors::all_detectors;
use vg_parsers::all_parsers;
use vg_policy::LayeredPolicyEngine;
use vg_vault::{Vault, VaultConfig};

const TEST_KEY: [u8; 32] = [7u8; 32];
const SECRET_TOKEN: &str = "Zx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We";

fn fixture() -> String {
    format!(
        "escalate to jane.doe@example.com and cc ops@example.com on the thread.\n\
         Customer IBAN GB29 NWBK 6016 1331 9268 19 is under review.\n\
         Session token {SECRET_TOKEN} must be rotated.\n"
    )
}

fn global_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
}

fn repo_ns() -> Namespace {
    Namespace::Repo(RepoId("veilgremlin-t09-demask".to_string()))
}

fn admin() -> Actor {
    Actor {
        id: ActorId("reviewer-1".to_string()),
        roles: vec!["admin".to_string(), "reviewer".to_string()],
    }
}

fn build_policy(dir: &Path) -> (Policy, PathBuf) {
    let audit_path = dir.join("audit.jsonl");
    let engine = LayeredPolicyEngine::load(PolicyLayers {
        global: global_policy_path(),
        repo: None,
        session: None,
    })
    .expect("load default policy fixture");
    let vault = Vault::open_with_key(VaultConfig::new(dir.join("vault.db")), TEST_KEY)
        .expect("open temp-keyed vault");
    let audit = JsonlAuditSink::open(&audit_path).expect("open temp audit sink");
    (
        Policy {
            engine: Box::new(engine),
            vault: Box::new(vault),
            audit: Box::new(audit),
        },
        audit_path,
    )
}

fn with_real_context<R>(body: impl FnOnce(&Context) -> R) -> R {
    let detectors = all_detectors();
    let detector_refs: Vec<&dyn Detector> = detectors.iter().map(|d| d.as_ref()).collect();
    let parsers = all_parsers();
    let parser_refs: Vec<&dyn Parser> = parsers.iter().map(|p| p.as_ref()).collect();
    let ctx = Context {
        parsers: &parser_refs,
        detectors: &detector_refs,
    };
    body(&ctx)
}

fn mask_fixture(policy: &Policy, ns: &Namespace) -> MaskedPack {
    let input = Input {
        buf: fixture().into_bytes(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, policy, ns)).expect("mask succeeds");
    pack
}

#[test]
fn masked_round_trip_restores_reversible_values_to_local_patch() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _audit) = build_policy(dir.path());
    let ns = repo_ns();

    let pack = mask_fixture(&policy, &ns);
    // Precondition: the pack really did mask the reversible values (else the test proves
    // nothing).
    assert!(!pack.bindings.is_empty(), "expected reversible bindings");
    assert!(pack.text.contains("EMAIL_001"), "text: {}", pack.text);
    assert!(pack.text.contains("IBAN_001"), "text: {}", pack.text);

    let restored = rehydrate(&pack, &policy, &ns, Destination::LocalPatch, &admin())
        .expect("demask to a local destination is allowed");

    // Reversible (Mask-class) values are restored via their bindings...
    assert!(
        restored.contains("jane.doe@example.com"),
        "restored: {restored}"
    );
    assert!(restored.contains("ops@example.com"), "restored: {restored}");
    assert!(
        restored.contains("GB29 NWBK 6016 1331 9268 19"),
        "restored: {restored}"
    );
    // ...while the irreversibly-redacted secret has no binding and stays redacted.
    assert!(
        restored.contains("[REDACTED:SECRET]"),
        "restored: {restored}"
    );
    assert!(!restored.contains(SECRET_TOKEN), "restored: {restored}");
    // No placeholder survives for a value that WAS bound.
    assert!(!restored.contains("EMAIL_001"), "restored: {restored}");
}

#[test]
fn demask_gate_denies_hard_deny_destinations_regardless_of_actor() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _audit) = build_policy(dir.path());
    let ns = repo_ns();
    let pack = mask_fixture(&policy, &ns);

    for dest in [
        Destination::RemoteModelPrompt,
        Destination::ObservabilitySink,
    ] {
        let err = rehydrate(&pack, &policy, &ns, dest.clone(), &admin())
            .expect_err("hard-deny destination must be denied even for an admin actor");
        assert_eq!(err.destination, dest);
        // The pack's text must not have been resolved on the denied path.
    }
}

#[test]
fn demask_gate_denies_a_policy_disallowed_local_destination() {
    // The default fixture sets local-explanation-buffer demask_allowed=false: not a
    // hard-deny destination, but the configurable policy gate still denies it.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _audit) = build_policy(dir.path());
    let ns = repo_ns();
    let pack = mask_fixture(&policy, &ns);

    let err = rehydrate(
        &pack,
        &policy,
        &ns,
        Destination::LocalExplanationBuffer,
        &admin(),
    )
    .expect_err("policy denies demask to local-explanation-buffer");
    assert_eq!(err.destination, Destination::LocalExplanationBuffer);
}

#[test]
fn spoofed_placeholder_not_minted_by_the_pack_is_left_untouched() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _audit) = build_policy(dir.path());
    let ns = repo_ns();
    let mut pack = mask_fixture(&policy, &ns);

    // Splice a placeholder-shaped string the pack never minted (no binding for it) into
    // the masked text. A demask that scanned text for `EMAIL_\d+` shapes would try to
    // resolve it; a demask driven only by the pack's bindings must leave it alone.
    pack.text
        .push_str("\nspoofed EMAIL_900 injected by the caller\n");

    let restored =
        rehydrate(&pack, &policy, &ns, Destination::LocalPatch, &admin()).expect("demask allowed");

    assert!(
        restored.contains("EMAIL_900"),
        "a placeholder the pack never minted must survive demask untouched: {restored}"
    );
    // The genuinely-minted one is still restored.
    assert!(
        restored.contains("jane.doe@example.com"),
        "restored: {restored}"
    );
}

#[test]
fn a_denied_demask_writes_an_audit_decision_and_resolves_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, audit_path) = build_policy(dir.path());
    let ns = repo_ns();
    let pack = mask_fixture(&policy, &ns);

    // mask wrote one Scan event; a denied demask adds one DemaskDecision(allowed=false).
    let before = JsonlAuditSink::open(&audit_path).expect("reopen").len();
    let _ = rehydrate(
        &pack,
        &policy,
        &ns,
        Destination::RemoteModelPrompt,
        &admin(),
    );
    let after = JsonlAuditSink::open(&audit_path).expect("reopen").len();
    assert_eq!(
        after,
        before + 1,
        "a denied demask must still record its decision in the audit log"
    );
}

#[test]
fn substitution_respects_token_boundaries_and_never_rescans_restored_values() {
    // Doubt-pass regression (T09 round 1, finding 7): the original per-binding
    // `String::replace` (a) corrupted unrelated substrings — a minted `EMAIL_001` would
    // rewrite user text `EMAIL_0015` — and (b) re-scanned already-restored values. The
    // single-pass substitution must leave a glued-on word character alone.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _audit) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        // The literal `EMAIL_0011` is raw user text sharing a prefix with the display the
        // pack will mint for the real address (`EMAIL_001`).
        buf: b"ticket EMAIL_0011 filed by jane.doe@example.com".to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
    assert!(
        pack.text.contains("EMAIL_0011"),
        "raw look-alike must survive masking: {}",
        pack.text
    );

    let restored =
        rehydrate(&pack, &policy, &ns, Destination::LocalPatch, &admin()).expect("demask allowed");
    assert!(
        restored.contains("ticket EMAIL_0011 filed by"),
        "boundary rule must protect the look-alike: {restored}"
    );
    assert!(
        restored.contains("jane.doe@example.com"),
        "the real binding must still restore: {restored}"
    );
}
