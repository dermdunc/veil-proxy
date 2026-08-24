//! End-to-end pipeline integration tests for `vg_core::scan`/`mask` (Task T07).
//!
//! Unlike the unit tests in `api.rs` (which never touch a real Wave B crate), these
//! compose the **real** implementations — `vg_detectors::all_detectors`,
//! `vg_parsers::all_parsers`, a temp-keyed real `vg_vault::Vault`, the default
//! `vg_policy` fixture, and a temp `vg_audit::JsonlAuditSink` — through `vg-core`'s own
//! trait objects, exactly as a caller (the CLI, an adapter) would. `vg-core` reaches
//! them only as dev-dependencies (the T04 precedent); it has no normal-build edge to any
//! of them.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use vg_audit::JsonlAuditSink;
use vg_core::conformance::assert_masked_pack_excludes_raw_values;
use vg_core::{
    mask, scan, ArtefactHint, AuditEvent, Context, Detector, DetectorId, EntityType, Finding,
    Input, Namespace, Parser, Policy, PolicyEngine, PolicyLayers, RepoId, Span,
};
use vg_detectors::all_detectors;
use vg_parsers::all_parsers;
use vg_policy::LayeredPolicyEngine;
use vg_vault::{Vault, VaultConfig};

/// Fixed key so the suite never touches the real OS keychain (see `Vault::open_with_key`).
const TEST_KEY: [u8; 32] = [7u8; 32];

/// A high-entropy token with no internal `-`/`.`/`/`/`_` delimiters, so the entropy
/// detector scores it whole (a delimited value can decompose into word-like segments the
/// detector deliberately excludes as a "structured identifier"). Flagged `Secret`, which
/// the default policy classes `irreversible-redact`.
const SECRET_TOKEN: &str = "Zx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We";

/// A realistic mixed artefact: the same email twice (stability), a second distinct email,
/// an IBAN, a high-entropy secret, plus a date and a path that must pass through untouched
/// (both decompose into structured-identifier segments the entropy detector excludes).
fn mixed_fixture() -> String {
    format!(
        "Deploy note 2026-07-18: escalate to jane.doe@example.com about the incident.\n\
         Page jane.doe@example.com again and cc ops@example.com on the thread.\n\
         Customer IBAN GB29 NWBK 6016 1331 9268 19 is under review.\n\
         Session token {SECRET_TOKEN} must be rotated before the weekend.\n\
         Config path /etc/veilgremlin/config.toml was touched by the deploy.\n"
    )
}

fn global_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
}

fn repo_ns() -> Namespace {
    Namespace::Repo(RepoId("veilgremlin-t07-tests".to_string()))
}

/// Assembles a `Policy` over the real vault/policy/audit at deterministic paths under
/// `dir`, returning the vault DB and audit-log paths so a test can re-open a fresh
/// inspector handle to prove what did (or did not) get persisted.
fn build_policy(dir: &Path) -> (Policy, PathBuf, PathBuf) {
    let db_path = dir.join("vault.db");
    let audit_path = dir.join("audit.jsonl");
    let engine = LayeredPolicyEngine::load(PolicyLayers {
        global: global_policy_path(),
        repo: None,
        session: None,
    })
    .expect("load default policy fixture");
    let vault =
        Vault::open_with_key(VaultConfig::new(&db_path), TEST_KEY).expect("open temp-keyed vault");
    let audit = JsonlAuditSink::open(&audit_path).expect("open temp audit sink");
    let policy = Policy {
        engine: Box::new(engine),
        vault: Box::new(vault),
        audit: Box::new(audit),
    };
    (policy, db_path, audit_path)
}

/// Number of persisted mappings in the vault at `db_path` — read through a fresh handle
/// so we observe exactly what `mask` committed, not the in-memory `Keyer` cache.
fn persisted_mapping_count(db_path: &Path) -> usize {
    Vault::open_with_key(VaultConfig::new(db_path), TEST_KEY)
        .expect("re-open vault for inspection")
        .mapping_count()
        .expect("count mappings")
}

/// Runs `body` with a `Context` over the real detectors/parsers. (The trait-object slices
/// borrow local `Vec`s, so they can't outlive a helper that returns them — hence a
/// closure.)
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

#[test]
fn scan_finds_the_expected_entities_over_the_full_buffer() {
    let input = Input {
        buf: mixed_fixture().into_bytes(),
        hint: ArtefactHint::default(),
    };
    let findings = with_real_context(|ctx| scan(&input, ctx));

    // Three email occurrences (two of one address, one of another) and one IBAN, all
    // over the raw buffer.
    let emails = findings
        .iter()
        .filter(|f| f.entity_type == EntityType::Email)
        .count();
    assert_eq!(emails, 3, "expected three email findings, got {findings:?}");
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Iban),
        "expected an IBAN finding, got {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Secret),
        "expected an entropy Secret finding, got {findings:?}"
    );
}

#[test]
fn mask_end_to_end_stabilises_placeholders_and_excludes_raw_values() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: mixed_fixture().into_bytes(),
        hint: ArtefactHint::default(),
    };
    let (pack, mapping_refs, event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    // Same value -> same placeholder: three email occurrences collapse to exactly two
    // distinct placeholders (the repeated address shares one).
    let email_hits = pack.text.matches("EMAIL_").count();
    assert_eq!(email_hits, 3, "text: {}", pack.text);
    assert!(pack.text.contains("EMAIL_001"), "text: {}", pack.text);
    assert!(pack.text.contains("EMAIL_002"), "text: {}", pack.text);
    assert!(!pack.text.contains("EMAIL_003"), "text: {}", pack.text);

    // The IBAN is masked (reversible) and the secret is irreversibly redacted.
    assert!(pack.text.contains("IBAN_001"), "text: {}", pack.text);
    assert!(
        pack.text.contains("[REDACTED:SECRET]"),
        "text: {}",
        pack.text
    );

    // The non-sensitive date and path pass through untouched.
    assert!(pack.text.contains("2026-07-18"), "text: {}", pack.text);
    assert!(
        pack.text.contains("/etc/veilgremlin/config.toml"),
        "text: {}",
        pack.text
    );

    // `.text` carries placeholders, never the raw detected values.
    let raw_values = [
        "jane.doe@example.com",
        "ops@example.com",
        "GB29 NWBK 6016 1331 9268 19",
        SECRET_TOKEN,
    ];
    assert_masked_pack_excludes_raw_values(&pack, &raw_values);

    // Stats reflect what was handled; nothing was artefact-blocked.
    assert_eq!(pack.stats.counts.0.get(&EntityType::Email), Some(&3));
    assert_eq!(pack.stats.counts.0.get(&EntityType::Iban), Some(&1));
    assert_eq!(pack.stats.counts.0.get(&EntityType::Secret), Some(&1));
    assert_eq!(pack.stats.blocked_artefacts, 0);

    // Reversible masks produced mapping refs; the returned Scan event carries the same
    // counts.
    assert!(!mapping_refs.is_empty());
    match event {
        AuditEvent::Scan { counts, .. } => {
            assert_eq!(counts.0.get(&EntityType::Email), Some(&3));
        }
        other => panic!("expected AuditEvent::Scan, got {other:?}"),
    }
}

#[test]
fn mask_mints_a_fresh_trace_id_on_every_call() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = || Input {
        buf: mixed_fixture().into_bytes(),
        hint: ArtefactHint::default(),
    };

    let (_pack, _refs, _event, trace_id_a) =
        with_real_context(|ctx| mask(&input(), ctx, &policy, &ns)).expect("mask succeeds");
    let (_pack, _refs, _event, trace_id_b) =
        with_real_context(|ctx| mask(&input(), ctx, &policy, &ns)).expect("mask succeeds");

    // Same fixture, two separate calls: the trace id must differ each time, proving it's
    // freshly minted per call rather than a fixed or content-derived value.
    assert!(trace_id_a != trace_id_b);
}

/// The masked-pack invariant as a property over every raw value in the fixture: no matter
/// which values the fixture holds, none may survive into `.text`.
#[test]
fn masked_pack_excludes_every_fixture_raw_value_property() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: mixed_fixture().into_bytes(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    // Every sensitive value the fixture is built from, asserted absent from the pack.
    for raw in [
        "jane.doe@example.com",
        "ops@example.com",
        "GB29 NWBK 6016 1331 9268 19",
        SECRET_TOKEN,
    ] {
        assert_masked_pack_excludes_raw_values(&pack, &[raw]);
    }
}

#[test]
fn env_hinted_artefact_is_blocked_with_no_content_and_nothing_interned() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, db_path, audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let secret_body = format!("API_TOKEN={SECRET_TOKEN}\nDB_PASSWORD=hunter2hunter2hunter2\n");
    // The literal dotfile name `.env` is the canonical Block example — and the regression
    // that matters: `Path::new(".env").extension()` is `None` in Rust, so before the
    // T07-review fix (`extension_candidates` in vg-policy) this exact hint fell through
    // to the artefact default and FAILED OPEN. A `secrets.env` name (which has a real
    // `env` extension) masks the bug, so this test deliberately uses the bare dotfile.
    let input = Input {
        buf: secret_body.clone().into_bytes(),
        hint: ArtefactHint {
            path: Some(PathBuf::from(".env")),
            language_id: None,
            mime_type: None,
        },
    };
    let (pack, mapping_refs, event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    // The artefact's content never reaches the pack.
    assert!(pack.text.is_empty(), "blocked pack text must be empty");
    assert!(!pack.text.contains(SECRET_TOKEN));
    assert_eq!(pack.stats.blocked_artefacts, 1);
    assert!(mapping_refs.is_empty());
    assert!(
        matches!(event, AuditEvent::Block { .. }),
        "expected AuditEvent::Block, got {event:?}"
    );

    // The block audit event was written (a fresh sink replays the fsync'd log).
    let replayed = JsonlAuditSink::open(&audit_path).expect("re-open audit log");
    assert_eq!(replayed.len(), 1, "the Block event must be persisted");

    // Nothing was interned for a blocked artefact.
    assert_eq!(persisted_mapping_count(&db_path), 0);

    // The *real*, production-emitted event (not a hand-constructed fixture) round-trips
    // through the telemetry reason dictionary — a doubt-driven-development finding: the
    // integration tests in `crates/vg-core/tests/telemetry.rs` can't reach
    // `telemetry::block_reason`'s `pub(crate)` text constant, so they necessarily
    // duplicate the literal by hand. This assertion uses `mask()`'s actual output
    // instead, so a future drift between `api.rs`'s reason string and the registry
    // (e.g. from a bad merge) fails here even if a hand-copied fixture elsewhere
    // happened to still match.
    let key = vg_core::telemetry::ActorPseudonymKey::from_bytes([9u8; 32]);
    assert!(
        vg_core::telemetry::EdgeEvent::try_from_audit_event(&event, &key).is_ok(),
        "the real AuditEvent::Block mask() just emitted must be a recognized reason"
    );
}

#[test]
fn irreversible_redact_value_is_redacted_and_never_vault_stored() {
    let dir = TempDir::new().expect("temp dir");
    let (policy, db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: format!("rotate the session token {SECRET_TOKEN} before friday").into_bytes(),
        hint: ArtefactHint::default(),
    };
    let (pack, mapping_refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    assert!(
        pack.text.contains("[REDACTED:SECRET]"),
        "text: {}",
        pack.text
    );
    assert!(!pack.text.contains(SECRET_TOKEN));
    // The irreversible class is never passed to `intern`: no mapping ref, and — proven
    // against the durable store — mapping_count stays 0.
    assert!(mapping_refs.is_empty());
    assert_eq!(persisted_mapping_count(&db_path), 0);
}

#[test]
fn partially_overlapping_findings_leak_no_detected_bytes() {
    // Doubt-pass High regression: the entropy detector's documented tokenizer residual
    // (`@`/`.`/`-` are token bytes) merges a secret with an adjacent email into ONE
    // `Secret` span, while the email detector claims just the email tail. The original
    // accept-or-drop overlap resolution let the more-specific `Email` win and DISCARDED
    // the whole `Secret` finding — leaking the secret prefix (bytes inside a *detected*
    // finding) raw into the masked output. The trim fix masks both.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    // userinfo@host: one entropy Secret over the whole token, one Email over the tail.
    let secret_prefix = "Zx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We";
    let input = Input {
        buf: format!("credential {secret_prefix}@ops.example.com in the log").into_bytes(),
        hint: ArtefactHint::default(),
    };

    // Preconditions: this really is a partial overlap between a Secret and an Email
    // finding (if detector behavior shifts, the test must fail loudly, not vacuously).
    let findings = with_real_context(|ctx| scan(&input, ctx));
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Secret),
        "fixture must trigger an entropy Secret finding, got {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Email),
        "fixture must trigger an Email finding, got {findings:?}"
    );

    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    assert!(
        !pack.text.contains(secret_prefix),
        "the secret prefix of a partially-overlapped finding leaked raw: {}",
        pack.text
    );
    assert!(
        !pack.text.contains("ops.example.com"),
        "the email portion must be masked too: {}",
        pack.text
    );
}

#[test]
fn ordinals_read_in_document_order_and_mapping_refs_are_deduped() {
    // Doubt-pass Low fixes, locked: (a) vault ordinals mint top-to-bottom (the FIRST
    // email in the buffer is EMAIL_001 — back-to-front interning minted them in reverse
    // reading order); (b) a value repeated N times contributes its MappingRef once.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: b"first.contact@example.com then second.contact@example.com then first.contact@example.com".to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, mapping_refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    let pos_1 = pack.text.find("EMAIL_001").expect("EMAIL_001 in text");
    let pos_2 = pack.text.find("EMAIL_002").expect("EMAIL_002 in text");
    assert!(
        pos_1 < pos_2,
        "EMAIL_001 must be the first email in document order: {}",
        pack.text
    );
    // first.contact appears twice → same placeholder both times, ref listed once.
    assert_eq!(pack.text.matches("EMAIL_001").count(), 2, "{}", pack.text);
    assert_eq!(
        mapping_refs.len(),
        2,
        "two unique values → exactly two deduped refs, got {mapping_refs:?}"
    );
}

/// A test-only detector emitting a crafted finding set: one wide `Secret` span with two
/// `Email` findings strictly inside it — the shape that splits the losing `Secret` into
/// THREE fragments during overlap trimming.
struct FragmentBait;

impl Detector for FragmentBait {
    fn id(&self) -> DetectorId {
        DetectorId("fragment-bait".to_string())
    }
    fn detect(&self, _buf: &[u8], _spans: &[Span]) -> Vec<Finding> {
        let f = |ty: EntityType, start: usize, end: usize| Finding {
            entity_type: ty,
            span: Span {
                start,
                end,
                node_kind: None,
            },
            confidence: 0.9,
            detector: self.id(),
        };
        vec![
            f(EntityType::Secret, 0, 30),
            f(EntityType::Email, 5, 10),
            f(EntityType::Email, 20, 25),
        ]
    }
    fn entity_types(&self) -> &[EntityType] {
        &[EntityType::Secret, EntityType::Email]
    }
}

#[test]
fn scan_event_counts_raw_detections_not_overlap_fragments() {
    // Codex round-2 regression: detection counts were taken AFTER overlap trimming, so a
    // Secret span split around two accepted Email winners (fragments 0..5, 10..20,
    // 25..30) recorded THREE Secret "detections" for one detector hit. The Scan event
    // must count what detection actually reported: Secret=1, Email=2.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: b"0123456789abcdefghijklmnopqrstuvwxyz".to_vec(),
        hint: ArtefactHint::default(),
    };
    let bait = FragmentBait;
    let detectors: Vec<&dyn Detector> = vec![&bait];
    let ctx = Context {
        parsers: &[],
        detectors: &detectors,
    };
    let (_pack, _refs, event, _trace_id) = mask(&input, &ctx, &policy, &ns).expect("mask succeeds");

    match event {
        AuditEvent::Scan { counts, .. } => {
            assert_eq!(
                counts.0.get(&EntityType::Secret),
                Some(&1),
                "one raw Secret detection must count once, not per fragment: {counts:?}"
            );
            assert_eq!(counts.0.get(&EntityType::Email), Some(&2), "{counts:?}");
        }
        other => panic!("expected a Scan event, got {other:?}"),
    }
}

#[test]
fn detection_latency_recorded_in_the_scan_event_is_within_the_25ms_budget() {
    // The contract's 25ms p95 budget was previously only enforced at 12x slack on
    // e2e wall clock (doubt-pass finding). The detect-only portion `mask` itself
    // measures excludes vault/audit I/O by construction, so it can be held to the real
    // budget deterministically via the Scan event it emits.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: mixed_fixture().repeat(50).into_bytes(),
        hint: ArtefactHint::default(),
    };
    let (_pack, _refs, event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    match event {
        AuditEvent::Scan { latency_us, .. } => assert!(
            latency_us <= 25_000,
            "detection latency {latency_us}us exceeds the 25ms budget"
        ),
        other => panic!("expected a Scan event, got {other:?}"),
    }
}
