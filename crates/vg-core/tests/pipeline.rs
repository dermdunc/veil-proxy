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
    Input, Namespace, Parser, Placeholder, Policy, PolicyEngine, PolicyLayers, RepoId, Span,
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
    // The entropy detector also flags two of the email addresses whole; those Secrets are
    // absorbed by their Email findings and counted as handled once each (DDD cycle 5), so
    // handled matches what the Scan event reports detected.
    assert_eq!(pack.stats.counts.0.get(&EntityType::Secret), Some(&3));
    assert_eq!(pack.stats.blocked_artefacts, 0);

    // Reversible masks produced mapping refs; the returned Scan event carries the same
    // counts.
    assert!(!mapping_refs.is_empty());
    match event {
        AuditEvent::Scan { counts, .. } => {
            assert_eq!(counts.0.get(&EntityType::Email), Some(&3));
            assert_eq!(
                counts.0.get(&EntityType::Secret),
                pack.stats.counts.0.get(&EntityType::Secret)
            );
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
fn agent_system_prompt_shapes_are_not_over_masked() {
    // veil-proxy#90 (XREPO-021), both shapes seen live in a real Claude Code system
    // prompt: a model ID's `-YYYYMMDD` suffix was masked as PHONE, and a sentence-final
    // email came out as `EMAIL_001[REDACTED:SECRET]` (the entropy token swallowed the `.`).
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: b"Haiku 4.5: 'claude-haiku-4-5-20251001'. \
The user's email address is fixture.author@example.com. Use it only to identify the user."
            .to_vec(),
        hint: ArtefactHint::default(),
    };
    // Precondition (DDD cycle 2, Codex): the entropy detector really does emit a Secret
    // overlapping the email, so this exercises the fragment drop, not just EmailDetector.
    let findings = with_real_context(|ctx| scan(&input, ctx));
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Secret
            && input.buf[f.span.start..f.span.end].ends_with(b"example.com.")),
        "fixture must trigger an entropy Secret over the email and its `.`, got {findings:?}"
    );

    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");

    assert_eq!(
        pack.text,
        "Haiku 4.5: 'claude-haiku-4-5-20251001'. \
The user's email address is EMAIL_001. Use it only to identify the user."
    );

    // DDD cycle 1 finding: the same stray fragment came from any token-byte punctuation
    // glued to the email, not just `.` -- Markdown bold is common in agent traffic.
    for (raw, want) in [
        (
            "write to fixture.author@example.com! today",
            "write to EMAIL_001! today",
        ),
        (
            "write to **fixture.author@example.com**. today",
            "write to **EMAIL_001**. today",
        ),
    ] {
        let input = Input {
            buf: raw.as_bytes().to_vec(),
            hint: ArtefactHint::default(),
        };
        let (pack, _refs, _event, _trace_id) =
            with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
        assert_eq!(pack.text, want);
    }
}

/// Masks `raw` through the real pipeline and returns the pack text.
fn mask_text(policy: &Policy, ns: &Namespace, raw: &str) -> String {
    let input = Input {
        buf: raw.as_bytes().to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, policy, ns)).expect("mask succeeds");
    pack.text
}

#[test]
fn listed_model_ids_are_not_garbled_in_any_delimiter_shape_seen_in_agent_traffic() {
    // veil-proxy#90 (XREPO-021): the phone detector's regex matches the `5-20251001` tail
    // of a dated Claude model ID. `vg_core::PROTECTED_LITERALS` scrubs bounded occurrences
    // before detection (`scan` and `mask` alike), so none of these shapes -- all seen around
    // model IDs in real agent traffic, or the documented Bedrock/Vertex forms -- changes.
    // (These cases lived in `phone.rs` while the fix was a detector-side shape rule; the
    // detector itself now flags `5-20251001` unconditionally, by design.)
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let phones_in = |raw: &str| -> Vec<Finding> {
        let input = Input {
            buf: raw.as_bytes().to_vec(),
            hint: ArtefactHint::default(),
        };
        with_real_context(|ctx| scan(&input, ctx))
            .into_iter()
            .filter(|f| f.entity_type == EntityType::Phone)
            .collect()
    };
    for raw in [
        "Haiku 4.5: 'claude-haiku-4-5-20251001'. When building",
        "model claude-opus-4-1-20250805 is pinned",
        "claude-sonnet-4-20250514",
        "models/claude-haiku-4-5-20251001/invoke",
        "Use claude-haiku-4-5-20251001\u{2019} for this",
        "the \u{201c}claude-haiku-4-5-20251001\u{201d} model",
        "claude-sonnet-4-5-20250929[1m]",
        "{\\\"model\\\":\\\"claude-haiku-4-5-20251001\\\"}",
        "is it claude-haiku-4-5-20251001?",
        "| claude-haiku-4-5-20251001|",
    ] {
        assert_eq!(mask_text(&policy, &ns, raw), raw, "garbled: {raw:?}");
    }
    // Shapes the ENTROPY detector (unchanged by #90, on main too) redacts whole as a
    // `Secret` -- `anthropic.<id>-v1` has a mixed `v1` segment, so it is not a structured
    // identifier and its 4.25 bits/byte clears the 3.5 threshold; `**<id>**`, `<id>!` and
    // `model=<id>&x=1` likewise. A pre-existing residual tracked in next-actions, not a
    // phone finding: the scrub is neutral on them, pinned here as "no PHONE" only.
    for raw in [
        "anthropic.claude-haiku-4-5-20251001-v1:0",
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "**claude-haiku-4-5-20251001**",
        "?model=claude-haiku-4-5-20251001&x=1",
        "use claude-haiku-4-5-20251001!",
    ] {
        let phones = phones_in(raw);
        assert!(
            phones.is_empty(),
            "scan found a phone in {raw:?}: {phones:?}"
        );
        let text = mask_text(&policy, &ns, raw);
        assert!(!text.contains("PHONE_"), "{raw:?} => {text:?}");
    }
    // Every listed literal, standalone and inside the real system-prompt sentence shape.
    for lit in vg_core::PROTECTED_LITERALS {
        let id = std::str::from_utf8(lit).expect("literals are ASCII");
        for raw in [id.to_string(), format!("Model: '{id}'. When building")] {
            assert_eq!(mask_text(&policy, &ns, &raw), raw, "garbled: {raw:?}");
            let phones = phones_in(&raw);
            assert!(
                phones.is_empty(),
                "scan found a phone in {raw:?}: {phones:?}"
            );
        }
    }
}

#[test]
fn a_number_beside_a_listed_model_id_is_still_masked_and_the_id_is_spliced_from_the_original() {
    // Before the scrub, `<id> 555-1234` (space or `-` joined) was one 16-digit phone
    // candidate the 7-15 digit filter rejected whole, so `555-1234` egressed raw.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    for (raw, want) in [
        (
            "claude-haiku-4-5-20251001 555-1234",
            "claude-haiku-4-5-20251001 PHONE_001",
        ),
        (
            "claude-haiku-4-5-20251001-555-1234",
            "claude-haiku-4-5-20251001-PHONE_001",
        ),
        (
            "call 415-555-1234 about claude-haiku-4-5-20251001.",
            "call PHONE_002 about claude-haiku-4-5-20251001.",
        ),
        // `-` bounds the occurrence, so the neighbour is judged exactly as it is anywhere
        // else: a bare 7-digit run is not a phone to this detector, with or without the ID.
        ("ref-5551234", "ref-5551234"),
        (
            "claude-haiku-4-5-20251001-5551234",
            "claude-haiku-4-5-20251001-5551234",
        ),
        ("ref-555-1234", "ref-PHONE_001"),
    ] {
        assert_eq!(mask_text(&policy, &ns, raw), want, "input {raw:?}");
    }
    // A straddle through an identifier-forming byte is not a bounded occurrence, so the
    // detector still sees `5-20251001` (and the entropy detector the whole token): fails
    // toward masking, nothing of the digits egresses.
    let text = mask_text(&policy, &ns, "claude-haiku-4-5-20251001_ext99");
    assert!(
        text.contains("PHONE_") && !text.contains("20251001"),
        "straddle must stay masked, got {text:?}"
    );

    // `scan` (what the benchmark scores) agrees with `mask` on where the number is.
    let input = Input {
        buf: b"claude-haiku-4-5-20251001-555-1234".to_vec(),
        hint: ArtefactHint::default(),
    };
    let phones: Vec<(usize, usize)> = with_real_context(|ctx| scan(&input, ctx))
        .into_iter()
        .filter(|f| f.entity_type == EntityType::Phone)
        .map(|f| (f.span.start, f.span.end))
        .collect();
    assert_eq!(
        phones,
        vec![(26, 34)],
        "expected exactly `555-1234` flagged"
    );

    // A finding that extends across the scrubbed bytes is still produced (from the
    // scrubbed copy) and the value interned is the ORIGINAL bytes, not the copy's.
    let raw = "mail claude-haiku-4-5-20251001@example.com now";
    let input = Input {
        buf: raw.as_bytes().to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
    assert_eq!(pack.text, "mail EMAIL_001 now");
    let binding = pack
        .bindings
        .iter()
        .find(|b| b.display == "EMAIL_001")
        .expect("EMAIL_001 is bound");
    let resolved = policy
        .vault
        .resolve(
            &Placeholder {
                display: binding.display.clone(),
                mapping_ref: binding.mapping_ref,
            },
            &ns,
        )
        .expect("resolve EMAIL_001");
    assert_eq!(
        resolved.expose_secret(),
        "claude-haiku-4-5-20251001@example.com",
        "the vault must hold the original bytes, never the scrubbed copy's"
    );
}

#[test]
fn unlisted_or_glued_model_id_shapes_fail_toward_masking() {
    // Documented residuals of the exact-literal scrub: anything not byte-identical to a
    // listed ID, or not bounded, is still a phone to the detector. Pinned so a future
    // "helpful" case-fold or fuzzy match is a deliberate decision, not drift.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    for raw in [
        "CLAUDE-HAIKU-4-5-20251001",
        "claude-haiku-4-5-20991231",
        "xclaude-haiku-4-5-20251001",
        "_claude-haiku-4-5-20251001_",
        "caf\u{e9}claude-haiku-4-5-20251001",
        "gpt-4.5-20251001",
    ] {
        assert!(
            mask_text(&policy, &ns, raw).contains("PHONE_"),
            "expected {raw:?} to over-mask (fail-safe)"
        );
    }
}

#[test]
fn only_punctuation_only_trimmed_secret_fragments_are_dropped() {
    // DDD cycle 2: pin both edges of the `resolve_overlaps` exception directly.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();
    let run = |raw: &[u8]| {
        let input = Input {
            buf: raw.to_vec(),
            hint: ArtefactHint::default(),
        };
        let findings = with_real_context(|ctx| scan(&input, ctx));
        let (pack, _refs, _event, _trace_id) =
            with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
        (findings, pack.text)
    };

    // E(i), DDD cycle 3: the dropped `.` fragment still counts as a handled Secret, so the
    // audit trail's detected-vs-handled never reads as an unmasked secret.
    let input = Input {
        buf: b"write to fixture.author@example.com. today".to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
    assert_eq!(pack.text, "write to EMAIL_001. today");
    match event {
        AuditEvent::Scan { counts, .. } => {
            assert_eq!(counts.0.get(&EntityType::Secret), Some(&1), "{counts:?}");
        }
        other => panic!("expected a Scan event, got {other:?}"),
    }
    assert_eq!(
        pack.stats.counts.0.get(&EntityType::Secret),
        Some(&1),
        "{:?}",
        pack.stats.counts
    );

    // DDD cycle 4: `**<email>**` drops two fragments of ONE raw Secret -- counted once.
    let input = Input {
        buf: b"write to **fixture.author@example.com** today".to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
    assert_eq!(pack.text, "write to **EMAIL_001** today");
    match event {
        AuditEvent::Scan { counts, .. } => {
            assert_eq!(counts.0.get(&EntityType::Secret), Some(&1), "{counts:?}");
        }
        other => panic!("expected a Scan event, got {other:?}"),
    }
    assert_eq!(pack.stats.counts.0.get(&EntityType::Secret), Some(&1));

    // A trimmed fragment carrying a digit is still masked.
    let (findings, text) = run(b"write to fixture.author@example.com!1 today");
    assert!(findings.iter().any(|f| f.entity_type == EntityType::Secret));
    assert_eq!(text, "write to EMAIL_001[REDACTED:SECRET] today");

    // An untrimmed, all-punctuation Secret is masked whole.
    let (findings, text) = run(b"token !@#$%^&*+=./-_!@#$%^&*+=./-_ end");
    assert!(
        findings.iter().any(|f| f.entity_type == EntityType::Secret),
        "fixture must trigger an entropy Secret, got {findings:?}"
    );
    assert_eq!(text, "token [REDACTED:SECRET] end");
}

#[test]
fn a_secret_ending_in_punctuation_is_still_masked_whole() {
    // DDD cycle 1 (Codex): a first draft trimmed trailing `.` from every entropy span and
    // so sent a real secret's final byte raw. Only *trimmed* punctuation-only fragments
    // beside a more specific finding may be dropped; an untrimmed Secret is masked whole.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();
    let input = Input {
        buf: br#"{"value":"zQ3v9Lm2Xp7RwT6uYbN8dKfJhC1sEoAi."}"#.to_vec(),
        hint: ArtefactHint::default(),
    };
    let (pack, _refs, _event, _trace_id) =
        with_real_context(|ctx| mask(&input, ctx, &policy, &ns)).expect("mask succeeds");
    assert!(
        pack.text.contains(r#""value":"[REDACTED:SECRET]"}"#),
        "text: {}",
        pack.text
    );
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

/// A `Hostname` finding (a `pass` class in the fixture policy) with a `Secret` that only
/// adds trailing `!!`: the Secret is absorbed, but none of its bytes are replaced.
struct PassBait;

impl Detector for PassBait {
    fn id(&self) -> DetectorId {
        DetectorId("pass-bait".to_string())
    }
    fn detect(&self, _buf: &[u8], _spans: &[Span]) -> Vec<Finding> {
        let f = |entity_type, start, end| Finding {
            entity_type,
            span: Span {
                start,
                end,
                node_kind: None,
            },
            confidence: 0.9,
            detector: self.id(),
        };
        vec![f(EntityType::Secret, 0, 19), f(EntityType::Hostname, 0, 17)]
    }
    fn entity_types(&self) -> &[EntityType] {
        &[EntityType::Secret, EntityType::Hostname]
    }
}

#[test]
fn a_secret_absorbed_by_a_pass_finding_is_not_counted_as_handled() {
    // DDD cycle 5: the absorbed-Secret count must not claim "handled" when the specific
    // finding that absorbed it was passed through raw.
    let dir = TempDir::new().expect("temp dir");
    let (policy, _db_path, _audit_path) = build_policy(dir.path());
    let ns = repo_ns();

    let input = Input {
        buf: b"build.example.org!! rest".to_vec(),
        hint: ArtefactHint::default(),
    };
    let bait = PassBait;
    let detectors: Vec<&dyn Detector> = vec![&bait];
    let ctx = Context {
        parsers: &[],
        detectors: &detectors,
    };
    let (pack, _refs, _event, _trace_id) = mask(&input, &ctx, &policy, &ns).expect("mask succeeds");
    assert_eq!(pack.text, "build.example.org!! rest");
    assert_eq!(
        pack.stats.counts.0.get(&EntityType::Secret),
        None,
        "{:?}",
        pack.stats.counts
    );
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
