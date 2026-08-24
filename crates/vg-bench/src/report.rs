//! The Go/No-Go report: an isolated [`Harness`] over the real pipeline, the six banked
//! measurements T10 owns, and a redaction-safe rendering.
//!
//! **Isolation.** The harness builds its own throwaway state dir (temp vault + audit + the
//! shipped `DEFAULT_GLOBAL_POLICY`) so benchmarking never touches a real vault or audit log,
//! and results are reproducible run-to-run. The display-collision round-trips each use a
//! *fresh* harness so the minted ordinals are deterministic regardless of sample order.
//!
//! **Redaction discipline (the tool measures what it must itself satisfy).** No raw detected
//! value is ever placed in the report. Every field below is a count, rate, ref, sample name,
//! or placeholder-shaped decoy — never a labelled value or a masked secret.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use vg_adapters_claude::{DEFAULT_GLOBAL_POLICY, STATE_DIR_ENV, VAULT_KEY_ENV};
use vg_audit::JsonlAuditSink;
use vg_core::{
    benchmark, mask, rehydrate, scan, spans_overlap, Actor, ActorId, Context, Destination,
    Detector, EntityType, Finding, HandlingClass, MaskedPack, Metrics, Namespace, Parser, Policy,
    PolicyEngine, PolicyLayers, RepoId, Span,
};
use vg_detectors::all_detectors;
use vg_parsers::all_parsers;
use vg_policy::LayeredPolicyEngine;
use vg_vault::{Vault, VaultConfig};

use crate::corpus::{LabelledCorpus, LabelledSample};

/// Fixed 32-byte key so the harness vault never touches the OS keychain. Test/CI seam only.
const HARNESS_KEY: [u8; 32] = [0x2a; 32];

/// Go thresholds from `docs/spec/requirements-and-design-spec.md` "Go/No-Go Criteria".
const SECRET_RECALL_GATE: f64 = 0.99;
const PII_RECALL_GATE: f64 = 0.95;
const FP_RATE_GATE: f64 = 0.03;
const CONSISTENCY_GATE: f64 = 0.99;
const P95_LATENCY_GATE_US: u64 = 50_000;
/// The documented in-process detection budget (interface-contracts.md: p95 < 25 ms).
const IN_PROCESS_P95_GATE_US: u64 = 25_000;

/// Options for a report run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Path to the `vg` binary for the cold-hook e2e latency measurement. `None` skips it
    /// (a library-only run has no binary to spawn).
    pub hook_binary: Option<PathBuf>,
    /// Timed cold-`vg hook` invocations (after one untimed warm-up that creates the vault).
    pub hook_iterations: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            hook_binary: None,
            hook_iterations: 30,
        }
    }
}

/// The isolated pipeline the harness scores through — mirrors `vg-adapters-claude`'s `Engine`
/// wiring but over a throwaway state dir and with no keychain/env seam.
struct Harness {
    _tmp: tempfile::TempDir,
    policy: Policy,
    detectors: Vec<Box<dyn Detector>>,
    parsers: Vec<Box<dyn Parser>>,
    ns: Namespace,
}

impl Harness {
    fn open() -> Result<Self, ReportError> {
        let tmp = tempfile::tempdir().map_err(|e| ReportError::Setup(e.to_string()))?;
        let global = tmp.path().join("global.policy.json");
        std::fs::write(&global, DEFAULT_GLOBAL_POLICY)
            .map_err(|e| ReportError::Setup(e.to_string()))?;
        let engine = LayeredPolicyEngine::load(PolicyLayers {
            global,
            repo: None,
            session: None,
        })
        .map_err(|e| ReportError::Setup(e.to_string()))?;
        let vault =
            Vault::open_with_key(VaultConfig::new(tmp.path().join("vault.db")), HARNESS_KEY)
                .map_err(|e| ReportError::Setup(e.to_string()))?;
        let audit = JsonlAuditSink::open(tmp.path().join("audit.jsonl"))
            .map_err(|e| ReportError::Setup(e.to_string()))?;
        Ok(Self {
            _tmp: tmp,
            policy: Policy {
                engine: Box::new(engine),
                vault: Box::new(vault),
                audit: Box::new(audit),
            },
            detectors: all_detectors(),
            parsers: all_parsers(),
            ns: Namespace::Repo(RepoId("vg-bench-seeded-corpus".to_string())),
        })
    }

    fn with_context<R>(&self, f: impl FnOnce(&Context) -> R) -> R {
        let dets: Vec<&dyn Detector> = self.detectors.iter().map(|d| d.as_ref()).collect();
        let pars: Vec<&dyn Parser> = self.parsers.iter().map(|p| p.as_ref()).collect();
        let ctx = Context {
            parsers: &pars,
            detectors: &dets,
        };
        f(&ctx)
    }

    fn scan_sample(&self, sample: &LabelledSample) -> Vec<Finding> {
        self.with_context(|ctx| scan(&sample.input, ctx))
    }

    fn mask_sample(&self, sample: &LabelledSample) -> Result<MaskedPack, ReportError> {
        self.with_context(|ctx| mask(&sample.input, ctx, &self.policy, &self.ns))
            .map(|(pack, _, _, _)| pack)
            .map_err(|e| ReportError::Mask(e.to_string()))
    }

    fn classify(&self, ty: &EntityType) -> HandlingClass {
        self.policy.engine.classify_entity(ty.clone())
    }

    /// True for a type the policy would actually mask or redact (a `Pass` type leaves the
    /// value raw, so it does not "protect" anything).
    fn is_protected(&self, ty: &EntityType) -> bool {
        matches!(
            self.classify(ty),
            HandlingClass::Mask | HandlingClass::IrreversibleRedact
        )
    }
}

/// Two byte spans overlap when each starts before the other ends.
/// A detected finding matches a label when the entity types are equal and the spans overlap.
fn matches_label(detected: &Finding, label: &Finding) -> bool {
    detected.entity_type == label.entity_type && spans_overlap(&detected.span, &label.span)
}

// ----- the report -----

/// The full Go/No-Go report.
#[derive(Debug, Clone)]
pub struct Report {
    pub sample_count: usize,
    /// Headline frozen-API metrics. `p95_latency_us` is always the in-process detection
    /// p95; the cold-hook e2e figure lives in [`ColdHook`].
    pub metrics: Metrics,
    /// The in-process `scan` p95 (µs) `benchmark` measured, always present.
    pub in_process_p95_us: u64,
    pub secret_recall: Recall,
    pub pii_recall: Recall,
    pub zero_raw_pii: ZeroRawPii,
    pub consistency: Consistency,
    pub detector_fp: Vec<DetectorFp>,
    pub collisions: Vec<CollisionResult>,
    pub dotenv_no_hint: Vec<DotenvResidual>,
    pub cold_hook: Option<ColdHook>,
    pub dead_policy_branches: Vec<DeadBranch>,
    /// Structural guards (doubt-pass): checks that a slice's *mechanism* fired, not just
    /// that its values were detected — the artefact Block actually blocking, masked JSON
    /// still parsing.
    pub structural: Vec<StructuralCheck>,
    pub gates: Vec<Gate>,
}

/// One structural pass/fail check tied to a named sample.
#[derive(Debug, Clone)]
pub struct StructuralCheck {
    pub name: String,
    pub sample: String,
    pub passed: bool,
}

/// Recall over a set of labels: matched / total.
#[derive(Debug, Clone, Copy)]
pub struct Recall {
    pub matched: usize,
    pub total: usize,
}
impl Recall {
    fn rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.matched as f64 / self.total as f64
        }
    }
}

/// Banked #2: the zero-raw-PII property over every sample.
#[derive(Debug, Clone)]
pub struct ZeroRawPii {
    pub checked: usize,
    /// Sample names where a masked/redacted labelled value survived into the mask output.
    pub violations: Vec<String>,
}

/// Placeholder-stability: unique masked values that mint one stable placeholder.
#[derive(Debug, Clone, Copy)]
pub struct Consistency {
    pub stable: usize,
    pub total: usize,
}
impl Consistency {
    fn rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.stable as f64 / self.total as f64
        }
    }
}

/// Banked #1: false positives for one detector across the corpus.
#[derive(Debug, Clone)]
pub struct DetectorFp {
    pub detector: String,
    pub total: usize,
    pub false_positives: usize,
    /// FPs on the benign-lookalike slice only — an un-dilutable numerator (any finding
    /// there is an FP by construction; more true positives elsewhere cannot improve it).
    pub benign_slice_fp: usize,
}
impl DetectorFp {
    pub(crate) fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.false_positives as f64 / self.total as f64
        }
    }
}

/// Banked #3: one display-collision round-trip.
#[derive(Debug, Clone)]
pub struct CollisionResult {
    pub sample: String,
    pub decoys: Vec<String>,
    /// True when at least one decoy equals a display the pack actually minted (the
    /// collision condition genuinely existed for this sample).
    pub decoy_minted: bool,
    /// True when a coincidental placeholder-shaped literal was corrupted by demask.
    pub corrupted: bool,
}

/// Banked #4: dotenv-shaped content with no path hint — what entity detection alone caught.
#[derive(Debug, Clone)]
pub struct DotenvResidual {
    pub sample: String,
    pub labelled_caught: usize,
    pub labelled_total: usize,
    /// Sensitive values only an artefact-level Block would catch — undetectable by entity
    /// detectors and unprotected here (count only; values withheld).
    pub residual: usize,
}

/// Banked #5: cold `vg hook` end-to-end latency (µs), binary-level.
#[derive(Debug, Clone)]
pub struct ColdHook {
    pub iterations: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub max_us: u64,
}

/// Banked #6: a policy branch that can never fire.
#[derive(Debug, Clone)]
pub struct DeadBranch {
    pub selector: String,
    pub keys: Vec<String>,
    pub reason: String,
}

/// One Go/No-Go gate outcome.
#[derive(Debug, Clone)]
pub struct Gate {
    pub name: String,
    pub criterion: String,
    pub measured: String,
    /// `Some(true/false)` = measured pass/fail; `None` = not evaluated by this harness.
    pub passed: Option<bool>,
}

/// Overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Go,
    NoGo,
    Incomplete,
}

impl Report {
    /// Run every measurement over `corpus` and assemble the report.
    pub fn generate(corpus: &LabelledCorpus, opts: &Options) -> Result<Report, ReportError> {
        let harness = Harness::open()?;
        let sample_count = corpus.samples.len();

        // Headline metrics through the frozen API (v1.4: benchmark(corpus, ctx, policy)).
        let core_corpus = corpus.to_core_corpus();
        let metrics = harness.with_context(|ctx| benchmark(&core_corpus, ctx, &harness.policy));
        let in_process_p95_us = metrics.p95_latency_us;

        let (secret_recall, pii_recall) = recall_split(&harness, corpus);
        let zero_raw_pii = zero_raw_pii(&harness, corpus)?;
        let consistency = placeholder_consistency(&harness, corpus)?;
        let detector_fp = detector_false_positives(&harness, corpus);
        let collisions = display_collisions(corpus)?;
        let dotenv_no_hint = dotenv_residuals(&harness, corpus);
        let dead_policy_branches = dead_policy_branches();

        let cold_hook = match &opts.hook_binary {
            Some(bin) => Some(measure_cold_hook(bin, opts.hook_iterations)?),
            None => None,
        };

        // `metrics.p95_latency_us` is ALWAYS the in-process figure (doubt-pass: a field
        // whose meaning flips with a CLI flag is unusable programmatically); the cold-hook
        // e2e p95 lives in `cold_hook` and its own gate.
        let structural = structural_checks(&harness, corpus)?;
        let gates = build_gates(
            &metrics,
            secret_recall,
            pii_recall,
            &zero_raw_pii,
            consistency,
            cold_hook.as_ref().map(|ch| ch.p95_us),
            &structural,
        );

        Ok(Report {
            sample_count,
            metrics,
            in_process_p95_us,
            secret_recall,
            pii_recall,
            zero_raw_pii,
            consistency,
            detector_fp,
            collisions,
            dotenv_no_hint,
            cold_hook,
            dead_policy_branches,
            structural,
            gates,
        })
    }

    /// The overall verdict: No-Go if any measured gate failed, Incomplete if any gate could
    /// not be measured (and none failed), else Go.
    pub fn verdict(&self) -> Verdict {
        if self.gates.iter().any(|g| g.passed == Some(false)) {
            Verdict::NoGo
        } else if self.gates.iter().any(|g| g.passed.is_none()) {
            Verdict::Incomplete
        } else {
            Verdict::Go
        }
    }
}

/// Per-type recall, split into Secret (the ≥99% gate) vs other PII/enterprise IDs (≥95%).
/// A label is recalled only if a detector finds it AND the policy masks/redacts its type.
fn recall_split(harness: &Harness, corpus: &LabelledCorpus) -> (Recall, Recall) {
    let mut secret = Recall {
        matched: 0,
        total: 0,
    };
    let mut pii = Recall {
        matched: 0,
        total: 0,
    };
    for sample in &corpus.samples {
        let detected = harness.scan_sample(sample);
        for label in &sample.expected {
            let bucket = if label.entity_type == EntityType::Secret {
                &mut secret
            } else {
                &mut pii
            };
            bucket.total += 1;
            let caught = harness.is_protected(&label.entity_type)
                && detected.iter().any(|d| matches_label(d, label));
            if caught {
                bucket.matched += 1;
            }
        }
    }
    (secret, pii)
}

/// Banked #2: mask every sample and assert every masked/redacted labelled value is absent
/// from the mask output.
fn zero_raw_pii(harness: &Harness, corpus: &LabelledCorpus) -> Result<ZeroRawPii, ReportError> {
    let mut violations = Vec::new();
    for sample in &corpus.samples {
        let pack = harness.mask_sample(sample)?;
        let protected: Vec<&str> = sample
            .expected_values
            .iter()
            .filter(|(ty, _)| harness.is_protected(ty))
            .map(|(_, value)| value.as_str())
            .collect();
        // The mandated conformance check (doubt-pass High: the hand-rolled `text.contains`
        // missed `policy_version` and every `bindings[].display` — fields serialized toward
        // callers). Run under a silenced panic hook so a violating assert can never print
        // the raw value to stderr; the violation is reported by sample name only.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vg_core::conformance::assert_masked_pack_excludes_raw_values(&pack, &protected);
        }))
        .is_ok();
        std::panic::set_hook(prev_hook);
        if !ok {
            violations.push(sample.name.clone());
        }
    }
    Ok(ZeroRawPii {
        checked: corpus.samples.len(),
        violations,
    })
}

/// Placeholder stability: for each unique masked labelled value, mask `"{v}\n{v}"` and check
/// both occurrences mint the same placeholder. The separator is a NEWLINE: the original
/// `|` probe was swallowed by the email detector (`|` is legal RFC-5322 atext, so
/// `a@x.com|a@x.com` scans as one two-email span pair with different raw values — the
/// doubt-pass proved the resulting 66.7% "instability" was a harness artifact, not a
/// product defect). No detector's charset crosses a newline. Directly exercises `mask`'s
/// HMAC-stable keying.
fn placeholder_consistency(
    harness: &Harness,
    corpus: &LabelledCorpus,
) -> Result<Consistency, ReportError> {
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut c = Consistency {
        stable: 0,
        total: 0,
    };
    for sample in &corpus.samples {
        for (ty, value) in &sample.expected_values {
            if !harness.is_protected(ty) || seen.insert(value.clone(), ()).is_some() {
                continue;
            }
            let probe = LabelledSample {
                name: String::new(),
                description: String::new(),
                input: vg_core::Input {
                    buf: format!("{value}\n{value}").into_bytes(),
                    hint: Default::default(),
                },
                expected: Vec::new(),
                expected_values: Vec::new(),
                slices: Vec::new(),
                decoys: Vec::new(),
                residual_secrets: Vec::new(),
            };
            let pack = harness.mask_sample(&probe)?;
            // Only values that mint a binding measure placeholder stability: an
            // irreversibly-redacted value collapses both probe halves to the same
            // `[REDACTED:*]` marker and would inflate the gate without any placeholder
            // existing (Codex round-2 High).
            if pack.bindings.is_empty() {
                continue;
            }
            c.total += 1;
            if let Some((left, right)) = pack.text.split_once('\n') {
                if left == right && pack.bindings.iter().any(|b| b.display == left) {
                    c.stable += 1;
                }
            }
        }
    }
    Ok(c)
}

/// Banked #1: per-detector false positives across the whole corpus. A raw `scan` finding is
/// a false positive when it overlaps **no** expected label of any type (an entropy `Secret`
/// over a real email overlaps the `Email` label, so it is not counted against entropy — it
/// caught something sensible, just typed it generically).
fn detector_false_positives(harness: &Harness, corpus: &LabelledCorpus) -> Vec<DetectorFp> {
    let mut totals: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for sample in &corpus.samples {
        let benign_slice = sample.slices.iter().any(|s| s == "benign-lookalike");
        let detected = harness.scan_sample(sample);
        for finding in &detected {
            let entry = totals
                .entry(finding.detector.0.clone())
                .or_insert((0, 0, 0));
            entry.0 += 1;
            let overlaps_any = sample
                .expected
                .iter()
                .any(|label| spans_overlap(&finding.span, &label.span));
            if !overlaps_any {
                entry.1 += 1;
                // Codex round-2 High: the corpus-wide rate is dilutable by adding true
                // positives elsewhere; the benign-lookalike-slice FP count is not — any
                // finding there is a false positive by construction.
                if benign_slice {
                    entry.2 += 1;
                }
            }
        }
    }
    totals
        .into_iter()
        .map(|(detector, (total, fp, benign_fp))| DetectorFp {
            detector,
            total,
            false_positives: fp,
            benign_slice_fp: benign_fp,
        })
        .collect()
}

/// Banked #3: mask→demask each display-collision sample in a FRESH harness (deterministic
/// ordinals) and report whether the round-trip corrupted a coincidental placeholder literal.
fn display_collisions(corpus: &LabelledCorpus) -> Result<Vec<CollisionResult>, ReportError> {
    let mut out = Vec::new();
    for sample in corpus.in_slice("display-collision") {
        let harness = Harness::open()?;
        let pack = harness.mask_sample(sample)?;
        let actor = Actor {
            id: ActorId("vg-bench".to_string()),
            roles: vec!["developer".to_string()],
        };
        // Slice precondition (doubt-pass): round-trip fidelity is only a collision signal
        // when nothing in the sample is irreversibly redacted — a redacted value alone
        // makes restored != content for a non-collision reason.
        if pack.text.contains("[REDACTED") {
            return Err(ReportError::Setup(format!(
                "display-collision sample {:?} contains an irreversibly-redacted value — \
                 the slice requires reversible-only content",
                sample.name
            )));
        }
        let minted: std::collections::BTreeSet<&str> =
            pack.bindings.iter().map(|b| b.display.as_str()).collect();
        let decoy_minted = sample.decoys.iter().any(|d| minted.contains(d.as_str()));
        let restored = rehydrate(
            &pack,
            &harness.policy,
            &harness.ns,
            Destination::LocalPatch,
            &actor,
        )
        .map_err(|e| ReportError::Rehydrate(e.to_string()))?;
        out.push(CollisionResult {
            sample: sample.name.clone(),
            decoys: sample.decoys.clone(),
            decoy_minted,
            // Round-trip fidelity: mask then demask must reproduce the original exactly.
            // Any difference means a coincidental placeholder-shaped literal was rewritten.
            corrupted: restored != sample.content(),
        });
    }
    // An EMPTY slice is a corpus regression (tags renamed/removed), not a clean result —
    // "0 of 0 corrupted" would be a vacuous pass forever (Codex round-2 High).
    if out.is_empty() {
        return Err(ReportError::Setup(
            "display-collision slice is empty — the corpus lost its collision samples".to_string(),
        ));
    }
    // Mint-format drift guard (doubt-pass Low): if no sample's decoy matches a display the
    // pack actually minted, the slice can no longer produce a collision and would read as
    // a false "clean" forever.
    if !out.iter().any(|c| c.decoy_minted) {
        return Err(ReportError::Setup(
            "display-collision slice: no decoy matches any minted display — mint format \
             drift; the slice has lost its bite"
                .to_string(),
        ));
    }
    Ok(out)
}

/// Banked #4: dotenv-shaped content with no path hint. Reports how many labelled sensitive
/// values entity detection caught, and how many residual values (short/structured secrets)
/// only an artefact-level Block would have caught.
fn dotenv_residuals(harness: &Harness, corpus: &LabelledCorpus) -> Vec<DotenvResidual> {
    let mut out = Vec::new();
    for sample in corpus.in_slice("dotenv-no-hint") {
        let detected = harness.scan_sample(sample);
        let caught = sample
            .expected
            .iter()
            .filter(|label| detected.iter().any(|d| matches_label(d, label)))
            .count();
        // A residual value is one entity detection does not find anywhere in the buffer.
        let residual = sample
            .residual_secrets
            .iter()
            .filter(
                |value| match find_span(&sample.input.buf, value.as_bytes()) {
                    Some(span) => !detected.iter().any(|d| spans_overlap(&d.span, &span)),
                    None => true,
                },
            )
            .count();
        out.push(DotenvResidual {
            sample: sample.name.clone(),
            labelled_caught: caught,
            labelled_total: sample.expected.len(),
            residual,
        });
    }
    out
}

/// First occurrence of `needle` in `haystack`, as a span.
fn find_span(haystack: &[u8], needle: &[u8]) -> Option<Span> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&i| &haystack[i..i + needle.len()] == needle)
        .map(|start| Span {
            start,
            end: start + needle.len(),
            node_kind: None,
        })
}

/// Structural guards (doubt-pass High/Med): the artefact-block sample previously proved
/// nothing (`mask` on a Block artefact returns empty text, so zero-raw-PII passed
/// vacuously and a dead `classify_artefact` would have gone unnoticed), and the
/// json-payload slice's "masking must survive as JSON" property was asserted but never
/// measured.
fn structural_checks(
    harness: &Harness,
    corpus: &LabelledCorpus,
) -> Result<Vec<StructuralCheck>, ReportError> {
    let mut out = Vec::new();
    for sample in corpus.in_slice("artefact-block") {
        let pack = harness.mask_sample(sample)?;
        out.push(StructuralCheck {
            name: "artefact-block-fires".to_string(),
            sample: sample.name.clone(),
            passed: pack.stats.blocked_artefacts > 0,
        });
    }
    for sample in corpus.in_slice("json-payload") {
        let pack = harness.mask_sample(sample)?;
        out.push(StructuralCheck {
            name: "masked-json-still-parses".to_string(),
            sample: sample.name.clone(),
            passed: serde_json::from_str::<serde_json::Value>(&pack.text).is_ok(),
        });
    }
    Ok(out)
}

/// Banked #6: policy branches that can never fire. The default policy's `by_language` rules
/// are unreachable because nothing in the pipeline populates `ArtefactHint.language_id` (the
/// hook/CLI set only `path`, and `classify_artefact` runs before any parser could infer a
/// language — and must, since a Block-classed artefact is refused before it is parsed). So
/// the report flags them explicitly rather than leaving policy that cannot fire.
fn dead_policy_branches() -> Vec<DeadBranch> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(DEFAULT_GLOBAL_POLICY) else {
        return out;
    };
    if let Some(by_lang) = value
        .get("artefacts")
        .and_then(|a| a.get("by_language"))
        .and_then(|m| m.as_object())
    {
        if !by_lang.is_empty() {
            out.push(DeadBranch {
                selector: "artefacts.by_language".to_string(),
                keys: by_lang.keys().cloned().collect(),
                reason: "STATIC CHECK of the shipped default-policy constant (not pipeline \
                         introspection): as of v1.4 no pipeline path populates \
                         ArtefactHint.language_id (hook/CLI set only `path`; \
                         classify_artefact runs before parsing, and must — a Block \
                         artefact is refused before it is parsed). Wire language_id from \
                         parser output post-classification, or drop the branch — and \
                         retire this canned check either way (T11)."
                    .to_string(),
            });
        }
    }
    out
}

/// Banked #5: spawn `bin hook pre-tool-use` cold, `iterations` times (after one untimed
/// warm-up that creates the vault), timing each process end-to-end.
fn measure_cold_hook(bin: &PathBuf, iterations: usize) -> Result<ColdHook, ReportError> {
    let tmp = tempfile::tempdir().map_err(|e| ReportError::Setup(e.to_string()))?;
    let state_dir = tmp.path().join(".veilgremlin");
    let key_hex: String = "2a".repeat(32);
    // A realistic PreToolUse payload with a sensitive value, so the timed path includes real
    // masking, not just a pass-through.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo contact jane.doe@example.com"}}"#;

    let invoke = || -> Result<u64, ReportError> {
        let start = Instant::now();
        let mut child = Command::new(bin)
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("hook")
            .arg("pre-tool-use")
            .env(VAULT_KEY_ENV, &key_hex)
            .env_remove(STATE_DIR_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ReportError::ColdHook(format!("spawn {}: {e}", bin.display())))?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(payload.as_bytes())
            .map_err(|e| ReportError::ColdHook(e.to_string()))?;
        let out = child
            .wait_with_output()
            .map_err(|e| ReportError::ColdHook(e.to_string()))?;
        let elapsed = start.elapsed().as_micros() as u64;
        // Validity check (doubt-pass High): a hook that exits with a usage error in ~1 ms
        // would otherwise report a superb p95 — the timing only counts if the invocation
        // actually masked. The payload is sensitive, so a v1.3 transform (exit 0 +
        // `updatedInput` JSON) is the only valid outcome.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let masked_ok = out.status.success()
            && serde_json::from_str::<serde_json::Value>(&stdout)
                .ok()
                .and_then(|v| {
                    v.get("hookSpecificOutput")
                        .and_then(|h| h.get("updatedInput"))
                        .map(|u| !u.to_string().contains("jane.doe@example.com"))
                })
                .unwrap_or(false);
        if !masked_ok {
            return Err(ReportError::ColdHook(
                "hook invocation did not produce a PARSED masked updatedInput transform \
                 (a substring check would accept an unmasked payload) — timing samples \
                 would be invalid"
                    .to_string(),
            ));
        }
        Ok(elapsed)
    };

    // Warm-up (untimed): first run creates the vault DB + writes the default policy, so the
    // timed runs measure steady-state open+load+mask, not one-time creation.
    invoke()?;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations.max(1) {
        samples.push(invoke()?);
    }
    samples.sort_unstable();
    Ok(ColdHook {
        iterations: samples.len(),
        p50_us: percentile(&samples, 0.50),
        p95_us: percentile(&samples, 0.95),
        max_us: *samples.last().unwrap_or(&0),
    })
}

/// Nearest-rank percentile of a sorted slice.
fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * q).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

fn build_gates(
    metrics: &Metrics,
    secret_recall: Recall,
    pii_recall: Recall,
    zero_raw_pii: &ZeroRawPii,
    consistency: Consistency,
    cold_p95_us: Option<u64>,
    structural: &[StructuralCheck],
) -> Vec<Gate> {
    let pct = |x: f64| format!("{:.1}%", x * 100.0);
    let mut gates = vec![
        Gate {
            name: "zero-raw-PII".to_string(),
            criterion: "no masked/redacted value survives into a mask output (zero)".to_string(),
            measured: format!("{} violation(s)", zero_raw_pii.violations.len()),
            passed: Some(zero_raw_pii.violations.is_empty()),
        },
        Gate {
            name: "secret-recall".to_string(),
            criterion: format!("≥ {}", pct(SECRET_RECALL_GATE)),
            measured: format!(
                "{} ({}/{})",
                pct(secret_recall.rate()),
                secret_recall.matched,
                secret_recall.total
            ),
            passed: Some(secret_recall.rate() >= SECRET_RECALL_GATE),
        },
        Gate {
            name: "pii-recall".to_string(),
            criterion: format!("≥ {}", pct(PII_RECALL_GATE)),
            measured: format!(
                "{} ({}/{})",
                pct(pii_recall.rate()),
                pii_recall.matched,
                pii_recall.total
            ),
            passed: Some(pii_recall.rate() >= PII_RECALL_GATE),
        },
        Gate {
            name: "false-positive-rate".to_string(),
            criterion: format!("< {}", pct(FP_RATE_GATE)),
            measured: pct(metrics.false_positive_rate),
            passed: Some(metrics.false_positive_rate < FP_RATE_GATE),
        },
        Gate {
            name: "placeholder-consistency".to_string(),
            criterion: format!("≥ {}", pct(CONSISTENCY_GATE)),
            measured: format!(
                "{} ({}/{})",
                pct(consistency.rate()),
                consistency.stable,
                consistency.total
            ),
            passed: Some(consistency.rate() >= CONSISTENCY_GATE),
        },
    ];
    // In-process detection budget (doubt-pass: the documented 25 ms budget was gated
    // nowhere, and --no-hook runs had no latency gate at all). Always measurable.
    gates.push(Gate {
        name: "in-process-detect-p95".to_string(),
        criterion: format!("< {} ms (scan, in-process)", IN_PROCESS_P95_GATE_US / 1000),
        measured: format!("{:.1} ms", metrics.p95_latency_us as f64 / 1000.0),
        passed: Some(metrics.p95_latency_us < IN_PROCESS_P95_GATE_US),
    });
    gates.push(Gate {
        name: "structural-checks".to_string(),
        criterion: "artefact Block fires; masked JSON still parses".to_string(),
        measured: format!(
            "{}/{} pass",
            structural.iter().filter(|c| c.passed).count(),
            structural.len()
        ),
        passed: Some(
            structural.iter().all(|c| c.passed)
                && structural.iter().any(|c| c.name == "artefact-block-fires")
                && structural
                    .iter()
                    .any(|c| c.name == "masked-json-still-parses"),
        ),
    });
    gates.push(Gate {
        name: "hot-path-p95".to_string(),
        criterion: format!("< {} ms (cold hook e2e)", P95_LATENCY_GATE_US / 1000),
        measured: match cold_p95_us {
            Some(us) => format!("{:.1} ms", us as f64 / 1000.0),
            None => "not measured (no vg binary supplied)".to_string(),
        },
        passed: cold_p95_us.map(|us| us < P95_LATENCY_GATE_US),
    });
    gates
}

/// Errors from a report run. All messages are redaction-safe (no labelled/masked values).
#[derive(Debug)]
pub enum ReportError {
    Setup(String),
    Mask(String),
    Rehydrate(String),
    ColdHook(String),
    Corpus(crate::corpus::CorpusError),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Setup(e) => write!(f, "harness setup error: {e}"),
            ReportError::Mask(e) => write!(f, "mask error during benchmark: {e}"),
            ReportError::Rehydrate(e) => write!(f, "rehydrate error during collision check: {e}"),
            ReportError::ColdHook(e) => write!(f, "cold-hook latency measurement error: {e}"),
            ReportError::Corpus(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReportError {}

impl From<crate::corpus::CorpusError> for ReportError {
    fn from(e: crate::corpus::CorpusError) -> Self {
        ReportError::Corpus(e)
    }
}
