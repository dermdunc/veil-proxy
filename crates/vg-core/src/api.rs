//! Library API owned by `vg-core`: `scan`/`mask`/`rehydrate`/`benchmark`, plus the
//! supporting types those signatures need (`Input`, `Context`, `Policy`, `Actor`,
//! `Destination`, `Corpus`, `Metrics`).
//!
//! T02 froze the signatures and implemented the one piece of real logic that does not
//! depend on any Wave B crate: `rehydrate`'s destination hard-deny gate. **T07 (this
//! task) wires the rest**: `scan` (parse → detect) and `mask` (classify artefact →
//! parse → detect → resolve overlaps → classify/mask each entity → audit), composing the
//! Wave B trait objects `vg-core` reaches only through `Context`/`Policy` — see
//! `docs/architecture/agent-factory-plan.md` §3. `vg-core` still does not depend on any
//! implementing crate except as dev-dependencies for the integration tests (the T04
//! precedent); the real detectors/parsers/vault/policy/audit arrive as trait objects.
//!
//! **Contract change (T07, recorded in `docs/architecture/interface-contracts.md` §2):**
//! `mask` gained a `ctx: &Context` parameter — `mask(input, ctx, policy, ns)`. The frozen
//! signature had no way to reach the detectors/parsers `scan` gets via `ctx`, and the
//! sanctioned fix per the contract-change protocol (`agent-factory-plan.md` §6) is an
//! explicit parameter, not smuggling detectors into `Policy` or pre-computing findings.

use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;
use uuid::Uuid;

use crate::audit::AuditEvent;
use crate::error::{MaskError, RehydrateDenied};
use crate::ids::ActorId;
use crate::telemetry::TraceId;
use crate::traits::{
    ArtefactHint, ArtefactKind, AuditSink, Detector, Parser, Placeholder, PolicyEngine, Secret,
    VaultStore,
};
use crate::types::{
    EntityCounts, EntityType, Finding, HandlingClass, MappingRef, MaskStats, MaskedPack, Namespace,
    PlaceholderBinding, Span,
};

/// Raw bytes plus whatever hint the caller already has about their shape.
#[derive(Debug, Clone, Default)]
pub struct Input {
    pub buf: Vec<u8>,
    pub hint: ArtefactHint,
}

/// The detectors and parsers `scan` runs, borrowed as trait objects so `vg-core` never
/// depends on the Wave B crates that implement them.
pub struct Context<'a> {
    pub parsers: &'a [&'a dyn Parser],
    pub detectors: &'a [&'a dyn Detector],
}

/// A resolved policy plus the vault/audit handles `mask` needs to classify, intern, and
/// record its decision. Bundled into one struct (rather than three separate `mask`
/// parameters) because `mask` always needs all three together.
pub struct Policy {
    pub engine: Box<dyn PolicyEngine>,
    pub vault: Box<dyn VaultStore>,
    pub audit: Box<dyn AuditSink>,
}

/// Where a (un)masked value is headed. `RemoteModelPrompt` and `ObservabilitySink` are
/// **hard-deny**: see [`rehydrate`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Destination {
    LocalPatch,
    LocalTestFixture,
    LocalExplanationBuffer,
    RemoteModelPrompt,
    ObservabilitySink,
    /// A demasked model response on its way back to the wrapped client via `vg-proxy`
    /// (masking-proxy plan §10.3 milestone M4) — not hard-deny (it's the whole point of the
    /// proxy: the human sees raw values, "invisible to the user" per the plan's own framing),
    /// and distinct from every existing variant, none of which mean "back to the local
    /// wrapped client that made the original request."
    ProxyResponse,
}

impl Destination {
    /// Stable key for `PolicyEngine::destination_allows_masked_only` lookups —
    /// deliberately a separate type ([`DestinationId`]) from `Destination` itself, since
    /// policy dictionaries key on a stable string, not the richer runtime enum.
    pub fn id(&self) -> DestinationId {
        let s = match self {
            Destination::LocalPatch => "local-patch",
            Destination::LocalTestFixture => "local-test-fixture",
            Destination::LocalExplanationBuffer => "local-explanation-buffer",
            Destination::RemoteModelPrompt => "remote-model-prompt",
            Destination::ObservabilitySink => "observability-sink",
            Destination::ProxyResponse => "proxy-response",
        };
        DestinationId(s.to_string())
    }

    /// True for destinations `rehydrate` denies regardless of actor or `PolicyEngine`
    /// impl — the "hard-deny... regardless of actor" invariant from
    /// `interface-contracts.md` §2. Public so callers (the `vg demask` CLI) can refuse a
    /// hard-deny destination *before* opening the vault/policy at all — the contract says
    /// the refusal must not depend on either being reachable (Codex round-2 finding).
    pub fn is_hard_deny(&self) -> bool {
        matches!(
            self,
            Destination::RemoteModelPrompt | Destination::ObservabilitySink
        )
    }
}

impl Serialize for Destination {
    /// Reuses `Destination::id()`'s existing stable slug rather than a second,
    /// independently-maintained string mapping (`telemetry::edge_event`'s
    /// `DemaskRequestPayload`/`DemaskDecisionPayload` wire shape uses this) — one source
    /// of truth for "what does this destination look like on the wire," policy-lookup
    /// key or telemetry field alike. `Destination` is a closed enum with no raw-string
    /// variant (already verified safe to serialize — see `telemetry::signing`'s module
    /// doc), so this can never leak anything beyond one of the fixed slugs below.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.id().0)
    }
}

/// Lightweight key `PolicyEngine` impls use to look up destination policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DestinationId(pub String);

/// Who is requesting a demask, checked by `PolicyEngine::demask_allowed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub id: ActorId,
    pub roles: Vec<String>,
}

/// A seeded evaluation corpus for `benchmark` (Task T10 populates real corpora).
#[derive(Debug, Clone, Default)]
pub struct Corpus {
    pub samples: Vec<CorpusSample>,
}

#[derive(Debug, Clone)]
pub struct CorpusSample {
    pub input: Input,
    pub expected_findings: Vec<Finding>,
}

/// Go/No-Go metrics, per `agent-factory-plan.md` §8.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Metrics {
    pub recall: f64,
    pub precision: f64,
    pub false_positive_rate: f64,
    pub p95_latency_us: u64,
}

/// Parses `input` with the first applicable parser (spans are enrichment only), then runs
/// **every** detector over the full raw buffer and returns all findings.
///
/// **Spans never gate detection** (T08 review, hard requirement): parser spans are passed
/// through to `Detector::detect` for structure-awareness, but detectors always scan the
/// whole buffer — the two documented YAML under-spanning reproducers (a `#` inside a
/// quoted value; single-quoted flow scalars, see `docs/decisions.md`) would become
/// missed-secret bugs if detection were span-gated.
///
/// Findings lying entirely inside a bounded Claude model ID ([`PROTECTED_LITERALS`]) are
/// removed, and a scrubbed window around each ID may add findings; see `detect`.
pub fn scan(input: &Input, ctx: &Context) -> Vec<Finding> {
    let spans = parser_spans(input, ctx);
    detect(&input.buf, &spans, ctx)
}

/// Detects, classifies, and masks `input` per `policy`: classifies the artefact (blocking
/// its content entirely if the policy says `Block`), scans every non-blocked artefact for
/// entities regardless of its artefact class, resolves overlapping findings, then masks /
/// redacts / passes each entity per its policy class, interning only reversible (`Mask`)
/// values into the vault. Emits one `AuditEvent` (a `Block` for a blocked artefact,
/// otherwise a `Scan`), both writing it via `policy.audit` and returning it.
///
/// The `ctx` parameter is the T07 contract change (see the module doc): without it `mask`
/// could not reach the detectors/parsers `scan` composes.
///
/// **Also returns a freshly-minted `TraceId`** (telemetry roadmap Phase 3,
/// `docs/next-actions.md`) — minted here, internally, on every call, not accepted as a
/// parameter. Verified before choosing that shape: every real call site in the workspace
/// (`Engine::mask_text` in `vg-adapters-claude`; `crates/vg-core/benches/mask_pipeline.rs`;
/// `Harness::mask_sample` in `crates/vg-bench/src/report.rs` — a doubt-driven-development
/// round caught an earlier version of this comment undercounting the third one) has no
/// other correlation id to supply instead, so accepting one as a parameter would just
/// push the same `Uuid::new_v4()` call up to the caller for no benefit. Not
/// invocation-scoped: a single turn that masks multiple artefacts gets multiple distinct
/// trace ids, one per `mask()` call, not one per invocation — real invocation-level
/// correlation needs a caller-supplied id from somewhere `mask()` itself has no access to
/// (e.g. the hook adapter's own event correlation, unverified and out of scope here). Not
/// a new source of non-determinism in a previously-pure function — `Scan.latency_us`
/// (wall-clock timing, below) already made this function's output caller-observably
/// non-deterministic before this change.
pub fn mask(
    input: &Input,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
) -> Result<(MaskedPack, Vec<MappingRef>, AuditEvent, TraceId), MaskError> {
    let trace_id = TraceId::from(Uuid::new_v4());
    let policy_version = policy.engine.version().to_string();

    // 1. Artefact-level Block FIRST, before the content is parsed or touched at all
    //    (doubt-pass finding: parsing a Block-classed artefact rested on the unstated
    //    assumption that no parser ever copies content into its output — `ArtefactKind::
    //    SourceCode(String)`/`NodeKind::Field(String)` are content-capable by type, and
    //    the CSV parser already clones header names into `Field`. `classify_artefact`
    //    reads only the hint, so checking it first costs nothing and removes the whole
    //    class). The Block event records `ArtefactKind::Unknown`: kind provenance would
    //    require parsing, and not touching blocked content outranks provenance detail.
    if policy.engine.classify_artefact(&input.hint) == HandlingClass::Block {
        let event = AuditEvent::Block {
            artefact: ArtefactKind::Unknown,
            // The shared constant, not a fresh literal: `telemetry::block_reason`'s
            // reason-dictionary lookup matches this exact string, so writing anything
            // else here (even an equivalent-meaning rewording) would silently make this
            // Block unrecognized by EdgeEvent::try_from_audit_event.
            reason: crate::telemetry::block_reason::BlockReason::ARTEFACT_POLICY_BLOCK_TEXT
                .to_string(),
        };
        policy.audit.write(event.clone())?;
        let pack = MaskedPack {
            text: String::new(),
            mapping_refs: Vec::new(),
            bindings: Vec::new(),
            stats: MaskStats {
                counts: EntityCounts::default(),
                blocked_artefacts: 1,
            },
            policy_version,
        };
        return Ok((pack, Vec::new(), event, trace_id));
    }

    // 2. Every non-Block artefact is entity-scanned regardless of its artefact class —
    //    `Pass` means "send after entity masking", never "skip detection" (T06 review,
    //    hard requirement: skipping here would make `Pass` fail open).
    // 3-4. Parse for enrichment spans, then detect: every detector over the FULL buffer
    //    (spans are enrichment only, never a gate — T08 review), via the same `detect`
    //    `scan` uses, so the protected-literal scrub applies identically on both paths.
    let spans = parser_spans(input, ctx);
    let detect_start = Instant::now();
    let mut findings = detect(&input.buf, &spans, ctx);
    let latency_us = detect_start.elapsed().as_micros() as u64;

    // Runtime span guard (doubt-pass finding): `Context` accepts any `&dyn Detector`, and
    // conformance is checked in each implementing crate's own tests, not at this seam. A
    // non-conformant span would panic the slice below (no pack, no audit event — the
    // worst failure shape for a masking tool), and a zero-width span would splice in a
    // phantom placeholder and intern the empty string. Drop both, loudly in debug.
    findings.retain(|f| {
        let ok = f.span.start < f.span.end && f.span.end <= input.buf.len();
        debug_assert!(
            ok || f.span.start == f.span.end,
            "non-conformant detector span {:?} from {:?}",
            f.span,
            f.detector
        );
        ok
    });

    // Detection counts for the Scan audit event come from the RAW findings, before
    // overlap resolution (Codex round-2 fix: resolve_overlaps now emits *fragments*, so
    // counting its output recorded one trimmed `Secret` finding as N detections —
    // corrupting the "what did detection find" audit metric the counts exist to answer).
    let mut detected_counts: BTreeMap<EntityType, usize> = BTreeMap::new();
    for finding in &findings {
        *detected_counts
            .entry(finding.entity_type.clone())
            .or_insert(0) += 1;
    }

    // 5. Resolve overlaps: no byte is masked twice, and a losing finding is trimmed to its
    //    uncovered fragments, never discarded whole. One narrow exception: a short
    //    ASCII-punctuation-only `Secret` fragment beside a more specific finding it lost
    //    to is dropped (and still counted as handled), see `resolve_overlaps`.
    // 6. Classify and intern in FORWARD document order (so vault ordinals read top-to-
    //    bottom: the first email in the buffer is EMAIL_001), collecting replacements;
    //    splices are applied back-to-front afterwards so offsets stay valid.
    let (ordered, absorbed) = resolve_overlaps(&input.buf, findings);

    let mut mapping_refs: Vec<MappingRef> = Vec::new();
    // display → MappingRef for every placeholder minted (contract v1.2). Deduped in lockstep
    // with `mapping_refs`: a value seen N times interns to one placeholder and is recorded
    // once, so `rehydrate` has exactly one binding per distinct minted display.
    let mut bindings: Vec<PlaceholderBinding> = Vec::new();
    let mut handled_counts: BTreeMap<EntityType, usize> = BTreeMap::new();
    let mut replacements: Vec<(Span, String)> = Vec::new();

    // On a mid-pipeline failure, values interned so far are durably in the vault; write a
    // best-effort partial Scan event so the audit trail accounts for them (doubt-pass
    // finding: `?` straight out of the loop left persisted mappings with zero audit
    // record). The best-effort write's own error is ignored — the original error wins.
    let mut intern_error: Option<MaskError> = None;

    for finding in &ordered {
        let ty = finding.entity_type.clone();
        let raw = &input.buf[finding.span.start..finding.span.end];
        // Contract-shape note: `Secret` is a `String` (frozen at T02), so a non-UTF-8
        // span cannot round-trip byte-exactly. Unreachable with the current all-ASCII
        // detectors (every T03 pattern matches pure-ASCII bytes); a future non-ASCII
        // detector needs a contract revisit, recorded in docs/decisions.md.
        let value = String::from_utf8_lossy(raw).into_owned();

        let replacement: Option<String> = match policy.engine.classify_entity(ty.clone()) {
            HandlingClass::Mask => {
                match policy.vault.intern(&Secret::new(value), ty.clone(), ns) {
                    Ok(placeholder) => {
                        // Dedup (doubt-pass finding): a value seen N times returns the
                        // same MappingRef N times; the pack lists each mapping once. The
                        // display↔ref binding is recorded in the same guard so `bindings`
                        // stays 1:1 with `mapping_refs` (contract v1.2).
                        if !mapping_refs.contains(&placeholder.mapping_ref) {
                            mapping_refs.push(placeholder.mapping_ref);
                            bindings.push(PlaceholderBinding {
                                display: placeholder.display.clone(),
                                mapping_ref: placeholder.mapping_ref,
                            });
                        }
                        Some(placeholder.display)
                    }
                    Err(e) => {
                        intern_error = Some(e.into());
                        break;
                    }
                }
            }
            // Never intern: the "irreversible class is never vault-stored" acceptance
            // criterion is tested, not assumed.
            HandlingClass::IrreversibleRedact => Some(redaction_marker(&ty)),
            // Entity-level Block: redact this span only — do not fail the whole artefact
            // for one entity — and count it like any other handled entity.
            HandlingClass::Block => Some(redaction_marker(&ty)),
            // Pass: leave the bytes untouched, and don't count a no-op as handled —
            // it was already counted in detected_counts above (from the RAW findings):
            // the Scan audit event answers "what did detection find", not only "what did
            // we replace" (doubt-pass finding; raw-not-fragment counting per Codex round).
            HandlingClass::Pass => None,
        };

        if let Some(replacement) = replacement {
            *handled_counts.entry(ty).or_insert(0) += 1;
            replacements.push((finding.span.clone(), replacement));
        }
    }

    // A Secret absorbed by more specific findings (covered by them, or its leftover
    // punctuation dropped beside them; see `resolve_overlaps`) counts as handled once, so
    // downstream consumers never read it as an unmasked Secret. Only when its bytes really
    // were replaced: neither its own class nor any specific finding over it is `Pass`
    // (DDD cycle 5). A Secret with any masked fragment is already counted above.
    let is_pass = |ty: &EntityType| {
        matches!(
            policy.engine.classify_entity(ty.clone()),
            HandlingClass::Pass
        )
    };
    for finding in &absorbed {
        let covered_by_pass = ordered.iter().any(|f| {
            f.entity_type != EntityType::Secret
                && f.span.start < finding.span.end
                && finding.span.start < f.span.end
                && is_pass(&f.entity_type)
        });
        if !is_pass(&finding.entity_type) && !covered_by_pass {
            *handled_counts
                .entry(finding.entity_type.clone())
                .or_insert(0) += 1;
        }
    }

    // 7. One `AuditEvent::Scan`: counts are ALL detections (including policy-Passed
    //    ones — the audit trail must be able to answer "what was found"); the pack's
    //    `MaskStats.counts` below are the *handled* subset (what was actually replaced).
    let event = AuditEvent::Scan {
        counts: EntityCounts(detected_counts),
        detector_version: detector_version(ctx),
        latency_us,
    };

    if let Some(err) = intern_error {
        // Doubt-driven-development finding, not fixed here: `trace_id` (minted above) is
        // dropped on every `Err` path, including this one — the one case that most wants
        // it, since the best-effort write just below leaves a *partial* Scan record in
        // the audit log with no id an operator could grep the log for to find it again.
        // Not fixed in this slice: `MaskError`'s variants lean on `#[from]` auto-
        // conversion (`AuditError`/`VaultError`/`PolicyError` via `?`, `crate::error`),
        // which doesn't compose with also carrying a mandatory `trace_id` field without
        // hand-rolling every conversion site — a real, separate redesign, not a
        // trace-id-threading-scoped change. Named here so it isn't silently lost.
        let _ = policy.audit.write(event); // best-effort partial record; original error wins
        return Err(err);
    }
    policy.audit.write(event.clone())?;

    // Apply splices back-to-front so earlier offsets stay valid.
    let mut out = input.buf.clone();
    replacements.sort_by_key(|(span, _)| std::cmp::Reverse(span.start));
    for (span, replacement) in replacements {
        out.splice(span.start..span.end, replacement.into_bytes());
    }
    let text = String::from_utf8_lossy(&out).into_owned();

    let pack = MaskedPack {
        text,
        mapping_refs: mapping_refs.clone(),
        bindings,
        stats: MaskStats {
            counts: EntityCounts(handled_counts),
            blocked_artefacts: 0,
        },
        policy_version,
    };
    Ok((pack, mapping_refs, event, trace_id))
}

/// Spans from the first parser whose `can_parse` claims `input.hint`, or none. Shared by
/// [`scan`] and [`mask`]; the first-match rule mirrors `vg_parsers::all_parsers`'s own
/// documented "caller takes the first `can_parse` match" contract.
fn parser_spans(input: &Input, ctx: &Context) -> Vec<Span> {
    ctx.parsers
        .iter()
        .find(|p| p.can_parse(&input.hint))
        .map(|p| p.parse(&input.buf).spans)
        .unwrap_or_default()
}

/// Runs every detector over the buffer and returns their findings. The one shared
/// detection path for [`scan`] and [`mask`] (the benchmark scores `scan` and the proxy
/// ships `mask`, so the two must never disagree on what is found). Every span is valid for
/// the caller's original bytes, which is what `mask` interns and splices from.
///
/// Protected literals ([`PROTECTED_LITERALS`]) are handled in two steps whose safety does
/// not depend on what any detector does with scrubbed bytes (Codex review of the first
/// scrub design: rewriting the ID's digits for *every* detector changed the entropy of a
/// whole token glued to it, so `<id>=<secret>` could drop below the threshold and leak):
///
/// 1. Every detector runs on the **original** buffer, and only a finding lying entirely
///    inside a bounded protected occurrence is removed. Every other finding `main` made is
///    kept, so the scrub can never hide a byte outside the constant's own bytes.
/// 2. Only when an occurrence exists, every detector also runs over a short window of the
///    `scrub_copy` copy around it (`SCRUB_WINDOW` bytes either side,
///    overlapping windows merged), and a finding from that pass is **added** when it
///    overlaps no occurrence, does not touch a window edge cut out of the middle of the
///    buffer (a truncated token), and is not already fully covered by a same-type finding
///    from step 1 (so audit counts are not inflated). This only ever adds masking: it is
///    what finds `555-1234` in `<id> 555-1234`, where on the original the ID's digits join
///    the number into one 16-digit candidate the phone detector rejects whole.
///
/// `spans` come from the parsers over the *original* buffer (see `parser_spans`); the
/// window pass runs without parser spans, which can only make it find more, not less.
fn detect(buf: &[u8], spans: &[Span], ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    for detector in ctx.detectors {
        findings.extend(detector.detect(buf, spans));
    }
    let occurrences = protected_occurrences(buf);
    if occurrences.is_empty() {
        return findings;
    }
    let inside = |s: &Span| occurrences.iter().any(|&(a, b)| a <= s.start && s.end <= b);
    let overlaps = |s: &Span| occurrences.iter().any(|&(a, b)| s.start < b && a < s.end);
    findings.retain(|f| !inside(&f.span));

    let scrubbed = scrub_copy(buf, &occurrences);
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in &occurrences {
        let lo = start.saturating_sub(SCRUB_WINDOW);
        let hi = (end + SCRUB_WINDOW).min(buf.len());
        match windows.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => windows.push((lo, hi)),
        }
    }
    let mut added = Vec::new();
    for (lo, hi) in windows {
        for detector in ctx.detectors {
            for mut f in detector.detect(&scrubbed[lo..hi], &[]) {
                let cut_edge =
                    (f.span.start == 0 && lo > 0) || (lo + f.span.end == hi && hi < buf.len());
                f.span.start += lo;
                f.span.end += lo;
                let already = findings.iter().any(|o| {
                    o.entity_type == f.entity_type
                        && o.span.start <= f.span.start
                        && f.span.end <= o.span.end
                });
                if !cut_edge && !already && !overlaps(&f.span) {
                    added.push(f);
                }
            }
        }
    }
    findings.extend(added);
    findings
}

/// Byte-exact literals the detectors must never be shown as digits: the dated Claude API
/// model IDs (veil-proxy#90, XREPO-021). A real Claude Code system prompt sends
/// `claude-haiku-4-5-20251001` on every request, and the phone detector's regex matches
/// its `5-20251001` tail (9 digits, a hyphen marker) -- the detector cannot tell that
/// apart from a number by shape: five review cycles of shape rules in `phone.rs` each
/// leaked a real number (`kontakt-030-20150612`, `tel-1-20251001_ext99`, ...), and a
/// listed ID glued to a real number (`claude-haiku-4-5-20251001 555-1234`) made one
/// 16-digit candidate the digit-count filter rejected whole, sending `555-1234` raw. So
/// the fix lives in `vg-core`'s shared detection path, as an exact match on the whole ID
/// (see `detect`).
///
/// **A code constant, deliberately not policy.** A repo- or session-layer list would be an
/// exfiltration primitive: whoever can write that layer (the upstream model is the
/// adversary on the response path, and it can ask the wrapped client to edit files) could
/// list a real value and have detection look away from it. Nothing here is fetched,
/// configurable, or case-folded. Matching is exact, case-sensitive bytes: `CLAUDE-HAIKU-
/// 4-5-20251001` is not a Claude API model ID and still over-masks (fails toward masking).
/// **A new dated model over-masks until it is added here** (`docs/next-actions.md`), as do
/// other providers' dated IDs (`o1-2024-12-17`, `gpt-4.5-20251001`).
///
/// Every entry starts with [`PROTECTED_LITERAL_FIRST_BYTE`] and none is a prefix of
/// another (both unit-tested), which is what lets the scrub's search stay a single pass.
pub const PROTECTED_LITERALS: &[&[u8]] = &[
    b"claude-3-haiku-20240307",
    b"claude-3-opus-20240229",
    b"claude-3-sonnet-20240229",
    b"claude-3-5-sonnet-20240620",
    b"claude-3-5-sonnet-20241022",
    b"claude-3-5-haiku-20241022",
    b"claude-3-7-sonnet-20250219",
    b"claude-sonnet-4-20250514",
    b"claude-opus-4-20250514",
    b"claude-opus-4-1-20250805",
    b"claude-sonnet-4-5-20250929",
    b"claude-haiku-4-5-20251001",
    b"claude-opus-4-5-20251101",
];

/// The byte every [`PROTECTED_LITERALS`] entry starts with: the scrub only tries the
/// literal list at positions holding it, so the per-request cost is one pass over the
/// buffer plus at most `PROTECTED_LITERALS.len()` short prefix compares per `c`.
const PROTECTED_LITERAL_FIRST_BYTE: u8 = b'c';

/// The prefix every [`PROTECTED_LITERALS`] entry shares (unit-tested), checked once before
/// the list is tried.
const PROTECTED_LITERAL_PREFIX: &[u8] = b"claude-";

/// Bytes of scrubbed context the window pass in `detect` gives each side of an
/// occurrence: well over the longest phone candidate the regex can build (about 31
/// bytes), which is the neighbour the window pass exists to find.
const SCRUB_WINDOW: usize = 64;

/// The three-byte UTF-8 encodings of U+2018/U+2019/U+201C/U+201D (`‘ ’ “ ”`): the only
/// non-ASCII bytes that bound a protected literal. Seen around model IDs in real agent
/// traffic (DDD cycle 5 on the shape rules this scrub replaced).
const TYPOGRAPHIC_QUOTES: [&[u8]; 4] = [
    b"\xE2\x80\x98",
    b"\xE2\x80\x99",
    b"\xE2\x80\x9C",
    b"\xE2\x80\x9D",
];

/// Returns a copy of `buf` in which every *bounded* occurrence of a [`PROTECTED_LITERALS`]
/// entry has had its digits overwritten, or `None` when `buf` holds no such occurrence
/// (the common case: no copy, no cost beyond the single scan). The copy is the same
/// length as `buf`, byte-for-byte identical outside the occurrences, so detector offsets
/// found on it address the same bytes of the original.
///
/// **What is overwritten.** Only the literal's ASCII digits, each replaced by the uppercase
/// letter `A` + digit (`claude-haiku-4-5-20251001` → `claude-haiku-E-F-CACFBAAB`). Letters
/// are what no digit-based detector (phone, IP, IBAN, sort code) can match, so no
/// candidate in the copy can borrow the ID's digits. The copy is only ever used by the
/// window pass in `detect`, which can add findings but never remove one, so what the fill
/// does to a glued token's entropy cannot cause a leak (Codex: as the sole detector input
/// it could, in both directions).
///
/// **Bounded.** The byte before the occurrence and the byte after it (when present) are
/// both non-identifier-forming: not an ASCII alphanumeric, not `_`, and not a non-ASCII
/// byte -- except that the four typographic quotes (`TYPOGRAPHIC_QUOTES`) count as bounds.
/// So `-`, `.`, `/`, `\`, `@`, `[`, `*`, `=`, `?`, `&`, `|` and every ASCII quote or
/// bracket bound an occurrence; `claude-haiku-4-5-20251001_ext99`, `…20251001x`,
/// `…202510019`, `xclaude-…` and `caféclaude-…` are not occurrences and still over-mask
/// (fail-safe). Why `-` and `.` bound even though each continues a phone candidate
/// (`5-20251001-5551234`): Bedrock writes `anthropic.<id>-v1:0`, and what the detectors
/// then see for the neighbour (`-5551234`) is exactly what they see for that neighbour
/// anywhere else in the text. A finding made on the original that extends past the
/// occurrence is always kept (`detect` step 1). The window pass is what finds `555-1234`
/// in `<id>-555-1234` (one 16-digit candidate on the original, rejected whole, so it
/// egressed raw before); `<id>-5551234` stays unchanged, as `ref-5551234` does, because
/// the phone detector declines a bare 7-digit run everywhere. Non-ASCII bytes are
/// identifier-forming for the same reason `phone.rs`'s word-boundary checks treat them so
/// (the last byte of `é` is not a word boundary); the four quotes are the exception
/// because they are the one non-ASCII neighbour real agent traffic puts beside a model ID,
/// and a quote glyph is never part of a value the ID could be hiding.
///
/// Cost: one pass over `buf`; at each `PROTECTED_LITERAL_FIRST_BYTE` at most
/// `PROTECTED_LITERALS.len()` prefix compares, each failing within a few bytes on
/// non-matching text; the copy is made lazily on the first occurrence.
#[cfg(test)]
fn scrub_protected_literals(buf: &[u8]) -> Option<Vec<u8>> {
    let occurrences = protected_occurrences(buf);
    (!occurrences.is_empty()).then(|| scrub_copy(buf, &occurrences))
}

/// The `[start, end)` byte ranges of every bounded protected-literal occurrence in `buf`,
/// in ascending, non-overlapping order. One pass; the literal list is only tried where
/// the shared `PROTECTED_LITERAL_PREFIX` matches, so adversarial input (a run of `c`
/// bytes, Codex review) costs one short compare per byte rather than one per literal.
fn protected_occurrences(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] != PROTECTED_LITERAL_FIRST_BYTE || !buf[i..].starts_with(PROTECTED_LITERAL_PREFIX)
        {
            i += 1;
            continue;
        }
        // No entry is a prefix of another (unit-tested), so at most one can match here.
        let hit = PROTECTED_LITERALS
            .iter()
            .find(|lit| buf[i..].starts_with(lit))
            .map(|lit| i + lit.len());
        match hit {
            Some(end) if bounded_left(buf, i) && bounded_right(buf, end) => {
                out.push((i, end));
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

/// `buf` with the ASCII digits of each occurrence overwritten (`A` + digit); same length.
fn scrub_copy(buf: &[u8], occurrences: &[(usize, usize)]) -> Vec<u8> {
    let mut copy = buf.to_vec();
    for &(start, end) in occurrences {
        for b in &mut copy[start..end] {
            if b.is_ascii_digit() {
                *b = b'A' + (*b - b'0');
            }
        }
    }
    copy
}

/// Identifier-forming: a byte that continues a word/identifier rather than ending it.
/// ASCII alphanumerics, `_`, and every non-ASCII byte (a multi-byte character is never
/// a boundary, with the typographic-quote exception handled by the callers).
fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || !b.is_ascii()
}

/// Whether a protected literal starting at `start` is bounded on the left: start of
/// input, a non-identifier ASCII byte, or a typographic quote ending right there.
fn bounded_left(buf: &[u8], start: usize) -> bool {
    start == 0
        || !is_identifier_byte(buf[start - 1])
        || TYPOGRAPHIC_QUOTES.iter().any(|q| buf[..start].ends_with(q))
}

/// Whether a protected literal ending at `end` is bounded on the right: end of input, a
/// non-identifier ASCII byte, or a typographic quote starting right there.
fn bounded_right(buf: &[u8], end: usize) -> bool {
    end == buf.len()
        || !is_identifier_byte(buf[end])
        || TYPOGRAPHIC_QUOTES.iter().any(|q| buf[end..].starts_with(q))
}

/// Resolves overlapping findings so no two accepted findings cover the same bytes — and,
/// apart from the one narrow exception below, no detected byte is ever dropped: the more
/// specific entity type wins over the generic
/// entropy `Secret`, and among equally specific findings the longer span wins (T03's docs
/// anticipate exactly the `Email`-over-`Secret` case). A losing finding is **trimmed to
/// its fragments not covered by higher-priority findings**, never discarded whole.
///
/// The trim (vs. the original accept-or-drop) is a doubt-pass High fix: the entropy
/// detector's own documented tokenizer residual merges a secret with an adjacent
/// email/host into one `Secret` span (`user-secret@host` shapes); accept-or-drop let the
/// `Email` tail win and silently discarded the `Secret` head — bytes inside a *detected*
/// finding surviving raw into the masked output. Trimming masks both: the email as
/// `EMAIL_NNN`, the uncovered head as its own `Secret` fragment.
///
/// **One narrow exception (veil-proxy#90, XREPO-021):** a `Secret` fragment of at most
/// `MAX_DROPPED_PUNCTUATION` bytes, made only of ASCII punctuation, is dropped rather than
/// masked, when the `Secret` lost bytes to a *more specific* (non-`Secret`) finding. The entropy tokenizer counts `.`/`!`/`*` etc.
/// as token bytes, so `<email>.` or `**<email>**` became one `Secret` whose leftover
/// punctuation was masked as its own `[REDACTED:SECRET]` beside `EMAIL_001` -- seen live
/// in a real Claude Code system prompt. An untrimmed `Secret` is always masked whole; a
/// `Secret` trimmed only by another `Secret` keeps every fragment; any fragment holding a
/// byte that is not ASCII punctuation (letter, digit, whitespace, control, non-ASCII) is
/// always masked. The fragment must also share a boundary with one of the specific
/// findings this `Secret` lost bytes to, not merely with any specific finding (DDD cycles
/// 4 and 5). A `Secret` with no kept fragment after losing to specific findings -- every
/// fragment dropped, or none left because they covered it exactly -- is returned
/// separately, once, so the caller can count it as handled exactly once (otherwise the
/// audit trail would show a detected-but-unhandled Secret, or count one Secret twice).
/// **Accepted residual:** up to 3 ASCII-punctuation bytes glued to *any* more specific
/// finding (email, phone, IP, IBAN -- including a false positive inside a real secret),
/// before or after it, now egress raw: `!#$<email>`, `<email>!!$` (a password shaped like
/// `Tr0ub4dor&3xK@horse.battery!!$` loses its last 3 bytes); longer runs stay masked.
///
/// Returned findings (both lists) are sorted in forward document order (ascending span
/// start), which the caller relies on for top-to-bottom vault ordinal minting.
fn resolve_overlaps(buf: &[u8], mut findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    findings.sort_by(|a, b| {
        specificity(&b.entity_type)
            .cmp(&specificity(&a.entity_type))
            .then((b.span.end - b.span.start).cmp(&(a.span.end - a.span.start)))
            // Stable, deterministic tiebreak so the resolution never depends on detector
            // ordering.
            .then(a.span.start.cmp(&b.span.start))
            .then(a.entity_type.cmp(&b.entity_type))
    });

    let mut accepted: Vec<Finding> = Vec::new();
    let mut absorbed: Vec<Finding> = Vec::new();
    for finding in findings {
        // Subtract every already-accepted interval from this finding's span; keep each
        // surviving fragment as a finding of the same type. An exact duplicate (or a
        // fully-covered lower-priority finding) yields no fragments and drops out — that
        // is the "never double-mask" half of the contract.
        let mut fragments = vec![(finding.span.start, finding.span.end)];
        // Indices into `accepted` of the more specific findings this one lost bytes to.
        let mut winners: Vec<usize> = Vec::new();
        for (idx, acc) in accepted.iter().enumerate() {
            let mut next = Vec::new();
            for (start, end) in fragments {
                if acc.span.start >= end || acc.span.end <= start {
                    next.push((start, end)); // no overlap with this accepted span
                } else {
                    if specificity(&acc.entity_type) > specificity(&finding.entity_type)
                        && !winners.contains(&idx)
                    {
                        winners.push(idx);
                    }
                    if start < acc.span.start {
                        next.push((start, acc.span.start)); // fragment left of the winner
                    }
                    if acc.span.end < end {
                        next.push((acc.span.end, end)); // fragment right of the winner
                    }
                }
            }
            fragments = next;
            if fragments.is_empty() {
                break;
            }
        }
        let mut kept_any = false;
        for (start, end) in fragments {
            debug_assert!(start < end);
            let fragment = Finding {
                span: Span {
                    start,
                    end,
                    node_kind: finding.span.node_kind.clone(),
                },
                ..finding.clone()
            };
            let punctuation_only = end - start <= MAX_DROPPED_PUNCTUATION
                && buf
                    .get(start..end)
                    .is_some_and(|b| b.iter().all(u8::is_ascii_punctuation));
            // Beside a finding this Secret actually lost bytes to, not any specific one.
            let beside_winner = winners.iter().any(|&w| {
                let acc = &accepted[w];
                acc.span.end == start || acc.span.start == end
            });
            if beside_winner && finding.entity_type == EntityType::Secret && punctuation_only {
            } else {
                kept_any = true;
                accepted.push(fragment);
            }
        }
        // Covered entirely by, or dropped beside, more specific findings: every detected
        // byte was handled by those, so the caller counts this Secret once (DDD cycle 5,
        // Codex: an exactly-covered Secret previously went uncounted).
        if !winners.is_empty() && !kept_any && finding.entity_type == EntityType::Secret {
            absorbed.push(finding);
        }
    }
    accepted.sort_by_key(|f| f.span.start);
    absorbed.sort_by_key(|f| f.span.start);
    (accepted, absorbed)
}

/// Longest punctuation-only `Secret` fragment `resolve_overlaps` may drop: covers the
/// observed `.`, `!`, `**` and `**.` shapes while bounding how many bytes of a real secret
/// that merely looks like `x@y.z!!` can egress raw (DDD cycle 5).
const MAX_DROPPED_PUNCTUATION: usize = 3;

/// Priority for overlap resolution. The entropy detector's catch-all `Secret` is the one
/// generic type — any concretely-typed finding (`Email`, `Iban`, `Password`, …) is more
/// specific and outranks it when they cover the same bytes.
fn specificity(ty: &EntityType) -> u8 {
    match ty {
        EntityType::Secret => 0,
        _ => 1,
    }
}

/// The fixed typed marker an `IrreversibleRedact`/entity-`Block` value is replaced with
/// (`[REDACTED:PASSWORD]`). Deliberately carries the type tag, never the value.
fn redaction_marker(ty: &EntityType) -> String {
    let tag = match ty {
        EntityType::Person => "PERSON",
        EntityType::Email => "EMAIL",
        EntityType::Phone => "PHONE",
        EntityType::Address => "ADDRESS",
        EntityType::Postcode => "POSTCODE",
        EntityType::EmployeeId => "EMPLOYEE_ID",
        EntityType::CustomerId => "CUSTOMER_ID",
        EntityType::AccountId => "ACCOUNT_ID",
        EntityType::Iban => "IBAN",
        EntityType::SortCode => "SORT_CODE",
        EntityType::InternalIp => "INTERNAL_IP",
        EntityType::Hostname => "HOSTNAME",
        EntityType::ApiKey => "API_KEY",
        EntityType::TraceId => "TRACE_ID",
        EntityType::Password => "PASSWORD",
        EntityType::PrivateKey => "PRIVATE_KEY",
        EntityType::Secret => "SECRET",
        EntityType::AccessToken => "ACCESS_TOKEN",
        // Fixed 2026-08-01: previously interpolated the policy-declared custom entity
        // class *name* into rendered text (`[REDACTED:CUSTOM:{name}]`). That name is not
        // vetted the way the fixed EntityType tags above are (a policy author could name
        // a class after the very thing it exists to protect, e.g. "project-nightingale"),
        // so it must never reach a remote-model-prompt destination -- collapse to the
        // same fixed marker every other entity type uses. See docs/decisions.md,
        // 2026-07-26 "Custom-entity-label leak: remediation agreed, NOT implemented".
        EntityType::Custom(_) => return "[REDACTED:CUSTOM]".to_string(),
    };
    format!("[REDACTED:{tag}]")
}

/// Provenance string for the `Scan` audit event: the sorted detector ids joined with `+`
/// (e.g. `email+entropy+ip`). A stable, human-legible record of which detector set
/// produced the counts, without embedding any raw value.
fn detector_version(ctx: &Context) -> String {
    let mut ids: Vec<String> = ctx.detectors.iter().map(|d| d.id().0).collect();
    ids.sort();
    ids.join("+")
}

/// Reverses the placeholders in a [`MaskedPack`] back to their raw values, for an
/// authorised, local destination.
///
/// **Contract v1.2 (2026-07-18, Task T09) — re-signed from `rehydrate(masked: &str, dest,
/// actor)`.** The frozen v1 signature took bare masked text and no vault handle, which
/// could not satisfy two hard requirements at once: (1) resolving needs a wired
/// `VaultStore`/`PolicyEngine` (the pack + `Policy` now supply them), and (2) the T07
/// review banked that demask must resolve **exclusively via the pack's own
/// [`PlaceholderBinding`]s — never by pattern-scanning text for placeholder-shaped
/// strings** (input already containing `EMAIL_001`-shaped text is indistinguishable from
/// pipeline output, so a text scan cannot tell a minted placeholder from a look-alike).
/// The pack carries the display↔ref pairing `mask` recorded at intern time; this function
/// substitutes only those displays. See `interface-contracts.md` §2 (v1.2) and
/// `docs/decisions.md`'s 2026-07-18 T09 entry.
///
/// Decision order (the hard-deny gate stays **first**, before any vault/policy
/// consultation, exactly as the frozen v1 body had it):
/// 1. **Hard-deny destinations** (`RemoteModelPrompt`, `ObservabilitySink`) are denied
///    unconditionally — regardless of actor, policy pack, or whether the vault is even
///    reachable.
/// 2. **`policy.engine.demask_allowed(dest, actor)`** — the configurable policy gate.
/// 3. **Per-ref `policy.vault.resolve`** for each binding, under `ns`, substituting only
///    the displays the pack itself minted.
///
/// **Inherent residual, recorded not hidden:** substitution is by exact display string, so
/// raw text that happens to equal a display the pack *did* mint (e.g. the user's prompt
/// literally contained `EMAIL_001` and the pack also minted `EMAIL_001` for a real address)
/// is substituted too. This is the nature of in-band text masking — a display and a
/// coincidental look-alike are the same bytes — and is strictly narrower than the scan-the-
/// text approach this design rejects: only displays the pack *actually minted* can ever be
/// touched, never an arbitrary placeholder-shaped string. A spoofed `EMAIL_999` that the
/// pack never minted has no binding and is left untouched.
///
/// A binding whose value cannot be resolved under `ns` (expired, purged, or a namespace
/// mismatch — all reported by the vault as `NotFound`) is left as its placeholder rather
/// than failing the whole demask: `RehydrateDenied` is an authorisation outcome, not a
/// per-value resolution one.
pub fn rehydrate(
    pack: &MaskedPack,
    policy: &Policy,
    ns: &Namespace,
    dest: Destination,
    actor: &Actor,
) -> Result<String, RehydrateDenied> {
    // 1. Hard-deny FIRST — decided before consulting the policy engine or the vault at
    //    all (Codex round-2: even the `version()` fetch counted as a consult, so it now
    //    happens only inside the post-decision audit write).
    if dest.is_hard_deny() {
        write_demask_decision(policy, &dest, actor, false);
        return Err(RehydrateDenied {
            destination: dest,
            actor: actor.id.clone(),
            reason: "destination is hard-deny in default policy".to_string(),
        });
    }

    // 2. Configurable policy gate.
    if !policy.engine.demask_allowed(dest.clone(), actor) {
        write_demask_decision(policy, &dest, actor, false);
        return Err(RehydrateDenied {
            destination: dest,
            actor: actor.id.clone(),
            reason: "policy denies demask to this destination for this actor".to_string(),
        });
    }

    // No `allowed: true` event here (doubt-pass reconciliation): the vault fail-closed-logs
    // every per-ref `resolve` attempt in its own append-only demask log, so an authorised
    // demask is already attributed there. Only *denials* never reach the vault — they are
    // what this event exists to record.

    // 3. Resolve each binding once under `ns`, then substitute in a single left-to-right
    //    pass over the pack text (doubt-pass fixes — the original per-binding
    //    `String::replace` loop had two defects this pass removes):
    //    - **Token boundaries**: `replace` matches substrings, so a minted `EMAIL_001`
    //      would corrupt unrelated text `EMAIL_0015`. A match here must not touch an
    //      alphanumeric/underscore on either side. Longest-display-first at each position
    //      keeps `EMAIL_1` from shadowing `EMAIL_10` (post-999 ordinals).
    //    - **No re-scanning restored values**: output is appended, never re-scanned, so a
    //      restored secret that itself contains a display-shaped string is left intact.
    let resolved: Vec<(&str, Option<Secret>)> = {
        let mut v: Vec<_> = pack
            .bindings
            .iter()
            .map(|b| {
                let placeholder = Placeholder {
                    display: b.display.clone(),
                    mapping_ref: b.mapping_ref,
                };
                (
                    b.display.as_str(),
                    policy.vault.resolve(&placeholder, ns).ok(),
                )
            })
            .collect();
        v.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
        v
    };

    let src = pack.text.as_str();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        let matched = resolved.iter().find(|(display, _)| {
            !display.is_empty()
                && src[i..].starts_with(display)
                && boundary_ok(src, i, i + display.len())
        });
        match matched {
            Some((display, Some(secret))) => {
                out.push_str(secret.expose_secret());
                i += display.len();
            }
            // Unresolvable binding (expired/purged/namespace mismatch): leave its
            // placeholder in place rather than failing the whole demask.
            Some((display, None)) => {
                out.push_str(display);
                i += display.len();
            }
            None => {
                let ch = src[i..].chars().next().expect("in-bounds char");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Ok(out)
}

/// True when the byte range `[start, end)` sits on token boundaries: the characters just
/// before and after are absent or not `[A-Za-z0-9_]`. Displays are `TYPE_TAG_NNN` tokens;
/// a display glued to more word characters is part of some longer string, not a minted
/// placeholder occurrence.
fn boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let before_ok = !text[..start].chars().next_back().is_some_and(is_word);
    let after_ok = !text[end..].chars().next().is_some_and(is_word);
    before_ok && after_ok
}

/// Best-effort audit of a demask *denial* (the only authorisation outcome the vault cannot
/// see — hard-deny and policy-deny return before any `resolve`). The write's own error is
/// dropped: the caller is already returning `RehydrateDenied`, so a failed audit write
/// cannot turn a denial into anything less safe. Successful demasks are attributed by the
/// vault's own fail-closed per-`resolve` demask log, not duplicated here.
fn write_demask_decision(policy: &Policy, dest: &Destination, actor: &Actor, allowed: bool) {
    // Panic-safe (T11 cross-model finding): the hard-deny denial is decided with zero
    // policy/vault *evaluation*, but it is recorded here via the audit sink and
    // `engine.version()`. A broken/custom sink or engine that panicked would otherwise
    // stop the denial from ever reaching the caller — a fail-*open*-shaped regression on
    // the strictest gate. Isolate the recording so the caller's denial always returns.
    let dest = dest.clone();
    let actor_id = actor.id.clone();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = policy.audit.write(AuditEvent::DemaskDecision {
            dest,
            actor: actor_id,
            allowed,
            policy_version: policy.engine.version().to_string(),
        });
    }));
    std::panic::set_hook(prev);
}

/// Runs every [`CorpusSample`] through the detection pipeline and reports Go/No-Go
/// [`Metrics`]: privacy recall, precision, false-positive rate, and a p95 detection
/// latency.
///
/// **Contract v1.3 → v1.4 (2026-07-18, Task T10) — `benchmark` gained `ctx: &Context`.**
/// The frozen `benchmark(corpus, policy)` had no way to reach the detectors/parsers it must
/// run to score the corpus — the identical gap `mask` hit at T07 (§2, v1.1). Resolved the
/// same sanctioned way (contract-change protocol, `agent-factory-plan.md` §6): an explicit
/// `ctx: &Context` parameter, not smuggling detectors into `Policy` (which would conflate
/// "what to do" with "how to find it") nor pre-scoring findings into `Corpus`. The frozen
/// [`Metrics`] **shape is unchanged** — the six richer banked measurements this task owns
/// live in `vg-bench`'s report layer, never as new `Metrics` fields. See
/// `interface-contracts.md` §2 (v1.4) and `docs/decisions.md`'s 2026-07-18 T10 entry.
///
/// **What each metric means here** (the report layer documents the Go thresholds):
/// - **recall** — *effective* privacy recall: an expected value counts as protected only
///   if it is both detected **and** classified `Mask`/`IrreversibleRedact` by `policy`. A
///   detected-but-`Pass` finding leaves the value raw on the wire, so it is not recall.
/// - **precision** / **false_positive_rate** — over the findings the policy would actually
///   act on (post overlap-resolution, so the entropy detector's `Secret` over a real email
///   is resolved to the `Email`, not double-counted), the share that do / do not match a
///   labelled expected finding. `false_positive_rate == 1 - precision`.
/// - **p95_latency_us** — p95 of the **in-process** `scan` time per sample. This is the
///   detection cost only; the report layer measures the *cold `vg hook` binary* p95
///   (process spawn + vault open + policy load + mask) separately and reports that as the
///   developer-felt number, per the banked latency measurement.
///
/// Matching is by entity type plus span overlap (labels carry authoritative type+span;
/// their `confidence`/`detector` provenance is not compared).
pub fn benchmark(corpus: &Corpus, ctx: &Context, policy: &Policy) -> Metrics {
    let mut total_expected = 0usize;
    let mut recalled = 0usize; // detected AND policy would mask/redact
    let mut total_effective = 0usize; // detected findings the policy would act on
    let mut true_positive = 0usize; // those matching a labelled expected finding
    let mut latencies_us: Vec<u64> = Vec::with_capacity(corpus.samples.len());

    for sample in &corpus.samples {
        let start = Instant::now();
        let (detected, _dropped) = resolve_overlaps(&sample.input.buf, scan(&sample.input, ctx));
        latencies_us.push(start.elapsed().as_micros() as u64);

        // A value is only *protected* if a detector found it AND the policy masks/redacts
        // it — a detected `Pass` entity leaves the raw value in the outgoing pack.
        let effective: Vec<&Finding> = detected
            .iter()
            .filter(|f| {
                matches!(
                    policy.engine.classify_entity(f.entity_type.clone()),
                    HandlingClass::Mask | HandlingClass::IrreversibleRedact
                )
            })
            .collect();

        for exp in &sample.expected_findings {
            total_expected += 1;
            if effective
                .iter()
                .any(|d| d.entity_type == exp.entity_type && spans_overlap(&d.span, &exp.span))
            {
                recalled += 1;
            }
        }
        for d in &effective {
            total_effective += 1;
            if sample
                .expected_findings
                .iter()
                .any(|e| e.entity_type == d.entity_type && spans_overlap(&e.span, &d.span))
            {
                true_positive += 1;
            }
        }
    }

    let recall = ratio(recalled, total_expected);
    let precision = ratio(true_positive, total_effective);
    // FP rate is over the findings the policy would act on: an over-flag that gets masked
    // is the precision/trust cost the <3% Go gate measures. `1 - precision`, but written
    // out so an empty-detection corpus reports 0.0, not the vacuous 1.0 `1 - 1.0` gives.
    let false_positive_rate = if total_effective == 0 {
        0.0
    } else {
        (total_effective - true_positive) as f64 / total_effective as f64
    };

    Metrics {
        recall,
        precision,
        false_positive_rate,
        p95_latency_us: p95(&mut latencies_us),
    }
}

/// Two byte spans overlap when each starts before the other ends. Used to match a detected
/// finding to a labelled expected one without requiring byte-exact boundaries (a label and
/// a detector may disagree by a trailing byte).
/// True when two spans overlap. Public (additive, non-contract) so the eval harness
/// scores with the same overlap definition the pipeline uses (doubt-pass: a privately
/// duplicated copy could drift).
pub fn spans_overlap(a: &Span, b: &Span) -> bool {
    a.start < b.end && b.start < a.end
}

/// `numerator / denominator` as a ratio in `0.0..=1.0`; an empty denominator is `1.0`
/// (vacuously perfect: no expected values to miss, or no detections to be wrong about).
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Nearest-rank p95 of the samples (µs). Empty input is `0`.
fn p95(latencies_us: &mut [u64]) -> u64 {
    if latencies_us.is_empty() {
        return 0;
    }
    latencies_us.sort_unstable();
    let idx = ((latencies_us.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(latencies_us.len() - 1);
    latencies_us[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectorId;

    // `rehydrate`'s hard-deny gate and its pack-driven substitution both need a real
    // `Policy` (engine + vault + audit) now that it is wired (contract v1.2), so those
    // assertions live in `tests/demask.rs`, which composes the real Wave B crates as
    // `tests/pipeline.rs` does. Only the pure, dependency-free checks stay here.

    fn finding(entity_type: EntityType, start: usize, end: usize) -> Finding {
        Finding {
            entity_type,
            span: Span {
                start,
                end,
                node_kind: None,
            },
            confidence: 1.0,
            detector: DetectorId("test".to_string()),
        }
    }

    fn spans(findings: &[Finding]) -> Vec<(usize, usize)> {
        findings
            .iter()
            .map(|f| (f.span.start, f.span.end))
            .collect()
    }

    #[test]
    fn punctuation_only_secret_fragment_beside_a_specific_finding_is_dropped() {
        // veil-proxy#90: `**<email>**` -- Secret over the whole token, Email inside it.
        let buf = b"**a@example.com**";
        let (accepted, dropped) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 0, 17),
                finding(EntityType::Email, 2, 15),
            ],
        );
        assert_eq!(spans(&accepted), vec![(2, 15)]);
        // Both fragments dropped: the raw Secret is reported once, not per fragment.
        assert_eq!(spans(&dropped), vec![(0, 17)]);
    }

    #[test]
    fn a_punctuation_fragment_not_beside_the_specific_finding_is_kept() {
        // DDD cycle 4: `!!!!` (40..44) touches only another Secret, never the Email, so it
        // stays masked even though its Secret overlapped the Email elsewhere.
        let buf = b"a@example.com_ZZZZZZZZZZZZZZZZZZZZZZZZZZ!!!!";
        let (accepted, dropped) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Email, 0, 13),
                finding(EntityType::Secret, 0, 40),
                finding(EntityType::Secret, 10, 44),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 13), (13, 40), (40, 44)]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_secret_trimmed_only_by_another_secret_keeps_its_punctuation() {
        // DDD cycle 3 (Codex + fresh-context): the exception applies only after losing
        // bytes to a MORE specific finding, never to an equally generic Secret.
        let buf = b"!@#$AB12CD34";
        let (accepted, dropped) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 4, 12),
                finding(EntityType::Secret, 0, 6),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 4), (4, 12)]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_non_ascii_or_whitespace_secret_fragment_is_never_dropped() {
        // DDD cycle 3 (Codex): a custom detector's Secret may cover non-ASCII bytes;
        // only pure ASCII punctuation qualifies for the drop.
        let buf = "\u{e9}a@example.com".as_bytes(); // `é` is 2 bytes
        let (accepted, dropped) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 0, buf.len()),
                finding(EntityType::Email, 2, buf.len()),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 2), (2, buf.len())]);
        assert!(dropped.is_empty());

        let buf = b"! a@example.com";
        let (accepted, dropped) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 0, buf.len()),
                finding(EntityType::Email, 2, buf.len()),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 2), (2, buf.len())]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_secret_covered_exactly_by_a_specific_finding_is_absorbed() {
        // DDD cycle 5 (Codex): an exactly-covered Secret yields no fragments; it must
        // still be reported so the caller counts it as handled.
        let buf = b"a@example.com";
        let (accepted, absorbed) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 0, 13),
                finding(EntityType::Email, 0, 13),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 13)]);
        assert_eq!(spans(&absorbed), vec![(0, 13)]);
    }

    #[test]
    fn a_punctuation_fragment_longer_than_the_cap_is_kept() {
        // DDD cycle 5: bounds how much of a real `x@y.z!!!!`-shaped secret can egress.
        let buf = b"a@example.com!!!!";
        let (accepted, absorbed) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Secret, 0, 17),
                finding(EntityType::Email, 0, 13),
            ],
        );
        assert_eq!(spans(&accepted), vec![(0, 13), (13, 17)]);
        assert!(absorbed.is_empty());
    }

    #[test]
    fn a_punctuation_fragment_beside_a_finding_it_never_lost_to_is_kept() {
        // DDD cycle 5: B's `!!!!` (40..44) touches only the IP, which B never overlapped;
        // B lost bytes to the Email elsewhere, which must not qualify the fragment.
        let buf = b"a@example.com_ZZZZZZZZZZZZZZZZZZZZZZZZZZ!!!10.0.0.1";
        let (accepted, absorbed) = resolve_overlaps(
            buf,
            vec![
                finding(EntityType::Email, 0, 13),
                finding(EntityType::Secret, 0, 40),
                finding(EntityType::Secret, 10, 43),
                finding(EntityType::InternalIp, 43, 51),
            ],
        );
        assert_eq!(
            spans(&accepted),
            vec![(0, 13), (13, 40), (40, 43), (43, 51)]
        );
        assert!(absorbed.is_empty());
    }

    #[test]
    fn destination_id_is_stable_for_policy_lookups() {
        assert_eq!(
            Destination::RemoteModelPrompt.id(),
            DestinationId("remote-model-prompt".to_string())
        );
    }

    #[test]
    fn hard_deny_destinations_are_recognised() {
        assert!(Destination::RemoteModelPrompt.is_hard_deny());
        assert!(Destination::ObservabilitySink.is_hard_deny());
        assert!(!Destination::LocalPatch.is_hard_deny());
        assert!(!Destination::LocalTestFixture.is_hard_deny());
        assert!(!Destination::LocalExplanationBuffer.is_hard_deny());
    }

    #[test]
    fn redaction_marker_never_carries_the_custom_dictionary_name() {
        // Regression for the custom-entity-label leak (docs/decisions.md,
        // 2026-07-26 "remediation agreed, NOT implemented" entry, closed
        // here): a policy-declared custom entity class name interpolated
        // into `MaskedPack.text` for an IrreversibleRedact/Block value is
        // exactly the kind of text that can reach a remote-model-prompt
        // destination. It must collapse to the same fixed marker every
        // fixed EntityType uses, never carrying the class name.
        let marker = redaction_marker(&EntityType::Custom("internal-project-codename".to_string()));
        assert_eq!(marker, "[REDACTED:CUSTOM]");
        assert!(
            !marker.to_lowercase().contains("codename")
                && !marker.to_lowercase().contains("internal-project"),
            "redaction marker must never leak the custom class name: {marker}"
        );
    }

    #[test]
    fn still_flags_fixed_type_redaction_markers_are_unaffected() {
        assert_eq!(redaction_marker(&EntityType::Email), "[REDACTED:EMAIL]");
        assert_eq!(
            redaction_marker(&EntityType::Password),
            "[REDACTED:PASSWORD]"
        );
    }

    #[test]
    fn protected_literals_share_a_first_byte_and_none_is_a_prefix_of_another() {
        // Both are what `scrub_protected_literals` relies on for its single-pass search.
        for (i, lit) in PROTECTED_LITERALS.iter().enumerate() {
            assert_eq!(lit[0], PROTECTED_LITERAL_FIRST_BYTE, "{lit:?}");
            assert!(lit.starts_with(PROTECTED_LITERAL_PREFIX), "{lit:?}");
            assert!(lit.is_ascii(), "{lit:?}");
            for (j, other) in PROTECTED_LITERALS.iter().enumerate() {
                assert!(
                    i == j || !other.starts_with(lit),
                    "{lit:?} is a prefix of {other:?}"
                );
            }
        }
    }

    #[test]
    fn scrub_replaces_only_the_digits_of_a_bounded_occurrence_and_keeps_length() {
        let raw = b"Haiku 4.5: 'claude-haiku-4-5-20251001'. Use it";
        let scrubbed = scrub_protected_literals(raw).expect("one occurrence");
        assert_eq!(scrubbed.len(), raw.len());
        assert_eq!(
            &scrubbed[..],
            &b"Haiku 4.5: 'claude-haiku-E-F-CACFBAAB'. Use it"[..]
        );
        assert!(
            scrubbed.iter().all(u8::is_ascii),
            "fill must stay ASCII letters"
        );

        // Two occurrences, different literals, nothing else touched.
        let raw = b"claude-opus-4-5-20251101 and claude-3-5-sonnet-20241022 at 415-555-1234";
        assert_eq!(
            scrub_protected_literals(raw).as_deref(),
            Some(&b"claude-opus-E-F-CACFBBAB and claude-D-F-sonnet-CACEBACC at 415-555-1234"[..])
        );
    }

    #[test]
    fn scrub_returns_none_when_no_bounded_literal_is_present() {
        for raw in [
            &b""[..],
            b"call 415-555-1234 now",
            b"claude-haiku-4-5-2025100",   // truncated
            b"CLAUDE-HAIKU-4-5-20251001",  // case-sensitive
            b"claude-haiku-4-5-20251001x", // continued by a letter
            b"claude-haiku-4-5-202510019", // continued by a digit
            b"claude-haiku-4-5-20251001_ext99",
            b"xclaude-haiku-4-5-20251001",
            b"_claude-haiku-4-5-20251001",
            "caf\u{e9}claude-haiku-4-5-20251001".as_bytes(),
            "claude-haiku-4-5-20251001\u{e9}".as_bytes(),
            "claude-haiku-4-5-20251001\u{a0}".as_bytes(), // NBSP: non-ASCII, not a quote
        ] {
            assert_eq!(
                scrub_protected_literals(raw),
                None,
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn scrub_treats_every_ascii_non_identifier_byte_and_typographic_quotes_as_bounds() {
        let id = "claude-haiku-4-5-20251001";
        let mut shapes: Vec<String> = vec![
            id.to_string(),
            format!("anthropic.{id}-v1:0"),
            format!("models/{id}/invoke"),
            format!("{id}[1m]"),
            format!("\\\"{id}\\\""),
            format!("**{id}**"),
            format!("?model={id}&x=1"),
            format!("{id}@example.com"),
            format!("{id}-555-1234"),
            format!("{id}-5551234"),
            format!("\u{2018}{id}\u{2019}"),
            format!("\u{201c}{id}\u{201d}"),
        ];
        for b in 0u8..=127 {
            if !is_identifier_byte(b) {
                let b = b as char;
                shapes.push(format!("{b}{id}{b}"));
            }
        }
        for raw in shapes {
            let scrubbed = scrub_protected_literals(raw.as_bytes()).unwrap_or_else(|| {
                panic!("expected a bounded occurrence in {raw:?}");
            });
            let expected = raw.replace(id, "claude-haiku-E-F-CACFBAAB");
            assert_eq!(scrubbed, expected.into_bytes(), "{raw:?}");
        }
    }
}
