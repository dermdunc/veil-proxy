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

use crate::audit::AuditEvent;
use crate::error::{MaskError, RehydrateDenied};
use crate::ids::ActorId;
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
pub fn scan(input: &Input, ctx: &Context) -> Vec<Finding> {
    let spans = parser_spans(input, ctx);
    let mut findings = Vec::new();
    for detector in ctx.detectors {
        findings.extend(detector.detect(&input.buf, &spans));
    }
    findings
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
pub fn mask(
    input: &Input,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
) -> Result<(MaskedPack, Vec<MappingRef>, AuditEvent), MaskError> {
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
        return Ok((pack, Vec::new(), event));
    }

    // 2. Every non-Block artefact is entity-scanned regardless of its artefact class —
    //    `Pass` means "send after entity masking", never "skip detection" (T06 review,
    //    hard requirement: skipping here would make `Pass` fail open).
    // 3-4. Parse for enrichment spans, then detect: every detector over the FULL buffer
    //    (spans are enrichment only, never a gate — T08 review).
    let spans = parser_spans(input, ctx);
    let detect_start = Instant::now();
    let mut findings = Vec::new();
    for detector in ctx.detectors {
        findings.extend(detector.detect(&input.buf, &spans));
    }
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

    // 5. Resolve overlaps: no byte is masked twice, and no detected byte is dropped —
    //    a losing finding is trimmed to its uncovered fragments, never discarded whole.
    // 6. Classify and intern in FORWARD document order (so vault ordinals read top-to-
    //    bottom: the first email in the buffer is EMAIL_001), collecting replacements;
    //    splices are applied back-to-front afterwards so offsets stay valid.
    let ordered = resolve_overlaps(findings);

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

    // 7. One `AuditEvent::Scan`: counts are ALL detections (including policy-Passed
    //    ones — the audit trail must be able to answer "what was found"); the pack's
    //    `MaskStats.counts` below are the *handled* subset (what was actually replaced).
    let event = AuditEvent::Scan {
        counts: EntityCounts(detected_counts),
        detector_version: detector_version(ctx),
        latency_us,
    };

    if let Some(err) = intern_error {
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
    Ok((pack, mapping_refs, event))
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

/// Resolves overlapping findings so no two accepted findings cover the same bytes — and
/// no detected byte is ever dropped: the more specific entity type wins over the generic
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
/// Returned findings are sorted in forward document order (ascending span start), which
/// the caller relies on for top-to-bottom vault ordinal minting.
fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
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
    for finding in findings {
        // Subtract every already-accepted interval from this finding's span; keep each
        // surviving fragment as a finding of the same type. An exact duplicate (or a
        // fully-covered lower-priority finding) yields no fragments and drops out — that
        // is the "never double-mask" half of the contract.
        let mut fragments = vec![(finding.span.start, finding.span.end)];
        for acc in &accepted {
            let mut next = Vec::new();
            for (start, end) in fragments {
                if acc.span.start >= end || acc.span.end <= start {
                    next.push((start, end)); // no overlap with this accepted span
                } else {
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
        for (start, end) in fragments {
            debug_assert!(start < end);
            accepted.push(Finding {
                span: Span {
                    start,
                    end,
                    node_kind: finding.span.node_kind.clone(),
                },
                ..finding.clone()
            });
        }
    }
    accepted.sort_by_key(|f| f.span.start);
    accepted
}

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
        let detected = resolve_overlaps(scan(&sample.input, ctx));
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

    // `rehydrate`'s hard-deny gate and its pack-driven substitution both need a real
    // `Policy` (engine + vault + audit) now that it is wired (contract v1.2), so those
    // assertions live in `tests/demask.rs`, which composes the real Wave B crates as
    // `tests/pipeline.rs` does. Only the pure, dependency-free checks stay here.

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
}
