# VeilGremlin — Implementation Plan and Repository Layout

**Status:** proposed, not ratified. Synthesises `docs/architecture/product-family.md` (family
design) with the cross-model telemetry review in this session (Codex, read-only, 2026-07-26).
Supersedes nothing until reviewed; see `docs/decisions.md`.

**Date:** 2026-07-26

---

## 0. The one-line answer on repos

**Two new repos now, one conditional, zero schema repos.**

| Repo | Status | Contains |
|---|---|---|
| `veil-proxy` | **Exists** (this repo, renamed from `veilgremlin`) | Masking data plane, `vg` CLI, agent adapters, **and the telemetry emitter + schema** |
| `veil-observatory` | **New — build 3rd** | Ingest gateway, curated store, alert lane, dashboard app |
| `veil-foundations` | **New — can start immediately** | Terraform only: Bedrock invocation control plane |
| `veil-identity-custodian` | **Conditional — gated on Q9** | Device→user mapping. Only exists if the existing MDM/CMDB fails the §6.3 separation-of-duties audit |

Two deliberate non-repos:

- **No separate schema/contract repo.** The telemetry schema has exactly one producer
  (`veil-proxy`) and, initially, one consumer. Codex's finding that `AuditEvent` is
  `#[non_exhaustive]` forces the conversion to live *inside* `vg-core` for compile-time
  exhaustiveness — so the Rust type is already the source of truth. Publish a versioned,
  generated schema artifact from `veil-proxy` rather than standing up a third repo and a
  three-way version dance. Revisit only if a second producer appears.
- **No separate dashboard repo.** It shares the observatory's data model and has none of its
  own. Splitting it buys independent release cadence at the cost of API versioning between two
  repos from day one, for a UI with nothing to version yet.

**Why `veil-identity-custodian` would be its own repo if built:** §6.3 requires that the party
who can *query telemetry* is not the party who can *resolve a pseudonym to a person*. Repo
separation does not enforce that by itself — deployment and IAM do — but co-locating the two in
one repo invites shared deployment, shared credentials, and shared reviewers, which is exactly
the collapse the control exists to prevent. Keep the seam visible in the source layout.

---

## 1. What changed this session, and why the plan starts where it does

Three findings reordered the work:

1. **The T10 precision NO-GO is closed.** `vg bench` verdict is **GO**, false-positive rate
   **0.0%** (was 16.7%), landed in #37 after two doubt-pass rounds. `README.md` and
   `.hekton/project.yaml` still advertise the old failing number and must be corrected — for a
   project whose credibility rests on publishing its real numbers, publishing a *stale* failing
   number is its own inaccuracy.
2. **The proposed `TelemetryEvent` design cannot be built as written.** `AuditEvent` is
   `#[non_exhaustive]` (`crates/vg-core/src/audit.rs:19`, deliberately, with more variants
   expected). An exhaustive `From<&AuditEvent>` is therefore impossible outside `vg-core`;
   callers need a wildcard arm, and that arm silently leaks every variant added later.
3. **`AuditEvent`, not S3, is the weakest link.** Six raw-capable `String` surfaces, not the two
   originally identified.

The consequence for sequencing: **the critical path runs through the repo that already exists.**
No central plane can be built honestly until the emitter's type story is correct.

---

## 2. Phase 0 — Correct the record (`veil-proxy`, days)

Cheap, unblocking, and required before any external communication.

| Task | Detail |
|---|---|
| Fix stale status | `README.md` status line + §Status, and `.hekton/project.yaml`'s `next_architecture_step`: FP rate is 0.0%, verdict GO |
| Re-verify the display-collision claim | README also cites a mask→demask collision in 1 of 3 round-trips; confirm whether #37 closed it or it remains open, and state whichever is true |
| Amend `product-family.md` §3.4 | Record that `From` → `TryFrom`, conversion lives in `vg-core`, and the `#[non_exhaustive]` constraint |
| Amend the PROPOSED `decisions.md` entry | It currently rests on the unbuildable design |
| Settle the rename tail | Directory move; GitHub repo rename still deferred per §10 Q1 |

**Exit gate:** every published status claim matches what `vg bench` actually returns today.

---

## 3. Phase 1 — The telemetry seam (`veil-proxy`, the hard prerequisite)

All of this is in the existing repo. Nothing central can start until it lands.

### 3.1 Close the six raw-capable surfaces

| Surface | Location | Fix |
|---|---|---|
| `Block { reason: String }` | `vg-core/src/audit.rs:35` | Replace with `BlockReasonCode` enum + `policy_rule_id` + counts |
| `ActorId(pub String)` | `vg-core/src/ids.rs:30` | Keyed HMAC pseudonym, computed locally, never the raw string |
| `detector_version: String` | built at `vg-core/src/api.rs:458` from `DetectorId(pub String)` | Bounded `DetectorSetId` / version token |
| `policy_version: String` | safe for the shipped loader only, not the `PolicyEngine` trait | Validated `VersionToken` newtype, private field |
| `EntityType::Custom(String)` | `vg-core/src/types.rs:38` | Bounded label type, or excluded from telemetry entirely |
| `ArtefactKind::SourceCode(String)` | `vg-core/src/traits.rs:38` | Bounded language enum |

> ### ⚠️ Correction — custom entity class names reach `MaskedPack.text`
>
> This item was first filed as "outside the telemetry scope but worth fixing," then over-corrected
> to "a live content leak on the shipped hot path." **Both were wrong.** The accurate statement,
> after tracing the code twice and having the second pass independently reviewed:
>
> **The defect is real, it affects two code paths, and it is not reachable through a production
> `vg run` today.**
>
> Two paths interpolate a policy-declared custom entity class *name* into `MaskedPack.text`, the
> artefact sent to the model:
>
> | Path | Handling classes | Renders |
> |---|---|---|
> | `redaction_marker` (`vg-core/src/api.rs:450`) | `IrreversibleRedact`, `Block` | `[REDACTED:CUSTOM:{name}]` |
> | `type_tag_for_display` (`vg-core/src/keying.rs:219`) | **`Mask` — the default class** | `CUSTOM_{SCREAMING_SNAKE}_001` |
>
> The `api.rs` chain is: `replacements` (`:303`) → spliced into `out` (`:322`) → `text` (`:325`).
> The `keying.rs` path is the more exposed of the two, since `Mask` is the default.
>
> **Why it is not reachable today:** no shipped detector declares `EntityType::Custom` — zero
> occurrences in `crates/vg-detectors/` or `crates/vg-adapters-claude/`. Nothing currently
> *produces* a `Custom` finding. But every other layer is already wired for it
> (`vg-vault/src/codec.rs:65,95`, `vg-policy/src/config.rs:313`, `keying.rs:219`), so the defect
> arms itself the moment a custom detector is added, with nothing guarding the path.
>
> **A latent leak in a security control, with all the plumbing already in place and no test
> covering it, still warrants fixing first** — but it is not an active incident, and this document
> should not have said it was.
>
> **The `keying.rs` fix is not trivial.** `screaming_snake` collapses non-alphanumerics, so
> `foo-bar` and `foo_bar` both render `FOO_BAR` — a display collision that
> `vg-vault/src/codec.rs:130-131` already tests for. Flattening the name naively risks `rehydrate`
> substituting the wrong value. Remediation is under three-model review; see task T15.
>
> Currently invisible to the suite: `assert_masked_pack_excludes_raw_values` would catch it, but
> no test supplies a custom label as the raw value.

### 3.2 The `TelemetryEvent` type

- Zero `String` columns: enums for kind/entity/artefact/destination/reason, integers for
  counts/latency/schema version, booleans for decisions, fixed-width hashes where identity is
  needed.
- All fields private. No constructor accepting `String`. No `serde_json::Value`, no `Debug`
  serialisation path.
- `TryFrom<&AuditEvent>`, **defined inside `vg-core`** so exhaustiveness is enforceable, with an
  explicit `TelemetryReject` for audit events that are not valid telemetry.
- Human-readable block explanations move to a **versioned reason dictionary** rendered
  dashboard-side, not shipped as text.

### 3.3 Emitter and lanes

- Two lanes per §4: batched bulk telemetry, and an immediate low-latency alert lane. Alert-lane
  payloads are *more* minimised than bulk, never less.
- Local on-device alert-rule evaluator (alerting must not depend on central bulk ingest).
- Independent opt-ins for the two lanes (§10 Q10), with "alert on, bulk off" as a tested state.
- Device pseudonym minted at enrolment — never the OS hostname (§6.1).

### 3.4 Gates

- Extend `assert_audit_event_excludes_raw_values` to a `TelemetryEvent` equivalent.
- A test proving `TelemetryEvent` cannot be constructed carrying a raw value.
- Schema published as a versioned artifact consumed by `veil-observatory`.

**Exit gate:** the emitter is type-level incapable of holding a raw value, and the schema is
structurally incapable of representing one.

---

## 4. Phase 2 — Identity decisions (blocking, cheap to decide, expensive to get wrong)

Every telemetry event carries a device pseudonym, so this gates the observatory.

1. **Audit the existing MDM/CMDB** against §6.3's bar: separation of duties, logged and
   justified resolution, re-identification as a deliberate act. Reuse it only if it passes;
   build the dedicated custodian rather than lowering the bar to fit the existing tool.
   → **Determines whether `veil-identity-custodian` exists.**
2. **Design spike on attestation** (§10 Q7, still open): mTLS device certs, TPM attestation, or
   SSO token exchange. Device-as-key does not answer what stops a device lying about which
   device it is. RBAC, evidence chain-of-custody, and incident response all assume this solved.

**Exit gate:** repo count is known; attestation mechanism chosen.

---

## 5. Phase 3 — `veil-observatory` MVP (new repo)

Ordered by Codex's build-first list.

1. **Ingest gateway before storage.** Deserialize only the narrow schema, reject unknown fields,
   validate enums/ranges/tokens, then write canonical Parquet. This — not access control — is
   what closes schema drift.
2. **Separate landing / quarantine / curated buckets.** Analysts see curated only. Quarantine is
   tightly held, short retention.
3. **Both lanes**, per §4.
4. **Detector tripwire**, per-record not per-batch, scanning only fields that should never be
   free text. See §7 below on why this is a tripwire and not a control.
5. **Legal/Risk/Privacy view first; CSOC alerting from day one.** Full CSOC investigation
   surface deferred.

**Explicitly skipped** (named theatre): raw string telemetry plus Lake Formation masking;
direct-to-S3 producer writes; S3 encryption as a no-raw-values control; Object Lock on
unvalidated landing data, which preserves rather than prevents a leak.

---

## 6. Phase 4 — `veil-foundations` (new repo, parallelisable **now**)

**This is the only workstream with no dependency on the telemetry work.** Different skillset
(Terraform/AWS, not Rust). If parallel capacity exists, start it in Phase 0.

- IAM model allowlists, Bedrock Guardrails, invocation logging, VPC endpoints/PrivateLink,
  cross-account layout.
- Module names avoid hardcoding `bedrock` where a two-line difference preserves portability
  (§10 Q6).
- Composes with `veil-proxy` as defence in depth: the proxy minimises what egresses, the walled
  garden constrains what can be invoked at all.

---

## 7. Phase 5 — Dashboard and full CSOC surface

- QuickSight/Athena/Lake Formation **over curated views only**. SPICE is a copy — never load
  raw-capable base tables into it.
- Athena workgroups with enforced, encrypted, lifecycled result locations. Query results are
  another copy.
- Identity resolution is a **separate audited service call, not a Lake Formation grant** — the
  one gap where Lake Formation's row/column model does not map onto the persona split.
- Portable data model (Parquet/Iceberg, optionally OCSF), so AWS-native is one deployment target
  rather than the only one (§10 Q11).

---

## 8. The detector tripwire — corrected reasoning

The idea (run `veil-proxy`'s own detectors over inbound telemetry as a last line) was assessed by
Codex against a 16.7% false-positive rate. **That number is stale — it is now 0.0%.**

This does *not* promote the tripwire to a control, for a reason independent of the number:
**0.0% is measured on the synthetic seeded corpus.** The original precision problem was surfaced
by a census against 197 real files — a different data distribution. Telemetry is a third
distribution again (UUIDs, version tokens, enum labels), and corpus-measured precision does not
transfer across distributions.

So Codex's conclusions stand, with better justification than it had:

- **Tripwire, not guarantee.** Never the headline control.
- **Per-record quarantine, not per-batch** — batch quarantine creates CSOC blind spots, which
  matters more now that alerting ships day one.
- **Scan only fields that should never be free text**, not raw JSON bytes. With a zero-string
  schema this degenerates into a structural-violation check, which is the right shape.

---

## 9. Risks and known non-goals

| Item | Position |
|---|---|
| **Emitter guarantee ≠ lake guarantee** | The single biggest risk. "The emitter cannot accept raw buffers" is not "the lake cannot contain raw values." The second needs structural schema exclusion **plus** ingest enforcement |
| **DSAR / right-to-erasure** | Declared a **non-goal**, not implied solved. No honest answer exists for erasure across a fleet of per-laptop reversible vaults |
| **Attestation mechanism** | Open (§10 Q7). Direction set, mechanism unchosen |
| **Recovery is under-designed** | Athena result buckets, SPICE extracts, and analyst exports are all secondary copies. Analyst downloads are incident response, not technical cleanup |
| **AWS-native vs portable** | Open (§10 Q11). A product-strategy call, not just engineering |
| **Positioning claim** | "PII never leaves the machine" must be retired for §3.5's weaker, true wording before any observatory ships |

---

## 10. Critical path, condensed

```
Phase 0 (days, veil-proxy)        ──┐
Phase 1 (telemetry seam, veil-proxy) ├── blocks everything central
Phase 2 (identity decisions)       ──┘
                                      │
                                      ├──> Phase 3: veil-observatory (new repo)
                                      └──> Phase 5: dashboard

Phase 4: veil-foundations (new repo) ── independent, start any time
```

**Start now, in parallel:** Phase 0 corrections, and `veil-foundations`.
**Do not start until Phase 1 lands:** anything that ships data off the laptop.
