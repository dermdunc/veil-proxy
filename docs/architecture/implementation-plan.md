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
> | `redaction_marker` (`vg-core/src/api.rs:430`) | `IrreversibleRedact`, `Block` | `[REDACTED:CUSTOM:{name}]` |
> | `type_tag_for_display` (`vg-core/src/keying.rs:206`) | **`Mask` — the default class** | `CUSTOM_{SCREAMING_SNAKE}_001` |
>
> The `api.rs` chain is: `replacements` (`:303`) → spliced into `out` (`:322`) → `text` (`:325`).
> The `keying.rs` path is the more exposed of the two, since `Mask` is the default.
>
> **Why it is not reachable today:** no shipped detector declares `EntityType::Custom` — zero
> occurrences in `crates/vg-detectors/` or `crates/vg-adapters-claude/`. Nothing currently
> *produces* a `Custom` finding. But every other layer is already wired for it
> (`vg-vault/src/codec.rs:65,95`, `vg-policy/src/config.rs:313`, `keying.rs:206`), so the defect
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

### 3.2 The `TelemetryEvent` type — **built, 2026-08-23**

**This section is superseded as the design source by
`docs/architecture/telemetry-receipt-reconciliation-plan.md`** (ratified 2026-08-23, all eleven
open questions resolved) — that document is the source of truth for the shape; this section
records what was actually implemented against it, in `crates/vg-core/src/telemetry/`.

The original single-undifferentiated-type sketch above was wrong: the ratified plan's §3.2
resolved it into **a signed envelope plus three record kinds**, not one type:

- **`Envelope`** (`telemetry/envelope.rs`) — fields common to every record: `schema_version`,
  `contract_revision`, `record_id`, `issued_at_us`, `device_ref` (nullable — per-laptop v1, no
  tenant scoping), `tenant_id` (nullable), `sequence`, `valid_until_us`, `integrity`. No `lane`
  field — the record kind already implies the lane. `Envelope::new` enforces
  `valid_until_us` is strictly after `issued_at_us` and within a bounded sanity window.
- **`Receipt`** (`veil.receipt.v2`, boxed inside `TelemetryEvent::Receipt`) — one per governed
  Bedrock invocation: `linkage` (`TraceLinkage`), `invocation`, `caller`, `controls`, `timing_us`,
  `edge_outcome`. `Action` (per-entity-class: `Masked | Redacted | Blocked | Allowed`, generated
  from `HandlingClass` via a compiler-enforced `From` impl) and `Outcome` (per-invocation) are two
  independent dimensions — the draft's `blocked_with_redaction` idea was a modelling error the
  ratified plan corrected.
- **`Alert`** (`veil.alert.v1`) — the immediate lane's own minimal type: `rule`, `severity` only.
  Not a filtered view of `Receipt`; a structurally separate, deliberately smaller type, so
  over-sharing on the low-latency path is a compile error, not a runtime discipline.
- **`EdgeEvent`** (`veil.edge_event.v1`) — non-invocation-scoped local acts:
  `DemaskRequest`/`DemaskDecision`/`BlockedAttempt`, each wrapping a private-fielded payload
  struct whose fields mirror their source `AuditEvent` variant exactly (no invented fields the
  source data can't supply).

Confirmed built:

- **Zero `String` columns** on the closed-enum/fixed-width types (`EntityClassId`,
  `ArtefactKindId`, `DeviceRef`, `ReasonCode`, `TraceId`, `RecordId`, `ActorPseudonym`, `Action`,
  `Outcome`, etc.) — see §3.2a. Seven identifier types (`VersionToken`, `DetectorSetId`,
  `ExceptionRuleId`, `TenantId`, `AlertRuleId`, `KeyRef`, `RegistryRef`) are `String`-backed
  underneath a private field and a fallible, charset-validated constructor — a **deliberate,
  documented divergence** from the letter of "zero `String` columns" (see `telemetry::ids`'s
  module doc): these identifiers are inherently human-legible, variable-content tokens that ops
  teams need to read, and collapsing them to a fixed-width hash now would trade real information
  loss for literal compliance, with no registry yet built to resolve a hash back to a string.
  Flagged repeatedly across independent review rounds, not missed.
- **All fields private. No constructor accepting an unvalidated `String`. No `serde_json::Value`.
  No `Debug` serialisation path** — none of the value types in `telemetry::` derive `Debug` (only
  the `thiserror::Error` types do, whose fields are compile-time-fixed safe labels). An earlier
  draft derived `Debug` throughout and leaned on it for tests before this requirement was caught.
  A later review round also found and closed a subtler version of the same leak: `#[derive(Hash)]`
  on a `String`-backed type is a verbatim recovery channel (a custom `Hasher` records the bytes
  it's given) — proven by an external-crate exploit, not just suspected. `Hash` is now absent from
  every type wrapping variable content.
- **`TryFrom<&AuditEvent>`, defined inside `vg-core`, exhaustive, no wildcard arm** — the six
  `AuditEvent` variants (`crates/vg-core/src/audit.rs:20-49`) each get an explicit,
  named `TelemetryReject` reason. As of this writing **every arm rejects**: `Scan`/`PolicyDecision`
  need trace-scoped aggregation (no trace id exists anywhere upstream in `vg-core` yet); `Block`
  needs the reason dictionary (§3.2's fourth bullet, below); `DemaskRequest`/`DemaskDecision` need
  `ActorId` pseudonymization (Phase 1a's first item, §3.1, not yet built). `MappingCreated`
  defaults to excluded (Q8) — an **open question, not a ratified exclusion**; revisit if a
  concrete persona query needs mapping-volume metrics.
- **Human-readable block explanations move to a versioned reason dictionary** — the `ReasonCode`
  type (an integer index) exists; the dictionary itself is not built (§3.2a, and reconciliation
  plan §5: "the reason-dictionary distribution mechanism... belongs with the policy/detector-pack
  distribution channel").

#### 3.2a Type inventory (the reconciliation plan's required §3.2a deliverable)

Every opaque type `TelemetryEvent`'s payloads use, its concrete Rust representation, and its
fallible constructor. **No JSON form/anchored pattern column** — schema generation (JSON Schema
output) is separate, not-yet-built work (§3.4); the "generated form" this deliverable also asks
for does not exist yet, so this table states the Rust side only and says so rather than inventing
a JSON shape ahead of the generator that would produce it.

| Type | Representation | Constructor | Notes |
|---|---|---|---|
| `TraceId` | `Uuid` (private) | `From<Uuid>`, infallible | Correlation id for a Bedrock invocation. UUID-, not ULID-backed — no ULID dependency exists in this crate. |
| `RecordId` | `Uuid` (private) | `From<Uuid>`, infallible | Identity of one telemetry record. |
| `VersionToken` | `String` (private) | `TryFrom<&str>`, fallible: charset `[A-Za-z0-9._-]`, ≤64 bytes, **empty allowed** | Matches `crates/vg-policy/src/config.rs:221-224`'s real, shipped `version` validator exactly, including its permissiveness on empty strings. |
| `DetectorSetId` | `String` (private) | `TryFrom<&str>`, fallible: same charset plus `+`, ≤64 bytes, empty rejected | `+` matches the real producer (`crates/vg-core/src/api.rs:465-469`'s `detector_version`, sorted ids joined with `+`). Charset matches *observed* detector ids, not an enforced bound — `DetectorId(pub String)` itself is still unconstrained (one of the six raw-capable surfaces above, not yet closed). |
| `ExceptionRuleId` | `String` (private) | `TryFrom<&str>`, fallible: shared base charset | Policy-authored exception-rule identifier. |
| `TenantId` | `String` (private) | `TryFrom<&str>`, fallible: shared base charset | Always `None` in v1 (ratified Q2: per-laptop enrolment only). |
| `AlertRuleId` | `String` (private) | `TryFrom<&str>`, fallible: shared base charset | Policy-authored alert-rule identifier. |
| `KeyRef` | `String` (private) | `TryFrom<&str>`, fallible: shared base charset | Opaque signing-key identifier. |
| `RegistryRef` | `String` (private) | `TryFrom<&str>`, fallible: shared base charset | Blocks the *shape* of the concrete leak the reconciliation plan §2.4 names (`:`/`/` in a raw repo path) but does not itself enforce hashing — callers are responsible for that. |
| `DeviceRef` | `[u8; 16]` (private) | `TryFrom<&[u8]>`, fallible: exactly 16 bytes | Matches the reconciliation plan's envelope sketch pattern exactly (`^dev_[a-f0-9]{32}$` = 32 hex chars = 16 bytes). `None` until `veil-custodian`'s enrolment registry exists. |
| `ReasonCode` | `u16` (private) | `From<u16>`, infallible | Index into the not-yet-built versioned reason dictionary. |
| `EntityClassId` | Closed enum, `#[non_exhaustive]`, 19 fixed variants + `Custom` (unit, no payload) | `From<&EntityType>`, infallible, exhaustive in-crate | Implements ratified Q6: custom entity-class *names* are structurally unrepresentable (a unit variant, not a validated string) — the fact/count of a custom-class detection still reaches telemetry via the `Custom` tag, only the name never does. |
| `ArtefactKindId` | Closed enum, `#[non_exhaustive]`, 11 variants, `SourceCode` collapses the language name | `From<&ArtefactKind>`, infallible, exhaustive in-crate | Same discipline as `EntityClassId` — `ArtefactKind::SourceCode(String)` is itself still raw upstream (§3.1), so telemetry must not transit the language name until it closes. |
| `ActorPseudonym` | `[u8; 32]` (private) | **No public constructor** — `pub(crate) fn from_bytes` only | Requires the keyed-HMAC-over-`ActorId` mechanism (§3.1, first bullet) — not yet built. Defining the shape now avoids inventing a throwaway pseudonymization scheme that would be thrown away again once the real one lands. |
| `Action` | Closed enum, `#[non_exhaustive]`, 4 variants | `From<HandlingClass>`, infallible, exhaustive in-crate | Per-entity-class handling; 1:1 rename of `HandlingClass`, not an addition. |
| `Outcome` | Closed enum, `#[non_exhaustive]`, 5 variants | Constructed directly (no fallible conversion needed) | Per-invocation/artefact outcome, independent of `Action`. |
| `EdgeOutcome` | Closed enum, 2 variants, no `Default` | Constructed directly | `complete`/`incomplete` must be stated explicitly — no fail-open default. |
| `DeploymentStage` | Closed enum, `#[non_exhaustive]`, 4 variants | Constructed directly | Sole survivor of the `caller.environment`/`deployment_stage` field family (ratified Q9 dropped the free-form `environment`). |
| `Severity` | Closed enum, `#[non_exhaustive]`, 5 variants, derives `Ord` | Constructed directly | **Hard invariant: append-only** — `Ord` is declaration-order-derived; inserting a variant between existing ones silently changes every downstream `severity >= X` comparison. |
| `SchemaVersion` | Closed enum, `#[non_exhaustive]`, 3 variants | Constructed directly | Mirrors `TelemetryEvent`'s own variant tag; kept because the eventual generated schema needs a concrete const. Consistency with the actual payload is enforced by `TelemetryEvent::new_receipt`/`new_alert`/`new_edge_event`. |
| `SigningAlgorithm` | Closed enum, `#[non_exhaustive]`, 2 variants | Constructed directly | Matches `veil-observatory`'s existing schema's algorithm enum. |

### 3.3 Emitter and lanes — **types built, wiring not started**

- **Three record kinds, not two lanes carrying undifferentiated payloads**: `Receipt` and
  `EdgeEvent` travel on the batched bulk lane; `Alert` travels on the immediate low-latency lane,
  and is its own minimised type rather than a filtered view of `Receipt` (§3.2). This corrects the
  original two-lane, one-shape sketch above.
- Local on-device alert-rule evaluator (alerting must not depend on central bulk ingest) — **not
  built**. No `TelemetryEvent` is constructed anywhere in production code; the types exist,
  nothing calls them outside `#[cfg(test)]`.
- Independent opt-ins for the two lanes (§10 Q10), with "alert on, bulk off" as a tested state —
  **not built**; this is a runtime/config concern with no code yet to test.
- Device pseudonym minted at enrolment — never the OS hostname (§6.1) — **not built**; gated on
  `veil-custodian`'s enrolment registry (reconciliation plan, ratified Q1), which does not exist
  yet. `Envelope::device_ref` is typed (`Option<DeviceRef>`) and stays `None`.
- **New, not originally budgeted**: an in-emitter aggregator that groups `AuditEvent`s by trace
  before minting a `Receipt` (reconciliation plan §3.2's own note: "new machinery... not yet
  budgeted"). Still not built, and still not scoped in detail — the trace id it would aggregate by
  doesn't exist upstream yet either (§3.2's `TryFrom` gap list).

### 3.4 Gates

- **Not literally "extend `assert_audit_event_excludes_raw_values` to a `TelemetryEvent`
  equivalent"** — that helper works because `AuditEvent`'s fields are public and string-shaped, so
  it can construct an event carrying a real raw value and assert it's absent from `Debug` output.
  `TelemetryEvent`'s types have no public constructor accepting a raw string and no `Debug` at
  all, so there's no rendering path left to check at runtime. Built instead:
  `assert_telemetry_token_rejects_raw_value` (`crates/vg-core/src/conformance.rs`) — proves a
  bounded-token constructor actually *rejects* non-conforming input, the mirror-image property.
- **"A test proving `TelemetryEvent` cannot be constructed carrying a raw value"** — satisfied
  structurally, not by a dedicated runtime test: no public constructor path exists from a raw
  `String` to any `telemetry::` value type. `crates/vg-core/tests/telemetry.rs` exercises the
  bounded-token rejection property (above) and locks in the exhaustive `TryFrom<&AuditEvent>`
  reject table so a change to any arm is a deliberate, reviewed test update.
- **Schema published as a versioned artifact consumed by `veil-observatory`** — **not built**.
  No `serde`/`schemars` dependency exists in `vg-core`; JSON Schema generation from the Rust types
  is separate, later work, matching `AuditEvent`'s own precedent (`vg-audit` maintains a hand-kept
  mirror schema so a `vg-core` type change is a compile error for persistence, not a silent
  reinterpretation) rather than deriving `serde` directly on the core type.

**Exit gate — partially met.** The type system is type-level incapable of holding a raw value
(built, tested, reviewed across four independent adversarial rounds — see `docs/decisions.md`).
The schema is not yet published as an artifact at all, so "structurally incapable of representing
one" doesn't apply yet — there is no schema, only the Rust types it would eventually be generated
from.

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
