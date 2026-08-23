# Telemetry / Receipt Schema Reconciliation Plan

**Status: RATIFIED 2026-08-23 — all eleven open questions (§4) resolved by the project owner.**
See §4a for the recorded decisions. Implementation (the §3.2a type inventory, the aggregator, the
`veil-custodian` enrolment/signing-key registry, and the paired ADR-0004 scope note) has not
started; this document records the *decisions*, not the build.

Cross-repo planning document for the
VeilGremlin family. Reconciles `veil-proxy`'s `TelemetryEvent` design (design-only, no code yet)
with `veil-observatory`'s draft `veil.receipt.v1` JSON Schema (hand-authored, unvalidated).
Written 2026-08-23; revised the same day after an independent adversarial review pass.
No files in either repo were modified by either pass.

**What changed from the draft after critique.** Thirteen findings were raised; I verified every
citation against the source files and confirmed eleven outright, partially confirmed two, and
rejected three specific sub-claims (listed in the disposition table in §0). Three changes are
material. First, the draft's central recommendation — "veil-proxy's Rust type is canonical,
demote the observatory schema" — was made on incomplete evidence: `veil-observatory` has an
**accepted** ADR (ADR-0004) whose rationale states JSON Schema is "the *wire contract*" and that
"making it the source of truth keeps the contract provider-portable." The recommendation
survives, but its justification is rewritten and it now requires a **two-sided** ratification
with an explicit scope note on ADR-0004, not a unilateral demotion (§2.5, §3.1). Second, the
draft's "one envelope, two payload kinds" shape was wrong: `veil-proxy` has already ratified the
alert lane as a *deliberately more minimised* payload, and a pre-send `Block` never produces a
Bedrock invocation to correlate against — so the shape is now **three record kinds** (§3.2).
Third, the draft's `blocked_with_redaction` decision value was a genuine modelling error —
`IrreversibleRedact` is not `Block`, and redacted content is usually still *sent* — so action and
outcome are now two independent dimensions (§2.2, §3.2). Beyond the critique, this pass found
three further defects in `veil.receipt.v1` that neither document caught (§2.4a). The blocking
question set changed: Q3 and Q1 and Q2 were widened, Q4 demoted to non-blocking, and one new
blocking question (Q5, contract-change governance) was added.

Path abbreviations used below:
- `VP` = `/Users/hekton/Development/hekton/factory-output/veilgremlin`
- `VO` = `/Users/hekton/Development/veil-observatory`

All `file:line` citations in this document were re-verified by direct read during the
critique-review pass. Where the draft's or the critique's line numbers were off, they are
corrected silently in the body and flagged in §0 where the slip changed the meaning.

---

## 0. Disposition of the critique's thirteen findings

| # | Claim | Verified? | Disposition |
|---|---|---|---|
| 1 | VO ADR-0004 makes JSON Schema the contract source of truth; the plan's canonical-ownership call outruns its evidence | **Confirmed as text, overstated as conflict** | Quote is exact (`VO/docs/decisions/ADR-0004-implementation-stack.md:27`, ADR status `accepted`, `:3`). But it is a *rationale* bullet contrasting JSON Schema with **pydantic**, not an authorship claim. Recommendation stands; justification and ratification mechanics rewritten (§2.5). Critique's proposed alternative (neutral IDL / protobuf) **rejected** — it reinstates exactly the three-way version dance VP's ADR-014 amendment rejected, and `#[non_exhaustive]` still forces exhaustiveness into `vg-core` regardless of IDL |
| 2 | Alert lane is a third payload kind, not `lane = alert` on the same records | **Confirmed** | Plan revised to three record kinds (§3.2). Critique's fallback suggestion — "keep v1 receipt-only, defer non-invocation telemetry" — **rejected**: VP has ratified two lanes with independent opt-ins and "alert on, bulk off" as a *tested state* (`VP/docs/architecture/implementation-plan.md:146-149`), so a receipt-only v1 leaves the alert lane with no defined payload |
| 3 | Pre-send `Block` does not fit the receipt model | **Confirmed** | Real and structural. Folded into §2.2 and §3.2; drives new open question Q7 |
| 4 | Receipt schema lacks `additionalProperties: false`; not treated as blocking | **Confirmed** | Verified: **zero** occurrences in `veil.receipt.v1.schema.json`; **eight** in `veil.ai_activity.v1.schema.json` (`:7, :46, :79, :134, :162, :210, :271, :320`). Promoted to a blocking exit gate (§3.3) |
| 5 | Field sketch does not yet satisfy zero-String | **Confirmed** | Type inventory added as a required deliverable (§3.2a) |
| 6 | Integrity story under-specified; Q3 too narrow | **Confirmed** | Q3 rewritten as "receipt authenticity and freshness model" (§4) |
| 7 | Q1 scoping too narrow | **Confirmed** | Q1 rewritten to name the governed inventory (§4). One clarification the critique did not make explicit is added: opt-in and bypass-detection have *different denominators* (§2.1) |
| 8 | Residual privacy risk from metadata-only fields understated | **Partially confirmed** | Substance accepted but it identifies no field beyond those §2.4 already flags; its real contribution is purpose-limitation/joinability as a ratification item. Added as **non-blocking** Q10, not a schema change |
| 9 | Versioning inconsistent with closed-schema ingest | **Confirmed** | A genuine internal contradiction in the draft. Resolved with a two-part version identifier and a quarantine rule (§3.4) |
| 10 | Redaction semantics muddled; `blocked_with_redaction` is wrong | **Confirmed** | Draft error. Action and outcome split into two dimensions (§3.2) |
| 11 | Q2 too narrow — misses the Bedrock evidence surface | **Confirmed** | Q2 widened to endpoint coverage and correlatability (§4) |
| 12 | Q4 `MappingCreated` is not blocking | **Confirmed** | Accepted. Demoted to non-blocking with `TelemetryReject` as the stated default (§4) |
| 13 | "No migration cost" overstated | **Confirmed** | `VO/docs/decisions/ADR-0015-first-vertical-slice-scope.md:11` puts signed-receipt ingestion in accepted scope. Wording corrected throughout: *no deployed producer; low but non-zero cost* |

Citation slips corrected: the critique cites `VP/docs/architecture/product-family.md:379-383`
for the alert-lane resolution — the sentence actually spans `:381-385`; and `:418-420` for the
minimal payload — it spans `:418-421`, with the same content also on the diagram edge at `:409`.
Neither slip changes the finding. The draft's `implementation-plan.md:145-146` for
"alert payloads more minimised" is `:146-147`; `:133-138` for zero-String is `:134-138`;
`:142-143` for the reason dictionary is `:141-142`.

---

## 1. The problem

Two repos independently drafted the same wire contract from opposite ends and neither has seen
the other's draft. `veil-proxy` has a ratified set of *design constraints* for a `TelemetryEvent`
type (zero `String` columns, `TryFrom<&AuditEvent>` inside `vg-core`, the Rust type as the
source of truth, a generated schema artifact — `VP/docs/decisions.md:2881,2883`,
`VP/docs/architecture/implementation-plan.md:24-29,132-159`) but **no concrete field list**.
`veil-observatory` has a **concrete field-by-field JSON Schema**
(`VO/schemas/veil.receipt.v1.schema.json`) transcribed from a research pack
(`VO/docs/research/veil-observatory-dr.md:104-177`) that its own session log calls "an
unvalidated draft guess" (`VO/docs/session-log.md:345`). The drafts disagree on what the edge
component *is* (opt-in laptop telemetry vs. mandatory per-invocation control receipts from an
AWS-fleet "Veil Edge"), on shape (event stream vs. aggregated receipt), on typing discipline
(closed enums vs. regex-constrained strings), on integrity (no signing vs. mandatory KMS
signing), and — the finding this revision adds — on **who is entitled to author the contract at
all**, where both repos hold accepted decisions that read as claims on the same authority.

Nothing is deployed and nothing emits either shape yet (`VO/docs/session-log.md:345`), so this
is the cheapest moment the convergence will ever be. It is not *free*: `veil-observatory` has
accepted scope that already assumes signed receipts as an ingest input — its first vertical
slice ingests "synthetic Bedrock invocation records, CloudTrail events and signed Veil receipts
→ validate against versioned contracts" (`VO/docs/decisions/ADR-0015-first-vertical-slice-scope.md:11`),
with scenario B1 turning on "invocation with no receipt at all" (`:15`). Changing the contract
now costs ADR amendments, fixture rewrites, and scenario re-derivation on the observatory side.
That is a low cost paid in documents, not a deployed-producer migration — but the plan should
say *low*, not *nil*.

---

## 2. Concrete points of disagreement

### 2.1 Naming drift is really deployment-model drift (the big one)

"Veil Edge" and "veil-proxy" name the same *role* — the masking component in front of Bedrock —
but the two docs assume **different deployments of it**, and several receipt fields only make
sense in one of them:

| Evidence | veil-proxy assumption | veil-observatory assumption |
|---|---|---|
| `VP/docs/spec/requirements-and-design-spec.md:16-18` — "local-first privacy control plane... on a developer's machine... on laptops without waiting for a control-plane rollout" | Per-laptop, single-user, local vault | — |
| `VP/docs/architecture/product-family.md:254-269` — telemetry crosses the boundary "only if `veil-observatory` is deployed and enabled"; ADR-015 (`VP/docs/decisions.md:2882`): telemetry "may leave, opt-in only" | **Opt-in** fleet telemetry, two lanes with independent opt-ins (`VP/docs/architecture/implementation-plan.md:146-149`) | — |
| `VO/docs/research/veil-observatory-dr.md:100` — "Veil Edge should emit a **signed, privacy-preserving control receipt** for every governed Bedrock invocation"; `VO/docs/architecture/security-privacy-principles.md:10` and ADR-0014 — a **missing** receipt is "a coverage defect or bypass signal, not a normal state" | — | **Mandatory** per-invocation receipt; absence = bypass alarm |
| `VO/schemas/veil.receipt.v1.schema.json:7-21` — required `edge_instance_id`, `tenant_id`, `aws_account_id`, `aws_region`; example `edge_instance_id: "edge-eu-west-2-a-17"`, `tenant_id: "org-123"` (`VO/docs/research/veil-observatory-dr.md:122-123`) | Device pseudonym minted at enrolment, "explicitly never the OS hostname" (`VP/docs/architecture/implementation-plan.md:150`, `VP/docs/decisions.md:2838-2841`) | Regional gateway-fleet instance naming, multi-tenant SaaS envelope |

Two genuine conflicts hide under the naming:

1. **Opt-in vs. absence-as-bypass — and the denominator problem.** These are contradictory as
   stated. veil-proxy's ratified ADR-015 makes telemetry opt-in; veil-observatory's correlation
   model treats a missing receipt as a tamper/bypass *finding*
   (`VO/docs/decisions/ADR-0014-deterministic-correlation.md:13` — "If Tier 1 fails, the
   invocation is treated as having **no receipt** — which is a finding, not an error";
   `VO/schemas/veil.ai_activity.v1.schema.json:115-120` — "null is a COVERAGE GAP SIGNAL").

   The draft proposed scoping the rule to "enrolled, opted-in devices." That is necessary but
   insufficient, and the reason is worth stating precisely because it is the crux the critique
   correctly identified without naming: **the two sides use different denominators.**
   veil-proxy's opt-in governs *whether a receipt is emitted* and is enumerated **device-side**.
   The observatory's bypass detection starts from *Bedrock-side evidence* — invocations
   observed in governed accounts/regions/routes — and is enumerated **cloud-side**. A device
   opting out does not remove its Bedrock traffic from the observatory's denominator; it removes
   the receipt. So "opted-in fleet" alone cannot be the scope, because the observatory cannot
   see the opt-in state of a device it has never heard from. The governed inventory has to be
   expressed in terms the observatory *can* enumerate: managed accounts, regions, IAM roles,
   applications, and endpoint families — cross-referenced against an enrolment registry that
   someone must own. Without that, `receipt_ref = null` is ambiguous across at least five
   distinct causes (§2.2a). **Blocking human decision (Q1).**

   Supporting evidence that this is already an open item on the observatory side, not an
   invention of this plan: `VO/docs/research/open-questions.md:11` asks exactly "what happens to
   correlation and receipt-to-invocation linkage for any call that bypasses the Veil-instrumented
   client entirely?" and answers only "this needs turning into an actual detection rule."
   `VP/docs/architecture/product-family.md:216-223` makes the complementary point from the other
   side: the redundant masked-only audit trail "only holds if the composition is enforced (IAM
   makes bypassing `veil-proxy` impossible)."

2. **Instance identity.** `edge_instance_id`'s pattern `^[A-Za-z0-9_.:-]{1,128}$`
   (`VO/schemas/veil.receipt.v1.schema.json:34-37`) happily accepts
   `laptop-jsmith.corp.acme.com` — an OS hostname, which veil-proxy's own taxonomy classes as
   enterprise-sensitivity data (`VP/docs/spec/requirements-and-design-spec.md:165`) and which
   §6's device-identity decision explicitly excludes (`VP/docs/decisions.md:2838-2841`, which
   calls the "device name is already sent in logs today" premise "the leak to fix, not a
   baseline to keep"). The reconciliation is easy once named: `edge_instance_id` **is** the
   enrolment-minted device pseudonym, format-constrained to make a hostname unrepresentable
   (see §3.2).

Note the pack's SaaS framing is not entirely foreign to veil-proxy —
`VP/docs/architecture/product-family.md:832-835` already flags telemetry residency for "a
centralized (esp. SaaS) `veil-observatory`," and the spec claims a "gateway-ready" posture
(`VP/docs/spec/requirements-and-design-spec.md:187`). The drift is about **which deployment v1
of the wire contract must serve**, not about whether the other is imaginable.

### 2.2 Structural mismatch: three shapes, not two

`AuditEvent` (`VP/crates/vg-core/src/audit.rs:20-49`) is six discrete variants; the plan derives
`TelemetryEvent` per-variant via `TryFrom` (`VP/docs/architecture/implementation-plan.md:139-140`).
The receipt (`VO/schemas/veil.receipt.v1.schema.json`) is **one record per Bedrock invocation**
aggregating decision + detections + timing.

The draft concluded this composes into two payload kinds. That was wrong on two counts, both
raised by the critique and both confirmed here.

**(a) The alert lane is a third kind, already ratified as such.**
`VP/docs/architecture/product-family.md:381-385` resolves the lane question explicitly: "alert-class
events get a second, distinct delivery lane — sent individually and immediately on a rule match,
never batched — alongside the unchanged batched bulk-telemetry lane." And `:418-421` fixes the
payload: "the alert-lane payload is *more* minimised than bulk telemetry, not less... a rule id,
a severity, a device pseudonym (§6), and a timestamp is enough to page someone; it is
deliberately not enough to reconstruct what happened." The architecture diagram's own edge label
says the same (`:409`). `VP/docs/architecture/implementation-plan.md:146-147` carries this into
the build plan.

This is not a lane flag over the same record. A receipt is *evidence* — it must be complete
enough to prove a control ran. An alert is *routing* — it must be small enough that shipping it
immediately, on a rule match, over a low-latency path, leaks nothing. Putting `lane: alert` on a
receipt-shaped record makes the alert lane strictly worse than its ratified design, which is the
one direction `product-family.md:416` names as forbidden ("without quietly relaxing the stricter
requirement"). Three kinds.

**(b) A pre-send `Block` produces no Bedrock invocation, so it cannot be a receipt.**
`AuditEvent::Block { artefact, reason }` (`VP/crates/vg-core/src/audit.rs:35-38`) fires when
policy says "do not send." If nothing is sent, there is no Bedrock call, no
`requestMetadata.veil_trace_id` in any invocation log, and therefore nothing for ADR-0014's
Tier-1 exact-match join to match against
(`VO/docs/decisions/ADR-0014-deterministic-correlation.md:11-13`, which forbids fuzzy and
time-window receipt matching outright). Emitting a receipt for a blocked-before-send attempt
would create a receipt that can *never* correlate — which the observatory's model has no state
for. Its `receipt_state` enum covers `full | degraded | absent | integrity_failed`
(`VO/schemas/veil.ai_activity.v1.schema.json:122-130`) — all four describe a receipt's relation
to an *observed invocation*. "Control decision with no invocation" is a fifth thing.

Mapping the six variants with both corrections applied:

| `AuditEvent` variant (`audit.rs`) | Record kind | Fit |
|---|---|---|
| `Scan { counts, detector_version, latency_us }` (`:21-25`) | Receipt — `controls.detections[]` (`:221-250`), `controls.detector_bundle_version` (`:212-214`), `timing` (`:268-286`) | Composes — receipt is the roll-up |
| `PolicyDecision { artefact, class, policy_version }` (`:26-30`) | Receipt — `controls.decision` (`:258-265`), `controls.policy_bundle_version` (`:209-211`) | Composes, **but** the receipt has no artefact-kind field and cannot express redaction (see below) |
| `Block { artefact, reason }` (`:35-38`) | **Edge event** if pre-send; receipt only if the invocation was actually issued | **Diverges** — see (b) above. Receipt has no reason field at all; the planned `BlockReasonCode` + versioned reason dictionary (`VP/docs/architecture/implementation-plan.md:87,141-142`) needs a home |
| `MappingCreated { mapping_ref, entity_type }` (`:31-34`) | **None** by default (Q8) | No receipt field can carry a mapping ref |
| `DemaskRequest { dest, actor }` (`:39-42`) | Edge event | Demask is a local post-response act; no `veil_trace_id`/`requestMetadata` to correlate with |
| `DemaskDecision { dest, actor, allowed, policy_version }` (`:43-48`) | Edge event | Same |

**The redaction defect, stated correctly.** `HandlingClass` has four variants —
`Mask` ("Reversible typed placeholder via vault"), `IrreversibleRedact` ("One-way; never
vault-stored"), `Block` ("Do not send (artefact-level)"), and `Pass` ("Non-sensitive") —
`VP/crates/vg-core/src/types.rs:81-89`, matching the spec's handling-class table
(`VP/docs/spec/requirements-and-design-spec.md:169-174`). The receipt's `detections[].action`
enum is `masked | blocked | allowed` (`:241-248`) and its `controls.decision` enum is
`allow | allow_with_masking | blocked` (`:258-265`). Neither can represent redaction.

The draft proposed adding `redacted` to `action` **and** `blocked_with_redaction` to `decision`.
The first is right; the second is a modelling error and the critique is correct to call it
dangerous. `IrreversibleRedact` is *not* `Block`: the artefact is normally still **sent**, with
the redacted spans one-way destroyed. Reporting that as any flavour of "blocked" inverts the
compliance meaning — it claims data did not reach the model when it did.

The deeper reason the receipt cannot patch its way out of this with one more enum value:
`Mask`/`IrreversibleRedact`/`Pass` are decisions about **entity classes within** an artefact,
while `Block` is explicitly "artefact-level" (`types.rs:86-87`). One enum cannot carry both
granularities. The fix is two independent dimensions (§3.2).

Note also that the receipt does not even *require* `detections` —
`controls.required` is `["policy_bundle_version", "detector_bundle_version", "decision"]`
(`:203-207`). A receipt asserting `decision: "allow_with_masking"` with no detections array at
all validates today. That is an evidentiary hole neither the draft nor the critique caught; see
§2.4a.

### 2.2a What `receipt_ref = null` currently means

Because §2.1's denominator problem and §2.2's structural gaps interact, `receipt_ref: null`
(`VO/schemas/veil.ai_activity.v1.schema.json:115-120`) is today ambiguous across at least five
causes, only one of which is the bypass it is documented to signal:

1. genuine bypass — a real invocation that dodged `veil-proxy`;
2. ordinary opt-out — an enrolled device with the bulk lane off (`VP/docs/decisions.md:2882`);
3. unenrolled device — never in the fleet, out of scope entirely;
4. unsupported endpoint — `bedrock-mantle` traffic, which has no per-request metadata tagging at
   all (`VO/docs/research/veil-observatory-dr.md:90`, and the schema's own note at `:185`);
5. missing infrastructure — invocation logging not enabled in that account/region
   (`VO/docs/research/open-questions.md:9`).

Disambiguating these is the actual content of Q1 and Q2, and neither can be answered inside
either repo alone. Until they are, a bypass detector built on this field will either spam false
findings or be tuned down until it misses real ones.

### 2.3 Typing philosophy

veil-proxy: zero `String` columns, enums/integers/fixed-width hashes, all fields private, no
constructor accepting `String` (`VP/docs/architecture/implementation-plan.md:134-138`). The
receipt schema instead uses open regex strings widely, and is **inconsistent with its own
hardening**: it constrains `detections[].class` tightly with an explicit ADR-0012 rationale
(`:231-235`) and `caller.environment` likewise (`:147-153`, "Caught by the ops-leak fuzz test the
moment the field was threaded through"), yet leaves `allowed_exceptions[]` items (`:252-256`),
`caller.repository_id` and `caller.workspace_id` (`:135-146`), `invocation.operation` (`:187-189`),
`aws_region` (`:46-48`), both bundle-version fields (`:209-214`), and every `integrity` field
except `algorithm` (`:298-319`) completely unconstrained — each one a fresh instance of the
ops-leak class its own fuzz test exists to catch
(`VO/docs/decisions/ADR-0012-csoc-only-raw-evidence.md:29-50`).

The gap is *partly* JSON Schema's limits (an open set of detector classes cannot be a closed
`enum` across detector-pack updates) and *partly* just unfinished work. The resolution is not
"make JSON Schema into Rust": it is that **the schema stops being hand-authored at all** —
generated from the Rust type (§2.5), so closed enums render as JSON `enum`s, pseudonyms and
hashes render as anchored fixed-width patterns, reason codes render as integers into a versioned
dictionary, and free text becomes unrepresentable *by construction* rather than forbidden by
review vigilance.

The critique's caution here is correct and worth preserving as a standing warning: **"generated
from Rust" does not by itself make an open external domain safe.** `aws_region`, `operation`,
`model_ref`, and detector class names are open domains owned by third parties. Generation only
helps to the extent the Rust side actually uses a bounded type; a `struct Region(String)` newtype
generates a `"type": "string"` and nothing improves. Hence the type inventory in §3.2a is a
required deliverable, not a detail.

### 2.4 The six raw-capable surfaces vs. their receipt analogues

Does the receipt already reflect the *fixed* versions of the six surfaces
(`VP/docs/architecture/implementation-plan.md:83-92`)?

| Surface (fix planned in veil-proxy) | Receipt analogue | Verdict |
|---|---|---|
| `Block { reason: String }` (`audit.rs:35`) → `BlockReasonCode` enum + `policy_rule_id` + counts | No reason field; only `decision`/`action` enums | Safe by omission, but loses the reason entirely — needs the dictionary-index field added |
| `ActorId(pub String)` (`ids.rs:30`, confirmed still raw) → keyed HMAC pseudonym | `caller.principal_ref`, pattern `^[A-Za-z0-9_.:-]{1,128}$` (`:123-125`) | **Inherits the risk.** The pattern accepts a raw username (`jsmith`) or email local-part verbatim. Needs a pseudonym-format pattern (prefix + fixed-width hex), per Boundary 5 (`VO/docs/architecture/trust-boundaries.md:21-23`) whose *intent* is already pseudonymous. The DR pack's own example is already correctly shaped — `"principal_ref": "usr_pseudo_9f2c"` (`:139`) — the schema just doesn't enforce it |
| `detector_version: String` (built from `DetectorId(pub String)`, `ids.rs:26`) → bounded `DetectorSetId` | `controls.detector_bundle_version`, unconstrained string (`:212-214`) | **Inherits the risk** — needs a version-token pattern |
| `policy_version: String` → validated `VersionToken` | `controls.policy_bundle_version`, unconstrained string (`:209-211`) | **Inherits the risk** — same |
| `EntityType::Custom(String)` (`types.rs:38`) → bounded label or excluded | `detections[].class`, pattern `^[a-z0-9_]+(:[a-z0-9_]+)?$`, max 64 (`:231-235`) | **Half-fixed.** Charset and length are constrained (their ADR-0012 lesson), but a custom class *name* like `acme_project_titan_codenames` still transits verbatim — the same class of leak veil-proxy just closed in `MaskedPack` and in `EntityType`'s `Display` impl, which now collapses `Custom(_)` to a fixed `"CUSTOM"` tag (`VP/crates/vg-core/src/types.rs:73`, `VP/docs/decisions.md:2884-2887`). Full fix = classes drawn from the versioned detector-bundle registry and validated against it at ingest |
| `ArtefactKind::SourceCode(String)` (`traits.rs:38`) → bounded language enum | No artefact-kind field in the receipt | Safe by omission; add as a closed enum if artefact context is wanted |

Bonus finding in the same class: `caller.repository_id`'s worked example is a **raw repo
identifier** (`"github://org/repo"`, `VO/docs/research/veil-observatory-dr.md:142`) with no
schema constraint at all (`:135-140`) — "repo-specific IDs" are explicitly
enterprise-sensitivity data in veil-proxy's taxonomy
(`VP/docs/spec/requirements-and-design-spec.md:165`). `caller.environment` is
pattern-constrained but still free-form within that pattern (`:147-153`) — `prod-euc1-payments`
matches `^[a-z0-9_-]{1,32}$` and leaks infra naming. These should become hashed refs or registry
IDs, mirroring `ai_activity`'s own `identity_arn_ref` / `source_ip_ref` "hashed reference, not
the ARN itself" discipline (`VO/schemas/veil.ai_activity.v1.schema.json:144-156`) — the
observatory has already invented the right pattern one schema over and simply not applied it
here.

### 2.4a Three further defects in `veil.receipt.v1`, found in this pass

Not raised in the draft or the critique; found by direct read of the schema during verification.
All three are cheap to fix and all three weaken evidence in the same direction — toward a receipt
that *looks* valid while asserting less than a reader assumes.

1. **`detections` is optional.** `controls.required` is
   `["policy_bundle_version", "detector_bundle_version", "decision"]` (`:203-207`). A receipt with
   `decision: "allow_with_masking"` and no `detections` array validates. It claims masking occurred
   while carrying zero evidence of what was masked — and `ai_activity` copies exactly this field
   family into `declared_masked_classes`, so the gap propagates downstream. `detections` must be
   required (possibly empty, but present) whenever `decision` is anything other than `allow`.
2. **`edge_outcome` is optional with `"default": "complete"`** (`:322-330`). A receipt that omits
   the field is read as a *complete* receipt. That is fail-open on the exact coverage signal the
   field exists to carry — the DR pack's "failure receipt stub" mechanism
   (`VO/docs/research/veil-observatory-dr.md:181`) depends on the distinction being explicit.
   Make it required, no default.
3. **`integrity`'s fields are unconstrained strings.** `payload_sha256`, `nonce`, and `signature`
   are bare `"type": "string"` (`:298-303, :317-319`) — no length, no charset, no encoding. A
   SHA-256 hex digest is a fixed 64-character `^[a-f0-9]{64}$`. As written, the integrity block is
   itself an unbounded free-text channel sitting inside the structure whose job is to prove the
   record was not tampered with.

### 2.5 Source of truth — the governance conflict, resolved

This is the load-bearing item, and the draft got it wrong by omission. The critique's claim is
**real**. The ADR exists, it is `accepted`, and the quoted text is exact.

`VO/docs/decisions/ADR-0004-implementation-stack.md:3` — "**Status: accepted** — 2026-07-24
(ratified during night-shift NS-001; was proposed at scaffold time)".

`VO/docs/decisions/ADR-0004-implementation-stack.md:27`, verbatim:

> - **`dataclasses` + JSON Schema over `pydantic`**: JSON Schema is the *wire contract* that a
>   future non-Python consumer (or an AWS Glue job) must honour; making it the source of truth
>   keeps the contract provider-portable rather than encoding it in a Python-specific validation
>   library. `dataclasses` gives typing without a dependency.

Against `VP/docs/decisions.md:2881` (ADR-014 as amended and ratified 2026-07-26), verbatim:

> No schema repo because `AuditEvent` is `#[non_exhaustive]`, forcing the telemetry conversion
> into `vg-core` — the Rust type is already the single source of truth, so a third repo would buy
> a three-way version dance and nothing else.

**Where I agree with the critique.** The draft treated `VO/contracts/README.md:15` ("None of
these are final... Fable should validate and formalise all of them") plus
`VO/docs/session-log.md:345` ("an unvalidated draft guess") as concessions that Rust owns the
contract. They are not. Both concede only that *this particular draft file* is provisional. The
draft cherry-picked, and its recommendation to "demote the observatory schema" was a unilateral
move against an accepted ADR it had not read. That is a real governance defect and the critique
is right to call it disqualifying for a ratification packet.

**Where I disagree with the critique, and why.** The critique reads ADR-0004:27 as a claim on
contract *authorship* that directly contradicts VP. Read in place, it is narrower than that, in
three checkable ways:

1. **It is a rationale bullet, not the decision.** The Decision section is `:18`: "**Python
   ≥3.11, `src/` layout, stdlib-first.** Runtime dependency: `jsonschema` only... Domain models
   via stdlib `dataclasses`." The ADR's title is "Initial Implementation Stack" and its Problem
   statement (`:7`) asks "What language, runtime and dependency set implements Veil Observatory's
   ingestion, correlation, detection and investigation surface?" Nothing in the decision scope
   concerns who authors a cross-repo wire contract.
2. **The alternative it rejects is pydantic, not Rust.** The bullet's own framing is
   "`dataclasses` + JSON Schema **over `pydantic`**." "Source of truth" there means *the contract
   lives in a JSON Schema file rather than being encoded in Python class definitions* — an
   argument about where the contract lives **within** the observatory's own codebase.
3. **Its stated purpose is provider-portability**, satisfied by the artifact's *form*, not its
   provenance: "a future non-Python consumer (or an AWS Glue job) must honour" it. A JSON Schema
   generated from Rust is exactly as portable to a Glue job as one typed by hand. The ADR's
   Consequences section (`:31`) confirms the operative concern is runtime validation mechanics —
   "Contract validation is explicit (`validate_or_raise`) rather than automatic on construction"
   — which a generated schema does not disturb at all.

**The resolution.** The two decisions are compatible under a distinction neither repo wrote down:

> **Contract *form*** is governed by VO ADR-0004: the wire contract is a language-neutral JSON
> Schema artifact, versioned, validated at every adapter and store boundary, never a
> language-specific model class.
>
> **Contract *provenance*** is governed by VP ADR-014 as amended: that artifact is **generated
> from `vg-core`'s `TelemetryEvent`** and published from `veil-proxy`. It is never hand-edited,
> in either repo.

Both hold simultaneously. VO validates against a JSON Schema file exactly as ADR-0004 requires;
VP keeps the single-source-of-truth property that `#[non_exhaustive]` forces on it anyway
(`VP/crates/vg-core/src/audit.rs:18-19`, and the doc comment at `:15-17` already notes new
variants "still go through the contract-change protocol" — a protocol that, notably, is not
written down anywhere).

**What genuinely remains conflicted, and must be decided by a human.** Under generation, the
observatory cannot change the contract it consumes. Its accepted ADR-0015 scope depends on
receipt fields (`:11,15`), and its ADR-0012 fuzz discipline has already produced *better* field
constraints than the plan's Rust side currently has types for (`:231-235`, `:147-153`). A
provenance rule with no change-proposal path makes the consumer a bystander to its own
requirements. That is the actual residual conflict, and it is a process gap rather than an
ownership one. **New blocking decision (Q5): the cross-repo contract-change protocol.**

**Rejected alternative.** The critique proposes "JSON Schema/protobuf/OpenAPI/Serde-compatible
IDL as the language-neutral contract with generated Rust/Python types." Rejected on VP's own
existing reasoning: a hand-authored neutral IDL reinstates precisely the "three-way version
dance" that ADR-014's amendment rejected (`VP/docs/decisions.md:2881`), and it does not remove
the `#[non_exhaustive]` constraint — the `TryFrom<&AuditEvent>` conversion still has to live in
`vg-core` for compile-time exhaustiveness (`VP/docs/decisions.md:2883`), so the Rust type remains
the place where "new audit fact" becomes "wire change" regardless. An IDL would add a third
artifact to keep in sync while relocating no decision. The critique's *other* alternative —
"Rust-owned producer types plus a separately ratified wire schema and cross-referenced
conformance tests" — is substantially what §3.3 step 6 already proposes, and is adopted.

**Recommendation, restated with the corrected basis:** the generated artifact published from
`veil-proxy` is canonical **as to provenance**; JSON Schema remains the contract **as to form**;
ratification requires a *paired* record in both repos (§3.1), including a scope note appended to
VO ADR-0004 — written by the observatory, not imposed on it.

`veil.ai_activity.v1` is **not** part of the wire contract — it is observatory-internal, derived
downstream (it merges Bedrock evidence the edge never sees) — and does not move to veil-proxy.
Only fields it copies from receipts (`declared_masked_classes`, `edge_reported_stage`,
`receipt_ref`, `receipt_state`) must track the canonical receipt shape.

### 2.6 Integrity, authenticity and freshness

The receipt mandates an `integrity` block — payload hash, nonce, algorithm, signature, optional
KMS key (`VO/schemas/veil.receipt.v1.schema.json:288-321`). veil-proxy's `TelemetryEvent` design
says nothing about signing (`VP/docs/architecture/implementation-plan.md:132-159` — absent). This
is not receipt-specific decoration: observatory's Boundary 3 treats integrity failure as a
distinct tampering signal, "handled distinctly from a receipt that's simply missing"
(`VO/docs/architecture/trust-boundaries.md:13-15`), and `receipt_state: "integrity_failed"` is a
first-class state (`VO/schemas/veil.ai_activity.v1.schema.json:122-130`). **veil-proxy's design
must grow a signing requirement for all three record kinds** — an unsigned alert lane would be
the *easier* forgery target, and alert payloads are supposed to be more minimised, not less
protected (`VP/docs/architecture/product-family.md:418-421`).

The draft framed the open question as "which key." The critique is right that this is too
narrow, and the evidence supports the wider framing on both sides. The observatory's principles
require five mechanisms together — "nonce, monotonic per-edge sequence number, issue timestamp,
short replay window, canonicalised-payload hash"
(`VO/docs/architecture/security-privacy-principles.md:9`, from
`VO/docs/research/veil-observatory-dr.md:181`) — and the current schema implements **two** of
them (`payload_sha256`, `nonce`); there is no sequence field and no replay-window field anywhere
in it. Separately, `VO/docs/research/open-questions.md:23` records signing-key management as
unresolved on the observatory side too: "doesn't specify key rotation policy, per-Edge-instance
vs. shared keys, or cross-account signing verification if Observatory's central evidence zone is
a different account than the Edge instance."

One distinction the critique draws that is worth keeping explicit: **payload signing is not
transport attestation.** The family has ratified mTLS device certificates for attestation
(`VP/docs/decisions.md:2894`), which proves *this connection came from an enrolled device*. It
does not prove *this record was produced by that device and not altered afterwards* — which is
what Boundary 3 needs. The two candidate keys remain the custodian-issued device key and KMS
`Sign` via the same AWS credentials used for Bedrock (the DR pack prefers asymmetric for exactly
the cross-team portability reason, `:179`), but the question they answer is only part of the
model. **Blocking human decision (Q3), widened.**

### 2.7 Small but real: units and timestamps

`AuditEvent::Scan.latency_us` is microseconds (`VP/crates/vg-core/src/audit.rs:24`); the
receipt's `timing` block is milliseconds throughout (`:268-286`). For a project that treats the
hot path "like a low-latency trading system" where "every millisecond counts"
(`VP/docs/spec/requirements-and-design-spec.md:184-185`), ms granularity destroys the signal it
exists to carry. Also `issued_at` is an ISO-8601 string (`:30-33`) while veil-proxy's zero-String
rule implies integer epoch time, and `edge_started_ms`/`edge_completed_ms` are bare integers with
no declared epoch at all (`:276-281`). Trivial to fix pre-implementation, breaking after.

---

## 3. Recommended reconciliation

### 3.1 Settle identity and authority first (Phase R0 — decisions, no code)

1. **Paired ratification of the source-of-truth split (§2.5).** Not a unilateral demotion. Two
   records, one in each repo, saying the same thing from each side:
   - In `VP/docs/decisions.md`: the published artifact is **JSON Schema** (not a Rust-only
     definition), it is normative for consumers, and `veil-proxy` is its sole publisher.
   - In `VO/docs/decisions/`: a scope note on ADR-0004 recording that "source of truth" in `:27`
     means *the JSON Schema artifact rather than a Python model class*, and does not assert
     observatory authorship of the wire contract — written by the observatory, as an amendment
     in its own voice. ADR-0004 is not superseded; its decision (`:18`) is untouched.
   - Both records reference the change protocol from Q5.
2. Ratify in both repos: **"Veil Edge" = `veil-proxy`**, one component, and the v1 wire contract
   targets veil-proxy's actual deployment: per-device, enrolment-based, opt-in. Fleet-gateway and
   multi-tenant SaaS fields stay in the schema only where they cost nothing (nullable
   `tenant_id`), never as required envelope.
3. Resolve Q1 (governed inventory), Q2 (governed invocation surface), Q3 (authenticity and
   freshness model), Q5 (change protocol) — all blocking.
4. Record in `VO/contracts/README.md` that `veil.receipt.v1.schema.json` is a research
   transcription, superseded by the generated artifact once published.

### 3.2 One contract, three record kinds (the shape decision)

Neither draft wins whole; the honest merge is a **signed envelope + three payload kinds**, all
generated from `vg-core`:

```
veil.telemetry.v1 envelope (every record, every lane)
  schema_version        const per payload kind (e.g. "veil.receipt.v2")
  contract_revision     integer, additive-only within a schema_version (see §3.4)
  record_id             prefixed ULID, anchored pattern
  issued_at_us          integer epoch microseconds
  device_ref            enrolment pseudonym, anchored pattern ^dev_[a-f0-9]{32}$
                        (replaces edge_instance_id; a hostname is unrepresentable)
  tenant_id             nullable; null for self-hosted single-org
  sequence              integer, monotonic per device (replay defence)
  valid_until_us        integer epoch microseconds — explicit freshness window (§2.6)
  integrity             { payload_sha256, nonce, algorithm enum, key_ref, signature }
                        all fixed-width, anchored (§2.4a-3)
```

Note there is no `lane` field. The lane is implied by the record kind and by the delivery path;
a flag would invite exactly the "one lane serving two jobs" collapse
`VP/docs/architecture/product-family.md:383-385` rejects.

**Kind A — invocation receipt (`veil.receipt.v2`).** The observatory draft's shape, kept:
linkage block with `veil_trace_id` (veil-proxy adopts Bedrock `requestMetadata` stamping, which
its design currently lacks entirely), invocation context, caller context, controls, timing,
`edge_outcome`. Emitted **only when a Bedrock invocation was actually issued** (§2.2b). Amended:

- **Two decision dimensions replacing one** (§2.2, fixing the draft's error):
  - `detections[].action` — per entity class: `masked | redacted | blocked | allowed`, a direct
    generation of `HandlingClass` (`VP/crates/vg-core/src/types.rs:81-89`).
  - `controls.outcome` — per invocation/artefact: `sent_unmodified | sent_masked | sent_redacted
    | sent_masked_and_redacted | blocked_before_send`. `blocked_before_send` appears here only
    for the artefact-level partial-block case; a wholly blocked attempt is Kind C.
  - Explicitly **not** `blocked_with_redaction`. Redaction is not blocking.
- `detections` becomes **required** whenever `outcome != sent_unmodified` (§2.4a-1).
- `edge_outcome` becomes **required**, no default (§2.4a-2).
- `block_reason_code` — integer index into the versioned reason dictionary
  (`VP/docs/architecture/implementation-plan.md:87,141-142`).
- `principal_ref` / `repository_id` / `workspace_id` / `environment` become anchored pseudonym or
  registry-ref patterns, or hashed refs on the `identity_arn_ref` model
  (`VO/schemas/veil.ai_activity.v1.schema.json:144-156`).
- Bundle versions get version-token patterns; `allowed_exceptions` becomes exception-rule IDs,
  pattern-bound.
- Timing in microseconds, epoch declared.
- `aws_account_id` / `aws_region` kept — the observatory needs them for tier-2 corroboration
  (`VO/docs/decisions/ADR-0014-deterministic-correlation.md:12`) and the edge does know the
  account it invokes.
- `additionalProperties: false` at **every** object boundary (§3.3).
- Roll-up rule: the receipt aggregates that invocation's `Scan`/`PolicyDecision`/`Block`-derived
  data; those variants do not *also* ship as discrete bulk records. One fact, one place.

**Kind B — alert (`veil.alert.v1`).** Its own minimal schema, matching the ratified payload
exactly: rule id, severity, device pseudonym, timestamp
(`VP/docs/architecture/product-family.md:409,418-421`) — plus the envelope and its signature.
Deliberately *not* a receipt subset or a field mask over one, because a mask is a filter someone
can widen; a separate generated type makes over-sharing a compile error in `vg-core`. It carries
no detection classes, no counts, no caller context, no trace linkage. If an investigator needs
more, they get it from the hot tier under that tier's existing retention and pseudonymisation
discipline, which is precisely the mechanism `product-family.md:421-425` specifies ("what CSOC
gets on day one is speed, not scope").

**Kind C — non-invocation edge event (`veil.edge_event.v1`).** Discrete records for:
`DemaskRequest` / `DemaskDecision` (dest enum, actor pseudonym, allowed bool, policy version
token); **blocked-before-send attempts** (`AuditEvent::Block` where nothing reached Bedrock —
artefact kind, reason code, policy version, but no `veil_trace_id`, because none exists); and —
pending Q8 — `MappingCreated`. These correlate by `session_id` / `local_trace_id`, never by
`veil_trace_id`, and never attach to an `ai_activity` invocation by any means, which is
consistent with ADR-0014's no-fuzzy-matching rule rather than a loophole in it. The observatory
ingests them as a second stream feeding demask- and bypass-oriented findings.

**Where the invariant lives.** `TelemetryEvent` in `vg-core` becomes the enum of these three
payloads plus the envelope, zero-String, private fields, `TryFrom<&AuditEvent>` with
`TelemetryReject` — unchanged from the ratified plan (`VP/docs/decisions.md:2883`), now with a
concrete target shape. The conversion is no longer 1:1 for invocation-scoped variants: a small
in-emitter aggregator groups audit events by trace before minting a receipt, and must decide at
trace close whether the invocation was issued (Kind A) or blocked before send (Kind C). **That
aggregator is new machinery the veil-proxy plan did not budget for and must be named in its
Phase 1** — it also holds unsent evidence in memory, so it is itself in scope for the no-raw-value
gates.

Proposed field sketch (**synthesis — nothing below is written down in either repo yet; every line
needs review**):

| `TelemetryEvent` (Rust, vg-core) | Wire (generated JSON Schema) | Source |
|---|---|---|
| `Receipt { linkage, invocation, caller, controls, timing_us, edge_outcome }` | `veil.receipt.v2` | Aggregated `Scan` + `PolicyDecision` + issued-invocation `Block` |
| `TraceLinkage { veil_trace_id: TraceId, logical_interaction_id: TraceId, local_trace_id: TraceId, parent: Option<RecordId>, session: Option<SessionId>, attempt: u16 }` | `linkage` | new (absent from every `AuditEvent` variant) |
| `Controls { policy_version: VersionToken, detector_version: DetectorSetId, outcome: Outcome, detections: Vec<Detection>, block_reason: Option<ReasonCode>, exceptions: Vec<ExceptionRuleId> }` | `controls` | `Scan` / `PolicyDecision` / `Block` |
| `Detection { class: EntityClassId, count: u32, action: Action }`, `Action = Masked \| Redacted \| Blocked \| Allowed` | `controls.detections[]` | `EntityCounts` + `HandlingClass` |
| `Alert { rule: AlertRuleId, severity: Severity }` — envelope supplies device and time | `veil.alert.v1` | local rule evaluator, not `AuditEvent` |
| `Demask { kind: Request\|Decision, dest: Destination, actor: ActorPseudonym, allowed: Option<bool>, policy_version: VersionToken, session: SessionId }` | `veil.edge_event.v1` | `DemaskRequest` / `DemaskDecision` |
| `BlockedAttempt { artefact: ArtefactKindId, reason: ReasonCode, policy_version: VersionToken, session: SessionId }` | `veil.edge_event.v1` | `Block` where nothing was sent |
| `MappingCreated { entity_type: EntityTypeId, mapping_ref: MappingRef }` — **only if Q8 answers yes** | `veil.edge_event.v1` | `MappingCreated` |

### 3.2a Required deliverable: the type inventory

Before any of §3.2 is buildable, `veil-proxy` must publish a table mapping every opaque type name
above to a concrete non-raw-capable Rust representation and its generated JSON form. The critique
is right that the names alone prove nothing — the current codebase still has
`DetectorId(pub String)` and `ActorId(pub String)` (`VP/crates/vg-core/src/ids.rs:26,30`),
`EntityType::Custom(String)` (`VP/crates/vg-core/src/types.rs:38`), and
`ArtefactKind::SourceCode(String)` (`VP/crates/vg-core/src/traits.rs:38`), all of which the plan
*intends* to bound (`VP/docs/architecture/implementation-plan.md:85-92`) and none of which is
bounded yet. Each entry must state: representation (fixed byte array / ULID / bounded parsed
token / closed enum / registry ID / integer), the fallible constructor, and the anchored pattern
or `enum` it generates. Types over externally-owned open domains — `aws_region`,
`invocation.operation`, `model_ref`, detector class names — must say explicitly whether they are
closed enums regenerated with the artifact, or registry IDs validated against a versioned
registry at ingest. "Newtype over `String`" is not an acceptable entry.

### 3.3 Ordered change list

**veil-proxy (first — critical path per `VP/docs/architecture/implementation-plan.md:58-59`):**

1. Amend implementation-plan §3.2 with the envelope + three-kind shape, the signing requirement,
   trace linkage (Bedrock `requestMetadata` stamping), and the aggregation step.
2. Publish the §3.2a type inventory.
3. Build `TelemetryEvent` per the amended plan; extend the conformance gates
   (`assert_telemetry_event_excludes_raw_values`, the non-constructibility test — plan §3.4),
   and add the aggregator's in-flight buffer to their scope.
4. Implement schema generation. **Generation must emit `additionalProperties: false` at every
   object boundary** — for `veil.receipt.v1` that is roughly fourteen nested objects, of which
   zero are closed today while `veil.ai_activity.v1` closes eight. Add a generator test asserting
   that no emitted object lacks it (mechanised, not reviewed).
5. Publish `veil.receipt.v2` + `veil.alert.v1` + `veil.edge_event.v1` + the `veil.telemetry.v1`
   envelope as the versioned artifact.

**veil-observatory (second — consumes, does not author, but may propose per Q5):**

6. Replace `veil.receipt.v1.schema.json` with the generated artifact; mark v1 superseded in
   `contracts/README.md`; never accept the v1 shape at ingest (nothing ever emitted it).
7. Update `ai_activity.v1`'s receipt-derived fields (`receipt_ref`, `receipt_state`, class
   patterns, `edge_reported_stage`) to track v2; add ingest handling for the alert and edge-event
   streams; add a `receipt_state` value (or a separate field) for the Kind C control-decision
   case §2.2b identifies, which the current four-value enum cannot express.
8. Re-derive the ADR-0015 scenario fixtures (`:13-15`) against v2 — the low-but-non-zero migration
   cost §1 names.
9. Point the ops-leak fuzz test and the ADR-0012 fitness suite at the generated schemas.
   Observatory's tests become the **consumer-side** check on veil-proxy's generator — a genuinely
   useful cross-repo gate: type system on one side, fuzz on the other, same invariant. This is
   exactly the "two different mechanisms, same invariant, deliberately continuous across the
   boundary" discipline `VP/docs/architecture/product-family.md:699-705` already argues for, and
   it is also what makes Q5's change protocol enforceable rather than advisory: a failing
   consumer-side fuzz test is the observatory's structural veto.

### 3.4 Versioning, reconciled with closed-schema ingest

The draft said "additive fields = minor release, no const bump" while also endorsing VP's ingest
rule to "**reject unknown fields**" before storage
(`VP/docs/architecture/implementation-plan.md:183-185`). The critique is right that these
contradict: under strict rejection, an additive field is a breaking change for every consumer that
has not upgraded. §3.3's `additionalProperties: false` requirement makes the contradiction sharper
still, since rejection becomes structural rather than a policy the ingest layer chooses.

**Resolution — a two-part version identifier plus a quarantine rule:**

- `schema_version` (const, e.g. `"veil.receipt.v2"`) changes on **any** semantic or shape change,
  including field removal, type change, and enum-value changes.
- `contract_revision` (integer, monotonic) increments on **additive-only** changes within a
  `schema_version`.
- Ingest rule: a consumer validates against the highest revision it knows. If
  `contract_revision` is **higher** than the consumer's, unknown fields are expected — the record
  routes to **quarantine** (which `VP/docs/architecture/implementation-plan.md:186-187` already
  provides for) rather than being silently accepted or hard-dropped. Quarantine depth is itself
  the upgrade-lag signal. If `contract_revision` is equal or lower and unknown fields appear, that
  is a genuine violation and the record is rejected.
- Consumers ingest `schema_version` N and N-1 for one deprecation window, **once real producers
  exist**. Today they need only N.

This keeps additive evolution cheap without making "reject unknown fields" a lie, and it removes
the ambiguity the critique names — one const covering multiple shapes — because a shape is now
identified by the pair, not by the const alone.

`AuditEvent` gaining a variant (`#[non_exhaustive]`, `VP/crates/vg-core/src/audit.rs:19`) forces
a `TryFrom` decision in `vg-core` at compile time — the designed choke point where "new audit
fact" becomes "wire change or explicit `TelemetryReject`". The source comment at `:15-17` already
refers to a "contract-change protocol" governing this; Q5 is the request to actually write it.

---

## 4. Open questions needing a human decision

**Blocking:**

- **Q1 — The governed inventory (widened from the draft).** Not merely "scope the bypass rule to
  opted-in devices," which the observatory cannot evaluate (§2.1). Name the inventory in terms the
  observatory can enumerate cloud-side — managed accounts, regions, IAM roles/principals,
  applications, endpoint families — and name who owns the enrolment registry that inventory is
  cross-referenced against, and how the five distinct causes of `receipt_ref = null` (§2.2a) are
  told apart. Touches ratified ADR-015 (`VP/docs/decisions.md:2882`) on one side and ADR-0014 plus
  `VO/docs/architecture/security-privacy-principles.md:10` on the other; already an acknowledged
  gap in `VO/docs/research/open-questions.md:11`.
- **Q2 — Governed invocation surface for contract v1 (widened).** Confirm v1 serves per-laptop
  enrolment (nullable `tenant_id`, `device_ref` = enrolment pseudonym), with gateway/SaaS as a
  later revision — *and* decide which invocation surfaces are in scope and correlatable.
  Specifically: is `bedrock-mantle` traffic scoped out or flagged as an unmonitored-path finding
  (it has neither invocation logging nor `requestMetadata` tagging —
  `VO/docs/research/veil-observatory-dr.md:90`, `VO/docs/research/open-questions.md:7`, and the
  schema's own note at `:185`); and does the contract carry the **effective region set** for
  cross-region inference profiles, or only the caller's home region
  (`VO/docs/research/veil-observatory-dr.md:92`, `VO/docs/research/open-questions.md:19`)? The
  research pack recommends the former and the draft schema does not implement it.
- **Q3 — Receipt authenticity and freshness model (widened from "which key").** Settle together:
  signing key (custodian-issued mTLS device key vs. KMS `Sign` via the Bedrock-account credentials
  — the DR pack prefers asymmetric for cross-team portability, `:179`); canonicalisation algorithm
  and exactly which fields the signature covers; per-device vs. shared keys and rotation;
  cross-account verification when the evidence zone is a different account
  (`VO/docs/research/open-questions.md:23`); replay-window length and sequence-gap handling. Note
  that payload signing is distinct from the already-ratified mTLS attestation
  (`VP/docs/decisions.md:2894`) — attestation authenticates a connection, signing authenticates a
  record (§2.6).
- **Q4 — Alert-lane signing and opt-in interaction.** The alert lane must be signed (§2.6), but
  `VP/docs/architecture/implementation-plan.md:149` makes "alert on, bulk off" a *tested state*.
  Confirm the signing identity is available to a device that has opted out of bulk telemetry
  entirely, and that alert-lane enrolment does not backdoor the bulk-lane opt-out.
- **Q5 — Cross-repo contract-change protocol (new, from §2.5).** Under generated-from-Rust
  provenance, `veil-observatory` consumes a contract it cannot edit while holding accepted scope
  that depends on it (`VO/docs/decisions/ADR-0015-first-vertical-slice-scope.md:11`) and fuzz
  discipline that has already produced better constraints than the Rust side has types for. Define
  how the observatory proposes a field, what obliges veil-proxy to answer, who arbitrates, and what
  the consumer-side veto is (§3.3 step 9 proposes: a failing ADR-0012 fitness test blocks
  publication). Without this, "Rust is canonical" reads as "the consumer has no vote," which is not
  what §2.5 recommends and not something a human should ratify by accident.

**Non-blocking (decide before ratification, not before drafting):**

- **Q6** — Custom entity classes: excluded from telemetry entirely vs. registry-validated bounded
  labels (§2.4). Note `EntityType::Display` already collapses `Custom(_)` to `"CUSTOM"`
  (`VP/crates/vg-core/src/types.rs:73`), so "excluded" is the cheaper default.
- **Q7** — `receipt_state` extension: does the Kind C control-decision-without-invocation case get
  a fifth `receipt_state` value, a separate field, or a separate finding type
  (`VO/schemas/veil.ai_activity.v1.schema.json:122-130`)? Observatory-side modelling, but the wire
  contract must not foreclose it.
- **Q8** — Does `MappingCreated` cross the wire at all? *Demoted from blocking* on the critique's
  reasoning, which holds: it carries only `mapping_ref` and `entity_type`
  (`VP/crates/vg-core/src/audit.rs:31-34`); `VP/docs/architecture/product-family.md:265-269`
  permits mapping refs but the hard boundary is that reversal material never crosses (`:242-252`),
  which is unaffected either way; and no observatory source requires mapping-volume metrics. The
  safe default — explicit `TelemetryReject` for v1 — is defensible, reversible additively under
  §3.4, and does not block receipt ratification. Revisit only when a concrete persona query needs
  it.
- **Q9** — `caller.environment` / `deployment_stage`: keep both? `deployment_stage` is a closed
  enum and safe (`:155-167`); free-form `environment` probably dies (§2.4). If kept, who owns the
  registry it is compared against?
- **Q10** — Purpose limitation and joinability for telemetry metadata itself (from critique #8).
  Pseudonymisation is not anonymisation — `VP/docs/spec/requirements-and-design-spec.md:61` says so
  explicitly, and `VP/docs/architecture/product-family.md:832-835` flags that device pseudonyms
  plus metadata may be personal data with its own residency question. Ratification should state
  retention, residency, permitted joins, and the re-identification path for telemetry metadata, not
  just assert "hashed refs." Non-blocking for the *schema*; blocking for a DPIA
  (`VO/docs/architecture/security-privacy-principles.md:11`).
- **Q11** — OCSF normalisation point (`VP/docs/architecture/product-family.md:682-692`): emitter or
  observatory-side. Recommend observatory-side; keep the wire contract veil-native.

---

## 4a. Ratification decisions (2026-08-23)

Decided by the project owner in conversation, working through §4 in order. Recorded here
verbatim as the ratifying record for this document; see `docs/decisions.md` for the
cross-referenced ledger entry.

| # | Decision |
|---|---|
| Q2 (core) | **Per-laptop enrolment only for v1.** No near-term SaaS/gateway deployment is planned; building for it now would be speculative complexity. `tenant_id` stays nullable/unused; gateway/SaaS fields deferred to a later `schema_version`. |
| Q2 (bedrock-mantle) | **In scope, flagged as an unmonitored-path finding.** `aws.service_endpoint` enum includes `"bedrock-mantle"`; the observatory reports mantle volume as a known coverage gap (ties into Q7), never as a bypass signal, since Tier-1 correlation is structurally impossible for it. |
| Q2 (region tracking) | **Full effective region set.** Add `effective_region_set: [region, ...]` alongside the required `aws_region` (caller's home region), populated when a cross-region inference profile actually used more than the home region. |
| Q1 | **`veil-custodian` owns the enrolment registry** — device enrolment (and, per Q3, signing-key issuance) is a natural extension of the mTLS device-cert issuance it already owns. `veil-observatory` queries it to resolve governed-inventory membership without being able to resolve `device_ref` → real identity, preserving the §6.3 separation-of-duties bar. |
| Q5 | **Lightweight change protocol: PR + fitness-test veto.** `veil-observatory` proposes changes as a PR against veil-proxy's type inventory or schema generator; veil-proxy's conformance/fitness gates plus human review decide; veil-proxy retains merge authority per the §2.5 provenance decision; outcome recorded in both repos' `decisions.md`. No new role, no RFC process, no SLA — matches this project's existing low-ceremony convention. |
| Q3 (signing key) | **Custodian-issued device signing key**, minted at enrolment alongside the existing mTLS device cert, both tied to the same `device_ref`. Verifiable without AWS account access — works regardless of which account the observatory's evidence zone sits in. |
| Q3 (replay window) | **Short, fixed window — 5 minutes — for both lanes**, no per-lane configuration surface. **Consequence for Phase 1 (flagged, not reopened):** the in-emitter aggregator (§3.2) cannot hold a trace open and batch-send hours later — records must be signed and stamped close to mint time, with retried delivery against the original `issued_at_us`, not re-stamped on retry. An offline laptop reconnecting after >5 minutes sends records that are rejected as stale; Phase 1 needs an explicit decision on whether those get dropped, re-minted with a fresh timestamp (and what that implies for evidentiary accuracy), or queued with a distinct "delayed" marker. Not re-litigated here — owned by whoever designs the aggregator. |
| Q4 | **Signing identity is independent of bulk-lane opt-out.** The device signing key is minted once at enrolment, not at bulk-lane opt-in; a device with bulk off and alerts on still signs its alerts normally. |
| Q6 | **Custom entity classes excluded from telemetry.** `detections[].class` collapses any custom-detector match to a fixed `"custom"` tag, mirroring the existing `EntityType::Display` collapse elsewhere in the codebase (`VP/crates/vg-core/src/types.rs:73`). No detector-specific custom class name ever transits the wire; volume/counts for custom-class matches remain visible. |
| Q9 | **Drop `caller.environment`; keep `deployment_stage` only.** `deployment_stage`'s closed 4-value enum is safe as-is; free-form `environment` is dropped rather than bound to a registry, closing the infra-naming leak class named in §2.4 outright rather than mitigating it. |
| Q11 | **Observatory-side OCSF mapping.** veil-proxy emits its native shapes (`veil.receipt.v2` / `veil.alert.v1` / `veil.edge_event.v1`) only. Any OCSF export/SIEM-integration mapping happens downstream in `veil-observatory`, decoupled from `vg-core`'s versioning — reconsidered and reversed from an initial emitter-side lean once the tension with the zero-String/closed-enum invariant was named: OCSF's category/activity/severity taxonomy is exactly the kind of externally-owned open domain §2.3 already warns generation alone doesn't make safe, and it would couple every future OCSF revision to a `vg-core` change unrelated to veil-proxy's own audit model. |
| Q10 | **Written into the ratification packet now, not deferred to a separate DPIA track.** Retention, residency, permitted joins, and the re-identification path for telemetry metadata (device pseudonyms + metadata are personal data under GDPR even hashed, per `VP/docs/spec/requirements-and-design-spec.md:61`) are to be documented alongside the Q1 enrolment-registry work, since both sit on the same `veil-custodian` separation-of-duties boundary. **Not yet written — this is a next action, not a completed deliverable of this session** (see `docs/next-actions.md`). |
| Q7, Q8 | Left as recorded in §4 — Q7 (whether the Kind C control-decision-without-invocation case gets its own `receipt_state` value) is observatory-side modelling deferred until that work starts; Q8 (`MappingCreated`) keeps its default `TelemetryReject`, revisited only if a concrete persona query needs mapping-volume metrics. |

**Not yet done, tracked as next actions:** the §3.2a type inventory; the `veil-custodian`
enrolment-registry and signing-key-issuance build-out (Q1, Q3); the Q10 metadata-privacy write-up;
and the paired `VO/docs/decisions/` scope note on ADR-0004 that §3.1 requires before either side
treats this as fully ratified cross-repo (drafting that note in `veil-observatory`'s own voice was
explicitly left for a separate confirmation, not done automatically in this session).

---

## 5. What I am NOT resolving here

- **`ai_activity.v1` internals** beyond its receipt-derived fields — observatory-internal.
- **Transport and delivery** (HTTPS ingest vs. SQS, batching windows, retry/backfill,
  fail-open/fail-closed) — the DR pack has opinions (`:94`); separate design. Note it interacts
  with Q3's replay window, so the two should not be settled in isolation.
- **The prose-stub contracts** (finding, evidence reference, data passport, application risk
  profile, detector bundle — `VO/contracts/README.md:9-13`) — downstream of this contract.
- **Retention/residency of telemetry itself** (`VP/docs/architecture/product-family.md:832-835`,
  24-hour hot tier per `VP/docs/decisions.md:2895`) — policy, not schema, though Q10 asks for it to
  be stated at ratification.
- **The reason-dictionary distribution mechanism** (how dashboards get code→text) — belongs with
  the policy/detector-pack distribution channel.
- **Actor/device authentication mechanics** — ratified as mTLS device certs in `veil-custodian`
  (`VP/docs/decisions.md:2894`); this plan consumes the resulting pseudonym and, pending Q3, is
  explicit that record signing is a *separate* mechanism from that attestation.
- **The alert rule set itself** — `VP/docs/architecture/product-family.md:370-377` puts rule
  evaluation locally in `veil-proxy` against a versioned rule set distributed like policy. Only
  `AlertRuleId`'s wire representation is in scope here; the rules are not.

---

## 6. Provenance of this document

Draft written 2026-08-23 from a first read of both repos. Subjected to an independent adversarial
critique the same day (13 findings, via `codex exec` at `xhigh` reasoning effort). This revision
verified every cited file and line in both the draft and the critique by direct read before
accepting or rejecting each finding; §0 records the disposition of all thirteen, including the
three sub-claims rejected and the reasons. Three defects in `veil.receipt.v1` (§2.4a) and one
modelling gap in `receipt_state` (§2.2b, Q7) were found in this pass and appear in neither prior
document.

Pipeline: Fable (draft) → Codex (critique) → Opus (this revision). Not committed to either repo
by the pipeline itself. Placement in `VP/docs/architecture/` and a pointer note in
`VO/contracts/README.md` were confirmed with the project owner before this file was written here.
