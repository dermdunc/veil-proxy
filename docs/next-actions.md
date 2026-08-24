# Next Actions: VeilGremlin

Repo source-of-truth for the live work queue. Tasks T01–T11 are defined in
[`architecture/work-breakdown.md`](architecture/work-breakdown.md); the build method is in
[`architecture/agent-factory-plan.md`](architecture/agent-factory-plan.md). The full history of
completed work lives in [`docs/session-log.md`](session-log.md), [`docs/decisions.md`](decisions.md),
and [`docs/build-log/`](build-log/README.md). This file is the forward queue only, not a second log.

## Build status

T01–T11 complete; interface contract v1.4; 221 tests pass. **T11 human sign-off returned NO-GO
(2026-07-19)** — the hook adapter is a validated proof-of-mechanism but does NOT ship: it does
not deliver "invisible governance / PII never leaves the machine" without an egress proxy, and
the keychain UX is poor. See the 2026-07-19 T11 sign-off entry in `docs/decisions.md`. The mask/
demask logic, vault, detectors, pipeline, and tool-path masking are all validated.

## Now — the next milestone (supersedes the prior sign-off blocker order)

- [x] **M1 — transport + routing skeleton (2026-07-25, merged to main as 8da9561).**
      `crates/vg-proxy`: plain-HTTP `hyper` loopback server + deny-by-default route classifier,
      no upstream client, no credentials. Hardened by 3 doubt-driven-development rounds (11
      real fixes) before merge. See `docs/session-log.md`/`docs/decisions.md` (2026-07-25) and
      `<hekton-machinery>/docs/plans/veilgremlin-masking-proxy-plan-v1.md` §10.3.
- [x] **M2 — daemon core (2026-07-25).** `Daemon`: opens `Vault` once (`open`/`open_with_key`,
      mirroring `Vault`'s own two-constructor pattern); H2 session-namespace shim (`session.rs`)
      resolving the `X-VG-Namespace` header or a registered loopback address; the session-scoped
      accumulated binding store (H1's fix) as a data structure, not yet fed real content. Tested
      in isolation via direct calls — not yet wired into the HTTP server's request path (that's
      M3+, once there's something schema-aware to route toward). Hardened by 2 doubt-driven-
      development rounds (single-model + Codex cross-model, 12 real fixes, including a
      cross-session mapping-deletion bug in round 1's own new `unregister_port` primitive). See
      `docs/session-log.md`/`docs/decisions.md` (2026-07-25). **MERGED** as `def856f` (PR #39).
- [ ] **Local masking proxy + daemon — M3 next.** Intercept the actual request to the model
      endpoint, mask the entire assembled payload (prompt + context) via the vault, demask the
      response — invisible to the user. This is what turns the proven mechanism into a product
      that actually solves the governance/risk/privacy problem. The already-deferred "route
      masked request to Bedrock" / LiteLLM-gateway warm path. **#1 — nothing above it.** Next up:
      M3 (request masking, Anthropic direct, non-streaming — `schema/anthropic.rs` +
      `mask_request.rs` wired end-to-end against a mock upstream), per the plan's §10.3 build
      order.
- [x] **Precision NO-GO — CLOSED AND MERGED** as `6f4ea5d` (PR #37). `vg bench` verdict is now
      **GO**, false-positive rate **0.0%** (was 16.7%). Four doubt-pass rounds run, STOP signal
      reached. Branch `agent/claude/t10-fp-detector-fixes`
      implements the targeted fix (`EntropyDetector` git-SHA-context exclusion,
      `PhoneDetector` ISBN-13/10 checksum + ZIP+4 shape exclusion, `is_structured_identifier`
      `=`-handling closing a `LICENSE_KEY=ACME-2026-DEMO-KEY`-shaped residual). Rounds 1-3
      (alternating single-model/Codex, each targeted at the previous round's own new code)
      found and closed 22 real findings, several Critical false-negative regressions among
      them. **Round 4 (single-model, targeted at round 3's code) is the STOP signal**: its
      only findings were an already-accepted, already-named residual restated more sharply
      (fixed an overclaiming comment, not the mechanism — closing it fully would need real
      dictionary/word-likelihood detection, out of scope) and one defensive hardening with no
      live exploit path. **23 findings total across 4 rounds, every freely-fixable
      false-negative gap closed**, each with a regression test reproducing the reviewer's own
      counterexample — full detail in `docs/decisions.md` (2026-07-22 entries). `cargo test
      --workspace`, `clippy -D warnings`, `fmt --check` all pass after every round. **`vg
      bench` verdict: GO** — false-positive-rate is now **0.0%** (was 16.7%), all other gates
      unchanged/PASS. **This does not ship on its own — human review before merge**; the
      masking-proxy milestone (#1 above) and the display-collision fix (below) are unrelated
      and still open regardless of this gate's status.
- [ ] **Fix the display-collision corruption** (1 of 3 mask→demask round-trips). Implement
      collision-avoiding minting at intern time (skip an ordinal whose display already occurs in
      the raw text), as the T09 doubt-round and T10 eval both recommended, now with data.
- [ ] **Resolve or drop the dead `artefacts.by_language [dotenv]` config path** confirmed
      unreachable by the T10 eval (classify-before-parse makes it unreachable). Fix the wiring or
      remove the config surface.

## T11 review scope (attribution/hardening items surfaced during the build)

- [ ] **F4, demask authorisation is attribution, not authentication.** `--actor`/`--role` are
      self-asserted and the wrapped agent can invoke `vg demask` via its own shell. Candidate
      hardening: hooks refuse to spawn `vg demask` from inside a wrapped session; packs get
      restrictive perms; the vault key never enters the wrapped environment.
- [ ] **F3, upward state-dir discovery trusts any ancestor `.veilgremlin/`.** Now warns; T11
      should decide whether to refuse a discovered-not-created state dir, plus policy-signature
      verification (already stubbed for Phase 2).
- [ ] **F5, packs accumulate masked-text plaintext, unbounded.** Gitignore mitigates
      exfil-via-commit; a TTL/purge command (`vg pack purge`) is still deferred here.
- [ ] **dotenv-without-hint residual:** one seeded value only an artefact Block would catch (no
      filename hint). Decide detection vs accepted-residual.

## Later phases (designed, not started)

- [ ] Warm-path local NER (GLiNER), designed but off by default.
- [ ] LiteLLM gateway, MCP server mode, CI/CD mode, cloud-agent packaging.
- [ ] Synthetic-data generation and quasi-identifier leakage scoring.

## Standing conventions

- [ ] Add a `docs/build-log/` entry as each future material task lands, per the standing rule in
      `AGENTS.md`/`CLAUDE.md`/`CODEX.md`.
- [ ] Re-audit build-log coverage against actual work after each task.

## Session Update: 2026-07-25 — M1 + M2 landed: masking-proxy transport, routing, and daemon core

- [ ] M3: request masking
- [ ] Anthropic direct
- [ ] non-streaming (schema/anthropic.rs + mask_request.rs wired end-to-end against a mock upstream)

## Session Update: 2026-07-26 — product family established, leak found

- [x] ~~Human review of `docs/architecture/product-family.md`~~ — **merged** (PR #41), along with
      the project-identity rename `veilgremlin` → `veil-proxy`. `veil-walled-garden` was renamed
      `veil-foundations` in the same pass.
- [x] ~~Decide the sibling repos~~ — `veil-custodian` and `veil-foundations` scaffolded, planned,
      and their plans merged. `veil-observatory` deliberately **not** created; gated behind
      Phase 1a.
- [x] ~~Attestation mechanism~~ — **mTLS device certificates** (`veil-custodian` ADR-A).
- [x] ~~Retention windows~~ — **24-hour hot tier → S3** for regulatory hot/cold archive (ADR-B).

### Now open, in priority order

- [x] ~~Remediate the custom-entity-label leak — needs a compiler.~~ **FIXED 2026-08-01** —
      `cargo`/`rustc` are installed (1.96.1, matching `rust-toolchain.toml`); that blocker was
      stale. Implemented exactly the three-model-reviewed plan: `vg-core/src/api.rs`'s
      `redaction_marker` and `vg-core/src/keying.rs`'s `type_tag_for_display` both collapse
      `EntityType::Custom(_)` to a fixed tag (`[REDACTED:CUSTOM]` / `CUSTOM`), `KeyerState.ordinals`
      re-keys on the rendered display tag instead of the full `EntityType`, and
      `vg-vault/src/schema.rs`'s unique index collapses `entity_custom` to `''` for every
      `entity_kind = 'custom'` row via a `CASE` expression. `type_tag_for_keying` (the
      cryptographic HMAC input, a different function) is unchanged and still embeds the raw
      name — that string only ever feeds a digest, never rendered text. 6 new regression tests
      (3 vg-core keying, 2 vg-core api, 1 vg-vault DB-level race test) plus 1 corrected test that
      previously asserted the leaking behaviour as expected (`keyer_display_uses_custom_dictionary_tag`
      → `keyer_display_never_carries_the_custom_dictionary_name`). No migration needed, per the
      prior verification that no `.veilgremlin` state dir or `vault.db` exists on this machine —
      note this remains true only because no real vault predates the fix; `CREATE INDEX IF NOT
      EXISTS` would not upgrade an already-created index of the same name.
- [x] ~~Separate demask correctness bug, fixed by the same work~~ **FIXED 2026-08-01** — duplicate
      displays (the root cause of the silent `vg demask` exit-0) can no longer be created: the
      vault's unique ordinal index now rejects a second row that would render to an
      already-used display string, across custom classes as well as within one.
- [ ] **Re-run `vg bench`** and bank the current display-collision measurement — still open,
      scoped to a separate unit (ecosystem compliance-loop A3). Ran once here as a post-fix
      sanity check: verdict remains **GO**, unrelated FP-rate gates unaffected; display-collision
      measured at 1 of 3 samples corrupted (a different root cause — see the "T11: collision-
      avoiding minting" recommendation in `vg bench`'s own output — not banked as part of this
      item, left for the dedicated unit).
- [ ] **Audit-log third path — reachability corrected 2026-08-01, this is a real gap, not
      "local-only."** `vg-audit/src/record.rs:212` serialises `EntityType::Custom(name)` as
      `{"custom":"<name>"}`, and `vg-cli/src/main.rs:476-478` claims in a doc comment that
      audit events "leak nothing" — false for the `Custom` arm. A same-model + Codex review
      of the 2026-08-01 leak fix (docs/decisions.md) found this reachable by the *same*
      mechanism just closed for `vg diff`/`vg inspect`: a wrapped agent invoking `vg audit`
      as a shell command reads back whatever JSON is in the log — including the raw class
      name — as `vg audit` pretty-prints already-serialized log lines verbatim
      (`vg-cli/src/main.rs:~502`) rather than re-deriving safe display text. Not fixed here,
      deliberately: `EntityTypeV1` (`vg-audit/src/record.rs`) is a *stored, versioned*
      serialization format historical audit logs may already depend on, and a same-day
      change to it under this fix's time pressure risks exactly the kind of undercoordinated
      addition doubt-driven-development's STOP-and-decompose guidance warns against. Needs
      its own reviewed change: likely a `CUSTOM` collapse in the serialised form itself (not
      just at print time, matching the vg-core Display fix's approach) plus an explicit
      decision on backward-compatibility with any already-written `{"custom":"<name>"}` log
      lines. A hard prerequisite for v1.5 telemetry regardless. Raised as decision packet
      material for the launching session's compliance loop.
- [x] ~~Phase 1a, `TelemetryEvent` + `TryFrom` in `vg-core`~~ **Built 2026-08-23, merged to
      `main` via PR #47 (`https://github.com/dermdunc/veilgremlin/pull/47`).** —
      `crates/vg-core/src/telemetry/` (envelope + `Receipt`/`Alert`/`EdgeEvent`, the §3.2a type
      inventory, `TryFrom<&AuditEvent>` exhaustive with no wildcard arm), `interface-contracts.md`
      bumped to v1.5 (§7a), `implementation-plan.md` §3.2-3.4 rewritten to match what was actually
      built. Reviewed across **four** rounds of adversarial review (single-model → Codex →
      single-model → Codex+Opus in parallel) — see `docs/decisions.md`'s 2026-08-23 entries for
      the full findings list; most severe was a **proven** `#[derive(Hash)]` side-channel on the
      `String`-backed token types (an external-crate exploit recovered raw strings byte-for-byte
      through a custom `Hasher`), closed by removing `Hash` from every type wrapping variable
      content. `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide,
      311 tests passing, zero regressions.
      **Every `TryFrom<&AuditEvent>` arm still rejects** — this is the honest, reviewed state, not
      an oversight (see `telemetry::mod`'s module doc). What's still needed before any arm can
      return `Ok`, in the order the reject reasons name:
      - [x] ~~**`ActorId` pseudonymization** (keyed HMAC, computed locally)~~ **Built
        2026-08-23, merged to `main` via PR #48
        (`https://github.com/dermdunc/veilgremlin/pull/48`).** —
        `crates/vg-core/src/telemetry/pseudonymize.rs`
        (`ActorPseudonymKey`, `pseudonymize_actor`), `crates/vg-vault/src/keychain.rs`
        (`load_or_create_actor_pseudonym_key`, per-device OS-keychain-backed, fixed
        `account = "default"`), `EdgeEvent::try_from_audit_event` (a **second**,
        key-carrying conversion entry point alongside the frozen, keyless
        `TryFrom<&AuditEvent>` — the ratified signature at `docs/decisions.md:2883` can
        never take a key, so it stays reject-only forever; this new function is what
        actually unblocks `DemaskRequest`/`DemaskDecision` in practice). Two rounds of
        adversarial review (single-model, then Codex cross-model). See
        `docs/decisions.md`'s 2026-08-23 pseudonymization entry for the full findings
        list and the residual risks recorded below, still open:
        - **Env-var test seam (`VG_ACTOR_PSEUDONYM_KEY_HEX`) can silently defeat the
          "no cross-device correlation" guarantee** if the same value is ever set on two
          machines — no structural fix found within this codebase's existing test-seam
          architecture (same shape as `VAULT_KEY_ENV`); mitigated with a loud stderr
          warning naming the specific consequence, not solved.
        - **`ActorPseudonymKey::from_bytes` is unrestricted `pub`** (needed so
          `crates/vg-core/tests/telemetry.rs`, a separate compiled crate, can construct
          test keys) — nothing in the type system stops a production caller from
          fabricating a fixed/weak/shared key instead of using
          `vg_vault::load_or_create_actor_pseudonym_key`. A sealed-trait/capability-token
          redesign could close this; not attempted here as disproportionate to this
          slice. Candidate hardening item for a future session.
        - **Keychain create-race, inherited from `load_or_create_db_key`, widened for
          this key**: two `vg-*` processes launched near-simultaneously on a device's
          first-ever run can each mint a different key (no atomic compare-and-set
          available via the `keyring` crate). Wider than the DB key's version of the
          same race because every vault on a device shares one fixed
          `(service, account)` pair. Not fixed.
      - **The versioned reason dictionary** — unblocks `Block` → `EdgeEvent::BlockedAttempt`.
        Distribution mechanism deliberately unscoped (reconciliation plan §5).
      - **The in-emitter aggregator** (groups `AuditEvent`s by trace before minting a
        `Receipt`) plus **Bedrock `requestMetadata` trace stamping** — unblocks
        `Scan`/`PolicyDecision`. No trace id exists anywhere upstream in `vg-core` today; this
        is the biggest remaining gap. Must also implement the Q3 5-minute replay-window
        consequence flagged in the reconciliation plan's §4a (an offline device reconnecting
        after the window elapses needs a drop/re-mint/queue decision, not made yet).
      - JSON Schema generation (no `serde`/`schemars` dependency exists in `vg-core` yet) —
        needed before the "schema published as a versioned artifact" exit gate is met.

### Telemetry roadmap sequencing (planned 2026-08-23, revised after adversarial review; not yet built)

Sequences the items above by what's genuinely blocking what, not by the order they're listed —
worked out in a dedicated planning session after PR #47/#48 merged, then reconciled against a
heavy fresh-context critique the same day (every claim below re-verified against the code, both
directions). Full context in that session's plan (not committed to this repo; summarised here so
it isn't lost).

**Three findings from reading the code, not assumed, that reorder the obvious sequencing:**
- **Bedrock `requestMetadata` trace stamping is blocked on there being a Veil-owned Bedrock
  request body at all** — not on M3 as a universal truth. Stamping needs whoever serialises the
  final Bedrock request; today nothing in this workspace does. `vg-proxy` has "no upstream client
  anywhere in this crate" (`vg-proxy/src/lib.rs:11`), and the Claude adapter deliberately builds
  none either, leaving transport to the wrapped Claude Code CLI
  (`vg-adapters-claude/src/wrapper.rs:4`). **For the proxy path — the only planned owner — that
  owner is M3**, this file's own stated **#1 priority**, which hasn't started. A future
  direct-Bedrock adapter path would be an alternative owner and would unblock stamping
  independently; no such path is planned, so plan on M3.
- **No first-party production path emits `AuditEvent::PolicyDecision`.** The workspace has exactly
  three production `policy.audit.write` call sites (grep-verified): `api.rs:173` (`Block`),
  `api.rs:306` (`Scan`), `api.rs:627` (`DemaskDecision`). The type is `pub` and `vg-audit` still
  *reconstructs* `PolicyDecision` when reading back historical records
  (`vg-audit/src/record.rs:420`), so "never constructed anywhere" was too strong — but nothing we
  ship *mints* one. Scope the aggregator to what our own code emits, and see the next finding for
  why dropping it isn't free.
- **`AuditEvent`s alone cannot build a `Receipt`** (this is the finding that actually changes the
  plan). `Controls` requires policy version, outcome, per-entity `Detection { class, count,
  action }`, a `ReasonCode` block reason, and exceptions (`telemetry/receipt.rs:235`,
  `receipt.rs:167`). `Scan` carries only aggregate counts, detector version and latency
  (`audit.rs:21`); `Block` carries an artefact kind and a free-text reason. Some of the missing
  data is closer to hand than that gap implies — `mask()` returns `(MaskedPack, Vec<MappingRef>,
  AuditEvent)`, and `MaskedPack` already carries `policy_version` and per-type `EntityCounts`
  (`types.rs:182`, `:166`) — but `outcome`, per-detection `action`, `block_reason`, and
  `exceptions` have no source today, not even inside `mask()`. So a decision is owed before
  Phase 3: either mint a real per-decision control event (the role `PolicyDecision` was shaped
  for), or define the aggregator over a richer `mask()` outcome plus newly-derived fields rather
  than over bare `AuditEvent`s. Not decided here; recorded as a Phase 3 prerequisite.

**Recommended phases** (same-phase items have no hard dependency on each other):
- **Phase 0 — zero dependencies:** the Q10 privacy write-up (below); the fieldless-enum `Hash`
  cleanup (below). Cheapest items, no reason to wait.
- [x] ~~**Phase 1 — the emitter.**~~ **Built 2026-08-23** — `crates/vg-audit/src/telemetry_sink.rs`
  (`TelemetryCountingAuditSink`/`SharedTelemetrySink`/`TelemetryConversionCounts`, a decorator
  around any `AuditSink`, attempts `EdgeEvent::try_from_audit_event` on every write and counts
  the outcome per `AuditEvent` variant — intercepts at the `AuditSink` boundary as planned, not
  inside `mask()`), wired into `Engine::open` (`crates/vg-adapters-claude/src/runtime.rs`) behind
  a new opt-in policy flag (`RawPack.telemetry_enabled`, `crates/vg-policy/src/config.rs`, reached
  via a new default `PolicyEngine::telemetry_enabled()` trait method,
  `crates/vg-core/src/traits.rs`) — **not originally scoped in this phase's sketch above**,
  added because wiring into real production construction (a scope decision made in this
  session's interview, since the two earlier telemetry PRs deliberately stayed unwired) meant
  ADR-015's "opt-in, never opt-out" ratification needed an actual config surface, which
  previously didn't exist anywhere in the code.
  **A second, more consequential scope addition, found only during review, not planned going
  in:** `StatePaths` (`crates/vg-adapters-claude/src/state.rs`) now carries its own
  `Provenance`, and `Engine::open` refuses to honor `telemetry_enabled()` when the state dir's
  provenance is `Discovered` (F3 — a `.veilgremlin/` adopted wholesale from a cloned repo's
  ancestor directory). Before this fix, a hostile repo could silently trigger real OS-keychain
  secret generation via a committed `repo.policy.json`, with zero operator-facing signal, on the
  automatic `vg hook` path Claude Code invokes on every tool call. Found by a fresh-context
  adversarial reviewer during this session's doubt-driven-development pass, confirmed by a
  second, Codex cross-model round after the fix. See `docs/decisions.md`'s 2026-08-23 Phase 1
  entry for the full findings list (this and two smaller fixes: mutex-poison recovery so a
  telemetry-only fault can never block the real audit-log write; an env-var test-cleanup guard).
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
  **Scope, still accurate:** Phase 1 buffers **unsigned payload candidates** (`EdgeEvent` values
  and conversion outcomes), *not* `TelemetryEvent`s — full records stay custodian-blocked (see
  the still-open `veil-custodian` item below), and nothing here transmits anywhere; counts are
  in-memory only, inspectable via `Engine::telemetry_counts()`.
- [x] ~~**Phase 2 — the reason dictionary.**~~ **Built 2026-08-23** —
  `crates/vg-core/src/telemetry/block_reason.rs` (new: `BlockReason`, a small
  **code-defined** registry, `ARTEFACT_POLICY_BLOCK_TEXT` constant, `classify()` exact-match
  lookup). **Scope changed from this entry's own original sketch, by explicit choice made in
  this session's interview, after checking the actual code first**: there is exactly one
  production `AuditEvent::Block` construction site in the whole workspace
  (`crates/vg-core/src/api.rs`'s `mask()`), and `vg-policy`'s `ResolvedPolicy` has no separate
  "reason text" concept anywhere — building the full policy-pack-distributed mechanism this entry
  originally sketched (a `PolicyEngine` contract change, merge semantics for reason ownership,
  inheriting the still-stubbed `verify_signature` risk) for one fixed reason string was judged
  premature. The registry is versioned like `detector_version`/`policy_version` strings are —
  shipped with the code — not operator-editable; nothing in `vg-policy` changed.
  `EdgeEvent::try_from_audit_event`'s `Block` arm now resolves a recognized reason to `Ok` in
  production for real (`crates/vg-core/tests/pipeline.rs` proves this against the actual
  `mask()`-emitted event, not a hand-built fixture). New `TelemetryReject::UnrecognizedReason`
  (an unregistered reason string) and `TelemetryReject::RequiresEnvelopeConstruction` (the frozen,
  keyless `TryFrom<&AuditEvent>`'s now-accurate reject for a *recognized* `Block` reason, since
  that entry point still can't build `Envelope`/`Integrity`) — the now-permanently-dead
  `RequiresReasonDictionary` variant was removed rather than left stale.
  Two rounds of adversarial doubt-driven-development review (single-model, then Codex
  cross-model), both offered and accepted — see `docs/decisions.md`'s 2026-08-23 Phase 2 entry
  for the full findings list. Most notable: round 2 caught that round 1's own fix for the frozen
  `TryFrom`'s `Block` arm was itself incomplete (it unconditionally claimed "would resolve,"
  which was false for an unrecognized reason) — fixed by having that arm classify the reason
  first, the same way the newer entry point does. **Named risk, deliberately not solved:** "every
  `Block` construction site uses a registered constant" is enforced by review discipline, not the
  type system — `AuditEvent` being `#[non_exhaustive]` restricts cross-crate matching, not
  cross-crate *construction* (confirmed: `crates/vg-audit/tests/sink.rs` already constructs
  `AuditEvent::Block` from a different crate with its own reason strings).
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
- [x] ~~**Phase 3 (partial) — trace-id threading + aggregator skeleton.**~~ **Built 2026-08-24** —
  `mask()` (`crates/vg-core/src/api.rs`) now mints a fresh `TraceId::from(Uuid::new_v4())`
  internally on every call and returns it as a 4th tuple element, rather than accepting one as a
  parameter — verified against every real call site in the workspace (`Engine::mask_text` in
  `vg-adapters-claude/src/runtime.rs`, `crates/vg-core/benches/mask_pipeline.rs`, and
  `Harness::mask_sample` in `crates/vg-bench/src/report.rs` — a doubt-driven-development round
  caught an earlier version of this claim undercounting the third one), none of which has any
  other correlation id available to supply. New `TraceBuffer`
  (`crates/vg-core/src/telemetry/aggregator.rs`, `pub(crate)`) buffers `AuditEvent`s by trace,
  tracks a per-trace age baseline, and exposes `insert`/`events_for`/`aged_before`/`remove` —
  deliberately no completion detection and no eviction policy, matching Phase 1/2's own precedent
  for a real, tested, **not-yet-wired** piece. Two rounds of doubt-driven-development review
  (single-model, then Codex), both accepted — see `docs/decisions.md`'s 2026-08-24 entry for the
  full findings list, most notably a real security regression caught and fixed: an earlier version
  derived `Ord`/`PartialOrd` on `TraceId` reasoning a single comparison "only returns an
  `Ordering`," missing that a *public* `Ord` lets any holder binary-search the wrapped `Uuid` out
  bit-for-bit via ~128 adaptive comparisons — the same class of channel `telemetry::ids` already
  treats as serious for `Hash`. Fixed by confining ordering to a `pub(crate)`-only
  `TraceId::ordering_key() -> u128`, used only inside `TraceBuffer`'s own `BTreeMap`.
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
  **Two open decisions still gate the real aggregator, not the skeleton just built:** the receipt
  data source (third finding above), and the Q3 replay-window drop/re-mint/queue question, which
  blocks the buffer-eviction policy specifically. **Also named, not solved:** `mask()`'s
  `trace_id` is unreachable on every `Err` return (including the one partial-audit-write path that
  would most benefit from it) — fixing this means redesigning `MaskError`, which currently leans
  on `#[from]` auto-conversion incompatible with also carrying a mandatory field; a real, separate
  change. Bedrock stamping stays split into a future session, blocked on M3 (`vg-proxy` has no
  upstream client yet).
- **Phase 4 — JSON Schema generation + publish.** *Publishing* is sequenced last on purpose:
  regenerating a published schema after Phase 3 changes `Receipt`'s shape is worse than
  generating it once after that shape is real. The **generator machinery and its local tests
  should start early** (alongside Phase 1/2) — it's the first mechanized proof that the Rust
  shapes emit closed JSON objects with no surprise strings, and that feedback is worth having
  before Phase 3, not after. **Named trade-off, accepted:** the harness will need rework when
  Phase 3 moves `Receipt`'s shape; that cost is cheaper than discovering an open-object leak at
  publish time. `additionalProperties: false` at every object boundary is a generator test
  (reconciliation plan §3.3 item 4), not a review checklist item.
- **Phase 5 — delivery, named but not designed.** The reconciliation plan defers transport and
  delivery (§5: HTTPS ingest vs. SQS, batching windows, retry/backfill, fail-open/fail-closed)
  and explicitly notes it interacts with Q3's replay window, "so the two should not be settled in
  isolation." That deferral is fine for a schema plan; it is not fine for a roadmap whose stated
  goal is one real, signed `TelemetryEvent` reaching `veil-observatory`. Phase 1's local buffer is
  a placeholder, not a delivery story: with a fixed 5-minute freshness window, buffering policy
  and delivery policy are the same decision. Owns its own scoping session; sequenced after
  Phase 3 only because record shape should stop moving first.
- **Not phase-gated:** the six-raw-capable-`String`-surfaces item (below) deserves its own scoping
  pass, bigger than a cleanup item; the `ActorPseudonymKey::from_bytes` provenance hardening item
  (below) needs its own design decision before implementation; the env-var cross-device-
  correlation residual (below) likely stays an accepted, documented risk rather than a plannable
  item unless the test-seam architecture itself changes.

`veil-custodian` (device enrolment + signing-key issuance, below) blocks `Envelope`/`Integrity`
construction regardless of how much of the above lands — no `TelemetryEvent` can be fully
assembled and signed without it, which is why Phase 1 is scoped to unsigned candidates above.
Deliberately not planned in detail here — that's a separate repo's own session; what `veil-proxy`
needs from it is named in the item below.

- [ ] **Close the six raw-capable `String` surfaces at their source** (`docs/architecture/implementation-plan.md`
      §3.1) — **still open, not done by the `TelemetryEvent` build above.** `ActorId(pub String)`,
      `DetectorId(pub String)`, `Block.reason: String`, `policy_version: String`,
      `EntityType::Custom(String)`, `ArtefactKind::SourceCode(String)` are all still raw in
      `vg-core`'s own base types; the telemetry layer works around this by rejecting or
      collapsing at the telemetry boundary (e.g. `EntityClassId::Custom` collapses the name).
      `ActorId` pseudonymization (built 2026-08-23, above) unblocks conversion for
      `DemaskRequest`/`DemaskDecision` via the second entry point, but does not touch
      `ActorId`'s own `pub String` field — the underlying type is still raw.
- [ ] **Minor consistency cleanup: several fieldless `telemetry::` enums still derive `Hash`**
      (`SchemaVersion`, `SigningAlgorithm`, `DeploymentStage`, `Action`, `Outcome`,
      `EdgeOutcome`, `Severity`) — found by a Codex cross-model doubt-driven-development
      round during the 2026-08-23 pseudonymization work, out of scope for that change (all
      pre-existing, merged in PR #47). Not an active leak (they carry no fields, so a derived
      `Hash` has no raw bytes to expose) — the concern is purely convention consistency with
      the rest of `telemetry::`'s "no `Hash`" rule. Small, low-risk, self-contained cleanup for
      a future session.
- [ ] **`veil-custodian`: build the device enrolment registry and signing-key issuance** (Q1, Q3
      ratifications). Extends the existing mTLS device-cert issuance (`docs/decisions.md:2894`)
      with: an enrolment registry `veil-observatory` can query for governed-inventory membership
      without resolving identity, and a per-device signing keypair minted alongside the mTLS cert.
      Blocks `veil-proxy`'s receipt-signing work and `veil-observatory`'s bypass-detection rule.
- [ ] **Write the Q10 telemetry-metadata privacy section** (retention, residency, permitted joins,
      re-identification path) into the ratification packet, alongside the Q1 registry work — the
      plan explicitly deferred this write-up, it is not yet done
      (`docs/architecture/telemetry-receipt-reconciliation-plan.md` §4a).
- [x] ~~Get the `veil-observatory` ADR-0004 scope note actually accepted on that side.~~
      **Reviewed and accepted-with-edits 2026-08-23** by a dedicated `veil-observatory`-side
      session (own judgment, not a rubber stamp — see that repo's `docs/session-log.md`). Marker
      flipped from "Proposed amendment" to "Amended." Merged to `main` via PR #8
      (`https://github.com/dermdunc/veil-observatory/pull/8`, fast-forward `835d083..457105c`),
      branch deleted.
- [x] ~~New cross-repo decision surfaced by the veil-observatory-side review: should ADR-0014's
      correlation/determinism suite get the same formal CI-veto status ADR-0012's fuzz test has
      under Q5?~~ **Resolved by `codex` critique (`xhigh` effort, 2026-08-23): no, not as
      proposed.** ADR-0012's fuzz test is genuinely schema-shaped (canaries in string fields,
      checkable against arbitrary schema-conformant instances) and maps cleanly onto a
      producer-schema veto. ADR-0014's guarantees (exact-match `veil_trace_id` correlation, no
      fuzzy fallback, replay determinism) live in pipeline/adapter *behavior*
      (`correlator.py`, `bedrock.py`, `receipt.py`), spread across three test files, not the one
      suite named in the ADR-0004 scope note — a schema can protect the *fields* correlation
      needs but can't prove the *behavior*. Wiring the whole existing `test_pipeline.py` in as a
      schema-level veto would be a category error. **Deferred, not ratified**, until a first
      generated schema artifact exists. When it does, build a narrow, purpose-built
      **correlation-contract gate** instead of reusing the broad suite: stable field-name/pointer
      checks on the `linkage` block, plus a synthetic fixture matrix (valid pair / missing trace /
      mismatched trace / duplicate trace / account-region mismatch / `bedrock-mantle`
      unmonitored-path) that `veil-proxy` CI can run against `veil-observatory`'s adapters without
      needing live pipeline data. Not blocking anything today — no schema artifact exists on
      either side yet.

M3 (request masking) remains the standing product priority; the leak fix is small and should not
displace it for long.

## Session Update: 2026-08-01 — Cross-link unified regulatory control register

- [ ] Human reviews and merges PR #44; Lane B decision packets B1-B9 follow

## Session Update: 2026-08-01 — Close the custom-entity-label leak — full doubt-cycle

- [ ] Human reviews and merges PR #45; audit-log serialization fix needs its own scoped session

## Session Update: 2026-08-01 — Bank display-collision measurement, propose vg-bench CI gate

- [ ] Human reviews and merges PR; install ci-proposed/ci.yml when ready (see its README for the exact command)
