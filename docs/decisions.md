# Decisions: VeilGremlin

## ADR Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-06-30 | Initial scaffold as factory-output (Hekton) | Local-first privacy shield; built by the Hekton factory; no `hekton-` prefix per taxonomy |
| 2026-06-30 | Repo created **private** initially under a personal account | Private is reversible — flip to public when ready to open-source |
| 2026-06-30 | ADR-001 Core language = **Rust** | Memory/thread safety, no GC, small trusted core, enterprise reviewability |
| 2026-06-30 | ADR-002 Local vault = **SQLCipher SQLite** | Encrypted, local, queryable; supports normalisation/TTL/audit |
| 2026-06-30 | ADR-003 Detector mix = **deterministic hot path + optional GLiNER warm path** | Latency + explainability + recall balance |
| 2026-06-30 | ADR-004 First integration = **Claude Code wrapper + hooks on Bedrock** | Fastest enterprise proof, no central platform dependency |
| 2026-06-30 | ADR-005 Masking = **typed placeholders, not synthetic values** | Transparent, stable, auditable, debug-safe |
| 2026-06-30 | ADR-006 Demasking = **explicit, local, policy-gated** | Prevents re-exposure to cloud models; supports oversight |
| 2026-06-30 | ADR-007 Policy = **native YAML/TOML now; Cedar later** | Low dependency now; strong auth later |
| 2026-06-30 | ADR-008 Gateway = **LiteLLM later; core stays separate** | Hardened small core + provider-independence |
| 2026-06-30 | ADR-009 Supply chain = **sign + SBOM + reproducible builds + no telemetry** | Trust prerequisite for a privacy binary |
| 2026-06-30 | ADR-010 Placeholder key = **salted HMAC over canonicalised value+type+namespace** | Stable consistency without leaking original structure |
| 2026-06-30 | **Build method = agent factory, contract-first** | Squads own one crate each; interfaces frozen end of Wave A to enable safe parallel agent work (see `architecture/agent-factory-plan.md`) |
| 2026-07-03 | Build driven through Hekton's task-DAG orchestrator (`agentic-control-tower`), not manual per-task dispatch | `.hekton/veilgremlin-dag.toml` is now the machine source of truth for the T01-T11 DAG (transcribed from `architecture/work-breakdown.md`); `.hekton/build-tasks/*.md` are generated engine-gateway-lab task specs (regenerate via `dag gen-specs`, don't hand-edit). `.control-tower/` tracks each task's lifecycle. All build tasks route through `claude-cli`/`codex-cli` (cloud, V1 scope — no local-model build capability exists yet) at `privacy: vendor-allowed` (this repo's own source isn't privacy-sensitive; see `.hekton/project.yaml`'s `privacy_boundary: internal`). See `agentic-control-tower`'s root `decisions.md` ADR-013 for the full orchestrator design. |
| 2026-07-04 | Repo made **public** under the **dermdunc** account | VeilGremlin is an enterprise architecture/governance/risk tool, not agentic-engineering tooling — it belongs under the professional-identity account per Hekton's domain-based GitHub routing decision (see `~/hekton/docs/decisions.md`, 2026-07-04). Refines the 2026-06-30 private-scaffold decision above. |
| 2026-07-17 | ADR-011 (T05) `vg-vault` = **SQLCipher via `rusqlite` (vendored OpenSSL), OS-keychain-wrapped DB key, per-install salt in an encrypted `meta` table; `Keyer` ordinal counters reseeded from persisted rows at open** | Encrypted-at-rest reversible mapping store; keychain wrap keeps the key off disk; reseed prevents display-ordinal collision/drift across process restarts. Added an additive `Keyer::seed_ordinal` to `vg-core` (not a frozen-contract change). See the 2026-07-17 T05 entry below. |
| 2026-07-18 | ADR-012 (T07) **`vg-core::scan`/`mask` pipeline wired; contract bumped v1 → v1.1 (`mask` gains `ctx: &Context`)** | `mask` needs the same detectors/parsers `scan` runs but the frozen signature had no `Context`; the sanctioned contract-change fix is an explicit param, not smuggling detectors into `Policy` or pre-computing findings. Also fixed the pipeline order (artefact-Block short-circuit; `Pass` never skips detection; full-buffer detection with spans as enrichment; specific-over-generic overlap resolution; irreversible/entity-Block never interned; one Scan/Block audit event; vault owns demask attribution). See the 2026-07-18 T07 entry below. |
| 2026-07-25 | New crate **`crates/vg-proxy`**, milestone M1 (transport + routing skeleton) | First implementation milestone of `~/hekton/docs/plans/veilgremlin-masking-proxy-plan-v1.md` (v3.1); plain-HTTP `hyper` loopback server + deny-by-default route classifier, zero egress risk by construction (no upstream client exists yet). See the 2026-07-25 entry below. |
| 2026-07-25 | Milestone M2 (daemon core) — `Daemon` opens `vg-vault` once, H2 session-namespace shim (`session.rs`), registration-not-derivation port fallback | Second implementation milestone of the masking-proxy plan; tested in isolation via direct calls, not yet wired into the HTTP server (M3+ has something schema-aware to route toward). See the 2026-07-25 entry below. |

Full reasoning and the Mermaid-illustrated design are in [`spec/requirements-and-design-spec.md`](spec/requirements-and-design-spec.md).

## 2026-07-04 - Repo visibility flipped to public

### Context

The original 2026-06-30 scaffold created VeilGremlin as a private repository under a personal
account, per the standard factory-output default. On review, that account domain was the wrong fit
for this specific project: VeilGremlin is an enterprise architecture/governance/risk tool (a
privacy shield for agentic coding workflows), which belongs under the `dermdunc`
professional-identity account. This prompted a wider Hekton policy addition — see
`~/hekton/docs/decisions.md`'s 2026-07-04 entry adding a domain heuristic to factory-output
GitHub routing.

### Decision

- Settled the repository under the `dermdunc/veilgremlin` account, keyed to `~/.ssh/id_ed25519`,
  and verified reachability with `git ls-remote origin`.
- Flipped visibility to public (`gh repo edit --visibility public --accept-visibility-change-consequences`)
  in the same session — not deferred to a later "ready to open-source" milestone as the original
  scaffold decision assumed.
- Updated all current-state metadata to match: `.hekton/project.yaml` (`owner`, `github_account`,
  `github_remote_url`, `privacy_boundary: public`, `architecture.owner`), `.hekton/governance.yaml`
  and `.hekton/risk-register.yaml` (`owner`), the repo-local mind-palace mirror
  (`mind-palace/.../index.md`), and the `Owner:`/`Privacy boundary:` headers in `README.md`,
  `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, and `docs/spec/requirements-and-design-spec.md`.
- Closed `docs/risks.md`'s RISK-0010 (an early git-remote authentication mismatch) as moot.
- Left historical entries alone: `docs/session-log.md` and this file's own 2026-06-30 entries
  describe what was true at the time and are not rewritten.

### Consequences

- VeilGremlin is now publicly visible at `github.com/dermdunc/veilgremlin` — the code, docs, and
  full history (including this decision) are world-readable from this point forward.
- No build work has happened yet (T01/T02 dispatch remains deliberately deferred, per
  `docs/next-actions.md`), so this move happened before any real implementation existed to review
  for accidental sensitive content — the safer order, rather than flipping visibility after code
  exists.
- Future factory-output projects should get the account-domain call made explicitly at scaffold
  time, per the new Hekton-wide routing guidance, rather than needing a post-hoc move like this one.

## 2026-07-14 - GO-LIVE dispatch (real) and T01 built directly after a dispatch-mechanism gap

### Context

The "no Rust toolchain" blocker (2026-07-04, above) was re-checked this session against
`agentic-control-tower/docs/go-live-dependencies.md`, which had already found the toolchain
installed on 2026-07-07 (re-checked 2026-07-13) — the local claim was stale. Independently
re-verified: `cargo`/`rustc`/`cargo-audit` were already present via Homebrew; only `cargo-deny`
was missing, installed this session. With the toolchain question resolved, the human authorized
the real GO-LIVE dispatch: `dag dispatch T01` through `agentic-control-tower` +
`engine-gateway-lab`.

### What happened

The dispatch mechanism itself worked correctly end to end: DAG state transition, worktree
isolation (`engine-gateway-lab/.worktrees/run-20260714-T01`, branch
`gateway/run-20260714-T01`), routing to `claude-cli`, and the verify gate all fired as designed.
But the nested `claude -p --output-format json --permission-mode acceptEdits` headless call
tried to run a Bash command (checking whether the Rust toolchain was actually installed — the
same stale claim this session had just corrected) and stalled on a tool-use permission prompt
with no human present to approve it in a one-shot `-p` invocation. Rather than erroring, it
returned "The tool is waiting on your approval for this command..." as its final result. The
gateway adapter treated this as a normal completion (no error, non-empty result text), wrote it
to `.hekton/build-tasks/T01-output.md`, and the DAG's verify step correctly failed on the
missing `Cargo.toml` — but nothing had actually been built, and the run's own timestamps
(dispatch and verify within the same second) confirm no real work occurred.

### Decision

Given three options (retry with `bypassPermissions`, block the run and stop, or build T01
directly), the human chose to build T01 directly in the existing worktree rather than debug or
loosen the nested dispatch's permission mode — the toolchain question was already settled, and
building it directly avoided disabling the nested agent's own confirmation safety net just to
work around a one-off stale-data trip-up. Built: a 9-crate Cargo workspace (`vg-core`,
`vg-detectors`, `vg-parsers`, `vg-vault`, `vg-policy`, `vg-audit`, `vg-cli`,
`vg-adapters-claude`, `vg-bench` — matching `agent-factory-plan.md`'s squad-to-crate mapping),
empty skeleton crates per `interface-contracts.md`'s note that Squad 0/Task T02 owns the
canonical trait and type definitions, `.github/workflows/ci.yml` (fmt, clippy -D warnings,
cargo-deny, cargo-audit, build --locked, bench compile-check), `deny.toml`, and a release
skeleton (`release/README.md`) with SBOM/signing explicitly stubbed, not silently omitted.

Verified locally before committing: the DAG's own verify command
(`cargo build --locked && cargo fmt --check`) passes; also `cargo clippy --workspace
--all-targets --locked -- -D warnings`, `cargo deny check`, and `cargo audit` all pass;
`cargo bench --workspace --locked --no-run` compiles. One real fix needed along the way:
`cargo-deny`'s bans check flags intra-workspace `path` dependencies with no `version` as
wildcard dependencies — added `version = "0.1.0"` alongside every `path = "../vg-*"` dependency
to satisfy it, a standard pattern, not a workaround.

### Consequences

- This is VeilGremlin's actual first line of code and the factory's first real end-to-end build
  through the DAG orchestrator → engine-gateway → adapter chain — the evidence both
  `agentic-control-tower` and `engine-gateway-lab` need for their own Transformer/platform
  promotions.
- The unattended-dispatch gap (headless `-p` mode cannot approve a Bash tool call) is real and
  not VeilGremlin-specific — flagged in `docs/next-actions.md` for `engine-gateway-lab`/
  `agentic-control-tower` to pick up; not fixed here, since fixing the dispatch mechanism itself
  is out of scope for a VeilGremlin build task.
- T02 (freeze `vg-core`'s shared types) is next; per `agent-factory-plan.md`, Wave B does not
  dispatch until T01 **and** T02 both merge.

## 2026-07-14 - Doubt-driven-development on the T01 PR: CI was actually red, docs overclaimed

### Context

Before merging the T01 PR (#2), ran a fresh-context adversarial review against the actual task
spec, `interface-contracts.md`, and `agent-factory-plan.md`, with instructions to independently
verify every claim rather than trust the text — including by reading the real GitHub Actions
run, not just the local terminal output this session had already captured.

### Findings and disposition

- **Confirmed, fixed:** the `deny` job in `.github/workflows/ci.yml` was `runs-on: macos-latest`.
  `EmbarkStudios/cargo-deny-action@v2` is a Docker container action — container actions only run
  on Linux-hosted GitHub runners. The actual PR's CI run failed on this job on every push
  ("Container action is only supported on Linux"), while every doc this session wrote —
  including the entry above, `docs/session-log.md`, and the PR body — claimed "cargo deny check:
  PASS." That claim was true for the local Homebrew binary, a different execution path from the
  Docker-based CI job; nobody had checked the real CI run before writing "PASS." Fixed:
  `runs-on: ubuntu-latest` for that job only.
- **Confirmed, fixed:** this project is explicitly bound to `~/hekton`'s Hekton Documentation
  Contract (`CLAUDE.md:18`), which requires `.hekton/agent-run-log.yaml` and
  `.hekton/change-log.yaml` updated every session with a structural/build change — T01 is exactly
  that kind of change (a from-scratch build engine), and neither file was touched. Added
  `RUN-0003`/`CHG-0003`.
- **Confirmed, fixed:** `docs/project-walkthrough.md` still read "No Rust code yet... session is
  design and scaffolding only" and "Implementation: not started" after T01's real code existed —
  the Plain-English Walkthrough Contract requires this file stay current and a dated entry land
  under `docs/walkthroughs/` after a meaningful build session. Updated the walkthrough file and
  added `docs/walkthroughs/2026-07-14-t01-workspace-scaffold.md`.
- **Confirmed, not fixed (flagged instead):** the branch (`gateway/run-20260714-T01`, the ACT/
  engine-gateway dispatch tooling's own naming convention) doesn't match
  `agent-factory-plan.md`'s documented `feat/<squad>-<task-id>-<slug>` convention. Not renamed —
  the branch is already pushed with an open PR, and renaming it costs more (force-push, PR
  re-target) than the mismatch itself does. Recorded as a real, unreconciled gap between two
  repos' git conventions for a future session to resolve, not silently accepted.
- **Verified genuinely correct** (reviewer ran the actual commands, not just read the code): the
  9-crate layout matches the squad ownership table exactly; `[lints] workspace = true` is present
  in every crate and clippy's `-D warnings` genuinely passes with zero suppressions; the `vg`
  binary name and `vg-bench`'s criterion wiring are both correct; no crate is missing.

### Why this matters

This is the second time this session that an independent, fresh-context check (first the lab-
readiness eval's own doubt-driven-development pass, now this one) caught a claim of "all pass"
that wasn't true for the environment that actually matters, not the one that was convenient to
check locally. The pattern is the same both times: verify against the real target (a live
GitHub Actions run here; a 0-byte YAML file there), not against what ran cleanly on this one
machine.

## 2026-07-14 - Doubt-driven-development round 2 (Codex cross-model): six more findings, fixed

### Context

After round 1's fix was independently confirmed (real GitHub Actions run green, all 6 jobs
passing), ran a second, cross-model review (Codex, `codex exec --sandbox read-only`) against the
same T01 PR, seeded with round 1's findings and instructed to focus on what round 1 might have
missed rather than re-confirm it.

### Findings and disposition

- **Confirmed, fixed:** no `cargo test` CI job existed. T01 itself has no logic to test, but the
  job should exist now so T02 onward's first real tests are gated in CI from day one rather than
  retrofitted later. Added a `test` job to `.github/workflows/ci.yml`.
- **Confirmed, fixed:** the Rust toolchain was unpinned — every CI job used
  `dtolnay/rust-toolchain@stable` (a floating channel, not a pinned version), and no
  `rust-toolchain.toml` existed, contradicting this project's own reproducibility standard
  ("documented → scripted → idempotent-ish → logged → reproducible on a blank machine"). Added
  `rust-toolchain.toml` (channel `1.96.1`, matching this machine's installed toolchain) and
  pinned every CI job's `dtolnay/rust-toolchain` ref to the same version.
- **Confirmed, fixed:** `docs/risks.md`'s RISK-0002 mitigation read as if bench-based p95 gating
  were already enforced in CI. It isn't — there's no hot-path code yet to benchmark; only the
  harness compiles. Added a status-update note to the mitigation cell rather than rewriting the
  aspirational target, which is still correct for later tasks.
- **Confirmed, fixed — and the most on-the-nose finding of the whole session:**
  `scripts/check-prereqs.sh`, `docs/local-assumptions.md`, and `scripts/verify-project.sh` still
  didn't check for the Rust toolchain at all, meaning they'd pass clean on a machine with no
  Cargo whatsoever — the *exact* gap flagged in `docs/next-actions.md` on 2026-07-04
  ("`check-prereqs.sh` doesn't check for it either... needs: Rust toolchain... and
  `check-prereqs.sh` updated to check for all three so this doesn't get silently rediscovered
  again") and prepared as an unapplied diff in `~/hekton`'s VeilGremlin dogfood runbook earlier
  this same session — but never actually applied to this repo until this fix. Applied now, to
  all three files, plus made `verify-project.sh` actually run `cargo build --locked && cargo fmt
  --check` rather than only check file presence.
- **Confirmed, fixed:** every crate hardcoded `version = "0.1.0"` on its intra-workspace `path`
  dependencies (added in round 1 to satisfy `cargo-deny`'s wildcard-dependency check). This
  works today but would silently drift from `[workspace.package].version` on the next bump —
  8 places to remember to update by hand. Refactored to the idiomatic Cargo pattern:
  `[workspace.dependencies]` declares each `vg-*` crate once (path + version), and every
  consuming crate uses `{ workspace = true }`. A version bump now only touches two places
  (`workspace.package.version` and `workspace.dependencies`), not every crate.
- **Confirmed, fixed — ironic given the whole exercise:** round 1's own fix to
  `docs/project-walkthrough.md` (correcting the stale "No Rust code yet" claim) introduced a new
  overclaim: "T01 workspace/CI merged 2026-07-14" and "T01 is merged" — the PR was (and still
  is, pending human review) open, not merged. Fixed to "built... PR open — not yet merged."
  Same overclaim did not appear in the dedicated walkthrough doc, only in the updated
  `project-walkthrough.md` sections. Also corrected `README.md`'s stale "Next: Wave A" status
  line (still described T01 as not-yet-started) and `docs/session-log.md`'s unqualified `cargo
  deny check: PASS` line (now notes it was local-only and wrong for the real CI run).

### Why this matters

Two real lessons, not one: first, the same "verify the real target, not the convenient one"
lesson as round 1 (the check-prereqs.sh gap in particular — a fix sitting *written and ready* in
a different repo's runbook for hours before actually being applied here, because nobody closed
that loop until an adversarial review asked "does this script still lie about what's required?").
Second, a fix session can introduce its own overclaim while correcting someone else's — the
"T01 is merged" line proves that doubt-driven-development needs to re-examine its own prior
output, not just the original artifact, on each cycle.

## 2026-07-15 - Task T02: vg-core's shared types, trait seams, and conformance stubs

### Context

With T01 merged, T02 (Squad 0) was next: freeze `vg-core`'s shared types and library API,
define the trait seams every Wave B crate implements against, and provide contract-conformance
test stubs — per `docs/architecture/interface-contracts.md` and `T02.md`'s acceptance
("interface-contracts.md v1 frozen; types compile; conformance test scaffold exists").

### What happened with the dispatch

Retried the real ACT GO-LIVE dispatch mechanism (`dag dispatch T02`) rather than building
directly from the start, since T01's stall was specifically triggered by a stale-toolchain
Bash check that no longer exists. First attempt failed on a transient API connection error
("Connection closed mid-response") — not the same permission-mode issue as T01. Second attempt
ran for the full tool timeout (~10 minutes) and was killed mid-run — but unlike T01, this was
genuine progress being cut short, not an instant stall: the worktree
(`engine-gateway-lab/.worktrees/run-20260715-T02`) had 7 new files and 787 lines of real Rust
written (`types.rs`, `traits.rs`, `api.rs`, `error.rs`, `ids.rs`, `audit.rs`, `conformance.rs`,
plus `tests/conformance_stubs.rs`), with no still-running process and no further file changes —
consistent with the work having actually finished writing but the outer process being killed
before the adapter's trailing steps (verify, output-artifact write, ACT session close) could run.

### Decision

Picked up the work in place rather than re-dispatching from scratch (which would have discarded
real, substantial progress) or discarding it. Verified it independently before trusting it:
`cargo build` (needed to update `Cargo.lock` for three new dependencies — `thiserror`, `uuid`,
`zeroize` — that `--locked` alone can't add), then the actual T02 `verify_command` — `cargo build
--locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check && cargo test` — which
passed clean after one `cargo fmt --all` pass (the interrupted run hadn't reached the formatting
step). Read the generated code directly (not just trusted the test pass) given this is the
*frozen* interface contract every later task builds against — found it faithfully matches
`interface-contracts.md`: `Secret` zeroizes on drop with a redacting `Debug` impl; `rehydrate`'s
destination hard-deny gate (`RemoteModelPrompt`/`ObservabilitySink`, regardless of actor) is
implemented for real, not stubbed, since correctly identified as the one piece of T02 logic that
doesn't depend on any Wave B crate; everything else pipeline-related is an explicit `todo!()`
naming the task that wires it (T07/T09/T10), not a silently-incomplete stub.

### Consequences

- This is the second piece of VeilGremlin's real business logic (after T01's empty scaffold) and
  the first real security-relevant invariant with a test proving it.
- T01 + T02 both need to merge before Wave B (five parallel squads) can dispatch, per
  `agent-factory-plan.md`.
- Not yet run: a doubt-driven-development pass on this PR. T01 got two rounds before merging;
  given `rehydrate`'s hard-deny logic is genuinely security-relevant (not just scaffolding),
  the same discipline probably applies here — left as an explicit next action, not assumed.

## 2026-07-15 - Doubt-driven-development on the T02 PR: contract left in DRAFT, a real vault bug

### Context

Ran the same two-round process as T01 (single-model fresh-context review, then Codex
cross-model) against the T02 PR before merging, given `rehydrate`'s hard-deny gate and the
vault/audit conformance helpers are genuinely security-relevant, not just scaffolding.

### Findings and disposition

- **Confirmed, fixed — the most severe finding:** `docs/architecture/interface-contracts.md`
  was never touched by this PR, despite T02's literal acceptance criterion being "interface-
  contracts.md v1 frozen." The doc still read "Status: DRAFT until end of Wave A (Task T02),
  then FROZEN" in present tense. Worse, its illustrative code never defined at least 11 types
  the actual implementation needed and had to invent (`ArtefactHint`, `ArtefactKind`,
  `NodeKind`, `Destination`, `DestinationId`, `Context`, `Input`, `Policy`, `Actor`, `Corpus`,
  `CorpusSample`, `Metrics`), and had two concrete deviations from the real code:
  `EntityType::Custom(String)` wasn't in the doc's literal enum, and `PolicyLayers` used the
  doc's literal `Path` — which isn't valid Rust for an owned field (`Path` is `?Sized`) — where
  the real code correctly used `PathBuf`. The entire point of freezing this document is so Wave
  B squads can build in parallel without reading each other's (or `vg-core`'s) internals; a
  document that's still in draft with 11 missing types defeats that purpose. Fixed: added a new
  §0 (supporting types), reconciled every deviation, flipped Status to FROZEN with today's date,
  and updated the Versioning section to record what changed at freeze time — all in this same
  PR, since nothing has consumed the "frozen" contract yet (Wave B hasn't dispatched), so a
  separate contract-change PR would have been process for its own sake.
- **Confirmed, fixed — the most severe *code* finding:** `MockVault::resolve` in
  `conformance_stubs.rs` **ignored its `ns` parameter entirely** (it was already prefixed
  `_ns`) — a value interned under one `Namespace` would resolve successfully under any other
  namespace. `interface-contracts.md`'s own `Namespace` design exists specifically to scope
  placeholder stability per session/repo/org; silently ignoring that on resolve is a real
  security-relevant defect in the template every Wave B squad (specifically `vg-vault`, Task
  T05) will read as the reference shape. Fixed: `MockVault` now stores the namespace alongside
  each mapping and returns `VaultError::NotFound` on a namespace mismatch (indistinguishable
  from "doesn't exist" to the caller, per the now-documented contract); `VaultStore`'s trait
  doc and `interface-contracts.md` §5 both now state namespace isolation as an explicit,
  required invariant, not an implied one; `assert_vault_roundtrip` now takes a second,
  distinct namespace and asserts cross-namespace resolution fails.
- **Confirmed, fixed:** no reusable `PolicyEngine` conformance helper existed — the hard-deny
  check was only an ad-hoc inline test in `conformance_stubs.rs`, not part of
  `vg_core::conformance` the way every other trait's check was. Added
  `assert_policy_engine_denies_hard_deny_destinations`; the existing test now calls it.
- **Confirmed, fixed:** `assert_audit_event_excludes_raw_values` checked only the literal raw
  string against `{event:?}`'s output — a raw value containing control characters (e.g. a
  newline) renders `Debug`-escaped, so the unescaped literal search would false-negative on
  exactly that leak. Fixed to also check the value's escaped form.
- **Confirmed, fixed:** `assert_masked_pack_excludes_raw_values` only checked `.text`, not
  `.policy_version` (also a `String` field the contract's invariant covers). Fixed; documented
  that `mapping_refs` needs no check since `MappingRef` is type-enforced to hold only an opaque
  `Uuid`, never a real key.
- **Confirmed, fixed:** `assert_detector_contract` didn't validate that returned `Span`s are
  in-bounds (`start <= end <= buf.len()`) — later pipeline code slices by these spans, so an
  out-of-bounds span from a "conformant" detector is a real latent panic/bug source downstream.
  Added the bounds check.
- **Confirmed, fixed:** every conformance helper required `T: Sized` (e.g. `D: Detector`), but
  the library API holds detectors/parsers/vault/audit as trait objects (`Context`, `Policy`) —
  a Wave B crate testing a `Box<dyn Detector>` registry couldn't call these helpers without
  extra wrapper plumbing. Relaxed every bound to `?Sized`.
- **Confirmed, fixed (documentation, not a code change):** the parser conformance test used a
  `MockParser` that can never panic by construction, so it only proved the harness call itself
  didn't crash, not that any real parser is panic-safe. Added a second test running the helper
  against a small battery of adversarial buffers (empty, invalid UTF-8, large/unbalanced) and a
  doc comment on `assert_parser_never_panics` warning that a trivial mock proves nothing about
  a real implementation — squads copying the template need their own equivalent battery against
  actual parsing logic.
- **Confirmed, documented as an inherent contract limitation, not fixed as a bug (matches T01's
  precedent for exactly this class of finding):** `Secret::expose_secret() -> &str` lets a
  caller copy the value out before `Drop` zeroizes it, and `rehydrate`'s own frozen signature
  (`-> Result<String, RehydrateDenied>`) requires returning an owned, non-zeroizing `String` at
  the one exit point that matters — so the zeroize-on-drop guarantee is cosmetic by the
  contract's own shape, not something T02 introduced. Documented explicitly in `traits.rs`,
  `types.rs` (`MaskedPack`'s doc comment no longer overclaims enforcement it doesn't have
  either), and `interface-contracts.md` §5, rather than left as a silent gap.

### Why this matters

The standout lesson here is different from T01's: last time, the bugs were in *scaffolding*
(CI config, docs) — real, but not security-relevant. This time, the most severe finding
(`MockVault` ignoring namespace) is a template defect in code whose entire purpose is to be
copied by four future crates, one of which (`vg-vault`) implements the exact trait this bug was
in. A conformance stub that doesn't test the invariant it's supposed to enforce isn't neutral —
it's actively worse than no stub, since it gives a false sense that the pattern has been
validated. The interface-contracts.md gap reinforces a lesson from the v1 phased plan: a
"frozen" artifact that nobody actually re-reads before building against it (Wave B hasn't
started yet, so nothing depended on it being current — but soon will) drifts from day one
unless updating it is part of the same PR that changes what it describes, not a follow-up.

## 2026-07-15 - Task T03: five deterministic detectors, plus a two-round doubt-driven-development pass

### Context

First genuinely successful unattended `code-implement` dispatch in the factory. The initial
attempt (terse one-line task description) got a clarifying question back from `claude -p`
instead of any code — headless one-shot mode has no follow-up channel, so that question was
the entire session. Root-caused and fixed at the task-spec level (both `.hekton/veilgremlin-dag.toml`,
the source of truth, and the regenerated `.hekton/build-tasks/T03.md`): rewrote the description
with concrete file/module/trait guidance and an explicit "use your judgment, don't ask" instruction.
Re-dispatched; this time claude wrote all five detectors for real (`email.rs`, `phone.rs`, `ip.rs`,
`iban_sortcode.rs`, `entropy.rs`, ~800 lines, plus a criterion bench) matching the prompt closely.
`Cargo.lock` needed a manual regenerate (new `regex`/`criterion` deps never locked) and one clippy
unused-import — both mechanical, fixed in the worktree, not logic changes.

### Findings and disposition (Codex cross-model doubt-pass, gpt-5.5, read-only sandbox)

Reviewed against the `Detector` trait contract (span validity, no panics, determinism,
confidence bounds) with an explicit security lens (false negatives in a PII/secret detector
mean real leaks). 9 findings, reconciled:

- **Fixed — real bug, not just a documented limitation:** `ip.rs`'s IPv6 pattern's own comment
  claimed it "deliberately does not attempt" IPv4-mapped addresses (`::ffff:192.0.2.1`), implying
  a clean miss — but the generic hex-group alternatives actually produced a truncated PARTIAL
  match (`::ffff:192` out of the full address), which is worse than a miss for a redaction tool:
  most of the real address (`.168.1.1`) was left sitting unredacted next to a redaction marker.
  Added an explicit IPv4-mapped alternative, ordered first (this crate's regex alternation is
  leftmost-first, not leftmost-longest, so ordering matters for which alternative wins).
- **Fixed — real gap in the entropy detector's core purpose:** `is_token_byte` excluded common
  password special characters (`!@#$%^&*`), so a genuinely high-entropy password like
  `aB3!xY7@qR2#nM8$pL5%zK` was silently split into sub-20-byte fragments at every special
  character, each individually below the length floor — a systematic miss of a realistic secret
  shape, not a hypothetical one, for the one detector whose whole job is catching secrets with no
  fixed format. Added those bytes; deliberately did NOT add `:`/`;`/`(`/`)` (too common as genuine
  field/prose/timestamp delimiters — see the next item).
- **Found only because the IPv6 fix now works correctly, then fixed:** the IPv4-mapped fix exposed
  that the embedded `192.168.1.1` inside a matched `::ffff:192.168.1.1` ALSO independently matches
  the standalone `ipv4_pattern()`, producing two overlapping findings for one real address.
  `detect()` now drops an ipv4 finding when it's fully contained inside an ipv6 finding's span.
- **Confirmed, documented as an accepted residual, not fixed:** colon-delimited compound secrets
  (`user:token`) are still split and individually missed — `:` is too common a genuine delimiter
  (timestamps, URLs, "key: value" idioms) to safely add to `is_token_byte` without risking spurious
  merges elsewhere; the narrower punctuation-only fix above was judged the better trade-off.
- **Confirmed, documented as an accepted residual, not fixed:** a phone number like
  `+1 (415) 555-2671` only matches from the parenthesised group onward, leaving the leading `+1`
  (just a country code, not the subscriber number) outside the redacted span. Low severity;
  fixing it safely would need a real regex restructure, judged not worth the risk for this gap.
- **Already documented in the code's own comments, not new bugs:** bare unseparated phone numbers
  and 6-digit sort codes in JSON/API shapes (`{"phone":"02079460958"}`) are excluded by design
  (phone.rs/iban_sortcode.rs already discuss this ambiguity); `YYYY-MM-DD` dates matching the phone
  heuristic is the exact example phone.rs's own docstring already calls out.
- **Real but out of `vg-detectors`' own scope, not fixed here:** independent detectors (e.g. IP vs
  phone) can produce overlapping findings for the same span with different entity types when a
  value's digit/separator shape satisfies more than one detector (`192.168.100.42` reads as both).
  Cross-detector arbitration isn't part of the `Detector` trait's contract; likely T04/T09 territory
  (typed-placeholder keying / cross-cutting policy), not a `vg-detectors` bug.
- **Refuted:** IBAN mod-97 checksum validation is NOT missing scope — `docs/architecture/work-breakdown.md`
  assigns "Luhn/mod-97 checksum validators" specifically to **T04**, not T03; `iban_sortcode.rs`'s own
  comment correctly describes this as regex-only by design, matching the actual task breakdown, not
  the broader aspirational spec the reviewer initially read it against.

### Round-2 verification pass (same Codex model, fresh session): checked the three fixes above for new bugs

Found 5 more, none requiring a code change — reconciled:

- **Confirmed, accepted, documented (2, both caused by the `is_token_byte` fix above):**
  including `@` makes an ordinary email (`jane.doe@example.com`) sit right at the entropy
  threshold, so it can ALSO get tagged `Secret` alongside `EmailDetector`'s own more specific
  `Email` finding for the same span — a precision cost (over-flagging), not a leak, and
  consistent with this detector's own stated philosophy of flagging *any* sufficiently
  random-looking token. More seriously: `@` can also merge a real secret with a long
  low-entropy suffix (e.g. Basic-Auth-in-URL style `<secret>@internal.example.com`) and
  dilute the merged token's entropy below threshold — a genuine false-negative shape, but
  removing `@` would just reopen the original multi-special-character password gap this fix
  closed. Judged: keep `@`, document both as accepted trade-offs (comments added to
  `entropy.rs`), don't chase further — each further tweak to a coarse byte-classification
  heuristic trades one realistic secret shape for another rather than strictly improving
  coverage.
- **Confirmed, pre-existing (not introduced by this session's fixes), documented, not fixed:**
  `=` is a token byte, so a long low-entropy key name merged with `=<secret>` can similarly
  dilute a real secret's entropy below threshold. Same class of trade-off as above.
- **Confirmed, accepted, documented:** the IPv4-mapped-IPv6 fix only covers the specific
  `::ffff:` prefix (the common, still-valid form); rarer/deprecated embedded-IPv4 shapes
  (`2001:db8::192.168.1.1`, an IPv4-compatible form RFC 4291 itself deprecated in 2006; a
  malformed `::ffff:0:192.168.1.1`) still produce the same partial-match behavior the fix
  was meant to close, just for a rarer input. Judged not worth generalizing further, matching
  the original scope call on embedded-IPv4 notation.
- **Same already-documented class as the first pass, not a new issue:** the phone detector
  matching a dotted IPv4 address (`10.10.10.10`) as a phone number is the identical
  cross-detector-overlap class already documented above (IP vs phone), independently
  rediscovered rather than a distinct new finding.
- **All three fixes verified correct** for their stated purpose (regex alternation ordering,
  overlap-dedup logic, tokenizer broadening) — no regressions found in the fixes themselves,
  only in their interaction with adjacent, unrelated inputs (emails, `=`-delimited keys),
  which is the residual surface documented above, not a defect in the fix logic itself.

Two full cross-model review cycles on this one crate is the stop point (per the
doubt-driven-development skill's own guidance: escalate rather than grind a third cycle
alone) — the remaining residual surface is a property of a coarse, deliberately simple
byte-classification heuristic, not a bug queue to keep chasing.

### Why this matters

Two genuinely new, generalizable lessons from this one task: (1) headless one-shot dispatch is
extremely sensitive to prompt specificity — the exact same task, described tersely, produced a
clarifying question and nothing else; described concretely with file/module/trait guidance, it
produced ~800 lines of real, well-tested, well-documented work on the first attempt. (2) A
security detector's own documentation can be *wrong* about its own limitations in a way that
matters: this code's comment said a case was "not attempted" (implying a safe miss) when it was
actually mishandled (an unsafe partial match) — the fix isn't just adding a feature, it's
correcting a false safety claim the code made about itself.

## 2026-07-16 - Dogfooding plan (Codex) + a real CI-enforced latency gate + a real detector census

### Context

Reviewed the remaining fan-out (Wave B: T04/T05/T05b/T06/T08; Wave C: T07/T09; Wave D: T10/T11)
against the product's actual goal — mask PII by design, but be an invisible control with
trading-system-grade latency discipline (tail-latency awareness and real CI enforcement, not a
literal microsecond target for a human-interactive hook). Two concerns: the p95 latency budget
was compile-check-only in CI until T10 wires up baseline management, and each Wave B crate is
built and tested in isolation against the frozen contract with no cross-crate integration
exercised until T07, several tasks away.

### Decision 1: a real, CI-enforced latency gate now, not deferred to T10

Added `crates/vg-detectors/tests/latency_gate.rs` — a plain `#[test]` (runs on every PR via the
existing `cargo test` CI job, zero new CI config) asserting the whole detector suite's p95 stays
within 4x the interface contract's 25ms budget across 200 iterations. Deliberately coarse: a
tight bound would be flaky on noisy shared CI runners; this is a regression backstop (catches an
accidentally-uncompiled regex, a hot-path allocation, an O(n²) detector), not precise tracking —
Task T10 still owns real p95/p99 baseline management. Independently corroborated by a Codex
planning pass (below) reaching the identical design ("plain Rust test... not Criterion as the
hard gate... generous margin") before seeing this implementation.

### Decision 2: cross-crate integration requirements added to Wave B/C task specs now

`.hekton/veilgremlin-dag.toml` (source of truth) and `docs/architecture/work-breakdown.md`
updated:
- **T04** (placeholder/HMAC keying) must integration-test against real `Finding`s from
  `vg-detectors::all_detectors()` (T03, already closed), not only mock values.
- **T08** (parsers) must integration-test its real `Span` output against
  `vg-detectors::all_detectors()` on a realistic fixture, and explicitly record whether the fact
  that all five T03 detectors currently ignore their `spans` parameter (confirmed 2026-07-16,
  `_spans` in every `detect()` signature) is an accepted stage-appropriate gap or a real one —
  don't let it go unnoticed until T07.
- **T09** (CLI/hooks) gained an explicit UX-latency acceptance criterion: a human runs a real
  interactive session with the hooks wired in and confirms no perceptible friction, recorded
  honestly in this file — the first point the "invisible control" goal is even testable.

### Decision 3: a Codex planning pass on dogfooding, ahead of implementing any of it

Asked a fresh Codex session (read-only, planning only, no code) to plan how to dogfood VeilGremlin
incrementally as it's built, rather than only at T10. Its plan (full transcript not reproduced
here) independently converged on several of the decisions above, and added:
- The highest cross-crate integration risks beyond T03↔T08: T04↔T05 (placeholder/vault behavioral
  disagreement — "types compile, behavior disagrees"), T06↔T08 (policy only sees `ArtefactHint`,
  parser returns `ArtefactKind` — a `.env` file could parse fine and never get blocked until T07
  notices), T05b↔everything (raw-value leak into audit events).
- A concrete, immediately-actionable step requiring no new pipeline: a read-only "detector
  census" — run the already-built `vg-detectors` against real Hekton artifacts to surface real
  edge cases and real-world latency, years before T10's formal eval harness exists. Explicit
  design constraint carried into the implementation: never print or store matched values, only
  counts/spans/detector-IDs/latency/paths.
- A concrete, Hekton-specific edge-case list the current 5 detectors would plausibly miss:
  absolute local paths, SSH aliases, API key *variable names* (vs. values), broker-auth token
  metadata fields, operational IDs (run-IDs, RISK-IDs, branch names — "no detector for factory
  control-plane identifiers"), hostnames (`EntityType::Hostname` exists in the type system, no
  detector implements it yet), and commit-SHA/HMAC ambiguity.
- Its structural recommendation: treat dogfooding and latency discipline as ongoing Wave B/C
  cross-cutting work, not something T10 owns alone — T10 becomes the *formal* eval harness, not
  the *first* time real data touches the product.

### Decision 4: ran the census for real — a significant, evidenced precision finding

Built `crates/vg-detectors/examples/census.rs` per the design above and ran it against both
VeilGremlin's own repo and `engine-gateway-lab`'s (197 files, ~1.1MB, real docs/YAML/logs — not
synthetic fixtures). Results: 11.2ms total scan time (0.057ms/file average) — confirms the
detectors are fast on real content, no latency surprise. But the finding-count breakdown is a
real precision concern, not a synthetic one:

```
email          findings=12
entropy        findings=2468   <- dominant, and mostly false positives (see below)
iban-sortcode  findings=28
ip             findings=69
phone          findings=783    <- also mostly false positives (see below)
```

Manually verified (not via the census tool, which deliberately never surfaces matched text) that
the entropy detector's dominant hit class is exactly the Codex-predicted "operational IDs" gap:
Hekton's own `run-YYYYMMDD-EG-NNN` run identifiers (e.g. `run-20260608-EG-012`) are ~19-20 bytes
of mixed digits/letters/hyphens — precisely the shape `is_token_byte` + the 20-byte floor +
3.5 bits/byte threshold was tuned to catch for real secrets, with nothing in the current design
to distinguish "high-entropy secret" from "high-entropy but totally benign structured
identifier." The phone detector's high count is the already-documented date/ID-as-phone
ambiguity, now empirically quantified at real scale rather than a single hand-built test case.

**This matters concretely for Task T06 (policy) and T07 (pipeline):** if masking goes live with
today's detector precision unchanged, the product would redact the overwhelming majority of
routine operational identifiers, dates, and structured IDs in ordinary agent-factory documents —
directly working against the "invisible control" goal by making output needlessly noisy. This is
a genuine design question, not a quick regex fix: whether to (a) add an allowlist/exclusion
mechanism at the policy layer for known-safe structured shapes, (b) tighten the entropy/phone
heuristics further (with the same risk/reward trade-offs already documented for T03), or (c)
accept and formally measure this as part of T10's already-tracked `false_positive_rate` Go/No-Go
metric. Not decided here — flagged as a real, evidenced open question for whoever builds T06/T07,
not guessed at. `census.rs` is kept in the repo (an `examples/` binary, not part of the normal
build/test path) so this can be re-run cheaply as each Wave B/C task lands, per the Codex plan's
ladder (detector-only now → parser+detector after T08 → stubbed mini-pipeline after
T04/T05/T06/T05b → real `mask()` after T07 → real dogfood after T09).

## 2026-07-16 - Fixed the entropy/phone false-positive finding (hybrid: detector patch now, T10 stays the gate)

### Context

Ran the census's open question (allowlist? tighter heuristics? defer to T10?) through a
Codex planning pass before deciding, per the human's request. Codex read the actual frozen
`PolicyEngine`/`Detector` contracts and the real detector code before answering, and
recommended a hybrid: fix the two dominant detector-level false-positive classes now
(`EntropyDetector`, `PhoneDetector`), keep Task T10 as the formal precision/recall gate,
and explicitly deprioritized a per-finding policy-layer allowlist for now — the frozen
`PolicyEngine::classify_artefact`/`classify_entity` contract has no per-finding-shape hook,
so building that properly is a real cross-cutting contract change, not a quick add, and a
regex-based allowlist would itself be a potential attacker-controlled bypass surface if not
carefully scoped. Human approved the hybrid.

### What was actually fixed

**`PhoneDetector`**: added `looks_like_iso_date`, excluding matches shaped like a strict
`YYYY-MM-DD`/`YYYY.MM.DD` calendar date (plausible year/month/day) rather than a phone
number. Narrow and generic — does not exclude arbitrary grouped numbers, only the exact
date shape.

**`EntropyDetector`**: added `is_structured_identifier`. **This required a correction
mid-session**: the first version assumed Hekton's own `run-YYYYMMDD-EG-NNN` run IDs were
the dominant false-positive shape (matching the census's original hypothesis) and only
excluded 3+-segment hyphen-delimited tokens with short alpha/bounded-digit segments.
Measuring it against real `engine-gateway-lab` content (via a temporary, never-committed
local debug print — not the census tool, which by design never surfaces matched text) showed
this removed only 1 of 1849 entropy findings on that fixed corpus. The actual dominant
classes were **file paths** (`scripts/gateway-run.sh`, `.hekton/risk-register.yaml`) and
**snake_case/kebab-case identifiers** (`requires_confirmation`, `local-coding-harness`) —
`is_token_byte` treats `/`, `.`, and `_` as part of a token, so a whole path or identifier is
scored for entropy as one blob, and the character-class mix clears the threshold even though
every piece is an ordinary word. Corrected to split on the token's own internal delimiters
(`/`, `.`, `_`, `-`) and exclude when every resulting segment is purely alphabetic (any
length) or purely numeric (<=8 digits) — catches paths/identifiers/operational-IDs
generically, not via a Hekton-specific dictionary.

**Accepted residual, not fixed**: a real secret that happens to be a dictionary-word
passphrase joined by delimiters (e.g. `correct-horse-battery-staple`) would also be excluded
— indistinguishable from a real identifier without a semantic/dictionary check this detector
doesn't have. A secret whose segments mix letters and digits (the vast majority of real
base64/hex/API-key shapes) is unaffected.

### Measured impact (isolated before/after on identical, untouched `engine-gateway-lab`
content — not the confounded combined-repo numbers, since this session's own doc edits also
grew VeilGremlin's own corpus)

```
                 before   after
entropy          1849     182    (-90%)
phone            618      54     (-91%)
```

Latency unaffected (10.19ms / 197 files across both repos, vs. 11.2ms before). Full
`cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check &&
cargo test` green throughout, including 5 new tests (2 phone, 3 entropy) built directly from
the real false-positive examples found.

### Decision

Ship the corrected detector-level fix now; T10 remains the formal `false_positive_rate`
gate for the residual ~10% and any future drift. The mid-session correction is itself
evidence for why "measure on real content, don't just theorize" (the whole point of the
census/dogfooding effort) matters — the first, unmeasured version of this exact fix would
have shipped almost no real improvement.

## 2026-07-17 - Added a build log, distinct from the session log

### Context

Human asked for a build log tracking "everything we're doing in this repo," similar to the
Hekton Workshop Gremlin's `docs/build-log/YYYY-MM-DD-*.md` convention and, to a degree, the
Hekton Field Journal. Since VeilGremlin already has a comprehensive internal
`docs/session-log.md`, the open question was what a build log adds that isn't already
covered — asked the human directly rather than assume scope: lightweight dated docs only,
a full publishable Astro-on-Pages site (like `terminal-velocity`/`borrow-native`), or just
writing about VeilGremlin from the Field Journal repo instead of building anything new here.
Human chose the lightweight option, explicitly to start.

### Decision

Added `docs/build-log/` — dated, deliberately written entries (`YYYY-MM-DD-<slug>.md`),
one per real event (a decision, a failure, a fix, a surprising result), not a mechanical
summary of `docs/session-log.md` and not one per session. Backfilled 7 entries covering the
repo's history to date: the initial scaffold, the flip to a public repo,
T01, T02, T03, the fan-out/latency-gate/census round, and the entropy/phone false-positive
fix (including its own mid-session self-correction, which became the best story of the
lot). Wired into the standing documentation contract: `AGENTS.md`, `CLAUDE.md`, and
`CODEX.md` all gained a rule to add an entry for future sessions with a real event, and
`AGENTS.md`'s traceability table now lists `docs/build-log/` alongside the existing
artefacts. Linked from `README.md`'s documentation table and `docs/project-walkthrough.md`
(which also got its own overdue refresh — it had gone stale claiming T01's PR was still
open and zero business logic existed, both no longer true).

No Astro site or GitHub Pages deploy yet — this repo is already public, so the files are
readable directly on GitHub without one. A site can be built later if the practice earns it
(see `docs/next-actions.md`), following the Workshop Gremlin's Build-log/Pages publisher
agent pattern rather than inventing a new one.

## 2026-07-17 - T04 typed-placeholder and HMAC keying

### Context

Headless one-shot dispatch (no follow-up channel — see `.hekton/veilgremlin-dag.toml`'s T04
entry). Implemented the formula `VaultStore`'s trait doc already names as authoritative:
"stable placeholder via salted HMAC over `(canonical(value), ty, ns)`". Several exact
naming/design choices were left to judgment per the dispatch instructions; recorded here
rather than asked, per that instruction.

### Judgment calls

1. **Case-folding in `canonicalize` is type-specific, not blanket.** Whitespace
   trim/collapse applies to every value; letter-case folding only applies to
   `Email`/`Hostname`/`InternalIp`/`Iban`/`SortCode`/`Postcode`/`TraceId` — types where case
   doesn't carry identity information. Secret-shaped types (`Password`, `PrivateKey`,
   `Secret`, `AccessToken`, `ApiKey`) and free-text/identifier types keep their case:
   lower-casing a secret would silently treat two genuinely different values as the same
   one, which is a correctness bug for exactly the class of value this tool most needs to
   keep distinct.

2. **HMAC salt is caller-supplied (`&[u8]`), not a hardcoded constant.** `vg-core` doesn't
   own persistent secret-key storage — `vg-vault` (Task T05) wraps the real key via the OS
   keychain per `interface-contracts.md` §5. A compiled-in salt would make "salted" a no-op
   (every install would key identically); `Keyer::new`/`placeholder_key` both take the salt
   as an argument so T05's `VaultStore::intern` impl can supply its own keychain-backed key.

3. **HMAC message uses an explicit `0x1F` (ASCII Unit Separator) between the canonical
   value, the entity-type tag, and the namespace tag**, rather than plain string
   concatenation — otherwise `value="ab", type="c"` and `value="a", type="bc"` would hash
   identically. Covered by
   `placeholder_key_has_no_naive_concatenation_collision` in `keying.rs`'s own tests.

4. **Ordinals are scoped per `(Namespace, EntityType)`, not globally per type.** The task
   description's wording ("the first time a distinct key is seen for a given `EntityType`
   within a `Namespace`...") was read as: each namespace gets its own independent
   `EMAIL_001, EMAIL_002, ...` sequence, matching `README.md`'s framing of placeholders as
   stable *within* a namespace and the acceptance criterion's own phrasing ("same value ->
   same placeholder within namespace"). A single shared global-per-type counter across
   unrelated sessions/repos/orgs seemed both harder to reason about for a user and not
   clearly what "within a `Namespace`" was asking for.

5. **Luhn/mod-97 validators are exposed as pure functions, not wired into `display`
   construction to synthesize a fake-but-checksum-valid card number or IBAN.** The task
   description's item 4 says these should let "a placeholder's own display value ... be
   checked (or constructed) to remain checksum-valid." Read literally, "constructed" could
   mean generating a full synthetic-looking replacement number. That would conflict with
   **ADR-005** (this file, 2026-06-30, frozen before this task): "Masking = typed
   placeholders, not synthetic values" — explicitly chosen over format-preserving fake data
   for Phase 1, for transparency/debuggability/audit reasons. Given the conflict, the
   frozen, earlier ADR was treated as authoritative: `display` stays `TYPE_TAG_NNN`
   (`EMAIL_001`, `ACCOUNT_ID_014`, matching `README.md`'s own example), and
   `luhn_is_valid`/`iban_mod97_is_valid` are exposed as standalone, independently useful
   validators (e.g. for a future detector-confidence booster or masking-quality check) —
   satisfying the "checked" half of item 4 without the "constructed" half's synthetic-value
   implication.

6. **Cross-crate integration test added per the 2026-07-16 acceptance-criterion addendum**
   (`crates/vg-core/tests/keying_integration.rs`): runs `vg-detectors::all_detectors()`
   (Task T03, already merged) over a fixture built from literal strings reused verbatim from
   each detector's own already-passing unit tests (so a detector regression shows up as a
   failed coverage assertion here, not silent no-op test), then feeds the real `Finding`
   spans/values through `Keyer`. Required adding `vg-detectors` as a **dev-only** dependency
   of `vg-core` (`crates/vg-core/Cargo.toml`) — not a real cycle in the normal build graph,
   since `vg-detectors`'s own (non-dev) dependency on `vg-core` is the only edge that matters
   for building either crate for real; Cargo resolves this pattern (a crate's own test
   binary dev-depending on one of its dependents) without issue.

### New dependencies

Added `hmac = "0.12"` and `sha2 = "0.10"` to `vg-core` (both RustCrypto crates, MIT/Apache-2.0
dual-licensed, matching `deny.toml`'s existing allowlist — same license family as the
already-present `zeroize`/`uuid`/`thiserror`).

### Validation status

**Not run in the dispatch session** — the sandboxed headless environment blocked all
`cargo`/`rustc` invocations pending an approval that never arrived (every attempt returned
"this command requires approval" with no prompt reachable in a one-shot headless run —
plain shell commands like `find`/`grep`/`git status` worked fine, so this looks like a
policy specifically gating toolchain execution, not a blanket Bash block). The module was
written and hand-traced carefully against the `hmac`/`sha2` crates' documented APIs and
existing crate conventions, including manual step-by-step verification of the Luhn and
mod-97 test vectors (`79927398713`/`79927398714`, `GB29NWBK60161331926819`/`...818`) by
hand.

**Verified post-dispatch, during PR review:** `cargo build --locked` compiled clean on the
first real attempt (only Cargo.lock needed regenerating for the two new dependencies,
`hmac`/`sha2`). `cargo clippy --workspace --all-targets --locked -- -D warnings` found one
trivial finding — a newer lint suggesting `.is_multiple_of(10)` over `% 10 == 0` in the
Luhn checksum — fixed. `cargo fmt --check` found routine reformatting (never run against
this file before) — applied. Full suite then green: 32 `keying` unit tests plus 5 real
cross-crate integration tests plus the existing 7 `vg-core` conformance tests, all passing,
including every hand-traced Luhn/mod-97 vector turning out correct. Confirms the "hand-trace
carefully, document what's unverified, don't guess" discipline worked as intended here — a
harder case than T01's silent stall or T03's clarifying question, since this time the agent
had no way to reach a compiler at all and still produced fully correct, review-ready code.

### Doubt-driven-development (Codex cross-model)

Passing tests don't substitute for reviewing logic the tests don't happen to cover, especially
in security-relevant keying code, so a fresh-context Codex review ran against the full diff
(`keying.rs`, `keying_integration.rs`, `lib.rs`, `Cargo.toml`) plus the frozen `VaultStore`
contract and this task's acceptance criteria, before this went to the human tollgate.

**Found and fixed (real bugs):**

1. **`EntityType::Custom` collision.** `Custom("foo-bar")`, `Custom("foo_bar")`, and
   `Custom("foo bar")` — three different policy-dictionary classes — all upper-snake-cased to
   the identical display tag `CUSTOM_FOO_BAR`, which was also being reused as the HMAC's
   entity-type input. Same value under three different `Custom` classes silently keyed
   identically, a direct violation of "type-sensitive by construction." Fixed by splitting a
   new `type_tag_for_keying` (embeds the raw, unmodified dictionary name) from the existing
   `type_tag_for_display` (cosmetic formatting only, safe to rename later).
2. **Compact vs. spaced/hyphenated IBAN and sort code keyed differently.** `canonicalize`
   collapsed whitespace but never stripped it, so the same real IBAN in its compact vs. spaced
   form (both of which `vg-detectors`' own IBAN detector already recognises as the same value)
   produced two different placeholders — a direct violation of this task's own "same value ->
   same placeholder within namespace" acceptance criterion. The same class of issue applied to
   sort codes and phone numbers. Fixed via a new `strip_cosmetic_separators` step, scoped
   narrowly to `Iban`/`SortCode`/`Phone` (not `Postcode`/`InternalIp`/`Hostname`, whose
   separators are structurally meaningful, not cosmetic).
3. **`PlaceholderKey`'s `Debug` impl leaked the real HMAC hex.** Any incidental `{:?}`
   formatting (a test failure message, a log line) would print the actual vault lookup key.
   Fixed to redact, matching `Secret`'s own `Debug` impl.

**Found and fixed (documentation only):** `iban_mod97_is_valid`'s doc comment now states
explicitly that it checks the mod-97 checksum only, not country-specific length or BBAN
structure — a caller could otherwise mistake it for a full IBAN format validator.

**Found, valid, not fixed here — a real cross-task interface gap for Task T05:** `Keyer`'s
per-`(Namespace, EntityType)` ordinal counters are session-only, in-memory state. `vg-vault`
(T05) doesn't exist yet, so this can't be fully resolved in T04, but it is a real requirement
T05 must satisfy: **when `VaultStore::intern` wraps a `Keyer`, it must reseed each namespace's
ordinal counters from the vault's own persisted records at construction time**, or two
different scenarios both produce a real bug — (a) a fresh `Keyer` after a process restart hands
out `EMAIL_001` to whatever value it sees first, which may not be the value the persisted vault
already calls `EMAIL_001`, and (b) if the vault ever holds more entries than the in-memory
counter has seen this session, a genuinely new value could collide with an already-assigned
display string. Recorded here and in `docs/next-actions.md` so T05 can't silently skip it.

**Found, valid, accepted as a trade-off — not fixed:**

- `Keyer::new` accepts an empty or low-entropy salt with no validation. Left unvalidated
  deliberately: this crate's own tests intentionally use short salts (`b"salt"`), and "salt
  strength" is a deployment/T05 concern (the real salt comes from the OS keychain per
  `interface-contracts.md` §5) that `vg-core` has no principled basis to enforce a threshold
  for.
- `Keyer::key_for` panics on a poisoned mutex rather than returning a `Result`. No code path
  currently panics while holding the lock, so this isn't reachable today, but if `vg-vault`
  wires `Keyer` directly into `VaultStore::intern` (which returns `Result<Placeholder,
  VaultError>`), a poisoned mutex would turn a recoverable error path into a process panic.
  Flagged for whoever builds that integration point in T05, not fixed speculatively against a
  failure mode that can't currently occur.
- The session cache is unbounded. Acceptable for Phase 1's in-process library/CLI lifetime
  (bounded by one masking invocation, not a long-running process); would need revisiting if a
  future daemon mode (deferred, see `interface-contracts.md`'s intro) keeps one `Keyer` alive
  indefinitely.

**Verification after fixes:** full workspace verify chain green — 31 `keying`-specific unit
tests (5 new, one per fixed/verified finding above) within `vg-core`'s 37-test unit binary (the
other 6 predate T04), 5 cross-crate integration tests, 7 conformance tests, 46 detector tests,
1 latency-gate test, all passing. Stopped at one cross-model cycle:
the findings were substantive and all got fixed or explicitly classified (contract requirement
for T05, or an accepted trade-off), not the "diminishing returns" pattern that would call for a
second round.

## 2026-07-17 - Merged T04 (PR #9); vault sync; fixed a real bug in sync-mirror-to-vault.sh

### Context

PR #9 (T04's implementation, folded together with the task-spec-guidance and T05-dependency
changes originally on the now-closed PR #8) merged to `main`. Human then asked to sync the
repo-local mind-palace mirror to the live Obsidian vault, and to confirm the build log is
genuinely tracking how/why/what this project is building, the way it will need to when
delivered as part of the final project (matching the Hekton workshop build-log
practice).

### Vault sync

Backed up the vault (`~/hekton/scripts/backup-obsidian-vault.sh`) before syncing, per Hekton's
standing policy. Ran `scripts/sync-mirror-to-vault.sh`: it correctly copied the refreshed
`session-log.md` onto disk, but its own `git add` line staged nothing at all, silently. Root
cause: the `git add` command listed `index.md`, `decisions.md`, and `session-log.md` — but
`decisions.md` is deliberately never mirrored to the vault (per this same script's own
`SUMMARY_FILES` array and boundary-rule comment, only 2 files). `git add` aborts the *entire*
command when any one pathspec doesn't match a file, so nothing got staged, and the subsequent
`git commit` silently did nothing — while the script still printed a false-positive "Committed
scoped vault update" message, since it never checks either command's exit status. Fixed the
script (`git add` now lists only the two files `SUMMARY_FILES` actually mirrors) and manually
staged/committed the pending vault update.

### Build-log coverage audit

Reviewed `docs/build-log/` against the actual work done to confirm it holds up as a real
delivered artifact, not just a backfilled list. Found one real gap: T04's own build-log entry
(written by the dispatching agent, describing its no-compiler-available constraint) predates
the subsequent Codex doubt-pass and never mentions the three real bugs that pass found, or the
minor self-report inaccuracy the fact-check pass caught. Added a second T04 entry,
"Three bugs a compiler would never have caught," covering that story specifically — matching
this log's own rule that a clean success is worth one line, but a caught wrong assumption is
the actual story worth telling in full.

### Decision

The build log is confirmed to cover, for every material task to date (scaffold through T04):
what was built, why (the real decision/tension behind it), and how (the actual mechanism —
dispatch failure modes, review rounds, fixes). It lives directly in this public repo's
`docs/build-log/`, so it ships with the project automatically — no separate publish step
required, unlike the Workshop Gremlin's Astro/Pages pattern, since VeilGremlin doesn't (yet)
have or need a standalone site for it. Re-audit this coverage after each future task, not just
at the end.

## 2026-07-17 — T05 (`vg-vault`): SQLCipher-backed `VaultStore`, keychain-wrapped key, Keyer reseed

### Context

Task T05 implements `vg_core::traits::VaultStore` in `crates/vg-vault` (previously an empty
stub). The dispatch fixed several choices (SQLCipher via `rusqlite`, OS-keychain key wrap via
`keyring`, `Secret` for raw values, call into `vg-core`'s `keying.rs` rather than reimplementing
HMAC, namespace isolation on `resolve`, TTL purge, cached prepared statements) and asked that any
remaining ambiguity be resolved by best judgment and recorded here rather than by asking (headless
one-shot, no follow-up channel). As with T04, no Rust toolchain/compiler was reachable in the
dispatch environment (`cargo` is gated behind interactive approval that a headless run can't
satisfy), so the code is written against the verified `vg-core` interfaces and left for a
compile/clippy/test pass at PR-review time.

### Decisions and recorded assumptions

1. **Added a `Keyer::seed_ordinal` method to `vg-core`'s `keying.rs` (the one cross-crate edit).**
   The dispatch's hard requirement — the vault's `Keyer` must have its per-`(Namespace,
   EntityType)` ordinal counters reseeded from persisted `mapping` rows at construction — was
   impossible against T04's `Keyer` as merged: its ordinal state is private with no reseed hook.
   `Keyer` is an internal T04 helper, **not** part of the frozen `interface-contracts.md` surface
   (§0–§8), so adding an additive, monotonic, idempotent `seed_ordinal(&self, ns, ty, max_ordinal)`
   is not a contract change. This is the minimal, correct way to satisfy the requirement without
   the vault reimplementing ordinal assignment or display formatting (`type_tag_for_display` is
   private to `keying.rs`).

2. **`intern` computes the lookup key with `placeholder_key` (non-mutating), and only calls
   `Keyer::key_for` (which mints an ordinal) once a value is confirmed new to the DB.** Calling
   `key_for` first would advance the ordinal counter for values that already have a persisted
   ordinal, causing gaps and divergence after a restart. The DB (keyed by the HMAC hex) is the
   durable source of truth for "already interned?"; the reseeded `Keyer` is used only to assign
   the next ordinal/display for genuinely new values.

3. **"Cache prepared statements on the struct" is implemented via rusqlite's
   `Connection::prepare_cached`, not a self-referential `Statement` field.** A `rusqlite::Statement`
   borrows its `Connection`, so storing both in one struct is self-referential and not idiomatic;
   `prepare_cached` maintains an LRU of compiled statements on the `Connection` itself, which is
   exactly the "don't re-prepare per call on the hot lookup path" intent. The `Connection` is behind
   a `Mutex` (it is `Send` but `!Sync`; `VaultStore` requires `Send + Sync`).

4. **No app-level second cipher on the value column.** SQLCipher encrypts the entire DB file with
   AES-256 (`interface-contracts.md` §5), so the raw value stored in a column is encrypted at rest
   by that layer. Adding a separate application-level encryption of the value column would be
   redundant defense-in-depth for Phase 1 and was not done; the schema stores the value in a column
   protected by the SQLCipher-encrypted, keychain-wrapped DB.

5. **The keying salt is a per-install random 32 bytes stored in a `meta` table inside the encrypted
   DB** (generated on first open), not a compiled-in constant — a hardcoded salt would make "salted"
   a no-op across installs (per `keying.rs`'s own note). It is protected by the same SQLCipher/keychain
   layer as the values.

6. **`Vault::open_with_key(config, key)` exists alongside `Vault::open(config)`.** `open` fetches the
   DB key from the OS keychain (generating one on first use); `open_with_key` takes a caller-supplied
   key and bypasses the keychain. This is the seam the test suite uses (temp-file DB + fixed key) so
   tests never touch or mutate the real macOS keychain, and it is also the hook for a future
   alternative key custodian. The "never persisted plaintext" guarantee is a property of the `open`
   keychain path; with `open_with_key` the caller owns the key's secrecy.

7. **`resolve` reports both a namespace mismatch and an expired mapping as `VaultError::NotFound`**,
   never distinguishing "exists in another namespace" from "doesn't exist" (the §5 isolation
   contract, checked by `assert_vault_roundtrip`). Every `resolve` attempt (success or not) appends
   one row to the append-only `demask_event` table, holding only the opaque `mapping_ref` and
   namespace — never the value.

8. **`rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature** was chosen over `bundled-sqlcipher`
   so the build vendors both SQLCipher and OpenSSL from source rather than depending on a system
   OpenSSL with dev headers (macOS ships LibreSSL without them). This makes the crate build heavier
   (needs a C toolchain + perl) but self-contained; flagged as a build-environment consideration for
   the PR-review compile pass.

9. **`EntityType`/`Namespace` are stored in structured, round-trippable columns** (`ns_kind`/`ns_id`,
   `entity_kind`/`entity_custom`) owned by `vg-vault`'s `codec` module — deliberately *not* the
   private one-way keying tags from `keying.rs` — so the construction-time reseed can reconstruct the
   real `(Namespace, EntityType)` to feed `seed_ordinal`. `Custom(name)` stores its raw dictionary
   name so two classes that format identically for display remain distinct.

### Validation status

Not compiled/tested in the dispatch environment (no reachable toolchain, as in T04). Code and tests
(`crates/vg-vault/tests/vault.rs`, unit tests in `codec.rs`/`keychain.rs`, and `seed_ordinal` tests in
`vg-core/keying.rs`) were written against the verified `vg-core` interfaces.

**Verified during PR review (2026-07-17):** the `bundled-sqlcipher-vendored-openssl` build compiled
clean (SQLCipher + OpenSSL from source, ~30s). Two fixes applied: the same trivial
`.is_multiple_of` clippy lint as T04, and a missing `Debug` on `Vault` (a test formats
`Result<Vault, _>` with `{:?}`) — added as a **redacting** manual impl rather than a derive,
since `Vault` holds the HMAC salt and a derive would print it. Full chain green:
`cargo build --locked && cargo clippy --workspace --all-targets --locked -- -D warnings &&
cargo fmt --check && cargo test` — 40 vg-core unit tests (+3 for `seed_ordinal`), 6 vg-vault
unit + 14 vault integration tests, plus all existing.

### Doubt-driven-development (Codex cross-model, 2026-07-17)

A fresh-context Codex review (given the diff + the frozen `VaultStore` contract + the
encryption/keying/namespace/TTL requirements) ran out of its turn budget mid-investigation
without a final synthesised verdict, but surfaced three concrete concerns I then chased down
in the code myself:

- **Fixed (real correctness bug): `intern` could return an expired-but-unpurged placeholder that
  `resolve` immediately rejects.** `resolve` filters on expiry (returns `NotFound` for an expired
  mapping) but `intern`'s `lookup_by_key` did not, so re-interning a value whose TTL had lapsed
  (before `purge_expired` ran) returned the stale placeholder — one that would then fail to
  resolve. Since `key_hex` is the `PRIMARY KEY`, minting a divergent new row is impossible, so the
  fix renews the expired row's TTL in place (re-minting `expires_at` exactly as a fresh intern
  would) and returns the same stable placeholder. New regression test
  `re_interning_an_expired_but_unpurged_value_renews_it_and_stays_resolvable`.
- **Reconciled (accepted design, documented): `resolve` writes a `demask_event` row on every
  attempt, including a failed namespace probe.** This is deliberate and correct — the schema
  comment and this task's own decision #7 both state a reversal (success or denial) must be
  attributable, and the row holds only the opaque `mapping_ref` + namespace, never the value.
  Forward note for **T07**: when the pipeline also drives the `vg-audit` `AuditSink`
  (`DemaskDecision`), avoid double-logging the same demask — decide which layer owns it.
- **Reconciled (round 1): the `UNIQUE (ns, ty, ordinal)` index is a *defense* against a
  cross-process ordinal race** (a duplicate-ordinal insert fails loudly rather than silently
  colliding). Cross-process openers are documented out of Phase 1 scope. **This claim was
  partly WRONG and was corrected in round 2 — see below.**

Namespace isolation on `resolve` was verified present and correct (returns `NotFound` on a
namespace mismatch, never distinguishing it from "doesn't exist" — `assert_vault_roundtrip`
passes). Round 1's Codex pass did not deliver a full verdict.

### Doubt-driven-development, round 2 (Codex cross-model, complete verdict, 2026-07-17)

Re-ran a tighter, exploration-forbidden Codex critique (round 1 had exhausted its budget
reading the wider repo). It delivered one concrete finding, and it invalidated round 1's own
reconciliation above:

- **Fixed (real bug): the ordinal `UNIQUE` guard did NOT actually fire for fixed entity types.**
  SQLite treats `NULL` as *distinct* in a `UNIQUE` index, and every fixed entity type (Email,
  Iban, …) stores `entity_custom = NULL`. So the index `(ns_kind, ns_id, entity_kind,
  entity_custom, ordinal)` never rejected a duplicate `EMAIL_001` for two different secrets in
  the same namespace — the exact collision round 1 claimed it "made fail loudly." Only
  `Custom(name)` rows (non-null `entity_custom`) were ever covered. Fixed by keying the index on
  `COALESCE(entity_custom, '')`, so all fixed-type rows share one key value and the constraint
  applies uniformly. New regression test
  `the_ordinal_unique_guard_fires_for_a_fixed_entity_type_null_entity_custom` (two `Vault`
  instances race the same ordinal; the second insert is now rejected). This is a good example
  of why a *complete* cross-model verdict was worth re-running for: round 1's partial pass left
  a plausible-but-false safety claim standing.

Full chain green after the fix: 40 vg-core + 6 vg-vault unit + 15 vault integration tests.

## 2026-07-17 - T05b audit sink: JSONL storage, versioned schema mirrors, and dependencies chosen to fit a hand-editable lockfile

### Context

T05b (Squad 5) dispatched headlessly to implement `vg_core::traits::AuditSink` in the
empty `vg-audit` stub crate. The task spec left the storage technology open (JSONL file
or SQLite, "pick one and record the choice, don't ask") and required versioned record
types plus the no-raw-values property test. Like T04's dispatch, this session had **no
reachable compiler**: every `cargo`/`rustc`/script invocation was permission-blocked in
the headless environment, which ended up shaping one real decision (below), not just the
validation story.

### Decisions

- **Storage = append-only JSON Lines file, fsynced per write** (`JsonlAuditSink`), not
  SQLite. Append-only maps directly onto `O_APPEND` + `fsync` with no schema/connection
  machinery; the audit log is a sequential record of events, not a queryable mapping
  store, so T05's SQLCipher choice solves a different problem and "one storage tech
  across both" bought nothing here. The deciding constraint was dependency-light-ness
  taken literally: serde/serde_json/thiserror/uuid are all already in `Cargo.lock` (via
  criterion's tree and `vg-core`), while `rusqlite`/SQLCipher are not — and with no
  runnable `cargo` in-session, a lockfile entry that can't be generated can't be added
  honestly (see next point).
- **`Cargo.lock` was updated by hand** — safe only because the change is a single
  dependency-edge list (`vg-audit`'s own entry) between packages already locked with
  checksums. Two would-be dependencies were dropped to keep it that way: `tempfile`
  (dev-dep; replaced by a 10-line std-only tempdir in the test file) and uuid's `serde`
  feature (replaced by a `#[serde(with)]` adapter over `Display`/`parse_str`, same wire
  format). The reasoning is recorded in `vg-audit/Cargo.toml` itself so the next agent
  doesn't "clean it up" into a broken `--locked` build.
- **The storage schema is a deliberate mirror, not serde derives on `vg-core` types.**
  `vg-core` is frozen and serialization is vg-audit's concern, so `record.rs` defines
  `RecordV1`/`EventV1` (+ mirrors of `EntityType`, `ArtefactKind`, `HandlingClass`,
  `Destination`) with explicit conversions both ways. Every record carries
  `schema_version` (currently 1); the exact v1 wire shape is pinned by a unit test that
  says, in its own doc comment, "a change here means a version bump and a new record
  type, not an edit". Conversions toward storage are fallible (`TryFrom`) for every
  `#[non_exhaustive]` contract enum, so a future contract variant fails loudly at write
  time instead of being silently dropped. `DestinationV1` serializes to exactly the
  stable `DestinationId` strings (`"remote-model-prompt"`, ...) so the audit log and
  policy dictionaries share one destination vocabulary — also pinned by test.
- **Recovery semantics, chosen and tested:** an unparseable line at open is skipped and
  counted (`skipped_lines()`) — that's what a torn write from a crashed writer looks
  like — and an unterminated final line is healed with a lone newline so the next append
  starts clean (the file is never truncated or rewritten). But a *well-formed* record
  with an unknown `schema_version` refuses to open (`OpenError::UnknownSchemaVersion`):
  silently skipping real records written by a newer build would make the audit trail
  quietly lossy, which is worse than failing.
- **`get` serves from an in-memory index** built by replaying the file at open —
  acceptable for Phase 1's in-process, per-invocation lifetime (same trade-off already
  accepted for T04's session cache). The index stores what the storage schema
  *round-trips to*, not the caller's original value, so a lossy conversion would fail
  the conformance roundtrip test immediately rather than hiding until the first restart.
- **The acceptance property test checks the persisted bytes, not just the Debug form.**
  `tests/sink.rs` writes every event variant "about" a table of adversarial raw values
  (newlines, tabs, quotes, backslashes, a realistic IBAN and API key, unicode) and
  asserts none appear in the file either verbatim or JSON-escaped — the exact leak class
  `assert_audit_event_excludes_raw_values`'s own doc warns about — plus a negative
  control proving the helper actually catches a deliberately leaky event.

### Assumptions (recorded, not asked — one-shot dispatch)

- Type names `JsonlAuditSink`/`OpenError` and the file layout (`lib.rs` + `record.rs`)
  were free choices; nothing in the contract names the concrete impl type.
- `OpenError` is a crate-local error type: `open()` isn't part of the frozen `AuditSink`
  trait, and `AuditError`'s single frozen `Write` variant is the wrong shape for it.
- Snake_case/kebab-case wire naming follows serde convention and the `DestinationId`
  precedent; nothing else in the repo had established a JSON naming style yet.

### Validation status

**Not compiled or tested in the dispatch session** — all toolchain access was
permission-blocked (same constraint as T04's dispatch; recorded there as a factory gap).
Mitigations: a line-by-line self-review pass that caught three real would-be compile errors
before handoff (`PathBuf` has no `Display` in thiserror format strings; an exhaustive match
on `#[non_exhaustive]` `Destination`; a moved-while-borrowed `path` in `open`), plus
rustfmt-canonical formatting written deliberately.

**Verified during PR review (2026-07-17):** the standard verify chain ran clean on the
first real attempt after a single `fmt` pass — `cargo build --locked && cargo clippy
--workspace --all-targets --locked -- -D warnings && cargo fmt --check && cargo test`,
with 8 sink tests + 3 record tests + the whole existing suite green.

### Doubt-driven-development (Codex cross-model, 2026-07-17)

A fresh-context Codex review, given the diff + the frozen `AuditSink` contract + the
redaction-safety requirement, found a strong set on this security-critical persistence
layer. Reconciliation:

**Fixed (real robustness/security):**
- **A crash mid-multibyte-UTF-8 in the torn final line bricked the whole log.** `open()`
  read the file with `read_to_string`, which fails entirely on any invalid UTF-8 —
  contradicting the documented "torn write tolerated" guarantee. Now reads raw bytes and
  decodes per line, so invalid UTF-8 is confined to (and tolerated in) the torn tail.
- **Any unparseable line was silently skipped, not just the torn final one.** A complete
  (newline-terminated) interior line that fails to parse is corruption/tampering, not a
  torn write, and silently dropping it made the index no longer represent the append log —
  the exact "quietly lossy" failure the `UnknownSchemaVersion` path was already written to
  avoid. Now only a genuinely torn *final* line is tolerated; every complete line must
  parse or `open()` returns the new `OpenError::CorruptLine`. This also closes the
  bypass where a malformed `schema_version` (e.g. the string `"2"`) failed `VersionProbe`
  and was skipped as torn instead of refused.
- **Recovery changed from newline-heal to truncation.** The old heal appended a `\n` to the
  torn tail, immortalising a garbage fragment that was re-skipped on every future open — and
  under the stricter rule above, that healed fragment would then read as a fatal
  complete-corrupt line. Truncating the torn tail back to the last complete record is the
  honest recovery (this sink fsyncs `record + '\n'` per write, so a tail without a trailing
  newline was never a committed record) and keeps the file all-complete-lines.
- **A duplicate `AuditId` on replay silently shadowed the earlier record** (`index.insert`
  overwrote it; `len()` under-counted). IDs are internal UUIDv4s, so a duplicate means the
  append-only log was spliced/tampered — now a hard `OpenError::DuplicateId`.
- **Error text could leak a raw value.** `unsupported()` Debug-formatted the *value* of an
  unknown future variant into `AuditError::Write` — a string a caller may log. For the one
  tool whose whole job is keeping raw values out of side channels, that is exactly the wrong
  failure. Now names only the *type*, never the value. Added a parent-directory fsync on
  first create (file-level fsync alone doesn't make a new dirent durable).
- Four regression tests added, one per fixed behaviour.

**Reconciled as accepted trade-offs (documented, not changed):**
- **The sink cannot enforce "no raw value persisted" — and by design does not try.** It has
  no oracle for what is "raw" (it never sees the vault or the original detected values), so
  it faithfully persists whatever event it is handed; keeping events clean is the
  *constructing* code's contract (Task T07), enforced at construction by
  `assert_audit_event_excludes_raw_values`. The struct doc now states this boundary
  explicitly. The property test proves well-constructed events don't leak; it cannot prove a
  buggy caller won't hand the sink a leaky `Block.reason`, because nothing at this layer
  could.
- **Single-live-sink coupling:** `get`'s in-memory index only reflects this sink's own
  writes; a second sink on the same file, or another process appending, needs a reopen to
  be seen. Made explicit in the struct doc; multi-opener coordination is out of Phase 1
  scope.

Round 1 stopped after one cross-model cycle — every finding was fixed or explicitly classified.

### Doubt-driven-development, round 2 (Codex cross-model, 2026-07-17)

A second, tighter Codex critique (re-run for a complete verdict across all Wave B tasks) found
one real bug that round 1's fixes had actually *introduced*:

- **Fixed (High): a valid-JSON final line with no trailing newline was indexed, then truncated
  off disk.** Round 1's recovery reads the torn tail, and if it happened to be a complete,
  parseable record, `index.insert`ed it — but the post-loop truncation then removed it from
  disk. So `get()`/`len()` reported an event that a reopen would lose: an index/disk
  inconsistency. Fixed by skipping the torn tail *unconditionally* (before parse/index), which
  is correct anyway — a record whose terminating `\n`+fsync never landed was never a
  durably-committed record for this sink, so discarding it is honest, and now index and disk
  agree. New regression test `a_valid_record_without_a_trailing_newline_is_not_indexed_then_lost`.
  Full chain green after: 13 sink tests + 3 record tests + the existing suite.

## 2026-07-17 - T06: `vg-policy` PolicyEngine implemented (`LayeredPolicyEngine`)

### Context

Implemented `vg_core::PolicyEngine` in `crates/vg-policy` (previously an empty stub). The
engine resolves up to three layered policy packs (session-over-repo-over-global) into one
validated policy and answers the six trait methods. See `crates/vg-policy/src/{config,engine}.rs`
and the fixtures/tests. Decisions taken during the task (recorded here rather than asked, per
the one-shot headless dispatch instruction):

### Decision — policy-pack format is **JSON** in Phase 1, not TOML/YAML (deviates from ADR-007)

ADR-007 (2026-06-30) said "native YAML/TOML now". The T06 spec restated that as "YAML
(`serde_yaml`) or TOML (`toml`) are both reasonable". I chose **JSON via `serde_json`** instead,
for one concrete, environment-driven reason: **cargo cannot run in this dispatch sandbox**, so
`Cargo.lock` cannot be regenerated. `serde`, `serde_core`, `serde_derive`, and `serde_json` are
*already fully resolved* in the workspace `Cargo.lock` (pulled in transitively by `criterion`),
whereas neither `toml` nor `serde_yaml` is present. Adding `toml`/`serde_yaml` would introduce
new registry packages (winnow, serde_spanned, toml_edit, indexmap, …) that I cannot resolve or
checksum by hand, which would break the `cargo build --locked` acceptance criterion. JSON adds
**zero** new locked packages — the only `Cargo.lock` change is adding the `serde`/`serde_json`
edges to `vg-policy`'s own dependency list.

This is a deliberate, reversible, Phase-1-scoped deviation, not a rejection of ADR-007. The
on-disk schema is format-agnostic serde structs (`RawPack` etc.), so switching the format crate
(e.g. to `toml`) is a one-line change in `LayeredPolicyEngine::read_layer` plus renaming the
fixtures — no schema or engine-logic change. **Follow-up (see next-actions):** when the build
environment can regenerate the lock, reconcile format with ADR-007 (TOML) or amend ADR-007 to
accept JSON. Neither `serde_yaml` (unmaintained/deprecated upstream) nor a hand-rolled parser
was considered a good option.

### Decision — the hard-deny rule is enforced *in code*, above the config layer

`demask_allowed` returns `false` for `Destination::RemoteModelPrompt` and
`Destination::ObservabilitySink` via an explicit `matches!` guard *before* the pack is consulted
— a malicious or misconfigured pack that sets `demask_allowed: true` for them cannot override it
(regression-tested in `malicious_pack_cannot_unlock_hard_deny_destinations`). This is the one
security-load-bearing part of the task; everything else is configuration plumbing. Verified with
`vg_core::conformance::assert_policy_engine_denies_hard_deny_destinations`. As defence in depth,
`destination_allows_masked_only` also forces `true` for those two destinations regardless of
pack contents (the send-side mirror of the same invariant — the contract only mandates the
`demask_allowed` half, this strengthens it at no cost).

### Decision — signed-pack verification is a clearly-marked always-accept stub

`config::verify_signature` returns `Ok(())` unconditionally in Phase 1 (interface-contracts.md
§6: "stub in Phase 1, enforced later"). The `signature` field is threaded through `RawPack` now
so Phase 2 can add real verification without a load-flow or schema change. Marked **PHASE 1
STUB — must be replaced before loading untrusted packs** in the doc comment.

### Smaller decisions (schema/semantics)

- **Entity/handling-class keys are stable kebab-case strings** (`config::entity_key`,
  `parse_class`) since `EntityType`/`HandlingClass` live in `vg-core` without serde derives and
  are `#[non_exhaustive]`. `Custom(name)` keys on its dictionary name directly; a future
  `EntityType` variant falls back to a lower-cased debug name (no breaking change here).
- **Unknown handling-class strings fail at load** (`ResolvedPolicy::from_raw`), not lazily at
  first `classify_*` — a pack typo is a load error.
- **Layer merge is key-by-key** (a repo/session layer overrides only the keys it names);
  destination rules merge *field by field* so one layer can flip `demask_allowed` without
  restating `masked_only`.
- **Fail-safe defaults:** unclassified entity → `Mask`; unconfigured destination →
  masked-only `true` and demask `false`; artefact default → `Pass`.
- **Optional role-gating:** a destination may list `demask_roles`; if non-empty the actor must
  hold one. This makes the `actor` parameter meaningful without over-building auth (Cedar is
  still ADR-007's later target).

### Validation status + doubt-driven-development (2026-07-17)

**Verified during PR review:** compiled clean (no new registry deps — `serde`/`serde_json`
already in the lockfile, chosen deliberately so `--locked` stays green); one `fmt` pass
applied; full chain green — 4 config + 9 engine tests plus the whole existing workspace suite.

**Codex cross-model doubt-pass** (given the diff + the frozen `PolicyEngine` contract + the
hard-deny requirement) ran out of its turn budget before a full verdict, but flagged the crux
(hard-deny bypass) which I then verified directly, along with the other fail-safe properties:

- **Hard-deny is unbypassable — verified.** `demask_allowed` returns `false` for
  `RemoteModelPrompt`/`ObservabilitySink` via a direct enum `matches!` checked *before* any pack
  rule is consulted, so no global/repo/session pack (malicious, misconfigured, or mistaken) can
  flip them. `destination_allows_masked_only` mirrors this on the send-side gate
  (`is_hard_deny_id` → forced masked-only). Confirmed against
  `assert_policy_engine_denies_hard_deny_destinations`.
- **Layering verified:** `load` merges global → (repo over global) → (session over repo),
  so session > repo > global. A malformed layer (or an unknown handling-class string) makes the
  *entire* `load()` fail (`PolicyError::Load`) — no partially-loaded, silently-wrong engine.
  Fail-safe.
- **Corrected the framing of one "fail-safe default" bullet above.** `artefact_default = Pass`
  is NOT fail-safe in the same sense as `entity_default = Mask`, and the review rightly flagged
  the asymmetry. It is nonetheless the *correct* default, for a real reason now documented in a
  code comment at `config::ResolvedPolicy::from_raw`: artefact class is a whole-file decision
  (`Block` refuses a file, `Pass` sends it), and defaulting unknown file types to `Block` would
  refuse everything not allow-listed and make the tool unusable — while their detected PII
  entities are STILL masked, because entity classification defaults to `Mask` independently.
  **Hard requirement recorded for T07:** artefact-`Pass` must mean "send after entity masking,"
  never "skip detection/masking for this file"; if T07 lets an artefact class short-circuit
  entity scanning, this default becomes a fail-open leak.

Because Codex did not deliver a full verdict, this counts as one partial cross-model cycle; the
concrete concern it raised (hard-deny bypass) is verified closed, and the asymmetry it would
have reached is documented and flagged forward.

### Doubt-driven-development, round 2 (Codex cross-model, complete verdict, 2026-07-17)

Re-ran a tighter, exploration-forbidden Codex critique (given the diff + the hard-deny/layering
contract inline) to get a complete verdict where round 1 had run out of budget. Result: **"no
issues found after thorough examination."** This is the only Wave B task whose second-round
critique surfaced nothing — consistent with the manual verification above (hard-deny
unbypassable, layering fail-safe, defaults documented). No code change from round 2.


## 2026-07-17 - T08 (`vg-parsers`) built (headless dispatch, unable to reach a compiler)

### Context

T08 (Squad 2): implement `vg_core::Parser` in `crates/vg-parsers/` — one module per format
(`json`, `yaml`, `toml`, `csv`, `log`, `diff`, `env`) plus tree-sitter for one source
language. Hard contract: **never panic on malformed input**, return best-effort spans.
Cross-crate requirement (interface-contracts.md, 2026-07-16): feed real `Span` output into
`vg_detectors::all_detectors()` and record whether the detectors' `_spans` no-op is an
expected gap. One-shot headless dispatch — ambiguities resolved by judgment and recorded
here rather than asked.

### Judgment calls recorded (no follow-up channel)

1. **Source language for tree-sitter = Rust** (`rust.rs`, `ArtefactKind::SourceCode("rust")`).
   The task said pick something simple and common if ambiguous; Rust is this project's own
   language (ADR-001) and the grammar crate is well maintained. Tree-sitter is error-tolerant
   by construction (produces `ERROR`/`MISSING` nodes, never fails), which matches the
   never-panic contract directly.

2. **JSON is hand-rolled, not `serde_json`.** `serde_json`'s tree parser gives no byte offsets
   and aborts at the first syntax error — the opposite of "best-effort spans over malformed
   input." `json.rs` is a single-pass tolerant byte tokenizer that classifies each string as an
   object `Key` (followed by `:`) or a `StringLiteral`/`Value`, and degrades an unterminated
   final string to a span clamped at end-of-buffer.

3. **YAML and TOML: third-party parser as a well-formedness gate, hand-rolled line scanner for
   spans.** `serde_yaml` and the `toml` crate both parse into an owned value tree with **no byte
   offsets**, so neither can answer "where in the buffer is this key." They are still
   load-bearing: (a) exercised on every parse, including the adversarial never-panic battery, so
   the third-party parsers' own panic-safety is verified alongside ours; and (b) for YAML, a
   *valid* document with no block-style `key:` structure (i.e. flow style `{a: 1}`, which is
   JSON-shaped) falls back to the JSON tokenizer for spans. Block-style YAML / TOML `key = value`
   / `[table]` / comments come from the quote-aware line scanners. This is why `serde_yaml` and
   `toml` are dependencies even though the spans don't come from them — recorded so a reader
   doesn't mistake them for dead weight. (Only `yaml.rs` was contractually required to "add
   serde_yaml or similar"; the `toml` crate is used the same way by choice, not mandate.)

4. **`.env` inline `#` is not a comment.** dotenv tools disagree on whether `KEY=val # x` has a
   comment; a value like `p#ssw0rd` or a URL fragment must never be truncated (and secrets live
   in exactly these values). Only a whole-line-leading `#` is a comment. TOML/YAML `#` handling
   *is* quote-aware because their grammars define it.

5. **Span structural tags** use the frozen `NodeKind` variants: object/map keys → `Key`, scalar
   values → `Value`/`StringLiteral`, CSV body cells → `Field(header_name)` (column-aware),
   log timestamp/level and diff added/removed/path → `Field(...)`, hunk headers → `Other("hunk")`,
   comments → `Comment`, tree-sitter identifiers → `Identifier`. All spans route through a single
   `util::span` helper that clamps `end` to buffer length and `start ≤ end`, so the Parser
   span-bounds invariant holds unconditionally even if a format's own scanning logic has an
   off-by-one.

### Cross-crate integration finding: the detectors' `_spans` no-op is an EXPECTED, stage-appropriate gap

**Required classification (interface-contracts.md, 2026-07-16).** `crates/vg-parsers/tests/detector_integration.rs`
feeds this crate's real `Span` output into `vg_detectors::all_detectors()` on realistic JSON,
`.env`, YAML, and CSV fixtures, and additionally pins the observed behaviour: feeding real
parser spans, an empty slice, and deliberately *wrong* spans all yield **identical** findings —
because every T03 detector's signature is `detect(&self, buf, _spans)`, ignoring `spans` today.

**This is an expected gap, not a real one**, for three reasons:
- **No contract is violated.** The detectors still satisfy their contract (valid findings,
  in-bounds spans, determinism) without consuming `spans`. The T03 detectors are regex/entropy
  scanners over the whole buffer; whole-buffer scanning is a *superset* of structure-scoped
  scanning, so nothing is missed by ignoring structure — it can only over-scan, never under-scan.
- **The pipeline that threads parser spans into detectors is T07** (masking-pipeline wiring in
  `vg-core`, Wave C), which does not exist yet. Parsers (T08) *produce* spans; T07 *wires* them
  in; span-aware detection is a deliberately later enrichment, consistent with the phased plan
  and interface-contracts.md §3–§4.
- **The no-op is now pinned by a test.** If a future change (T07, or a span-aware detector) makes
  `detect` actually consume `spans`, `detectors_currently_ignore_the_spans_parameter` breaks
  first and loudly, forcing this classification to be revisited rather than the no-op being
  silently assumed still true.

**Deferred opportunity, flagged for T07 (not a defect now):** the 2026-07-16 census found the
entropy/phone detectors' dominant false positives were on file paths and snake/kebab identifiers.
Span-awareness is the natural structural fix — e.g. scanning only `Value`/`StringLiteral` spans
and skipping `Key`/`Identifier`/`Comment` spans would cut exactly that false-positive class. That
is a T07-era enhancement (wire spans through, then let detectors opt into structure), not
something T08 can or should do inside `vg-detectors` (ownership rule: edit only your crate).

### Verification status — NOT built in-session (compiler unreachable), and a Cargo.lock action required

As with T04, this headless dispatch could not reach a compiler: every `cargo`/`rustc`/`python`
invocation (and any shell wrapper around one) is gated behind an approval prompt with no human
in a one-shot dispatch. The code is written for correctness and panic-safety by inspection, with
a thorough per-module adversarial `assert_parser_never_panics` battery (empty, truncated UTF-8,
unbalanced delimiters, all-NUL, every-byte-value, binary-masquerading-as-format) plus a shared
registry-wide battery in `lib.rs`. **These must be run at PR review**, exactly as T04 was:
`cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check &&
cargo test -p vg-parsers`.

**Two review-time actions specific to T08 (distinct from T04, which added no dependencies):**
- **`Cargo.lock` MUST be regenerated.** T08 adds four dependencies (`serde_yaml`, `toml`,
  `tree-sitter`, `tree-sitter-rust`) but `Cargo.lock` could not be updated without running cargo.
  Until a maintainer runs `cargo build` (or `cargo update -p vg-parsers`) and commits the
  refreshed `Cargo.lock`, **every `--locked` CI job (build, test, clippy, bench) will fail
  immediately** with "lock file needs to be updated." This is the top handoff item.
- **Verify the tree-sitter version pair resolves and compiles.** `tree-sitter = "0.22"` +
  `tree-sitter-rust = "0.21"` were chosen for the `set_language(&Language)` / `language()` API
  used in `rust.rs`. This pairing is the single most likely thing to need adjustment on first
  real build (the tree-sitter grammar crates changed `language()` → `LANGUAGE` in later
  versions); if it doesn't resolve, pin the matching pair rather than changing the call site
  blindly. `cargo fmt` at review will also absorb any residual formatting the hand-write missed.

**Verified during PR review (2026-07-17).** `Cargo.lock` regenerated (the four deps resolved;
the `tree-sitter 0.22` / `tree-sitter-rust 0.21` pairing compiled without adjustment). Fixed
during review: two trivial clippy items (`int_plus_one` in `env.rs`; unused `Span`/`Detector`
imports); two borrowed-temporary compile errors in tests (`let x = &Parser.parse(buf).spans`
dangles — bound the `ParseResult` first, in `env.rs` and `yaml.rs`); and **one real correctness
bug** — `yaml::falls_back_to_json_tokenizer_for_flow_style` failed because the block line-scanner
greedily matched the first `:` in a flow-style line `{"host": ...}` and emitted `{"host"` as a
bogus "key", so `spans` was never empty and the JSON-tokenizer fallback never fired. Fixed by
skipping block key-extraction for a segment that opens with a flow indicator (`{`/`[`), leaving
it to the JSON tokenizer (a line like `config: {host: db}` opens with `config`, so it is
unaffected). Full chain green after: 36 `vg-parsers` lib tests + 3 cross-crate integration tests
+ the whole existing suite.

### Doubt-driven-development (Codex cross-model, 2026-07-17)

A fresh-context Codex review ran (given the diff + the `Parser` never-panic/span-bounds
contract, focused on panics, out-of-bounds spans, and false-negative "missed value" spans). It
ran out of its turn budget before a full verdict, but its final assessment was explicit and
matches an independent read: **no out-of-bounds / panic risks found** (the hard contract holds —
backed by the per-module `assert_parser_never_panics` batteries and `every_span_is_within_bounds`
tests, all green), and the only residual is **partial spanning** — a syntactically valid value
covered by only part of a span, which *could* let a span-aware detector miss part of a secret.

Reconciled as a **documented, stage-appropriate concern flagged forward to T07**, not a current
bug: the T03 detectors currently *ignore* the `spans` parameter entirely (the `_spans` no-op,
asserted and explained in `tests/detector_integration.rs` and the section above), so today every
detector scans the raw buffer, not the spans — a partial span cannot cause a missed detection
until T07 wires spans into the pipeline. **Hard note for T07:** when spans start gating what a
detector scans, partial/underspanning becomes a real false-negative (missed-secret) risk;
before relying on parser spans to scope detection, add coverage that a value spanning multiple
tokens/lines (a multi-line string, a wrapped base64 blob, a quoted value with embedded
delimiters) is fully covered, or have the pipeline fall back to scanning the raw region. The one
real underspanning bug that *did* exist at this layer (the yaml flow-style mis-parse above) is
fixed.

### Doubt-driven-development, round 2 (Codex cross-model, complete verdict, 2026-07-17)

A second, tighter Codex critique confirmed **no panic / out-of-bounds-span risks** and named two
concrete instances of the partial-spanning class above. Both are Medium and, per the `_spans`
no-op, cannot cause a missed detection until T07 — so both are recorded here as **specific known
under-spanning limitations for T07 to close**, not fixed now (quote-aware YAML scanning in the
best-effort line scanner is real parser work with regression risk, and the well-formedness
gate + JSON fallback already back-stop structure):

1. **A `#` inside a quoted YAML value is treated as a comment.** `password: "abc #def"` yields a
   Value span over only `"abc` and a Comment span over `#def"`. `comment_start` requires a `#`
   preceded by whitespace but is not quote-aware. (The `.env` parser deliberately handles the
   analogous `pass#word` case; YAML's block scanner does not.) A secret containing ` #` would be
   split. **T07 fix direction:** make comment detection quote-aware, or have the pipeline scan
   the raw line for a value the parser under-spanned.
2. **YAML flow scalars that aren't JSON double-quoted strings are under-spanned.** The flow-style
   fallback reuses the JSON tokenizer, which only recognises `"…"` strings and bare scalars;
   single-quoted (`{token: 'sk-live-abc'}`) or unquoted flow scalars get no complete span.
   **T07 fix direction:** a YAML-aware flow tokenizer, or raw-region fallback.

Both are the same "detector could miss part of a value once spans gate detection" risk already
flagged above — now with concrete reproducers to test against at T07.

## 2026-07-18 — T07: masking pipeline wired (`scan`/`mask`), contract v1 → v1.1

### Context

`vg-core::scan` and `mask` were frozen-signature `todo!()` stubs since T02; every crate they
compose (detectors T03, keying T04, vault T05, audit T05b, policy T06, parsers T08) is now
merged. T07 replaced the two bodies with the real pipeline, reaching the implementations only
through `vg-core`'s own trait objects (`Context { parsers, detectors }`,
`Policy { engine, vault, audit }`) — no new normal-build dependency on any implementing crate;
the integration tests and criterion bench pull the real crates in as **dev-dependencies**, the
same resolves-fine cycle T04 established for `vg-detectors`.

### Contract change v1 → v1.1: `mask` gains `ctx: &Context`

The frozen `mask(input, policy, ns)` had no way to reach the detectors/parsers `scan` gets via
`Context`, yet `mask`'s whole job is detect-then-mask. Resolved through the contract-change
protocol (`architecture/agent-factory-plan.md` §6): added `ctx: &Context` →
`mask(input, ctx, policy, ns)`, bumped `interface-contracts.md` to **v1.1** with an inline
versioned note in §2 and a Versioning-section entry. Deliberately **not** done by smuggling
detectors into `Policy` (conflates "what to do" with "how to find it") or by having callers
pre-compute `Vec<Finding>` (duplicates `scan` at every call site and lets a caller mask a stale
or hand-forged finding set) — the explicit parameter is the sanctioned fix named in the dispatch.
No current caller existed (the CLI/adapters had not yet wired `mask`), so no call sites migrated.

### Pipeline order and the hard requirements it honours

1. **Artefact classified first.** `policy.engine.classify_artefact(&hint)`; a `Block` artefact
   (e.g. a `.env` per the default fixture) returns a `MaskedPack` with empty `text`,
   `stats.blocked_artefacts = 1`, no mapping refs, and an `AuditEvent::Block` — the content
   never reaches the pack.
2. **`Pass` ≠ "skip detection" (T06 review).** Entity scanning runs for every non-Block
   artefact regardless of artefact class, or `Pass` would fail open.
3. **Spans are enrichment only (T08 review).** The first `can_parse` parser supplies spans, but
   detectors always scan the **full raw buffer** — the two documented YAML under-spanning
   reproducers (`#` inside a quoted value; single-quoted flow scalars) would become
   missed-secret bugs if detection were span-gated.
4. **Overlap resolution: specific over generic, then longer span.** Greedy interval selection by
   priority — the entropy catch-all `Secret` (specificity 0) loses to any concretely-typed
   finding (specificity 1) covering the same bytes (the anticipated `Email`-over-`Secret` case),
   and among equally-specific findings the longer span wins. No bytes are ever masked twice.
5. **Class handling.** `Mask` → `vault.intern` + placeholder; `IrreversibleRedact` and
   entity-level `Block` → fixed typed marker `[REDACTED:TYPE]`, **never interned** (the
   "irreversible never vault-stored" criterion is tested); `Pass` → bytes untouched. Replacements
   applied back-to-front so earlier byte offsets stay valid.
6. **One audit event, written and returned.** `AuditEvent::Scan { counts, detector_version,
   latency_us }` (latency measured around the detect step; `detector_version` = sorted detector
   ids joined with `+`), or the `Block` event for a blocked artefact.

### Assumptions recorded (per the dispatch's "record, don't ask" instruction)

- **Detector-set provenance string.** The `Scan` event's `detector_version` has no single
  authoritative source (each detector has its own `DetectorId`, there is no crate-wide version),
  so it is composed as the sorted detector ids joined with `+` (e.g. `email+entropy+ip+iban-sortcode+phone`).
  Stable, human-legible, no raw value. Revisit if a real semver-style detector-pack version lands.
- **`stats.counts` / audit counts semantics.** Counts tally every *handled* finding (Mask,
  IrreversibleRedact, entity-Block) by entity type; a `Pass` finding is a no-op and is not
  counted. The same `EntityCounts` feeds both the `MaskedPack.stats` and the `Scan` event.
- **Non-UTF-8 spans.** Value extraction and the final pack text use `String::from_utf8_lossy`.
  The five deterministic detectors match ASCII-shaped values, so this is lossless in practice;
  a value with invalid UTF-8 would be interned in its lossy form. Acceptable for Phase 1.
- **Demask attribution has one owner (T05 review).** The vault's own `demask_event` table records
  every `resolve`. The pipeline therefore emits **no** `AuditEvent::DemaskDecision`; when
  `rehydrate`'s allowed path is wired (T07/T09, still `todo!()` — its frozen signature has no
  vault handle, so it is out of scope here), it must not double-log. The vault owns demask
  attribution in Phase 1.

### Validation

Headless dispatch: no compiler in-session (`cargo`/`rustc` approval-gated — see auto-memory). Not
compiled or run here; correctness is by construction against the read implementations and flagged
for verification at review. Added `crates/vg-core/tests/pipeline.rs` (e2e mask over a mixed
fixture through the real crates; the `assert_masked_pack_excludes_raw_values` property over the
fixture's raw values; `.env` block; irreversible-redact-never-interned via a fresh-handle
`mapping_count == 0`), `tests/pipeline_latency_gate.rs` (plain-`#[test]` CI gate extending the
`vg-detectors` precedent to the full pipeline), and `benches/mask_pipeline.rs` (criterion,
compile-checked in CI). `Cargo.lock` should be unchanged — the new dev-deps (`vg-parsers`,
`vg-vault`, `vg-policy`, `vg-audit`, `tempfile`, `criterion`) are all already in the workspace
graph.

**Verified during PR review (2026-07-18):** built clean after a lockfile refresh; one trivial
clippy lint (`sort_by_key`) and an `fmt` pass. Full workspace suite green.

### Doubt-driven-development (fresh-context Fable review, 2026-07-18)

Run per the doubt-driven-development skill before the tollgate. CLAIM: *"T07's `mask()`
composes six independently-built crates such that no raw detected value can reach
`MaskedPack.text`, the vault, or the audit trail in violation of policy — under overlapping
findings, malformed input, and every artefact class."* The DOUBT step was a **fresh-context
Fable subagent** (Opus authored this task; a different reviewing model with none of the
authoring session's context), given ARTIFACT + CONTRACT only and explicitly forbidden from
reading the author's own docs (decisions/session-log/build-log) to avoid contamination. It
returned a complete 13-finding verdict. Reconciliation (each finding re-verified against the
code before classification):

**Fixed — 2 High (both verified real before fixing):**
1. **Partial overlap dropped the losing finding whole, leaking its uncovered bytes raw.**
   `resolve_overlaps` was greedy accept-or-drop; the entropy detector's own documented
   tokenizer residual (`@`/`.`/`-` are token bytes) produces exactly the killing scenario — a
   `Secret` span over `userinfo@host` partially overlapped by an accepted `Email` tail meant
   the secret head survived raw into `pack.text`. Fixed: losers are **trimmed to their
   uncovered fragments**, never discarded. Regression test
   `partially_overlapping_findings_leak_no_detected_bytes`, with preconditions asserting the
   overlap actually occurs so it can't pass vacuously.
2. **A literal `.env` file was NOT blocked.** `Path::new(".env").extension()` is `None` in
   Rust, so the contract's canonical Block example fell through to `artefact_default = pass`
   and failed open — and the original test's `secrets.env` filename (which *does* have an
   `env` extension) masked the bug. Fixed in `vg-policy` (`extension_candidates`: dotfiles
   also try the first segment after the leading dot, mirroring `vg-parsers`' env matcher);
   the test now uses the bare `.env` name to lock the regression.

**Fixed — 4 Medium:** (3) an intern failure mid-loop left durably-persisted mappings with no
audit record — a best-effort partial `Scan` event is now written before the error propagates;
(4) Block-classed artefacts were parsed *before* the Block check on the unstated assumption
that parsers never copy content into output (`SourceCode(String)`/`Field(String)` are
content-capable; the CSV parser already clones header names) — Block is now checked first,
recording `ArtefactKind::Unknown` since not touching blocked content outranks provenance
detail; (5) artefact-scope `mask`/`irreversible-redact` in a pack was silently treated as
`Pass` (fail-open on a representable config) — now a load-time `PolicyError::Load` in
`vg-policy`, with a unit test; (6) the 25ms budget had no real enforcement — the detect-only
portion `mask` measures (excluding vault/audit I/O by construction) is now asserted <= 25ms
via the `Scan` event in a deterministic test, with the 12x e2e wall-clock gate kept as
backstop.

**Fixed — 4 Low:** runtime span guard at the seam (a non-conformant third-party detector span
panicked mid-mask — now dropped, loudly in debug); zero-width spans filtered (they spliced
phantom placeholders and interned the empty string); `mapping_refs` deduped; ordinals mint in
forward document order (first email in the buffer is `EMAIL_001` — classify/intern forward,
splice backward). Plus the `Scan` event's counts now record **all detections** (including
policy-`Pass`ed ones — the audit trail must answer "what was found") while `MaskStats.counts`
remains the handled subset, both documented.

**Documented as trade-offs / flagged forward (not fixed here):**
- **Non-UTF-8 spans can't round-trip** (`Secret` is a `String`, frozen at T02). Unreachable
  with the all-ASCII T03 detectors; recorded as a contract-shape limitation to revisit if a
  non-ASCII (warm-path NER) detector lands.
- **Placeholder spoofing surface** (input already containing `EMAIL_001`-shaped text is
  indistinguishable from pipeline output; the T04 display format has no delimiters). **Hard
  requirement recorded for T09:** `rehydrate`/demask must resolve exclusively via the pack's
  `MappingRef`s — never by pattern-scanning text for placeholder-shaped strings.

The reviewer also explicitly cleared what it checked and found sound (no raw-value path
through any error-message string; `detector_version` is ids only; the dev-dependency edges
create no build-graph cycle). Full suite green after all fixes (pipeline tests 5 -> 8;
vg-policy config tests +1).

### Codex cross-model round (2026-07-18, human-approved, run on the POST-fix diff)

Pointed deliberately at the surfaces the Fable-round fixes had just created (trimming
arithmetic, forward-intern/backward-splice split, best-effort audit path,
`extension_candidates`). Verdict: **one Medium finding — real, and introduced by the
interaction of two of the round-1 fixes:**

- **Scan-event detection counts were taken AFTER overlap trimming**, so one raw `Secret`
  finding split around two accepted higher-priority winners produced multiple fragments and
  was counted as multiple "detections" — corrupting exactly the "what did detection find"
  audit metric the raw-counts fix existed to provide. Fixed: `detected_counts` now
  accumulates from the RAW findings (post span-guard, pre-resolution). Regression test
  `scan_event_counts_raw_detections_not_overlap_fragments` uses a test-local mock detector
  emitting one `Secret` span containing two `Email` spans — the fragment-counting bug would
  report Secret=3; the test asserts Secret=1, Email=2.

Codex flagged nothing else on the post-fix state. Stop condition: two cross-model
fresh-context cycles complete (Fable full-verdict, then Codex on the fixed diff), the final
cycle yielding a single already-fixed Medium — the diminishing-returns pattern the
doubt-driven-development skill names as the stopping point. Full suite green: pipeline tests
8 -> 9.

## 2026-07-18 — T09: `vg` CLI + Claude Code adapter (contract v1.1 → v1.2)

### Context — a third distinct dispatch failure mode, and the rescue

The Opus dispatch was killed by **`API Error: Connection closed mid-response`** — a transient
network drop, distinct from T01's permission stall, T02's tool timeout, and T03's
clarifying-question dead-end. It died *after* writing the adapter and contract work (1,254
lines: `hook.rs`, `pack.rs`, `runtime.rs`, `state.rs`, `wrapper.rs`, the v1.2 contract change,
`tests/demask.rs`) but *before* the CLI, runbook, or docs. Per the runbook's human-rescue
procedure (the T02 precedent), the interrupted work was finished in place rather than
re-dispatched: everything Opus wrote compiled clean on the first real build, zero errors.

### Contract change v1.2 (executed by Opus, per the spec's direction)

- `MaskedPack` gains `bindings: Vec<PlaceholderBinding { display, mapping_ref }>` — populated
  by `mask` at intern time, carrying a typed display and an opaque UUID, never a value.
- `rehydrate` re-signed: `rehydrate(pack, policy, ns, dest, actor)` — hard-deny checked FIRST
  (before engine or vault), then `demask_allowed`, then per-binding `vault.resolve`,
  substituting **only the displays the pack itself minted** (longest-display-first so a
  shorter display can't corrupt a longer one it prefixes). This is what makes the banked
  "demask via `MappingRef`s only, never pattern-scanning" requirement real.

### Judgment call flagged for the doubt-pass: `rehydrate` DOES emit `AuditEvent::DemaskDecision`

The T05/T07-banked requirement said the vault owns demask attribution — no `DemaskDecision`
double-logging from the pipeline. Opus deviated, with an argued rationale left in the code:
the vault only logs `resolve` *attempts*, so a **hard-denied demask never touches the vault
and would otherwise leave no audit trace at all**. The two records are different grains
(vault: per-binding resolution attempts; rehydrate: one authorisation outcome per demask
call) and non-redundant. Accepted as the better reading of the requirement's *intent*
(auditability of denials) over its letter — verified live: a denied
`vg demask --to remote-model-prompt` writes `{"kind":"demask_decision","allowed":false}` and
the vault stays untouched.

### What the rescue added (this session, matching the adapter's conventions)

- **`vg-cli`** (the piece the crash prevented): `run` (writes hook settings, prints the
  pre-send summary, auto-appends `--settings` for a wrapped `claude*`, passes Bedrock env
  through — no HTTP client), `hook` (section-8 exit codes; stdin JSON), `inspect` (classes +
  spans, **never** matched text), `diff --masked` (masked text + stats; persists the pack),
  `demask --from <pack> --to <dest>` (stored packs only — never bare text), `audit`,
  `policy check`, `vault stats`. clap-derived help throughout.
- **CLI-level integration tests** (`crates/vg-cli/tests/cli.rs`, via `CARGO_BIN_EXE_vg` — no
  new test deps): binary round trip, hard-deny with no raw value on any stream, hook
  transform (exit 2) and pass-through (exit 0), inspect-never-leaks, help completeness.
  These sit on top of Opus's lib-level `tests/demask.rs` (round trip, both deny paths,
  spoofed-placeholder-untouched, denied-demask audit).
- **`docs/runbook-hooks.md`** — the walkthrough for the human UX-invisibility session (the
  acceptance criterion only a human can satisfy; scheduled at review, not claimed here).
- Live smoke over the real binary: mask → `contact EMAIL_001 about IBAN IBAN_001` →
  demask restores the original byte-for-byte → hard-deny refused with exit 1 → both
  decisions in `vg audit`.

### Validation

Full workspace chain green: build, `clippy -D warnings` (three trivial lints fixed:
`sort_by_key` x2, `ptr_arg`/`map_clone` in the new CLI), `fmt --check`, tests — **213 tests
across 28 binaries, 0 failures** (5 new CLI integration + 5 lib demask + 38 vg-core units
with the bindings type). Lockfile updated for `clap`(derive) + `serde_json` in `vg-cli` only.

## 2026-07-18 — T09 doubt-pass round 1 (Fable, fresh context): the §8 hook contract was inverted; contract v1.2 → v1.3

**Context.** Per the standing instruction (Opus authors → Fable doubts), a fresh-context
Fable subagent ran an adversarial pass over the full T09 diff (2,407 lines: Opus's
adapter/contract work + the rescue CLI/tests), given ARTIFACT + CONTRACT only. It returned
**18 findings (6 High / 8 Med / 4 Low)** — the strongest verdict of the project. Every
finding was re-verified against the code before classification; the keystone finding was
additionally verified against the platform's own hooks documentation rather than trusting
either the reviewer or the author.

### The keystone (finding 1, High → contract v1.3)

§8's frozen exit-code scheme (`0` pass / `2` transformed / `1` block, "matching Claude
Code hook semantics") **did not match Claude Code hook semantics**. Verified against the
hooks docs: exit **2** is the platform's only *blocking* exit code (stdout discarded,
stderr fed back); any other non-zero exit — including our "block" = 1 — is a
**non-blocking warning after which the raw content continues**; structured output is
parsed from stdout JSON **only on exit 0**. So as frozen: every fail-closed path
(unparseable payload, masking error, policy Block) failed **open** in the only consumer
the wrapper configures, and the transform path (exit 2 + masked stdout) never substituted
anything. The whole masking-by-replacement mechanism was inert against the real platform.

**Fix (v1.3, adapter boundary only — no `vg-core` type changed):**
- Block (policy Block, parse failure, schema drift, mask error, unrenderable masked
  payload) → **exit 2**, reason on stderr.
- Transform → **exit 0 + JSON**: `PreToolUse` → `hookSpecificOutput.updatedInput` (true
  in-flight masking of tool input — better than the old design, which had no substitution
  at all); `PostToolUse` → `hookSpecificOutput.updatedToolOutput` (true masking of the
  tool result); `UserPromptSubmit` → the platform cannot rewrite a prompt, so
  `{"decision":"block"}` with the masked text in the reason for the user to resubmit.
  **Deliberate UX cost:** a sensitive prompt now costs one resubmit; warn-and-send would
  ship the raw prompt and defeat the product. The runbook UX session judges this honestly.
- If a masked tool payload no longer re-parses into the payload's JSON shape → block
  (fail closed), never send raw.
- `docs/architecture/interface-contracts.md` §8 rewritten; missing v1.2 amendment (Opus
  referenced it from code but never amended the document) added at the same time.

### Also fixed this round (each re-verified, not rubber-stamped)

- **F2 (High):** `hook_command` now shell-quotes `vg_exe` as well as the state dir — an
  install path with a space previously made every hook fail to spawn, which under real
  semantics (finding 1) meant a **silently unmasked session**.
- **F6 (High):** the worktree's `vg-vault/Cargo.toml` still carried the pre-CI-fix
  `keyring = "2"` line (stale base — the worktree was cut before the cargo-deny fix
  merged), so the tollgate auto-apply would have **silently reverted the CI fix**. File
  restored byte-identical to main; the hunk vanishes from the landing diff.
- **F8 (Med):** schema drift now fails closed — a payload missing/mistyping `prompt` /
  `tool_input` / `tool_response` blocks instead of passing through unmasked (a Claude
  Code payload rename would otherwise disable the shield forever, indistinguishable from
  "nothing sensitive"). Well-formed-but-empty subjects still pass through. Tested.
- **F9 (Med, the flagged DemaskDecision deviation):** resolved per the banked T05
  requirement — the pipeline now writes DemaskDecision **only for denials** (the one
  outcome the vault can never see, since hard-deny/policy-deny return before any
  `resolve`); allowed demasks are attributed solely by the vault's own fail-closed
  per-resolve demask log. Double-logging removed. Residual: a denial whose audit write
  fails is still denied but unrecorded — accepted, documented in the fn doc.
- **F7 (Med):** `rehydrate` substitution rewritten as a boundary-aware single pass:
  token boundaries (a minted `EMAIL_001` no longer corrupts unrelated `EMAIL_0015`),
  restored values are never re-scanned, and a tampered pack with an empty display is
  refused at load (`str::replace("")` would have inserted the secret at every character
  boundary). Regression test added (`substitution_respects_token_boundaries…`).
- **F10 (Med):** `vg demask` now detects a partial restore (unresolved bindings leave
  their placeholders) — warns with the count and exits non-zero instead of silently
  emitting a half-restored artefact.
- **F11 (Med):** `vg audit` withholds unparseable log lines instead of echoing them
  verbatim (only parsed events are known redaction-safe; vg-audit's own sink refuses such
  lines for exactly this reason).
- **F12 (Med):** vault sets a 5s `busy_timeout` — T09 made one-process-per-hook the
  normal mode and Claude Code parallelises tool calls, invalidating the vault's
  "multi-process out of scope" assumption; a collision now waits briefly instead of
  failing the hook. Cross-process ordinal-reseed races remain a documented Phase-1 limit.
- **F13 (Med):** `vg run` detects `--settings=FILE` as well as `--settings FILE`, and
  **warns loudly when the user's own settings mean VeilGremlin's hooks were NOT
  injected** (previously the pre-send summary claimed protection that wasn't wired).
- **F15 (Low):** stored-pack schema check is `!=` (unknown version), not `>` (a
  hand-edited `schema_version: 0` was previously mis-read as v1).
- **F17 (Low, partial):** `VG_VAULT_KEY_HEX` now prints a loud warning when honoured
  (test seam visibly flagged in real sessions).
- **F5 (High, mitigation):** the state dir now self-gitignores (`.veilgremlin/.gitignore`
  containing `*`, written once at creation) — packs/audit/vault can no longer be swept
  into a commit by accident.

### Accepted trade-offs / deferred (documented, not hidden)

- **F3 (High) — upward state-dir discovery trusts any ancestor `.veilgremlin/`.** A
  cloned repo committing a permissive policy could disable the shield; a stray
  `~/.veilgremlin` captures every repo below it. Same trust model as committed git
  hooks/direnv, but for a *privacy control* it deserves better: **T11 follow-up** (e.g.
  refuse or warn on a discovered-not-created state dir; policy signature verification is
  already stubbed for Phase 2).
- **F4 (High) — demask authorisation is attribution, not authentication.** `--actor`/
  `--role` are self-asserted; `Destination` is a label, not a channel; and the wrapped
  agent itself can run `vg demask` (or read pack files' plaintext mapping refs) via its
  Bash tool. Phase 1 is a single-user local tool and the gate is honest attribution +
  audit, not an enforcement boundary — but the agent-can-demask hole is real and goes to
  **T11** (candidate: hooks refuse to spawn `vg demask` from inside a wrapped session /
  packs get restrictive perms + the vault key never enters the wrapped env).
- **F5 (High, remainder) — packs accumulate masked text plaintext, unbounded.** Gitignore
  mitigates exfil-via-commit; TTL/purge (`vg pack purge`) deferred to **T10/T11**.
- **F14 (Med, residual):** a pack-save failure still delivers the transform with only a
  stderr warning (debug log under v1.3); losing reversibility beats blocking the
  session's whole tool call. Accepted.
- **F16 (Low):** clap argument errors exit 2 → under v1.3 that now reads as a *block* —
  fail-closed aliasing, acceptable (was previously "transformed by empty string").
- **F18 (Low, partial):** a Bash `echo X > .env` carries no `file_path`, so artefact
  Block is bypassed (entity detection still applies) — inherent to hint-based artefact
  classification, **T10 eval** should measure it; the incoherent PostToolUse
  tool_input-fallback the finding also flagged was removed by the v1.3 rework (response
  only); masked-JSON splice damage is now fail-closed (see keystone fix); dead
  `by_language: dotenv` config noted for T10.

**Validation after round 1:** full workspace green — build, `clippy -D warnings`, `fmt`,
**217 tests / 28 binaries / 0 failures** (new: 3 hook-protocol CLI tests, drift +
transform-shape unit tests, boundary regression test). Round 2 (Codex cross-model, per
the established two-round pattern) pending explicit go-ahead.

## 2026-07-18 — T09 doubt-pass round 2 (Codex, cross-model): the fail-open hole *around* the round-1 fix

**Context.** Per the established two-round pattern, `codex exec --sandbox read-only`
(codex-cli 0.133.0) reviewed the post-round-1 diff (code + tests only, 2,783 lines;
author docs deliberately excluded per the doubt-driven-development skill), with the
CONTRACT section now encoding the *real* platform hook semantics. Verdict: 3 High /
3 Med / 1 Low. Reconciliation:

- **High 1 — VALID, FIXED (the round's real catch):** round 1 made every path *inside*
  `run_hook` fail closed, but an error that bubbled OUT of the hook command — state-dir
  resolution, `Engine::open` on a malformed policy / unwritable dir / failed keychain —
  hit `main()`'s generic handler and exited **1**, the non-blocking code: raw content
  would continue. Fourth instance this project of a fix leaving its own seam. `main()`
  now exits 2 for ANY error on the hook path; regression test added
  (`hook_fails_closed_when_the_engine_cannot_open`).
- **High 2 — valid TRADE-OFF, already documented:** an exact look-alike collision (raw
  text literally containing `EMAIL_001` while the pack mints `EMAIL_001`) is still
  substituted at both sites. This is the inherent in-band residual the `rehydrate` doc
  comment records (the reviewer could not see it — author docs were excluded); boundary
  checks fix the *substring* class, not the *exact-collision* class, which cannot be
  fixed at demask time (same bytes). Real fix would be collision-avoiding minting at
  mask time (skip an ordinal whose display already occurs in the raw text) — queued as a
  T10/T11 candidate, not done here.
- **High 3 — CONTRACT MISREAD (mine):** "MaskedPack must never contain a raw detected
  value" — the invariant as frozen applies to values whose policy class requires
  masking/redaction; an entity a policy explicitly sets to `pass` passes by *policy
  decision*. The compressed CONTRACT line fed to the reviewer over-claimed. Noted for
  future CONTRACT extracts; no code change.
- **Med 1 — VALID, FIXED:** the hard-deny gate consulted the policy engine before
  deciding (the `version()` fetch), and `vg demask` opened the whole engine before
  `rehydrate` could refuse — so "refused regardless of whether the vault is even
  reachable" was only behaviourally true (an open failure denied by erroring). Now: the
  version fetch happens only inside the post-decision audit write, `Destination::
  is_hard_deny` is public, and the CLI refuses hard-deny destinations **before**
  `Engine::open`.
- **Med 2 — VALID, FIXED:** `masked_payload` accepted any re-parse; a finding that
  rewrote an object *key* (or spliced structure) produced a schema-changed
  `updatedInput`. New `same_shape` guard: masked JSON must differ from the original only
  in string values (same nesting, same keys, same array lengths, identical non-string
  scalars) — anything else blocks.
- **Med 3 — VALID, FIXED (refinement):** partial-restore detection now compares
  boundary-token *counts* (pack text vs restored text) instead of mere presence, so a
  restored secret that legitimately contains placeholder-shaped text no longer
  false-fails a successful demask.
- **Low 1 — VALID, FIXED:** `lib.rs` crate docs still described the inverted v1
  protocol; brought in line with v1.3.

**STOP (named):** two full adversarial cycles complete (Fable fresh-context, then Codex
cross-model against the corrected contract). Round 2's only new High was a seam of the
round-1 fix and is closed with a test; every remaining known issue is a documented
trade-off with a T10/T11 owner. Next scrutiny is the human tollgate + the T11 review,
which is cycle 3 by a different reviewer class. **Validation:** full workspace green —
`clippy -D warnings`, `fmt`, **218 tests / 28 binaries / 0 failures**.

### Round-2 addendum (2026-07-18, caught by the demo-plan critique)

The round-2 "hard-deny before `Engine::open`" fix in `vg demask` over-corrected: the
pre-open early return also skipped `rehydrate`, silently **un-auditing** the one denial
the command can produce (the fresh-context review of the dogfood demo plan caught it by
noticing the plan's "denial appears in `vg audit`" step had become unsatisfiable).
Corrected to: engine opens → the denial flows through `rehydrate` and is audited, as
before; engine *cannot* open and the destination is hard-deny → still DENIED (stderr
says "denial unaudited"), never an error. Both properties now hold at once. CLI suite
re-verified green.

## 2026-07-18 — T10: eval harness (`vg-bench`) wired; contract v1.4; the Go/No-Go gate says NO-GO — and that is the deliverable working

**Context.** T10 dispatched under Opus from clean main (17b27d5, post spec-expansion PR
#24). The dispatch died with `API Error: Connection closed mid-response` — the same
failure mode #4 as T09 — but left ~1,300 lines of `vg-bench` (corpus loader, harness,
report, renderer, eval bench), the `vg bench` CLI subcommand (Go/exit-0, NoGo-or-
Incomplete/exit-1), a seeded 11-sample labelled corpus, and a properly documented
contract change. Rescued in place per the T02/T09 precedent; rescue delta was small:
`cargo fmt` (never ran), one `assert_eq!(…, true)` clippy lint, wiring the dead
`DetectorFp::rate` method into the renderer, and this documentation layer.

**Contract v1.4 (via protocol, Opus-authored):** `benchmark(corpus, ctx, policy)` — the
frozen signature had no way to reach detectors/parsers, the same gap and same sanctioned
fix as `mask` at v1.1. `Metrics` unchanged. interface-contracts.md amended.

**The result that matters — the harness's first verdict is NO-GO, honestly:**
- **false-positive-rate 16.7% vs the <3% gate.** The banked Wave B measurement finally
  has numbers: entropy 13.3% FP, **phone 40% FP** (2 FP / 5 findings). The 2026-07-16
  "hybrid: detector patch now, T10 stays the gate" decision is now quantified — the
  patch was not enough, and T10 is doing exactly the gating it was kept for.
- **placeholder-consistency 66.7% (8/12) vs ≥99%.**
- **Display-collision incidence 1/3 samples corrupted** (mask→demask round-trip) — the
  T09 doubt-round residual is real on realistic slices; report recommends
  collision-avoiding minting at intern time as a T11 decision, now with data.
- Passing: zero-raw-PII 11/11 (the §1 invariant property test), secret recall 5/5, PII
  recall 15/15, cold-hook e2e p95 22.44 ms (< 50 ms gate; validates the runbook's "tens
  of ms"), in-process detect p95 ~12 ms.
- Dead-config detection confirmed `artefacts.by_language [dotenv]` unreachable with an
  argued wiring constraint (classify-before-parse is mandatory), fix-or-drop routed to
  T11; dotenv-without-hint residual quantified (1 value only an artefact Block would
  catch).

The acceptance criterion was "thresholds evaluated to an explicit verdict", not "verdict
must be Go". A green harness reporting red product numbers is the tool working.

**Validation:** build, `clippy -D warnings`, `fmt --check`, tests — **221 / 0 failures**
in the worktree; `vg bench --no-hook` exits 1 on NO-GO as specified; report prints
refs/counts only (no raw corpus values observed in output).

## 2026-07-19 — T10 doubt-pass round 1 (Fable, fresh context): the NO-GO was right for the wrong reasons

**Verdict: 4 High / 7 Med / 6 Low**, measurement-integrity focused; the reviewer compiled
and ran the harness itself. Headline: one failing gate was honest (FP rate), the other
was fabricated by the harness's own probe; two passing gates were weaker than they looked.

**Fixed (re-verified against the code, then against a live run):**
- **H1** — the placeholder-consistency probe joined values with `|`, which is legal RFC-5322
  atext: the email detector matched *through* the separator, split the probe into two
  different raw values, and manufactured the 66.7% "instability". Probe now uses a newline;
  the gate reads **100% (12/12)**. The corpus will always contain emails — this would have
  been a permanent false NO-GO.
- **H2** — `measure_cold_hook` never checked the spawned hook succeeded; a future arg
  rename would yield ~1 ms usage-error timings and a glowing false p95. Now requires
  exit 0 + a masked `updatedInput` transform per invocation, else the measurement errors.
- **H3** — zero-raw-PII now runs the mandated
  `conformance::assert_masked_pack_excludes_raw_values` (covers `policy_version` and every
  `bindings[].display`, not just `text`) under a silenced panic hook so a violation can
  never print the raw value. Residual (documented): both checks are full-value
  containment; a partially-masked value's remainder is not caught — noted for T11.
- **H4/M4** — new structural-guards measurement + gate: the artefact-block sample now
  asserts `blocked_artefacts > 0` (previously it passed every gate vacuously even if
  `classify_artefact` died), and the json-payload slice's "masked output still parses as
  JSON" is measured instead of asserted. 2/2 PASS live.
- **M5** — dead-branch check relabelled as a STATIC check of the shipped constant with a
  retire-at-T11 note (it is a canned claim, not pipeline introspection).
- **M6/L5** — display-collision slice: irreversibly-redacted content now rejected at
  measurement time (round-trip infidelity is only a collision signal on reversible-only
  samples), each result records whether a decoy was actually minted, and the slice errors
  if NO decoy matches a minted display (mint-format drift would otherwise read as a false
  "clean" forever).
- **M7 (partial)** — the documented 25 ms in-process budget is now a real gate
  (`in-process-detect-p95`, always measurable, 6.9 ms PASS); `--no-hook` runs get latency
  gating instead of none.
- **L1** — `--hook-samples 0` is rejected instead of silently running once.
- **L2** — `spans_overlap` made `pub` in vg-core (additive, non-contract); the harness's
  private duplicate deleted — gated and banked scorers can no longer drift.
- **L4** — `Metrics.p95_latency_us` is now ALWAYS the in-process figure; the cold-hook e2e
  p95 lives in its own struct and gate. A frozen field no longer changes meaning with a
  CLI flag.

**Accepted trade-offs (documented, T11-routed):** M1 (per-detector FP denominators are
corpus-composition-sensitive; needs benign-slice-only denominators + a bigger corpus),
M2 (small-N gate resolution — the <3% FP gate needs ≥~34 benign findings to be
distinguishable; rendered as a caveat line in the report), M3 (typed vs untyped FP
definitions coexist; now stated in the report caveat rather than silently disagreeing),
L3 (transitive error-Display redaction assumption), L6 (repeated-value label inflation —
unguarded corpus-author footgun, noted in corpus README territory for T11).

**Post-fix state:** verdict still **NO-GO** — now for exactly one honest reason: overall
FP 16.7% (entropy on a commit SHA, phone on ISBN/zip — real product false positives).
Full run with cold hook: hot-path 14.9 ms PASS. 221 tests / 0 failures; clippy
`-D warnings` + fmt clean.

## 2026-07-19 — T10 doubt-pass round 2 (Codex, cross-model): three vacuous-pass holes in the round-1 fixes

**Verdict: 5 High / 3 Med / 1 Low.** Fourth consecutive review cycle in which fixes hid
fresh bugs only a cold pass caught. Reconciliation:

- **H (FP dilution) — FIXED:** per-detector FP rates were corpus-wide and dilutable by
  adding true positives elsewhere. `DetectorFp` now also carries `benign_slice_fp` — FPs
  on the benign-lookalike slice only, an un-dilutable numerator (any finding there is an
  FP by construction) — rendered beside the rate. Live: entropy 1, phone 2.
- **H (empty collision slice) — FIXED:** an empty `display-collision` slice now errors
  ("corpus lost its collision samples") instead of printing a vacuous `0 of 0`.
- **H (redactions inflating consistency) — FIXED:** binding-less probe values (irreversible
  classes collapsing to identical `[REDACTED:*]` markers) no longer count toward
  placeholder stability; stability additionally requires the probe halves to BE a display
  the pack minted. Gate now honestly 10/10 (was 12/12 with two vacuous entries).
- **H (substring transform check) — FIXED:** cold-hook validity now PARSES the stdout
  JSON, requires `hookSpecificOutput.updatedInput`, and asserts the raw payload value is
  absent from it — a regression emitting well-shaped-but-unmasked JSON is rejected.
- **H (one-legged structural gate) — FIXED:** the gate requires BOTH mechanisms present
  (artefact-block-fires AND masked-json-still-parses), not "all present checks pass".
- **M (recall on raw scan) — TRADE-OFF, documented:** recall is measured pre-overlap-
  resolution; a typed finding dropped by resolution still masks its bytes, so value-level
  protection is covered by the zero-raw-PII gate — typed recall is deliberately the
  detector-level number. Revisit if resolution semantics change.
- **M (in-process gate times scan only) — FIXED (label):** criterion renamed to
  "scan, in-process"; the mask/intern path is covered by the cold-hook e2e gate.
- **M (zero-raw filtered to protected types) — NOISE with a note:** a default-policy
  regression to `Pass` would indeed skip that value here, but the same regression fails
  the recall gates (`caught` requires `is_protected`), so the report still goes NO-GO —
  defence in depth, not a gap. Noted rather than changed.
- **L (example.co.uk) — FIXED:** not RFC-2606; corpus value replaced with
  `a.smith@support.example.org`.

**STOP (named):** two full adversarial cycles (Fable fresh-context, Codex cross-model)
plus reconciliation; round 2's Highs were all seams of round-1 fixes and are closed;
remaining items are documented trade-offs with T11 owners. Cycle 3 is the human tollgate
+ T11 review. **Post-fix state:** verdict NO-GO for exactly one honest reason (FP rate
16.7%: entropy on a commit SHA, phone on ISBN/zip — T11's inheritance, now with
un-dilutable numerators); all other gates PASS incl. cold-hook e2e 17.0 ms. **221 tests /
0 failures; clippy `-D warnings` + fmt clean.**

## 2026-07-19 — T11 hardening: the cross-model final-review findings that were cheap and pre-sign-off

Both T11 reviews (Fable, then Codex cross-model) returned **GO for v1 local-dogfood
sign-off** and converged on the backlog triage. This change lands the hardening findings
that were clean to fix before sign-off, so the tree the human signs is clean. Fixed:

- **Hard-deny denial is now panic-safe (Codex Med).** `rehydrate`'s hard-deny gate decides
  with zero policy/vault *evaluation*, but records the denial via the audit sink +
  `engine.version()`. A broken/custom sink or engine that *panicked* could previously stop
  the denial from reaching the caller — a fail-open-shaped regression on the strictest
  gate. The recording is now wrapped in `catch_unwind` under a silenced hook, so the denial
  always returns. (`api.rs write_demask_decision`.)
- **Corrupt-pack errors no longer echo untrusted field contents (Codex Low).**
  `PackError::BadMappingRef`/`BadNamespace` printed the raw field back to stderr — a hostile
  pack could carry a real value there, and this is a redaction tool. Now withholds the
  value, matching `vg audit`'s side-channel discipline. (`pack.rs`.)
- **`policy.version` is validated at load (Codex Low).** It is config-tainted and copied
  into every `MaskedPack` and blocked-hook stderr, so a version accidentally set to a real
  identifier would be persisted/echoed. Now restricted to <=64 chars of `[A-Za-z0-9._-]`,
  so it can never carry free text. (`config.rs`.)
- **F3 state-dir discovery now warns (Fable's highest-priority residual).** `StatePaths::
  resolve` returns a `Provenance` (Pinned / Discovered / CreatedInCwd); a *discovered*
  ancestor state dir (the F3 untrusted-input surface) emits a one-line stderr NOTE that its
  policy governs masking and should be pinned if unfamiliar. (`state.rs`, `main.rs`.)
- **Dead `by_language: dotenv` policy branch dropped** (both reviews + the T10 report's own
  note). `.env` handling works via the extension rule; `language_id` is unwireable under
  classify-before-parse. Removed from `DEFAULT_GLOBAL_POLICY`; the bench's dead-branch
  measurement now correctly reports "none — every policy branch is reachable."

**Deferred with reasons (already triaged post-sign-off by BOTH reviews — not skipped):**
- **Collision-avoiding minting** (display-collision 1/3): a genuine design tension, not a
  hardening fix — skipping an ordinal whose display occurs in the raw buffer would make a
  value's placeholder depend on buffer content, breaking the cross-artefact *stability*
  invariant. Needs a real design (reserved-display set or a non-colliding display format).
  First post-sign-off product fix.
- **Vault TTL / `vg vault purge` (NEW-2, F5):** a feature, not a fix — TTL is crate-capable
  but product-unreachable. Queue with pack retention.
- **`apply_key` key-hex zeroize (NEW-4):** cosmetic (the contract already documents zeroize
  as cosmetic at these exit points) and a proper fix wants the `zeroize` crate — a
  protected-Cargo change. Documented, not half-scrubbed.

**Validation:** build, `clippy -D warnings`, `fmt`, **221 tests / 0 failures**; F3 warning
smoke-verified; `vg bench` still runs (verdict unchanged: NO-GO on FP rate).

## 2026-07-19 — T11 human sign-off: NO-GO for v1 shipping (the UX gate did its job)

The human UX-invisibility session — the T11 acceptance criterion only a human can
satisfy — returned **NO-GO. VeilGremlin cannot ship as-is.** Recorded verbatim from the
operator's verdict during a live wrapped session (`vg run -- claude` on the demo sandbox).

### What the session VALIDATED (the build is not wasted)
The mask/demask mechanism works end-to-end: reading a fixture through the wrapped session
masked emails/IBANs to stable placeholders the model never saw, redacted the secret
irreversibly, and `vg demask` restored values locally; the hard-deny gate refused a remote
destination. The cryptographic vault, the detectors, the pipeline, and the **tool-path**
(`PreToolUse`/`PostToolUse`) masking all work and are invisible on the tool path.

### Why NO-GO — the hook adapter does not deliver the product's promise
*Invisible governance; PII never leaves the machine.* It doesn't, via hooks alone:

1. **The prompt/context path is not invisible.** Claude Code's platform lets a hook only
   *block* or *pass* a prompt — never rewrite it — so typed PII forces a block-and-resubmit
   that breaks "invisible" and pushes sanitisation back onto the user. And the hooks do not
   sit at the model **egress**: the full assembled request (system prompt, conversation
   history, MCP context) is not guaranteed masked, so the core "nothing leaves the machine"
   claim is not met by hooks at all.
2. **Keychain UX is poor.** Process-per-hook means repeated macOS keychain/login prompts.

Neither is a tweak. Both are resolved by the architecture the contract already deferred: a
**local masking proxy** that intercepts the actual request to the model endpoint, masks the
entire payload via the vault, and **demasks the response** — invisible to the user — with a
long-lived daemon holding the vault key once (which also removes the keychain friction).
Without it, VeilGremlin *proves the mechanism* but does not *solve* the governance / risk /
privacy problem it exists for.

### The gate worked as designed
This is human-led / agent-assisted functioning correctly: the factory built and validated
the hard parts under multi-model doubt review, and the human sign-off gate caught — **before
ship** — that the integration does not deliver the value. Catching this here, not in
production, is the entire point of the gate.

### Reprioritised roadmap (supersedes the T10/T11 backlog order)
1. **Local masking proxy** (egress interception + response demasking) + the daemon that
   holds the vault key. THE next milestone — the thing that makes the product real.
2. FP-rate precision + corpus growth (the eval NO-GO).
3. Collision-avoiding minting; vault TTL/purge; the rest of the T11 hardening backlog.

**Status:** v1 (hook adapter) = **validated proof-of-mechanism, NOT shippable.** Next
milestone: the masking proxy.

## 2026-07-21 - Considered an entity-relationship graph for FP reduction; rejected for the current NO-GO, redirected to targeted detector fixes

**Context:** a parallel architecture-review session in the `hekton` factory repo (working on
the masking-proxy pivot's next steps) proposed a graph-db-backed entity-relationship layer to
reduce false positives via co-occurrence signal (e.g. "this token clusters with known `PERSON`
entities elsewhere, so it's more likely a real name"). Before scoping that as a plan, checked
it against this repo's actual, current T10 data rather than assuming the FP class it targets.

**Finding:** it doesn't target the current NO-GO driver. Post-fix (T10 doubt-pass round 2,
2026-07-19), the un-dilutable benign-slice numerator is **entropy: 1 (a commit SHA), phone: 2
(ISBN/zip)** — format-collision (a string that matches a detector's pattern but is something
else entirely), not entity ambiguity. There is also no dedicated person/name detector in
`vg-detectors/src/` yet (`email.rs`, `entropy.rs`, `iban_sortcode.rs`, `ip.rs`, `phone.rs`
only) — `EntityType::Person` exists in `vg-core`'s type system but nothing currently produces
it, so a graph built to disambiguate person-name co-occurrence would sit on top of a
capability that isn't built, aimed at findings that aren't the ones failing the gate.

**Decision:** do not build the entity-relationship graph as the T10 close-out. Redirect to
targeted, deterministic detector fixes — same shape as the 2026-07-16 entropy/phone hybrid
patch that closed the prior dominant FP class: SHA-shape exclusion in `EntropyDetector`,
ISBN-checksum + zip-shape exclusion in `PhoneDetector`. Recorded as the concrete next action
(`docs/next-actions.md`); RISK-0004 updated in `docs/risks.md`.

**The graph idea is not discarded, only deferred and honestly re-scoped.** It may earn its
place later if/when a person/name detector is built and person-name ambiguity becomes a real
measured FP class — at that point it would be a legitimate, separate `vg-core`
detection-stage enhancement (co-occurrence signal feeding, never solely deciding, a
mask/no-mask call — a promote-only discipline mirroring the masking-proxy plan's own H1 rule
that a cache/signal must never be trusted as a substitute for a completed detection pass).
Documented as a speculative, unscheduled companion plan in the `hekton` factory repo
(`docs/plans/veilgremlin-entity-graph-plan-v1.md`), explicitly labelled as NOT the current
precision fix.

**Why this matters beyond this one call:** the graph idea was plausible on its face, and the
human had already agreed to scope it before this grounding check ran — a reminder that
"grounded against the merged repo" (this project's own stated authoring discipline for plans,
see the masking-proxy-plan's author line) has to mean actually reading the current data, not
just the shape of a plausible-sounding mechanism.

## 2026-07-21 - T10 precision fix implemented and verified GO locally (branch `agent/claude/t10-fp-detector-fixes`, PENDING REVIEW/MERGE)

**Context:** direct follow-on to the redirect decision above. Implemented the targeted fix
`docs/next-actions.md` pointed at, in `crates/vg-detectors/src/entropy.rs` and `phone.rs`.

**`EntropyDetector` — git-SHA exclusion.** New `looks_like_git_sha`: excludes a token from
`Secret` classification only when it is BOTH (a) 7-64 lowercase hex characters (covers
abbreviated/full SHA-1 and SHA-256 object IDs) AND (b) immediately preceded (after skipping
`:`/`=`/whitespace) by a case-insensitive context word (`commit`, `sha`, `sha1`, `sha256`,
`rev`, `hash`). Deliberately narrow on both axes — length/charset alone would risk silently
missing real secrets that happen to be lowercase hex (a real false-negative regression, worse
than the FP being fixed); context alone would do nothing for a non-hex token. Accepted,
named residual: a real secret that is coincidentally hex-shaped AND immediately preceded by
one of these words would still be missed — same posture as this file's other documented
residuals.

**`PhoneDetector` — ISBN-13/10 checksum + ZIP+4 shape exclusion.** The phone regex's own
match span turned out NOT to be the whole ISBN — its `{2,4}`-digit-group cap splits
`978-3-16-148410-0` into the inner fragment `3-16-148410`, starting mid-number (confirmed by
directly instrumenting the detector against the corpus content, not assumed). So the fix
first re-expands the match to the full contiguous digit/hyphen run in the buffer
(`expand_to_digit_hyphen_run`), then validates that run as an ISBN-13 (13 digits, `978`/`979`
prefix, alternating-weight mod-10 checksum) or ISBN-10 (10 digits, weighted mod-11 checksum,
digit-only — the `X`-check-digit form doesn't match this detector's digit-only pattern in the
first place, an accepted, named residual). Checksum validation, not a shape guess, so a real
13-digit hyphenated phone number would only be excluded if it also coincidentally satisfies
the ISBN checksum (~1-in-5000 with the prefix requirement) — verified with a dedicated
"wrong checksum still flags" test. ZIP+4 (`DDDDD-DDDD`, 5-then-4 digit grouping) is a
separate, structural (not checksum) exclusion — real phone numbers essentially never group
5-then-4.

**A third residual, found by re-running `vg bench` after the above two, not part of the
original ask.** `entropy` still showed 1 FP: `LICENSE_KEY=ACME-2026-DEMO-KEY` in the
`dotenv-shaped-no-path-hint` corpus sample — pre-existing, unrelated to the SHA/ISBN fixes,
newly visible as the sole remaining entropy FP once the commit-SHA one closed. Confirmed
via the corpus manifest that this value is deliberately listed under that sample's
`residual_secrets` (a KNOWN, accepted entity-detection miss the sample's own description
says "only the artefact Block would have caught") — so a fix here is squarely in scope, not
a new promise. Root cause: `is_structured_identifier`'s split set (`/`, `.`, `_`, `-`) didn't
include `=`, so a whole `KEY=value` assignment where BOTH sides are word/numeric-shaped
scored as one entropy blob across the `=` boundary. Fix: add `=` to the split set. Verified
this doesn't create a new residual class — a value segment mixing letters and digits (the
vast majority of real secret shapes) still fails the all-alpha/all-digit check and is
unaffected; only a segment that is ALREADY purely alphabetic or short-numeric on its own
(already excludable before this fix, just not across an `=` boundary) is newly reachable.

**Verified, not asserted:**
- `cargo test --workspace`: all green (was 221 tests pre-session; grew with the new
  regression tests for each fix — commit-SHA-with-context / hex-with-no-context /
  non-hex-after-commit / ISBN-13 valid+invalid-checksum / ISBN-10 valid+invalid-checksum /
  ZIP+4 / LICENSE_KEY / real-secret-after-`=`).
- `cargo clippy --all-targets -- -D warnings`: clean (one `manual_is_multiple_of` lint fixed
  along the way).
- `cargo fmt --check`: clean.
- `vg bench` (full run, hook latency included): **verdict GO.** false-positive-rate **0.0%**
  (gate `<3.0%`, was 16.7% at T10 sign-off); all other gates unchanged/PASS (zero-raw-PII,
  secret-recall 100%, pii-recall 100%, placeholder-consistency 100%, in-process-detect-p95
  13.4 ms, structural checks 2/2, hot-path-p95 15.0 ms). Detector-level FP: entropy 0/13,
  phone 0/3, both 0% including the benign-lookalike slice.

**What this does NOT mean.** The FP-rate gate (T10 dependency #3 on the reprioritised
roadmap) is closed, but nothing else changed: the masking proxy (#1, still not built) and
the display-collision corruption (1 of 3 collision samples still corrupted, confirmed again
in this same `vg bench` run) are unrelated, still-open items. This is not a ship decision.

**Not merged.** Landed on branch `agent/claude/t10-fp-detector-fixes`, PR pending. This repo
has repeatedly doubt-passed precision changes before merge (the 2026-07-15 and 2026-07-16
entropy/phone rounds, the T10 doubt-pass rounds 1-2) precisely because a privacy detector's
correctness has asymmetric stakes — a bad "fix" that quietly narrows detection is worse than
the false positive it removes. This change should get the same treatment before it lands,
not skip it because the harness result looks good.

## 2026-07-22 - Doubt-driven-development round 1 (single-model + Codex cross-model) on the T10 fix: 8 findings, all closed

**The instinct to skip a doubt pass because the harness result "looked clean" was checked, not
acted on** — the previous entry above already named this risk explicitly; this entry is that
check actually happening. Ran the full doubt-driven-development cycle: a fresh-context
single-model adversarial review (ARTIFACT + CONTRACT only, no reasoning/decisions.md narrative
passed in), then, on human request, a Codex cross-model second opinion via `codex exec
--sandbox read-only`, prompt piped via stdin (never shell-interpolated). Both reviewed the same
artifact independently and were reconciled together, not sequentially.

**Two Critical findings, confirmed with concrete counterexamples, both closed:**
- `is_structured_identifier`'s `=` split excluded a token whenever the VALUE side was a single
  alphabetic run, even a genuinely high-entropy one (`TOKEN=zQvLmXpRwTuYbNdKfJhCsEoAiPlMnQr`,
  4.71 bits/byte, was silently passing). **Fix:** the value must independently re-decompose
  into >=2 further segments (renamed the original logic to `is_structured_segments`, reused for
  both the whole-token check and the value-side check).
- `looks_like_isbn10` had no prefix to narrow its mod-11 checksum, so ordinary NANP-shaped phone
  numbers collide roughly 1-in-11 (Codex's concrete counterexample: `415-234-0002` passes the
  checksum outright with a phone marker present and no ISBN shape). Codex independently escalated
  the ZIP+4 shape-only exclusion (originally accepted here as a trade-off) to Critical for the
  same reason — a bare `DDDDD-DDDD` shape can't rule out some non-NANP phone formatting. **Fix:**
  both now additionally require an explicit text marker ("isbn" / "zip"/"postal") within a short
  lookback window, mirroring the git-SHA exclusion's context-gated posture. ISBN-13 stays
  checksum-only (its 978/979 prefix already narrows collisions to roughly 1-in-5000).

**High findings, closed:** `sha1`/`sha256` context markers were dead code (the backward
word-scan was alphabetic-only, so it stopped at the first digit and could never extract either
marker — fixed to alphanumeric); `hash` was too generic, matching as the tail of common compound
identifiers holding real sensitive values (`password_hash:`, `file_hash:` — removed from the
marker list entirely); `commit=<sha>` never worked as documented because `=` is a token byte, so
the entropy tokenizer never splits there in the first place, making the `=`-skip in the context
scan unreachable dead code (removed, documented as an accepted scope limit rather than claimed
to work).

**Medium finding, closed:** `expand_to_digit_hyphen_run` was unbounded — O(n) per match with
O(n) possible matches on an adversarial digit/hyphen-heavy buffer (O(n^2) risk on the 25ms p95
hot path) and could merge two adjacent real values across a match boundary. **Fix:** bounded to
`MAX_EXPAND = 24` bytes each direction (generous for any realistic 13-digit ISBN, narrow enough
to bound the cost).

**Every finding got a regression test reproducing the reviewer's own counterexample**, not just
a narrative fix — `still_flags_a_bare_alphabetic_secret_after_an_equals_sign`,
`still_flags_an_isbn10_checksum_collision_with_no_label` (using Codex's exact `415-234-0002`),
`still_flags_a_5_4_grouped_number_with_no_zip_or_postal_label`,
`sha1_and_sha256_context_words_now_actually_fire`,
`still_flags_a_hex_secret_after_the_removed_hash_marker`. `cargo test --workspace`,
`clippy -D warnings`, `fmt --check` all clean after every fix; `vg bench` re-run and reconfirmed
**GO** (FP rate still 0.0%) after the full round.

## 2026-07-22 - Doubt-driven-development round 2 (single-model, targeted at round 1's own fix code): 6 more findings, all closed

**Not treated as done after round 1** — the new code round 1 introduced (the marker-window
search, the bounded expansion, the restructured `=`-split logic) had not itself been doubted
yet, so it was reviewed a second time, scoped narrowly to just that new code (not a full
re-review of the whole file).

**Findings, all closed:**
- `is_structured_identifier`'s `=` fix only checked the VALUE side — a real secret sitting on
  the KEY side with a benign-looking value (`<32-byte secret>=run-2026-01-01`) would have been
  silently excluded, symmetric to the round-1 finding it was fixing. **Fix:** the key must also
  be no longer than `MAX_ASSIGNMENT_KEY_LEN` (24 bytes) — real identifier names are short by
  convention; a secret long enough to matter is not.
- `preceded_by_marker_within` was a raw substring search — `zip` matched inside `gzip`/`unzip`,
  which would wrongly exclude a real number sitting near either word. **Fix:** added
  word-boundary checks (byte before/after the match must be absent or non-alphanumeric).
  **Accepted, named residual:** "zip" as its own standalone word, used in an unrelated sense
  ("extract the zip" near an unrelated ticket number), is not resolved by this — the marker
  proves the word is present, not that it's being used in the postal-code sense.
- `MAX_EXPAND` bounds cost but only shrinks, doesn't eliminate, cross-match merging of two
  truly byte-adjacent real values into one coincidental ISBN-13 pass (ISBN-13 requires no text
  marker). **Not fixed further** — closing it fully would mean bounding expansion by the
  regex's own group structure rather than raw byte distance, a larger change; documented as an
  accepted, named residual instead, narrower than the pre-MAX_EXPAND unbounded version.
- `expand_to_digit_hyphen_run` didn't match `.`, asymmetric with the phone regex's own `[-. ]`
  separator class (under-recognized dot-separated ISBNs). Cheap fix, no leak risk added.
- `windows(0)` would panic on an empty marker — unreachable today (only static non-empty
  literals are passed) but guarded defensively anyway.

Regression tests added for each: `still_flags_a_secret_on_the_key_side_of_an_equals_sign`,
`still_flags_a_5_4_grouped_number_near_gzip_not_the_standalone_word_zip`,
`never_panics_or_hangs_on_a_long_digit_hyphen_run` (a 10,000+ byte adversarial digit/hyphen
buffer, proving `MAX_EXPAND` bounds cost rather than asserting a specific finding count).
`cargo test --workspace`, `clippy -D warnings`, `fmt --check` all clean; `vg bench` re-run and
reconfirmed **GO** (FP rate still 0.0%) after this round too.

**Where this stood after round 2:** human was asked whether to stop, run Codex on round 2's own
fixes, or merge as-is — chose the Codex round. That decision paid for itself immediately.

## 2026-07-22 - Doubt-driven-development round 3 (Codex cross-model, targeted at round 2's own fix code): 8 more findings, including one that undermined round 2's own fix

**Targeted, not a full re-review:** Codex reviewed only the new code round 2 introduced
(`MAX_ASSIGNMENT_KEY_LEN` in `entropy.rs`; `preceded_by_marker_within`'s word-boundary logic and
`expand_to_digit_hyphen_run`'s `.`-matching in `phone.rs`).

**The sharpest finding: round 2's own fix for the key-side gap was itself insufficient.**
`MAX_ASSIGNMENT_KEY_LEN = 24` was meant to stop a real secret from passing as the KEY side of a
`KEY=VALUE` assignment — but a flat length bound can't distinguish a secret from a name. A
realistic 20-24 byte high-entropy secret (`aB3dE5fG7hI9jK1lM2nP=run-2026-01-01`, right at
`DEFAULT_MIN_LENGTH`) still passed the cap while looking nothing like a real identifier — Codex
computed its entropy (4.53 bits/byte) to confirm it was a plausible real secret, not a contrived
edge case. **Fix:** replaced the length cap with the same rule already applied everywhere else in
this file — the KEY must independently satisfy `is_structured_segments` too, not just be short.
`LICENSE_KEY`/`API_KEY`/`AWS_SECRET_ACCESS_KEY` all decompose into >=2 word-like segments and
still pass; a bare high-entropy run has no internal delimiter and fails, by construction, not by
a threshold that has to be re-guessed. Accepted precision cost: a single-word key with no
delimiter (`TOKEN=<benign-value>`) no longer qualifies either — over-masking, not under-masking.

**Two more High findings, both closed:**
- The round-2 word-boundary fix for `preceded_by_marker_within` checked boundaries against the
  *truncated search-window slice*, not the real buffer — a marker sitting exactly at the
  window's start or end edge was treated as automatically boundary-OK regardless of what byte
  actually sat just outside the window. Concretely, `zip12345-6789` (marker glued directly onto
  the digits, zero separator) could still pass as if word-bounded. **Fix:** boundary bytes are
  now read from the full buffer at absolute indices, not the windowed slice.
- `.` was added to `expand_to_digit_hyphen_run` in round 2 to catch dot-separated ISBNs (a
  precision improvement), but Codex showed this meaningfully widened the ISBN-13 cross-match-merge
  residual round 2 had already named and accepted as narrow — dotted content (version strings,
  decimals, IP-like patterns) is far more common than hyphenated content, and ISBN-13 requires no
  text marker, so a real dotted phone-like value merging with adjacent digits into a valid ISBN-13
  checksum (`978.316.1484.100` collects the canonical valid ISBN-13 sequence) is realistic, not
  contrived. **Fix: reverted the `.` addition entirely.** The precision gain (recognizing a real
  but far less common formatting choice — ISO 2108 is predominantly hyphenated) wasn't worth
  widening a false-negative surface; dot-separated ISBNs remain a named, accepted residual.

**Two Medium findings, closed:** `_` was not treated as a word-forming character in the boundary
check, so `zip_code`/`customer_isbn` wrongly counted as containing the standalone marker word
(fixed: `_` now counts alongside alphanumerics); the long-digit-run performance test only proved
"does not panic," not that `MAX_EXPAND` actually bounds the walk (added a direct test on
`expand_to_digit_hyphen_run` itself asserting the exact bound).

**Every finding again got a regression test reproducing the reviewer's own counterexample:**
`still_flags_a_short_high_entropy_key_side_secret`, `ignores_a_multi_segment_key_and_value_assignment`,
`still_flags_a_number_with_a_marker_glued_directly_onto_it`,
`still_flags_numbers_near_compound_identifiers_containing_the_marker`,
`expand_to_digit_hyphen_run_is_bounded_by_max_expand`. `cargo test --workspace` (71
vg-detectors tests, up from 66), `clippy -D warnings`, `fmt --check` all clean; `vg bench`
re-run and reconfirmed **GO** (FP rate still 0.0%) after this round too.

**Where this stands:** three full doubt-driven-development rounds (round 1: single-model +
Codex cross-model; round 2: single-model, targeted; round 3: Codex cross-model, targeted) — 22
findings total, all closed, each with its own regression test. Round 3 is itself the concrete
answer to "is this worth another round" — it found a real bug in round 2's own fix, not noise,
which is exactly the STOP-condition test the doubt-driven-development skill names ("stop when
the next cycle returns only trivial findings"). This one didn't. Still landed on
`agent/claude/t10-fp-detector-fixes`, still **not merged** — human review is next; whether a
round 4 runs is the human's call, but three consecutive rounds each surfacing real, non-trivial
findings is itself informative about how much confidence a "vg bench says GO" result alone
should carry for this class of change.

## 2026-07-22 - Doubt-driven-development round 4 (single-model, targeted at round 3's own fix code): the STOP signal round

**Targeted, not a full re-review:** reviewed only the code round 3 changed (`is_structured_identifier`'s
both-sides-`is_structured_segments` check in `entropy.rs`; `preceded_by_marker_within`'s
absolute-buffer-position boundary logic and `expand_to_digit_hyphen_run`'s `.`-reversion in
`phone.rs`).

**This round's findings are qualitatively different from rounds 1-3 — the signal itself worth
recording, not just the findings:**

- **A real gap, but not a new one.** `is_structured_segments` checks character CLASS per
  segment, never whether a segment plausibly reads as a real word — so a secret with exactly
  ONE incidental delimiter landing precisely on a letter/digit type boundary
  (`AbCdEfGhIjKlMnOp-12345678`, 16 mixed-case letters + `-` + 8 digits, 4.64 bits/byte) still
  passes, on either side of `=` or as a bare token. This is not a new hole round 3 opened — it
  is the SAME residual this file already documented ("a real secret that happens to be a
  dictionary-word passphrase joined by delimiters... would also be excluded... indistinguishable
  from a real identifier without a dictionary/semantic check this detector doesn't have"),
  restated with a sharper example. **Not fixed:** closing it would mean real word-likelihood
  detection (e.g. rejecting per-letter-random case-switching) — a meaningfully bigger, riskier
  change than anything else in this file's history of narrow fixes, and out of scope for a
  detector deliberately not built as a dictionary/semantic checker. **What WAS fixed: the
  round-3 doc comment overclaimed** ("by construction, not a threshold that has to be guessed")
  beyond what the mechanism actually guarantees — corrected to name the residual honestly
  instead.
- **A latent, unreachable hardening gap, closed cheaply.** `preceded_by_marker_within` assumed
  `pos <= buf.len()` without asserting it; every current call site satisfies this, so it isn't
  live, but a function whose whole job is defending boundary conditions on adversarial input
  shouldn't rely on caller discipline for its own bounds. Added the guard.
- **A clean result on the `.`-reversion.** Confirmed, not assumed: traced every remaining branch
  in `phone.rs` and found no path that reintroduces dot-based merging. First genuinely clean
  sub-finding across four rounds.

**This is the STOP signal the doubt-driven-development skill names.** Rounds 1-3 each found
freely-fixable false-negative gaps — a cheap, targeted code change that closed a real leak
without meaningful cost. Round 4 found one already-accepted, already-named residual restated
more sharply (fixed the overclaiming comment, not the mechanism) and one defensive hardening
with no live exploit path. Diminishing returns, not zero returns — informative in itself.

`cargo test --workspace`, `clippy -D warnings`, `fmt --check` all clean; `vg bench` reconfirmed
**GO** (FP rate still 0.0%) after this round too. **Recommendation to the human: this is a
reasonable stop point** — 23 findings across four rounds, every freely-fixable false-negative
gap closed, remaining surface is a named, accepted, dictionary-check-shaped limit consistent
with this detector's stated design boundary. Still on `agent/claude/t10-fp-detector-fixes`,
still not merged; human review and merge decision are next.

## 2026-07-25 - Milestone M1: masking-proxy transport + routing skeleton

### Context

`~/hekton/docs/plans/veilgremlin-masking-proxy-plan-v1.md` (v3.1) is the design; both its
blocking spikes closed 2026-07-24 in the `~/hekton` factory repo, unblocking M1. `docs/next-actions.md`
already carried the masking proxy as item **#1 — nothing above it**. This session built the
plan's own §10.3 milestone 1: transport + routing skeleton, no real upstream, no real
credentials.

### Decision

Built `crates/vg-proxy` to the letter of §10.2/§10.3's M1 scope, and no further, with two
judgment calls the plan doesn't spell out explicitly:

1. **Module surface kept to exactly `route.rs` + `server.rs` + `error.rs`.** §10.2's full
   module list (`config.rs`, `daemon.rs`, `session.rs`, `schema/`, `mask_request.rs`, ...) is
   the crate's *eventual* shape across all milestones, not M1's. Stubbing those modules now
   with empty bodies would add surface area with no behavior to test against — deferred to the
   milestones that actually need them (M2 for `daemon.rs`/`session.rs`, M3 for `schema/` +
   `mask_request.rs`).
2. **`RouteVerdict` stays three-valued (`Mask`/`Pass`/`Block`) even though M1's own HTTP
   behavior only distinguishes two outcomes (matched vs. rejected).** The plan's route table
   in §5 step 2 is explicitly three-way, and M3 needs the `Mask`/`Pass` distinction to decide
   whether to run `vg_core::mask` at all — collapsing it to a boolean now would just require
   re-splitting it in M3 for no M1-scoped benefit.

Route table transcribed verbatim from §5 step 2 / §8.7, including the two scope corrections
the plan's v3.1 doubt pass made: "The Batch API" removed (never in Claude Code's real gateway
contract) and Bedrock Converse excluded (Claude Code never calls it) — both now enforced as
`Block`, not silently omitted.

### Consequences

- M1 is complete and independently testable per the plan's own milestone-granularity intent
  (§10.3: "scoped to be startable and finishable without the ones after it existing"). M2
  (daemon core) can start without anything in M1 changing.
- Zero egress risk by construction: `cargo tree -p vg-proxy` has no HTTP client dependency at
  all in this milestone, only a server. This is a stronger property than "the code doesn't
  currently call out" — there is nothing in the dependency graph capable of it yet.
- Branch `agent/claude/vg-proxy-m1-transport-routing` left open for human review before merge,
  per the git contract's "close branches deliberately" rule — not merged this session.

## 2026-07-25 - Doubt-driven-development round 1 on M1 (single-model + Codex cross-model)

### Context

Ran the `doubt-driven-development` skill against the M1 artifact (`crates/vg-proxy/src/{route,server,error}.rs`)
immediately after PR #38, per the user's request. Single-model adversarial review first, then a
Codex cross-model pass on the identical ARTIFACT/CONTRACT — offered per the skill's "never skip
the cross-model offer" rule, user chose to run it.

### Findings and disposition

Single-model pass: 8 findings. Codex pass: 8 findings, independently converging on the same
loopback-enforcement gap the single-model pass found (highest-confidence finding of the round —
two differently-built models flagging the identical gap from the identical prompt) and raising
several new ones. Reconciled against the artifact text and the plan's actual §5 step 2 wording
(precedence: contract misread > valid+actionable > valid trade-off > noise):

- **Fixed — accept-loop resilience.** `run()`'s connection loop used `accepted?`, propagating
  any single `TcpListener::accept()` `io::Error` (fd exhaustion, a transient ECONNRESET) out of
  the loop and killing the whole daemon. Now logs and continues, the conventional pattern for a
  long-lived server's accept loop.
- **Fixed — loopback binding enforced, not just documented.** Both reviewers independently
  flagged that `run()`'s doc comments assert "plain HTTP on loopback" but nothing checked
  `addr.ip().is_loopback()`. Added `ProxyError::NotLoopback` and a new `server::bind()` that
  refuses non-loopback addresses; `run()` now calls it. Split `run()` into `bind()` +
  `run_with_listener()` in the process — a deliberate, useful side effect, not scope creep: it's
  also what let the new integration test bind `127.0.0.1:0` and read the real port back via
  `TcpListener::local_addr()` instead of hardcoding a port.
- **Fixed — real wire-path test coverage.** Both reviewers noted `route_classification.rs` only
  ever called `route::classify` directly, never proving `server::handle`'s
  `req.uri().path_and_query()` extraction behaves the same way. Added
  `tests/server_smoke.rs`: real TCP connections against a real `bind`/`run_with_listener`
  instance for one case per verdict, hand-rolled HTTP/1.1 request bytes (no new production
  dependency — the client-side test code is a dev-dependency only, so `cargo tree`'s
  zero-egress-client claim for the shipped crate is unaffected).
- **Fixed — adversarial + regression test rows.** Added percent-encoded-slash and
  encoded-dot-segment Bedrock model-ID cases (both reviewers raised path-confusion concerns;
  confirmed and documented as intentional — matching happens on raw undecoded bytes, decode
  strictly happens later if ever, so these are correctly `Mask`, not a hole) and
  case-sensitivity/trailing-slash `Block` rows locking in today's fail-closed default against a
  future accidental normalization.
- **Fixed — dead `unwrap_or` fallback.** `request_target.split('?').next().unwrap_or(...)` is
  unreachable (`str::split` always yields ≥1 item); replaced with an explicit
  `split_once`-based match.
- **Fixed — bounded reflection.** Test-double response bodies echoed the caller's request-target
  unbounded; capped at 2048 chars.
- **Documented, not changed — Pass-route query-agnostic matching.** Both reviewers read the
  contract's two literal Pass-route examples (`GET /inference-profiles?type=SYSTEM_DEFINED`,
  `GET /v1/models?limit=1000`) as scoping "match on path only" to those exact queries. Re-reading
  §5 step 2: "match on path only, ignoring query string" is stated once, governing the whole
  classify step, not scoped to the Mask examples — and both Pass routes are non-context-carrying
  by design (Claude Code's own probes, not user content), so a query variant carries no
  additional masking risk. Classified as **noise** (reviewers lacked that framing), but since two
  independent models read it the same way, added an explicit doc comment on the `Pass` match arms
  so a future reader doesn't hit the same false alarm.
- **Documented, not changed — GET-with-body, absolute-form request-target authority dropped,
  Bedrock model-ID character class.** All three are real observations about future risk, not M1
  bugs: `handle()` never reads the request body for any verdict today (any milestone that starts
  forwarding `Pass` routes unchanged must not assume bodylessness); the plan's own design (§8.1)
  never derives the forwarding upstream from the client's request-target, so a silently-dropped
  absolute-form authority can't become a confused-deputy path unless that design changes; the
  plan calls the Bedrock model ID "opaque," not a specific grammar, so no character-class
  validation was added. All three are recorded as doc-comment invariants in `server.rs`/`route.rs`
  for whichever future milestone's own review should re-check them (M7/M8, real forwarding).
- **Accepted trade-off, not fixed — shutdown doesn't drain in-flight connections.** Real gap
  (spawned per-connection tasks are detached; `run_with_listener` returning `Ok(())` doesn't wait
  for them), but full graceful-shutdown lifecycle is `daemon.rs`'s job per §10.2's module split
  (M2, not M1) — documented in `run_with_listener`'s doc comment, not built early.

### Validation

`cargo test --workspace`: all green, 2 new tests in `vg-proxy` (server smoke test,
loopback-refusal test) plus the expanded table test, no regressions elsewhere. `cargo clippy
--workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
`scripts/verify-project.sh`: PASS.

## 2026-07-25 - Doubt-driven-development round 2 on M1 (single-model, targeted at round 1's own new code)

### Context

Per the repo's established doubt-pass pattern (each round targets the *previous* round's own
new code, not the whole file fresh — see the T10 FP-detector-fix rounds), ran a single-model
adversarial review against round 1's fix code specifically: the `bind()`/`run_with_listener()`
split, the `NotLoopback` error variant, the accept-loop fix, and the two new tests.

### Findings and disposition

- **Fixed (High) — `run_with_listener` completely bypassed the loopback check it was supposed
  to help enforce.** Round 1 made `run_with_listener` `pub` for testability; the loopback check
  lived only in `bind()`. Any caller — including M2's `daemon.rs`, the function's own next real
  consumer — could bind a listener to `0.0.0.0` directly and call `run_with_listener` with it,
  silently reopening the exact off-host-exposure gap round 1's fix was written to close. This is
  a genuinely more serious finding than anything in round 1: it's a bypass of round 1's own fix,
  introduced by the fix itself. Closed by re-checking `listener.local_addr()?.ip().is_loopback()`
  at the top of `run_with_listener`, so the invariant holds regardless of entry point — `bind()`'s
  check stays too, as cheap defense-in-depth (and fails faster, before a socket is even opened).
- **Fixed (Medium-High) — the accept-loop's error path had no backoff, risking a busy-loop under
  the exact conditions (fd exhaustion, rapid connect-then-RST) where accept() errors actually
  recur.** A bare `continue` with no yield point spins the loop under sustained accept failures,
  competing for scheduler time instead of giving other connections a chance to free descriptors —
  the same failure mode Go's `net/http.Server.Serve` backs off for. Added capped exponential
  backoff (5ms doubling to a 1s cap, reset on the next successful accept), gated behind a new
  `time` feature on the production `tokio` dependency (the crate's first — still no HTTP client
  feature anywhere in the graph, so the zero-egress-client property is unaffected).
- **Fixed (Medium) — test coverage proved the weaker, bypassable half of the loopback contract.**
  The round-1 test only exercised `bind()` directly; nothing tested `run_with_listener`'s own
  enforcement, so the test suite gave false confidence that "misconfigured caller gets no error"
  was fully closed when it only was for callers going through `bind()` first. Added a test that
  binds a raw `tokio::net::TcpListener` to `0.0.0.0` directly (bypassing `server::bind` entirely)
  and confirms `run_with_listener` still refuses it.
- **Documented, not fixed (Low) — `Ipv6Addr::is_loopback()` doesn't recognize IPv4-mapped IPv6
  loopback (`::ffff:127.0.0.1`).** A false-*rejection*, not a bypass — the safe direction of
  error for a security proxy. M1 doesn't need to support that address form; not fixed.

No other issues found in round 1's new code (the error variants themselves, the doc-comment
invariants, `is_bedrock_invoke`'s match-before-decode ordering) after thorough examination —
recorded as a real "clean" result on that part of the pass, not a sign of insufficient scrutiny.

### Validation

`cargo test --workspace`: all green, 3 tests in `vg-proxy`'s `server_smoke.rs` (up from 2), no
regressions elsewhere. `cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo
fmt --check`: clean. `scripts/verify-project.sh`: PASS.

### Stop condition

Two cycles run (single-model + Codex cross-model in round 1; single-model targeted at round 1's
own new code in round 2). Round 2 found one High-severity bypass of round 1's own fix — the
kind of finding that specifically justifies the "target the previous round's own new code"
pattern, since it wouldn't have been caught by re-reviewing the original files fresh. Given the
diminishing-but-real-findings trajectory (round 1: 6 real fixes; round 2: 3 real fixes, one
higher severity than anything in round 1), this warrants at least one more round before treating
M1 as settled — user to decide whether to run round 3 or stop here.

## 2026-07-25 - Doubt-driven-development round 3 on M1 (single-model, targeted at round 2's own new code)

### Context

User chose to continue after round 2's higher-severity finding. Single-model review targeted at
round 2's own new code specifically: the loopback re-check added to `run_with_listener`, the
accept-error backoff logic, and the new bypass-closure test.

### Findings and disposition

- **Fixed (High) — the backoff sleep wasn't raced against `shutdown`, so a sustained
  accept-error storm could delay shutdown observation by up to the current backoff (capped at
  1s) per iteration, repeatedly.** Once `tokio::select!` commits to the accept-error branch,
  `shutdown` isn't polled again until that branch's block finishes — a bare
  `sleep(backoff).await` runs entirely outside the race. This contradicted the documented "runs
  until shutdown resolves" contract during exactly the failure mode the backoff exists to
  survive. Fixed by nesting a `select!` around the sleep itself, racing it against `&mut
  shutdown` too.
- **Fixed (Medium — a real false-negative in the regression test itself) — the new
  `run_with_listener_refuses_a_non_loopback_listener_...` test (added in round 2) had no
  timeout, so if the loopback re-check it guards were ever removed, the test would hang forever
  instead of failing.** `run_with_listener` would fall into its accept loop; nothing connects to
  the `0.0.0.0:0` test listener, and `_shutdown_tx` isn't dropped until the test function
  returns — which can't happen while the function is still awaiting the hung call. This is
  exactly the kind of regression-test bug that defeats the test's own purpose: it would pass
  today and silently stop protecting anything if the fix under test were ever reverted, without
  ever turning red — it would just stall CI. **Verified directly, not just reasoned about:**
  temporarily reverted the loopback re-check in `run_with_listener`, confirmed the test now
  fails cleanly in ~2s with a clear panic message (`Elapsed(())`) instead of hanging, then
  restored the real fix. Closed by wrapping the call in `tokio::time::timeout`, matching the
  sibling test's existing pattern.
- Fixing the first finding incidentally resolved a third, minor doc/behavior-mismatch
  observation (the shutdown-semantics doc comment not mentioning the backoff-delay nuance) —
  once shutdown is genuinely observed promptly during backoff, there was nothing left to
  document as an exception.

No other issues found in round 2's new code (the loopback re-check's core logic — no real
TOCTOU, since `local_addr()` on an already-bound listener is a fixed OS-level fact, not
re-bindable out from under the running function; the backoff's doubling arithmetic — no
overflow risk, capped well within `Duration`'s range; the reset-on-success logic) after
thorough examination.

### Validation

`cargo test --workspace`: all green, no regressions. `cargo clippy --workspace --all-targets --
-D warnings`: clean. `cargo fmt --check`: clean. `scripts/verify-project.sh`: PASS. Additionally
verified the regression test's own effectiveness by deliberately reintroducing the bug it
guards against and confirming the test fails (not hangs) — see above.

### Stop condition

Three cycles run. Round 3's own new code (the shutdown-race fix in the backoff, the
now-timeout-wrapped test) was not itself re-reviewed by a fourth round — per the skill's
guidance ("escalate to the user rather than grinding a 4th alone"), stopping here and reporting
back rather than continuing solo. Findings trajectory across all three rounds: 6 → 3 → 2 real
fixes, genuinely diminishing, with round 3's fixes being smaller in scope (a race condition and
a test-hygiene gap) than round 2's (a security bypass). Reasonable stop point.

## 2026-07-25 - Milestone M2: daemon core (`Daemon`, H2 session-namespace shim)

### Context

PR #38 (M1 + 3 doubt-pass rounds) merged to `main` as `8da9561`. Read plan §5 H2 (the
session-namespace shim's human-locked design), §8.5 ("H1's fix," the accumulated binding store),
and the actual `vg-core`/`vg-vault` APIs (`Namespace`, `SessionId`, `PlaceholderBinding`,
`Vault::open`/`open_with_key`, `VaultStore::purge_expired`) before writing anything, per this
repo's own operating rules. Started M2 (§10.3 milestone 2) on
`agent/claude/vg-proxy-m2-daemon-core`.

### Decision

Built `Daemon` (`daemon.rs`) and `SessionShim` (`session.rs`) as a self-contained, directly
testable pair, deliberately **not** wired into `server::handle` — the milestone's own "serves
many sequential fake requests" framing, and the fact that M3 is explicitly where schema-aware
parsing and real forwarding start, both point to isolated testing being the right scope rather
than premature HTTP integration.

Two judgment calls made and documented up front, not left implicit:

1. **`Daemon::open`/`open_with_key` mirror `Vault`'s own two-constructor pattern exactly** —
   same naming, same "keychain path is production, `_with_key` is the test/alternative-custodian
   seam" split — rather than inventing a different shape, since `Daemon` is a thin owner of
   exactly one `Vault`.
2. **Port-fallback is registration, not derivation.** A stateless function deriving a
   `Namespace` from a port number (e.g. a deterministic UUID hash) would have been simpler to
   write, but would be *actively wrong*, not merely simplified: once the OS reassigns a port to
   an unrelated later session, a stateless derivation silently resolves it to the same
   `Namespace` the previous session used, defeating the isolation the shim exists to provide.
   `SessionShim::register_port` requires an explicit call instead. The real caller that would
   give registration true atomicity (a per-session-listener milestone) doesn't exist yet — this
   is named as an open gap, not silently assumed away (see the doubt-pass findings below).

### Doubt-driven-development, two rounds

**Round 1 (single-model):** 7 findings.

- **Fixed:** mutex-poisoning blast radius — `.lock().expect(...)` would have permanently
  poison-panicked every subsequent call from every session for the process's remaining life if
  any future change ever panicked while holding either lock. Every critical section here is a
  single `HashMap` op with no half-applied invariant, so recovering a poisoned guard
  (`unwrap_or_else(|p| p.into_inner())`) is safe.
- **Fixed:** a dual-stack port-collision bug — registrations were keyed by bare `u16`, so a
  daemon binding both `127.0.0.1` and `::1` on the same numeric port would have collided two
  distinct sessions onto one map slot. Re-keyed by the full `SocketAddr`.
- **Fixed:** `register_port`'s silent overwrite made observable — now returns the previously-
  registered `Namespace`, if any.
- **Fixed:** an unbounded, unvalidated header value echoed into `SessionError`'s `Display` —
  capped at 256 chars, same reasoning as M1's `MAX_ECHOED_TARGET_LEN`.
- **Fixed:** no concurrency test existed despite two `Mutex`es guarding shared state — added one
  hammering `register_port`/`resolve`/`record_bindings`/`bindings_for` from 50 threads
  concurrently.
- **Documented, not fixed — the port-reuse handoff race.** Nothing ties "session B starts
  listening on port P" to "`register_port(P, B)` has been called" atomically; the real caller
  that would provide that doesn't exist yet. `unregister_port` was added as the primitive a
  future caller needs to release a mapping the instant a session ends — the atomicity itself is
  deferred to that milestone.
- **Documented, not fixed — binding-store lifetime/eviction.** Already an explicitly open
  plan-level question (`docs/next-actions.md`: "session-store lifetime/eviction... still
  undecided," carried forward unresolved from v2) — not invented here, since a namespace token
  being reused would otherwise transparently hand back a prior session's accumulated bindings
  once demask is wired to this store (M4+), and the plan hasn't decided the policy yet.

**Round 2 (Codex cross-model, `codex exec --sandbox read-only`):** 9 findings.

- **Fixed (the most severe finding of either round) — a genuine cross-session correctness bug
  in round 1's own new `unregister_port`.** Remove-by-address-alone meant session A's delayed or
  stale cleanup call could delete session B's live mapping after B had already taken over the
  address (a real sequencing bug, not a hypothetical: exactly the port-reuse scenario round 1's
  own doc comment named as a known risk, now shown to have a second, sharper failure mode within
  the primitive meant to help address it). Changed to compare-and-remove: `unregister_port` now
  takes the `Namespace` the caller expects to be there and is a no-op if the current registration
  doesn't match. Regression-tested directly (`unregister_port_is_compare_and_remove_not_remove_by_address_alone`):
  A's stale cleanup naming A must not evict B; only a cleanup naming the *currently* registered
  namespace removes it.
- **Fixed — loopback enforcement missing at the registration boundary.** The same class of gap
  M1's own doubt-pass closed for the listener bind itself (round 1/round 2 of M1's pass),
  recurring here: `register_port` accepted any `SocketAddr`, including non-loopback. Now refuses
  with a new `SessionError::NotLoopback`.
- **Fixed — a false claim in the `lock()` helper's own doc comment.** It asserted every critical
  section is a single, panic-free `HashMap` op, but `record_bindings`'s `.extend(bindings)` ran
  caller-supplied iterator code *inside* the lock — an iterator that panics partway through would
  have left a torn, partially-applied batch under a poisoned-then-silently-recovered lock,
  contradicting the doc comment's own safety claim. Fixed by materializing `bindings` into a
  `Vec` before acquiring the lock, so the critical section really is infallible now.
- **Fixed — the nil UUID (`00000000-...-000000000000`) was accepted as a legitimate, distinct
  namespace.** A common uninitialized/default sentinel; now rejected the same way a malformed
  token is.
- **Added — `register_port_if_absent`.** For a caller that wants "clobbering an existing mapping
  is always suspicious" rather than "clobbering is fine, just tell me what I overwrote" (which
  `register_port`'s `Option<Namespace>` return already provided). Idempotent re-registration of
  the *same* namespace still succeeds; a *different* namespace trying to claim an already-claimed
  address is rejected via a new `SessionConflict` error type.
- **Classified as describing the plan's own already-locked design, not a gap — documented, not
  changed (4 findings):** (1) the header always winning over a registered address with no
  daemon-side validation against a "live session registry" — the plan states the token
  explicitly as "a tenancy selector, not an authenticator," and assigns spoofing/collision
  mitigation to the *injection* side (`vg-adapters-claude`'s `wrapper.rs`), not this shim's
  resolution side; building a live-session registry here would contradict that trust model, not
  fix a bug in it. (2) A real integration-time trap for whichever milestone wires a real
  `hyper::HeaderMap` into `resolve`'s `Option<&str>` parameter (`HeaderValue::to_str()` returning
  `Err` must map to `InvalidNamespaceHeader`, never silently to `None`) — nothing to fix in this
  crate today since no header-extraction code exists yet; documented as a doc-comment invariant
  for that future caller. (3) Same-display/different-`MappingRef` collisions in the binding
  store — an invariant that belongs to `vg-core`/`vg-vault`'s stable-placeholder keying guarantee
  (the same raw value always mints the same display within a namespace), not something this
  session store should independently defend against; doing so risks masking a real upstream
  keying bug rather than surfacing it.

### Validation

`cargo test --workspace`: all green, 13 tests in `vg-proxy/tests/daemon.rs`, no regressions
elsewhere. `cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`:
clean. `scripts/verify-project.sh`: PASS. `cargo tree -p vg-proxy -e normal`: confirmed no HTTP
client dependency anywhere in the graph — M2 remains zero-egress-risk by construction.

### Stop condition

Two cycles run (single-model, then Codex cross-model targeted at round 1's own new code). Per
user decision: stopping here rather than running a third round targeted at round 2's own new
code. The most severe finding class (cross-session correctness — the `unregister_port` bug) is
closed and directly regression-tested; the remaining open items (port-reuse atomicity,
binding-store eviction) are genuinely plan-level questions predating this session, not gaps this
session introduced.

## 2026-07-26 — PROPOSED, not yet ratified: VeilGremlin product-family architecture

**Context:** greenfield product/portfolio design requested for a taxonomy where "VeilGremlin"
becomes an umbrella family name spanning this repo (proposed external identity: `veil-proxy`),
a new telemetry/audit component (`veil-observatory`), a dashboard serving CSOC and Legal/Privacy
audiences, and a new Terraform project constraining Amazon Bedrock as an LLM invocation control
plane (`veil-walled-garden`). Full design in
[`docs/architecture/product-family.md`](architecture/product-family.md). **Design only — no
rename, no crate/Cargo.toml/source change was made or is proposed to happen automatically; this
entry and that document are proposals requiring separate human ratification before any of the
naming or repo-structure recommendations below are acted on.**

**Proposed, not ratified:**

- **PROPOSED ADR-013** — VeilGremlin becomes the family/umbrella brand; this repo's crates
  (`vg-*`), binary (`vg`), and Hekton project registration (`project_name: veilgremlin`) stay
  **permanently unchanged** — no rename now or later, matching the `git`/`gh`/`rg` short-binary-
  name pattern. Only the GitHub repo's external description/positioning would eventually
  reference "veil-proxy," and only once a second family repo exists to disambiguate from — not
  now. Rationale: the ambiguity is a documentation/positioning problem, not a source-naming one;
  a mechanical rename mid-flight of two unmerged branches (`agent/claude/t10-fp-detector-fixes`,
  `agent/claude/vg-proxy-m2-daemon-core`) would cost real merge friction for zero functional
  gain.
- **PROPOSED ADR-014** — Three repos for the family: this repo (`veil-proxy`, unchanged),
  `veil-observatory` (ingestion + event store + retention tiers + the dashboard as an app within
  it, not a fourth repo), `veil-walled-garden` (Terraform only, fully independent lifecycle).
  Rationale: the dashboard has no independent data model from `veil-observatory`'s event store;
  `veil-walled-garden` is a genuinely different artifact type (infra-as-code) with no code-level
  dependency on the other two.
- **PROPOSED ADR-015** — The claim "PII never leaves the machine" / "invisible governance"
  (as worded in the 2026-07-19 T11 sign-off entry, above) is retired in favour of a precise,
  weaker, true claim once `veil-observatory` exists: reversal material (vault, key, raw values)
  never leaves the laptop, unconditionally; masked telemetry (counts/refs/decisions, never a
  human-readable value) may leave, only opt-in, only via a new `TelemetryEvent` type that is
  type-level incapable of holding a raw value (stronger than `MaskedPack`'s current
  tested-not-type-enforced invariant, per `interface-contracts.md` §1). Full wording proposal in
  `docs/architecture/product-family.md` §3.5.
- **PROPOSED, sequencing note** — real actor/device authentication (today's `--actor`/`--role`
  are explicitly self-asserted attribution, not authentication — see `docs/next-actions.md`'s F4
  item) is recommended to land *before* `veil-observatory` ships anything, not after, since fleet
  policy distribution, dashboard RBAC, and evidence-pack chain-of-custody all inherit its
  weakness otherwise if built first.

**Explicitly not resolved by this proposal, named as an honest open problem:** DSAR / right-to-
erasure against a fleet of reversible per-laptop vaults has no engineering answer here — recorded
as a candidate non-goal, not a solved gap. See product-family.md §8.7 (section renumbered in the
2026-07-26 revision below; content unchanged).

**Next step:** human review of `docs/architecture/product-family.md` in full; ratify, amend, or
reject each proposed item above before any of §9's sequencing work begins.

## 2026-07-26 (same day, second pass) — product-family.md updated: two open questions answered, one new design direction developed

**Context:** direct continuation of the proposal above. The human answered two of the document's
open questions and set a new design direction; `docs/architecture/product-family.md` was updated
in place (still PROPOSED, not ratified) rather than left inconsistent with the answers. No
renames, source changes, or `session-log.md` edits were made — design-doc and this decisions.md
entry only.

**Resolved — dashboard build order (was open question Q4).** Legal/Risk/Privacy view ships
first; CSOC gets alerting (not the full investigation surface) from day one. Reworked §4
(personas) and §9 (sequencing, renumbered from §7) to specify what "alerting from day one"
actually requires beyond a Legal/Risk-only data model: a local, on-device alert-rule evaluator in
`veil-proxy`; a second, deliberately minimal, immediate/unbatched delivery lane distinct from the
batched bulk-telemetry lane (resolving an explicit tension with the earlier batched-push
recommendation — both lanes now coexist rather than one lane serving two incompatible latency
needs); and routing into the customer's existing on-call tooling rather than a bespoke pager.
The persona conflict (CSOC wants speed/detail, Legal/Risk wants minimisation/short retention) is
resolved by making the alert-lane payload *more* minimised than bulk telemetry, not less — CSOC
gets speed on day one, not additional scope or retention; the full investigation surface remains
deferred until the alerting lane has generated real demand for it.

**Direction set, not fully resolved — device identity (was open question Q7).** The human
proposed keying `veil-observatory` on the device rather than the user, with the device→user
mapping held separately. Developed into a new dedicated §6 (moved out of the gaps list, which
previously squeezed it into a single gap item): an opaque device pseudonym minted at enrolment
(explicitly never the OS hostname, which is itself enterprise-sensitivity-class data under this
project's own taxonomy — the premise that "device name is already sent in logs today" describes
the leak to fix, not a baseline to keep), a mapping held by a separate custodian, and resolution
back to a real identity treated as an explicit, authorised, audited act — architecturally the
same discipline `veil-proxy`'s vault/`rehydrate` already applies to data, deliberately *not*
literally reusing that code (the vault is laptop-local/single-tenant by design; the mapping
custodian must be centrally queryable — reusing the API would break one or the other). Named
explicitly as pseudonymisation, not anonymisation, matching the spec's existing GDPR caveat.
**Still open:** the cryptographic mechanism that backs "this device really is device X" — mTLS
certificate, TPM/hardware attestation, or SSO/IdP exchange — which §6 assumes gets answered but
does not answer itself.

**New: AWS-native dashboard options evaluated (new §7).** Given `veil-walled-garden` already
assumes AWS, evaluated QuickSight/Athena/Lake Formation/OpenSearch/Security Lake as a dashboard
implementation. Finding: Lake Formation's row/column-level access control genuinely maps onto the
Legal/Risk-vs-CSOC split (§4, §6), with one real gap — it governs *who can query which data*, not
the device-pseudonym-to-identity *resolution* step, which needs its own service with its own
audit trail rather than being conflated with an IAM/Lake Formation grant. Named the honest
downsides (QuickSight per-reader cost at fleet scale, Athena's latency being wrong for the alert
lane, Lake Formation's operational weight) and the biggest one: committing to AWS-native services
contradicts the VPC-portable posture recommended for `veil-observatory` generally. Recommendation:
commit to a portable **data model** (Parquet/Iceberg, optionally OCSF-normalised), not a portable
implementation — AWS-native becomes one deployment target among others, not the only one.

**Mechanical result:** §§6 and 7 are new; the former §6 (gaps) is now §8, former §7 (sequencing)
is now §9, former §8 (open questions) is now §10, with Q4 marked resolved, Q7 marked partially
resolved, and three new open questions added (mapping-custodian ownership; independent opt-in
for the alert lane vs. bulk lane; AWS-native vs. portable `veil-observatory` implementation).
Cross-references throughout the document were updated to match. Still fully proposed, not
ratified — same next step as above.

---

## 2026-07-26 — RATIFIED: the PROPOSED entries above, with amendments

The `PROPOSED ADR-013/014/015` entries above were reviewed and **merged as PR #41**. They are
ratified with the following amendments, recorded here rather than by editing the originals, so
the reasoning trail stays intact.

| Date | Decision | Rationale |
|---|---|---|
| 2026-07-26 | **ADR-013 ratified, and applied.** Project identity renamed `veilgremlin` → `veil-proxy`; VeilGremlin promoted to the family name. Runtime identity deliberately NOT renamed. | The `.veilgremlin/` state dir, the `com.veilgremlin.vault` keychain service, `veilgremlin-*-v1` policy version strings and `veilgremlin:` CLI prefixes name the *product*, not the repo. Renaming them would orphan every existing vault key and state directory for zero benefit. The `vg` crate prefix and binary likewise stand — treat `vg` as a short CLI verb like `git` or `rg`, independent of the product name. |
| 2026-07-26 | **ADR-014 amended.** Not three repos but **four**, and one deliberate non-repo. Created: `veil-custodian` (private), `veil-foundations` (private). Deferred by design: `veil-observatory`. No separate schema repo. | `veil-custodian` was originally conditional on auditing whether an existing MDM/CMDB met the separation-of-duties bar; building it settles that question in the safer direction rather than lowering the bar to fit an existing tool. `veil-foundations` supersedes the `veil-walled-garden` name now that inference profiles and cost attribution are in scope. No schema repo because `AuditEvent` is `#[non_exhaustive]`, forcing the telemetry conversion into `vg-core` — the Rust type is already the single source of truth, so a third repo would buy a three-way version dance and nothing else. |
| 2026-07-26 | **ADR-015 ratified.** "PII never leaves the machine" is retired in favour of a weaker, true claim separating reversal material from telemetry. | Reversal material (vault, key, raw values) never leaves the laptop, unconditionally, with or without an observatory. Telemetry (masked-shape events: counts, refs, decisions, outcomes) may leave, opt-in only. A strong false claim is worse than a weaker true one, and this project already made that trade publicly by publishing its own failing eval numbers. |
| 2026-07-26 | **The proposed exhaustive `From<&AuditEvent>` for `TelemetryEvent` is unbuildable; use `TryFrom`, defined inside `vg-core`.** | `AuditEvent` is `#[non_exhaustive]` (`vg-core/src/audit.rs:19`) by deliberate design, with more variants expected. Outside `vg-core` a caller must write a wildcard arm, and that arm is a silent leak path for every variant added later. `From` is also the wrong shape: it asserts every audit event is valid telemetry, which is false. Found by cross-model review, not by the original design pass. |
| 2026-07-26 | **Custom-entity-label leak: remediation agreed, NOT implemented.** Collapse both render paths to `CUSTOM_NNN` / `[REDACTED:CUSTOM]`; re-key `KeyerState.ordinals` on the rendered display tag; add a stricter vault unique index collapsing all custom rows into one ordinal domain. Salted-HMAC fingerprinting explicitly rejected. | Three-model review (proposal → Opus critique → Codex adjudication). HMAC was rejected because it lacks domain separation over a message space overlapping `placeholder_key`'s, which would render vault-key-derived bytes into model-bound text — a fix introducing a worse leak than it closes — and because a per-vault-random salt makes displays install-nondeterministic. The vault index change is required because `schema.rs:48-49` keys uniqueness on `COALESCE(entity_custom,'')`, letting two concurrent vaults each mint `CUSTOM_001`. **Not implemented because `cargo`/`rustc` are unreachable in this environment and this touches SQL indexes, keying ordinals and vault reseeding.** |
| 2026-07-26 | **No migration needed for the leak fix.** | The fix is not retroactive — `Vault::intern` short-circuits on `lookup_by_key` and returns the *persisted* display — so pre-existing custom mappings would leak forever. Verified by inspection that no `.veilgremlin` state dir and no `vault.db` exists on this machine, so no real vault holds `entity_kind='custom'` rows. The control is therefore ordering: land the fix before any custom detector ships. |
| 2026-07-26 | **Severity of the leak was mis-stated twice before settling.** Recorded deliberately. | First filed as "outside telemetry scope, worth fixing" (understated), then escalated to "a live content leak on the shipped hot path" (overstated). The verified position: real, affects two paths, **not reachable today** because no shipped detector emits `EntityType::Custom`, but every other layer is wired for it. A project that publishes its failing numbers should also publish its wrong calls. |

### Family-level decisions recorded in sibling repos

- **Attestation is mTLS device certificates** — `veil-custodian` ADR-A. Closes `product-family.md` §10 Q7.
- **Retention is a 24-hour hot tier feeding S3**, with lifecycle tiering for regulatory hot and cold archive — `veil-custodian` ADR-B.
