# Session Log: VeilGremlin

## 2026-07-04 - Repo ownership moved to dermdunc (public); build dispatch still deferred

Reviewed readiness to dispatch T01/T02 for real through `agentic-control-tower`'s task-DAG
orchestrator. Confirmed the DAG (`dag status`) shows both ready and the earlier GitHub-push
blocker was already resolved (an SSH host-alias fix, not just the HTTPS workaround). Found a new
blocker — no Rust toolchain on this machine — and, separately, the owner decided to hold off
starting real VeilGremlin build work until the wider Hekton factory-readiness pass is further
along. No build code was written and nothing was dispatched this session.

Separately, the owner determined VeilGremlin's GitHub home was wrong: it's an enterprise
architecture/governance/risk tool, not agentic-engineering tooling, so it belongs under the
`dermdunc` (public) account. Executed that move end-to-end.

### Changed / created files

- `.hekton/project.yaml`, `.hekton/governance.yaml`, `.hekton/risk-register.yaml` — owner,
  `github_account`, `github_remote_url`, `privacy_boundary` updated to dermdunc/public.
- `.hekton/change-log.yaml`, `.hekton/agent-run-log.yaml` — CHG-0002 / RUN-0002 entries for this move.
- `mind-palace/.../index.md` — owner/privacy_boundary updated to match.
- `README.md`, `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `docs/spec/requirements-and-design-spec.md` —
  `Owner:`/`Privacy boundary:` headers updated to dermdunc/public.
- `docs/decisions.md` — new ADR row + full entry recording the ownership/visibility move.
- `docs/next-actions.md` — GitHub-push item confirmed resolved; Rust-toolchain gap logged;
  T01/T02 dispatch re-deferred with reason; visibility-flip and SSH-key items closed as
  decided/superseded.
- `docs/risks.md` — RISK-0010 closed as moot (the early git-remote auth mismatch no longer applies).
- `docs/project-walkthrough.md` — dated update entry + open-question line resolved.

### Decisions Made

- Dispatch T01/T02 deliberately deferred again — not a technical blocker this time, a human call
  to wait for the wider Hekton readiness pass. The newly-found Rust-toolchain gap is logged but
  intentionally not fixed yet (no point installing a toolchain for a build that isn't starting today).
- GitHub repo settled under `dermdunc/veilgremlin` and made public in
  the same session, ahead of any real code existing — the safer order (nothing sensitive to leak
  by going public early, given zero implementation exists yet).

### Assumptions

- `dermdunc` is the correct long-term public identity for enterprise architecture/governance/risk
  factory-output projects, per the new Hekton-wide routing guidance this session also added to
  `~/hekton/config/github-accounts.yaml`.

### Risks / issues

- Repo is now public with zero implementation — low risk (nothing to leak yet), but any future
  session should assume anything committed from this point is world-readable immediately.
- No Rust toolchain installed — will block the very first dispatch (`T01`'s verify command needs
  `cargo`) whenever the deferred build session actually starts.

### Next Actions

- See `docs/next-actions.md` — Rust toolchain install + `check-prereqs.sh` update, then T01/T02
  dispatch, whenever the human decides the wider Hekton readiness pass is far enough along.

### Validation status

- `scripts/verify-project.sh` — passed (all required files present).
- `git ls-remote origin` and `gh api repos/dermdunc/veilgremlin` both confirmed the transfer +
  public visibility took effect.
- Mind-palace: repo-local mirror updated to match; live vault sync run via
  `scripts/sync-mirror-to-vault.sh` this same session (see commit in the vault repo).

## 2026-06-30 - Design & scaffold (factory-output)

Scaffolded VeilGremlin as a Hekton **factory-output** project and loaded it with the full Phase 0/1 design plus an agent-factory build plan. No implementation code yet (Hekton rule: stop before building unless asked).

### Changed / created files

- `docs/spec/requirements-and-design-spec.md` — full Phase 0/1 requirements & design spec (canonical), with all six Mermaid diagrams and Go/No-Go criteria.
- `docs/architecture/agent-factory-plan.md` — how teams of agents build VeilGremlin: squad topology, four build waves, contract-first method, DoD, git/PR protocol, quality gates.
- `docs/architecture/work-breakdown.md` — task DAG T01–T11 with owners, dependencies, acceptance.
- `docs/architecture/interface-contracts.md` — frozen crate seams (traits/types) enabling parallel agent work.
- `docs/research/deep-research-report.md` — source research report (copied in for provenance).
- `docs/architecture.md` — rewritten as architecture index.
- `docs/decisions.md` — ADR-001…ADR-010 + build-method decision.
- `docs/next-actions.md` — Wave A/B/C/D queue.
- `docs/project-walkthrough.md` — plain-English explainer.
- `docs/risks.md` — added product/build risks.
- `README.md` — real overview.
- `mind-palace/.../brief.md`, `mind-palace/.../index.md` — project brief mirror.

### Decisions Made

- Classification: factory-output; repo **private** initially (reversible).
- Core = Rust; vault = SQLCipher; placeholders not synthetic; demask explicit/local/gated; LiteLLM later; supply-chain (sign+SBOM+reproducible) first-class. (ADR-001…010.)
- Build method = contract-first agent factory (squad-per-crate, frozen interfaces, eval-gated).

### Assumptions

- The initial GitHub owner is as stated by the user; private-first is the safe default for a brand-new repo.
- The deep research report at `~/Downloads/deep-research-report-3.md` is the authoritative source context.

### Risks / issues

- **Push blocked:** an SSH host-alias/key mismatch meant `git push` over SSH to the initial private repo failed ("Repository not found"). Workaround: push over HTTPS with a `gh` token. Long-term fix: align the SSH key with the account, or standardise the remote on HTTPS. (Moot once the repo settled under `dermdunc/veilgremlin` — see the 2026-07-04 entry.)

### Next Actions

- Confirm first push (HTTPS+gh token path documented in next-actions).
- Dispatch Wave A: T01 (workspace+CI) and T02 (freeze contracts).
- Then batch-dispatch Wave B squads (T03/04, T05, T05b, T06, T08).

### Validation status

- `just validate-taxonomy` not yet run this session — recommend running before/after first push.
- Mind-palace: vault card + session-log created by scaffold; repo is source of truth (boundary rule). Vault mutation not performed beyond scaffold output (`vault_mutation_allowed: false`).

---

## Session: GO-LIVE dispatch (real) + T01 built directly

**Date:** 2026-07-14

### What Changed

Real `dag dispatch T01` run through `agentic-control-tower` + `engine-gateway-lab` — the
factory's first end-to-end build event. The dispatch mechanism worked correctly (worktree
isolation, routing, verify gate), but the nested `claude -p --permission-mode acceptEdits`
headless call stalled on a Bash-command permission prompt with no human to approve it, and
returned a "waiting on your approval" message instead of building anything — verify correctly
failed on the missing `Cargo.toml`. Built T01 directly instead of retrying the nested dispatch:
a 9-crate Cargo workspace (`vg-core`, `vg-detectors`, `vg-parsers`, `vg-vault`, `vg-policy`,
`vg-audit`, `vg-cli`, `vg-adapters-claude`, `vg-bench`), `.github/workflows/ci.yml`, `deny.toml`,
and a release skeleton (SBOM/signing stubbed).

### Decisions

See `docs/decisions.md` (2026-07-14 entry) for the full record: why direct build over retrying
with a looser permission mode, the cargo-deny wildcard-dependency fix, and the flagged
unattended-dispatch gap for `engine-gateway-lab`/`agentic-control-tower`.

### Assumptions

Empty skeleton crates are correct for T01 — `interface-contracts.md` names Squad 0/Task T02 as
the owner of the canonical trait/type definitions, so T01's job is the workspace + CI they land
in, not the types themselves.

### Risks

The dispatch-mechanism gap (headless `-p` mode cannot approve a Bash tool call) will recur for
any future task whose agent tries to run a Bash command mid-task — flagged in
`docs/next-actions.md`, not fixed here (out of scope for a VeilGremlin build task).

### Next Actions

- T02 next (freeze `vg-core` shared types + `interface-contracts.md` v1). Wave B does not
  dispatch until T01 and T02 both merge.
- Review/merge the T01 PR (`gateway/run-20260714-T01` → `main`).
- Flag the unattended-dispatch permission-mode gap to `engine-gateway-lab`/
  `agentic-control-tower` (separate repos, not addressed here).

### Validation status

- `cargo build --locked && cargo fmt --check` (the DAG's own verify command): PASS.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: PASS.
- `cargo deny check`: PASS locally (advisories/bans/licenses/sources all ok) — **but this was
  local-only and wrong**: the real GitHub Actions `deny` job was `runs-on: macos-latest`, and
  `cargo-deny-action@v2` is a Docker container action requiring Linux — CI failed on every push.
  Caught by a doubt-driven-development pass later the same day (see the follow-up session entry
  below); fixed to `ubuntu-latest`; the real CI run now shows all 6 jobs passing.
- `cargo audit`: PASS (0 vulnerabilities, 76 dependencies scanned).
- `cargo bench --workspace --locked --no-run`: compiles clean.

---

## Session: Doubt-driven-development round 2 (Codex cross-model) + fixes

**Date:** 2026-07-14

### What Changed

After round 1's fix (CI's `deny` job to `ubuntu-latest`, confirmed green on the real GitHub
Actions run), ran a Codex cross-model review of the same PR. Found and fixed: no `cargo test`
CI job existed at all; the Rust toolchain was unpinned (`dtolnay/rust-toolchain@stable`, no
`rust-toolchain.toml`); `docs/risks.md`'s RISK-0002 mitigation implied bench gating was already
enforced when it isn't (no hot-path code exists yet to benchmark); `scripts/check-prereqs.sh`,
`docs/local-assumptions.md`, and `scripts/verify-project.sh` still didn't check for the Rust
toolchain at all — the exact gap flagged on 2026-07-04 and never actually applied, applied now;
every crate hardcoded `version = "0.1.0"` on its intra-workspace path dependencies instead of
inheriting from `[workspace.dependencies]`, which would silently drift on a version bump; and,
found independently while double-checking round 1's own fix, `docs/project-walkthrough.md` now
claimed "T01 is merged" when the PR is still open — round 1 fixed a stale claim and introduced a
new one in the same edit.

### Decisions

Added `rust-toolchain.toml` pinning `1.96.1` (matches this machine's installed version) and
updated every CI job's `dtolnay/rust-toolchain@stable` to `@1.96.1`. Added a `test` CI job
(`cargo test --workspace --locked`) even though there are zero tests today — the job should
exist before T02 adds the first ones, not be retrofitted after. Refactored intra-workspace
dependencies through `[workspace.dependencies]` + `{ workspace = true }` (idiomatic Cargo
pattern) rather than a literal `version = "0.1.0"` in 8 places. Applied the prereq-check fix
that had been sitting prepared-but-unapplied since the VeilGremlin v1 dogfood runbook was
written earlier this session.

### Risks

None new; this is entirely hardening of what round 1 already shipped.

### Next Actions

- Human: review and merge the T01 PR.
- After merge: build/dispatch T02.

### Validation status

- `cargo build --locked && cargo fmt --check`: PASS (re-verified after the workspace-dependency
  refactor).
- `rust-toolchain.toml` added; CI actions pinned to match.
- Real GitHub Actions run confirmed green (all 6 original jobs; `test` job added but not yet
  re-run against the push — confirm on next CI run before merging).
---

## Session: T01 built + two doubt-driven-development rounds + PR merged

**Date:** 2026-07-14 22:11

### What Changed

Built Task T01 (9-crate Cargo workspace + CI + supply-chain skeleton) after the real ACT GO-LIVE dispatch stalled on a headless permission-mode gap. Ran two doubt-driven-development rounds (single-model, then Codex cross-model) that found and fixed a red CI job (cargo-deny-action needs Linux runners), missing test/toolchain-pin CI, stale reproducibility scripts, hardcoded dependency versions, and several stale-doc overclaims (including one round 1 itself introduced). Rewrote all 3 commits to use the Hekton commit footer (Hekton-Engine/Harness/Model/Workflow) instead of the generic Claude Code co-author line. PR #2 merged to main.

### Decisions

Built T01 directly rather than retry/loosen the nested dispatch's permission mode. Fixed the CI red job (ubuntu-latest for cargo-deny) rather than remove the check. Refactored intra-workspace deps through [workspace.dependencies] instead of hardcoded per-crate versions. Rewrote (not amended-in-place) the 3 commits via reset+cherry-pick to apply the Hekton footer, since they were already pushed with an open PR.

### Assumptions

Assumed the Hekton footer's engine=claude/harness=claude-code/model=claude-sonnet-5/workflow=t01-workspace-scaffold values are the right ones for this interactive-session build, per hekton-cli-lab's hkt commit schema.

### Risks

Branch name (gateway/run-20260714-T01) never matched agent-factory-plan.md's feat/<squad>-<task-id>-<slug> convention -- flagged, not fixed (already merged now, moot going forward for this branch but the dispatch tooling's naming convention still doesn't match VeilGremlin's own git contract for future tasks).

### Next Actions

- [x] Dispatch/build T02 — done 2026-07-15.

---

## Session: T02 built (real dispatch, picked up after a tool timeout)

**Date:** 2026-07-15

### What Changed

Retried the real ACT GO-LIVE dispatch for T02. First attempt hit a transient API connection
error; second attempt actually did the real work (7 new files, 787 lines: `vg-core`'s shared
types, trait seams, `rehydrate`'s hard-deny gate implemented for real, contract-conformance
test helpers + worked example) but was killed by a ~10-minute tool timeout before it could
close out formally — no stall this time, genuine progress cut short. Picked up in place: ran
`cargo build` to lock the 3 new dependencies (`thiserror`, `uuid`, `zeroize`), applied `cargo
fmt --all` (the interrupted run hadn't reached formatting), then verified the actual T02
`verify_command` end to end — all green, including 6 real tests.

### Decisions

Continued the interrupted work rather than re-dispatching from scratch or discarding it —
verified independently (build, clippy, fmt, test, plus reading the actual generated code
against `interface-contracts.md`) before trusting it, given this is the frozen contract every
later task builds against.

### Assumptions

None new.

### Risks

None new. Branch-naming mismatch (same issue as T01) still unresolved — see decisions.md.

### Next Actions

- [x] Doubt-driven-development pass — done 2026-07-15, see below.
- Human: review/merge the T02 PR.
- Once T01 + T02 both merge: batch-dispatch Wave B (T03/T04, T05, T05b, T06, T08).

### Validation status

- `cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check &&
  cargo test` (T02's own verify_command): PASS, 6 tests green.

---

## Session: Doubt-driven-development on T02 (two rounds) + fixes

**Date:** 2026-07-15

### What Changed

Ran the same two-round process as T01 (single-model, then Codex cross-model) against the T02
PR. Most severe finding: `interface-contracts.md` was never touched despite being T02's literal
acceptance criterion, still read "DRAFT," and was missing 11 types the real code needed. Most
severe *code* finding: the conformance example's `MockVault::resolve` ignored its namespace
parameter entirely — a value interned under one namespace would resolve under any other. Fixed
both, plus five more conformance-helper gaps (no `PolicyEngine` helper, an audit-escaping
false-negative, `MaskedPack`'s check missing a field, missing span-bounds validation, `Sized`
bounds blocking `dyn Trait` callers) and one documented-not-fixed contract-shape limitation
(`Secret`'s zeroize-on-drop is cosmetic given `rehydrate`'s own frozen return type).

### Decisions

Reconciled `interface-contracts.md` in the same PR rather than a separate contract-change PR,
since nothing has consumed the "frozen" contract yet (Wave B hasn't dispatched) — see
decisions.md for the full record and rationale on each fix.

### Risks

None new. The vault namespace-isolation bug is now caught by a passing test
(`assert_vault_roundtrip` requires a second, distinct namespace and asserts cross-namespace
resolution fails) rather than silently absent.

### Next Actions

- Human: review/merge the T02 PR (both interface-contracts.md and the code fixes are now in it).
- Once T01 + T02 both merge: batch-dispatch Wave B.

### Validation status

- `cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check &&
  cargo test`: PASS, 7 tests green in `vg-core` (was 6 — added the cross-namespace-rejection
  coverage and the adversarial-buffer parser battery).

## Session: T03 built (first genuinely unattended `code-implement` completion) + two rounds of doubt-driven-development + tollgate approved

### What happened with the dispatch

First attempt: terse one-line task prompt got a clarifying question back from headless
`claude -p` instead of any code — a real, previously-unseen failure mode (one-shot mode has
no follow-up channel, so the question was the entire session; the adapter still exited 0, so
the gateway ledger recorded `in-progress` as if something legitimate happened, and ACT's own
verify step trivially passed against the unchanged pre-existing code). Blocked via
`control-tower session block T03`, root-caused, and fixed at the task-spec level: rewrote the
description with concrete file/module/trait guidance plus an explicit "use your judgment,
don't ask" instruction, in both `.hekton/veilgremlin-dag.toml` (the source of truth) and the
regenerated `.hekton/build-tasks/T03.md`. Unblocked, reclaimed the stale worktree
(`review-prune`), re-dispatched.

Second attempt: real work — five detector modules (`email.rs`, `phone.rs`, `ip.rs`,
`iban_sortcode.rs`, `entropy.rs`, ~800 lines) plus a criterion bench, matching the prompt
closely. Verify initially failed on a `Cargo.lock` mismatch (new `regex`/`criterion` deps
never locked) and one clippy unused-import — both mechanical fixes in the worktree, not logic
changes. Full verify chain green after.

### Doubt-driven-development (two rounds, Codex cross-model both times)

Full findings and reconciliation are in `docs/decisions.md`'s 2026-07-15/16 entries — not
repeated here. Summary: round 1 found 9 issues (3 real bugs fixed: IPv4-mapped-IPv6 partial
match, entropy detector missing password special characters, a resulting IP self-overlap;
rest documented trade-offs or refuted against the actual task breakdown). Round 2 verified
those three fixes and found 5 more (2 real trade-offs the fixes themselves introduced,
documented not fixed; rest pre-existing or duplicate of round 1's findings). Stopped at two
cycles per the doubt-driven-development skill's own guidance.

### Tollgate

Approved by the human via `gateway-review.sh --task T03` — surfaced a real, previously-unhit
bug in that script (see Risks below) along the way, worked around live so the review could
proceed. Diff applied to the real repo, worktree pruned, `human_confirmed: true`,
`status: done`. `control-tower session close T03` recorded the summary.

### Decisions

See `docs/decisions.md` 2026-07-15/16 entries for the full detector-review reconciliation.

### Risks

Found (in `engine-gateway-lab`, not this repo): `gateway-review.sh` resolves
`output_artifact` relative to its own repo root unconditionally, which is wrong for
ACT-dispatched, worktree-isolated tasks whose spec (and therefore real output) lives in a
different repo — this is the first time that exact review code path has been exercised with
real output waiting (T01 never produced output, T02 was applied by hand outside this flow).
Logged as `engine-gateway-lab`'s RISK-0017; worked around for T03 with a placeholder file at
the wrong path, not fixed at the root this session.

### Next Actions

- Human: review/merge the T03 PR once opened.
- Decide serial-vs-concurrent for the remaining five Wave B tasks (T04/T05/T05b/T06/T08),
  now that T03's pilot has proven the rework loop (block → unblock → re-dispatch) and the
  RISK-0016 ledger fix, both for real. Per the runbook, default serial unless a future task
  runs cleanly unattended.
- `engine-gateway-lab`'s RISK-0017 (output-path resolution bug) needs a real fix before it's
  relied on again for cross-repo worktree tasks — not blocking, since the workaround is known
  and cheap to repeat, but worth closing before it's hit under less attention.

### Validation status

- `cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check &&
  cargo test`: PASS, 41 tests green in `vg-detectors`, confirmed in both the worktree and the
  real repo after the tollgate applied the diff.
- Criterion bench: ~0.62ms against the 25ms p95 budget.

## Session: Fan-out testing-strategy review + real CI latency gate + Codex dogfooding plan + real detector census

### What happened

Human asked to merge the T03 PR, get a status report, and review the fan-out phases
against VeilGremlin's actual goal (mask PII by design, be an invisible control, treat
latency with trading-system discipline). Merged T03's PR (#5) and `engine-gateway-lab`'s
RISK-0017 PR (#25). Reviewed `interface-contracts.md`'s real budget (p95 < 25ms, not
microseconds — clarified the "sub-microsecond trading system" framing as a *discipline*
of tail-latency awareness and CI enforcement, not a literal target humans could perceive
anyway) and found three real gaps in how Wave B/C tasks would test against each other:

- T04 (keying) and T08 (parsers) had no requirement to integration-test against T03's
  real `Finding`/`Span` output, only mock values — a real interface/shape mismatch could
  survive until T07 wires everything together.
- T09 (CLI/hooks) had no point where a human actually confirms the "invisible control"
  goal is met — latency budgets are necessary but not sufficient for "doesn't affect UX."
- There was no cheap, continuous way to exercise the real detectors against real content
  before T10's formal eval harness exists.

### Changes made

- Added a real, CI-enforced latency-regression gate (`crates/vg-detectors/tests/latency_gate.rs`,
  plain `#[test]`, 4x CI-safe slack over the 25ms budget) so every PR checks this now
  instead of waiting for T10.
- Added cross-crate integration acceptance criteria to T04 and T08, and a human
  UX-latency-verification criterion to T09, in `.hekton/veilgremlin-dag.toml` (source of
  truth) and regenerated `.hekton/build-tasks/{T04,T08,T09}.md`; mirrored in
  `docs/architecture/work-breakdown.md`.
- Asked a Codex subagent to plan (not review — explicitly a planning task) how to
  dogfood VeilGremlin as it's built, to benchmark and find edge cases early. Reconciled
  its plan against the actual codebase in `docs/decisions.md`; its independent conclusion
  matched the plain-`#[test]` latency-gate design already chosen.
- Built and ran `crates/vg-detectors/examples/census.rs`, a read-only tool (never prints
  or stores matched values, only counts/spans/entity-types/latency) against 197 real
  files across VeilGremlin and `engine-gateway-lab`.

### Census findings

Latency is fine: 11.2ms total across 197 files (0.057ms/file avg). But entropy (2468
findings) and phone (783 findings) detectors are dominated by false positives — verified
by hand that `engine-gateway-lab/docs/session-log.md` contains real `run-YYYYMMDD-EG-NNN`
shaped operational IDs that are exactly the byte-length/mixed-character shape the entropy
detector was tuned to catch. This is a genuine, evidenced precision problem, not a
latency problem, and it is **not decided or guessed at this session** — see Next Actions.

### Decisions

Full record (latency-gate design, DAG acceptance-criteria additions, Codex plan
reconciliation, and the census finding) in `docs/decisions.md`'s 2026-07-16 entry.

### Next Actions

- **Human decision needed:** how to address the entropy/phone false-positive rate before
  T06 (policy)/T07 (pipeline) go live — options include an operational-ID allowlist,
  tighter entropy heuristics, or deferring to T10's formal `false_positive_rate` metric.
  Not a call to make without the human.
- Re-run the census as each Wave B/C task lands, per the Codex plan's ladder
  (detector-only now -> +parsers after T08 -> stubbed mini-pipeline after
  T04/T05/T06/T05b -> real `mask()` after T07 -> real dogfood after T09).
- Serial-vs-concurrent for the remaining Wave B tasks (T04/T05/T05b/T06/T08) is still
  open from the prior session.

### Validation status

- `cargo test -p vg-detectors`: PASS, including the new `latency_gate.rs` test
  (p95 well within the 4x CI-safe margin).
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`: PASS after fixing
  2 clippy findings in the new `census.rs` example.
- Full workspace verify chain re-confirmed before opening the PR (#6) for this round.

## Session: Fixed the entropy/phone false-positive finding (Codex-planned, hybrid, measured)

### What happened

Asked Codex to plan out the three open options from the census finding (allowlist,
tighter heuristics, defer to T10) before deciding. Codex read the actual frozen
`PolicyEngine`/`Detector` contracts and the real detector code, then recommended a
hybrid: fix the two dominant detector-level false positives now, keep T10 as the formal
gate, and explicitly deprioritized a policy-layer allowlist (no per-finding hook in the
frozen contract; a regex allowlist is also a potential bypass-surface risk). Human
approved the hybrid.

Implemented `looks_like_iso_date` in `PhoneDetector` (excludes strict `YYYY-MM-DD`
shapes) and `is_structured_identifier` in `EntropyDetector`. The entropy fix needed a
mid-session correction: the first version assumed Hekton's own `run-YYYYMMDD-EG-NNN` run
IDs were the dominant shape (matching the census's original hypothesis) and barely
moved the needle when measured (1 of 1849 findings removed on real `engine-gateway-lab`
content, via a temporary local debug print, never committed). The real dominant classes
were file paths and snake_case/kebab-case identifiers — corrected to a generic
delimiter-splitting rule (segments must be purely alphabetic or purely numeric) that
catches both shapes without a Hekton-specific dictionary.

### Measured impact (isolated before/after via `git stash` on identical, untouched
`engine-gateway-lab` content)

```
                 before   after
entropy          1849     182    (-90%)
phone            618      54     (-91%)
```

Latency unaffected. The remaining ~10% is left for T10's formal `false_positive_rate`
gate, per the hybrid decision, not silently ignored.

### Decisions

Full record, including the mid-session correction and why "measure on real content, not
theory" mattered here concretely, in `docs/decisions.md`'s 2026-07-16 entry.

### Next Actions

- Re-run the census as each Wave B/C task lands (still open from the prior session).
- Serial-vs-concurrent decision for the remaining Wave B tasks still open.

### Validation status

- `cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check
  && cargo test`: PASS, 46 tests green in `vg-detectors` (5 new: 2 phone date-exclusion,
  3 entropy structured-identifier tests, built from the real false-positive examples
  found).

## Session: Merged PR #6; added a build log

### What happened

Merged PR #6 (fan-out review, latency gate, DAG acceptance criteria, Codex dogfooding
plan, real census, and the entropy/phone false-positive fix), pulled `main` up to date.

Human asked for a build log tracking work in this repo, similar to the Hekton Workshop
Gremlin's `docs/build-log/` convention and, to a degree, the Hekton Field Journal. Asked
what scope was wanted rather than assume it; human chose lightweight dated docs only, no
publishing site yet.

### Changes made

Added `docs/build-log/README.md` (the convention: one entry per real event, written for
a reader without context, not a mechanical summary of this file) plus 7 backfilled
entries covering the repo's history from the initial scaffold through the entropy/phone
false-positive fix. Wired the convention into `AGENTS.md`/`CLAUDE.md`/`CODEX.md` as a
standing rule for future sessions, and linked it from `README.md` and
`docs/project-walkthrough.md` — which also got a real content refresh, since it had
gone stale claiming T01's PR was open and no business logic existed.

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 entry.

### Next Actions

- Decide serial-vs-concurrent for the remaining Wave B tasks (T04/T05/T05b/T06/T08) —
  still open.
- Add a build-log entry as each future task lands, per the new standing rule.
- Revisit whether the build log earns a publishable site later (Astro-on-Pages, per the
  Workshop Gremlin's pattern) — not needed yet since this repo is already public.

### Validation status

- Docs-only change this session; no Rust code touched. Full workspace verify chain
  (`cargo build --locked && cargo clippy --all-targets -- -D warnings && cargo fmt
  --check && cargo test`) last confirmed green in the prior session's entry above.

## Session: T04 — typed-placeholder + HMAC keying (headless dispatch, 2026-07-17)

### What happened

Headless one-shot dispatch of Task T04. Implemented `crates/vg-core/src/keying.rs`: the
`VaultStore`-authoritative formula ("stable placeholder via salted HMAC over
`(canonical(value), ty, ns)`") plus the four supporting pieces the task spec named —
type-specific case/whitespace canonicalisation, per-`(Namespace, EntityType)` sequential
ordinal assignment for the `EMAIL_001`/`ACCOUNT_ID_014`-style `display` string, Luhn and
ISO 7064 mod-97-10 checksum validators, and a `Mutex`-backed session-scoped cache
(`Keyer`) so repeated keying of the same value doesn't recompute the HMAC. Added an
integration test (`crates/vg-core/tests/keying_integration.rs`) feeding real `Finding`s
from `vg-detectors::all_detectors()` (Task T03) through the new keying logic, per the
2026-07-16 cross-crate integration requirement added to this task's acceptance criteria.

### Changes made

- `crates/vg-core/src/keying.rs` (new) — `canonicalize`, `placeholder_key`,
  `PlaceholderKey`, `Keyer`/`Keyed`, `luhn_is_valid`, `iban_mod97_is_valid`, plus 25 unit
  tests.
- `crates/vg-core/src/lib.rs` — wired in `mod keying;` and its public re-exports.
- `crates/vg-core/Cargo.toml` — added `hmac`/`sha2` dependencies; added a dev-only
  `vg-detectors` dependency for the integration test.
- `crates/vg-core/tests/keying_integration.rs` (new) — 5 tests against real T03 detector
  output.
- `docs/decisions.md` — new 2026-07-17 T04 entry recording five judgment calls (see
  below) made without a follow-up channel to ask.

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 T04 entry: type-specific case-folding
(not blanket); caller-supplied HMAC salt (`vg-core` doesn't own persistent key storage);
an explicit separator byte in the HMAC message to prevent field-concatenation collisions;
ordinals scoped per `(Namespace, EntityType)`; and — the one worth flagging here
specifically — Luhn/mod-97 are exposed as pure validators but deliberately **not** wired
into `display` construction to synthesize a fake-but-checksum-valid card/IBAN number,
since that would conflict with ADR-005's frozen "typed placeholders, not synthetic
values" decision (2026-06-30).

### Assumptions

- Ordinal sequences are independent per namespace (each `Namespace` gets its own
  `EMAIL_001, EMAIL_002, ...`), not a single counter shared globally per `EntityType`
  across all namespaces — read from the acceptance criterion's "same value -> same
  placeholder **within namespace**" framing.
- `EntityType::Custom(name)`'s display tag upper-snake-cases the dictionary name
  (`internal-project-codename` -> `CUSTOM_INTERNAL_PROJECT_CODENAME`) rather than using
  the raw string, for consistency with the fixed types' `TYPE_TAG_NNN` shape.

### Risks

None new. This module doesn't touch the vault, policy, or audit paths yet — those land
with `vg-vault` (T05), which will be the first real caller of `Keyer`/`placeholder_key`.

### Next Actions

- T05 (`vg-vault`) should call into this module from `VaultStore::intern` rather than
  reimplementing keying — that's the whole point of building it standalone first.
- Remaining Wave B tasks (T05/T05b/T06/T08) still open.

### Validation status

**Not run in the dispatch session** — a fully headless, sandboxed dispatch: every
`cargo`/`rustc` invocation attempted returned an immediate "this command requires
approval" with no reachable prompt (plain shell — `find`/`grep`/`git status` — worked
fine, so this reads as a policy gating toolchain execution specifically, not a general
Bash block). The code was written and hand-traced carefully against the `hmac`/`sha2`
crate APIs and existing crate conventions, including manually verifying the Luhn and
mod-97 test vectors by hand digit-by-digit.

**Verified during PR review:** `cargo build --locked` compiled clean (only `Cargo.lock`
needed regenerating for the two new dependencies). `cargo clippy --workspace
--all-targets --locked -- -D warnings` found one trivial modern-lint finding
(`.is_multiple_of(10)` over `% 10 == 0`), fixed. `cargo fmt --check` found routine
reformatting (file had never been run through `cargo fmt`), applied. Full suite green
after: 32 `keying` unit tests + 5 cross-crate integration tests + the existing 7 `vg-core`
conformance tests, all passing — every hand-traced Luhn/mod-97 vector confirmed correct.

## Session: T04 doubt-pass, tollgate approval, PR consolidation, and merge

### What happened

Ran a Codex cross-model adversarial review on T04's diff before submitting for tollgate
approval. Found and fixed 3 real bugs: an `EntityType::Custom` HMAC collision (different
dictionary names with similar display formatting keyed identically), compact-vs-spaced
IBAN/sort-code/phone values canonicalising to different placeholders (a direct violation
of "same value -> same placeholder"), and `PlaceholderKey`'s `Debug` impl leaking the
full HMAC hex. Fixed a documentation gap in `iban_mod97_is_valid`'s scope. Found and
recorded (not fixable in T04 alone) a real cross-task interface gap: T05's `VaultStore`
must reseed `Keyer`'s ordinal counters from persisted vault state, added as a hard
requirement in T05's own acceptance criteria and `depends_on`.

Ran a second Codex pass fact-checking the dispatch's own self-reported output file
against the actual repo state — mostly found expected drift (the report predates the
fixes above), but caught one genuine, if minor, inaccuracy in the original self-report
(undercounted its own decisions.md entry's judgment calls, 5 vs. the actual 6) and one
real error in **my own** documentation (`docs/decisions.md` said "37 keying unit tests"
when 37 is `vg-core`'s total unit-test count, 31 of which are keying-specific) — fixed.

Tollgate-approved by the human via `gateway-review.sh`, which hit the same RISK-0017
output-path bug as T03 (worked around identically: a placeholder file at the wrong path
pointing to the real output location, not a fix at the root).

While preparing to apply the diff, discovered that an earlier `dag gen-specs` invocation
(scoped `--root` to the T04 worktree) had actually written its output to the **real**
veilgremlin repo instead, due to the tool resolving output paths from
`.hekton/project.yaml`'s canonical path rather than respecting `--root`. Caught
immediately via `git status`; the actual content it wrote (a T05-on-T04 DAG dependency
addition) was legitimate and intentional, so reconciled by applying the same edit
properly to the real repo's own `veilgremlin-dag.toml` rather than reverting it.

Consolidated PR #8 (T04's task-spec-guidance expansion + the T05 dependency addition)
into PR #9 (T04's actual implementation), since both ended up touching the same DAG
content; closed #8 as superseded. Merged #9. `git-guardrail` blocked the `Cargo.lock`-
touching commit from an agent session as designed; the human ran it directly.

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 entries (the doubt-driven-development
subsection under T04, and the separate "Merged T04; vault sync; fixed a real bug in
sync-mirror-to-vault.sh" entry below this session's later work).

### Risks

T05 (`vg-vault`, not yet built) has a new hard acceptance-criterion requirement (ordinal
reseeding from persisted state) that must not be silently skipped — see `docs/next-actions.md`.

### Next Actions

- Human: review/merge (done — PR #9 merged 2026-07-17T17:36:55Z).
- Decide serial-vs-concurrent for the remaining Wave B tasks (T05/T05b/T06/T08).

### Validation status

- Full workspace verify chain re-confirmed green in the real repo after the tollgate
  applied the diff and after folding in the consolidated DAG changes: `cargo build
  --locked && cargo clippy --all-targets -- -D warnings && cargo fmt --check && cargo
  test` — 37 `vg-core` unit tests (31 keying-specific), 5 integration tests, 7
  conformance tests, 46 detector tests, 1 latency-gate test, all green.

## Session: Merged PR #9; vault sync; audited and closed a build-log coverage gap

### What happened

Merged PR #9 to `main`. Backed up the Obsidian vault (`~/hekton/scripts/backup-obsidian-vault.sh`)
and ran `scripts/sync-mirror-to-vault.sh` to push the refreshed mirror `session-log.md` to
the live vault — this project's vault entry hadn't been synced since before T01, so it was
a large catch-up. The script copied the file correctly but its `git add` line silently
staged nothing (see `docs/decisions.md` for the root cause and fix): fixed the script,
manually staged/committed the pending vault update.

Human asked to confirm the build log genuinely tracks how/why/what this project is
building, since it needs to ship as part of the final delivered project the way the
Hekton workshop build-logs do. Audited `docs/build-log/`'s 8 existing entries against
the actual work done and found one real gap: the T04 entry (written by the dispatching
agent) predates the subsequent doubt-pass and never mentions the 3 real bugs found there.
Added a second T04 entry covering that story specifically.

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 entry, "Merged T04 (PR #9); vault sync;
fixed a real bug in sync-mirror-to-vault.sh."

### Next Actions

- Re-audit build-log coverage after each future task lands, not just retroactively.
- Decide serial-vs-concurrent for the remaining Wave B tasks (T05/T05b/T06/T08) — still open.

### Validation status

- Docs/script-only change this session; no Rust code touched.

## 2026-07-17 — T05 built: SQLCipher `VaultStore` in `vg-vault` (headless dispatch, no compiler reachable)

Implemented `vg_core::traits::VaultStore` in `crates/vg-vault` (previously an empty stub crate),
plus the one additive `vg-core` change the requirement forced (`Keyer::seed_ordinal`). As with T04,
no Rust toolchain was reachable in the dispatch environment (`cargo` is gated behind interactive
approval a headless run can't satisfy), so this is left for a compile/clippy/test pass at PR review.

### What changed / created

- `crates/vg-vault/src/lib.rs` — `Vault` struct + `VaultConfig`; `VaultStore` impl (`intern`/
  `resolve`/`purge_expired`); `Vault::open` (keychain-wrapped key) and `Vault::open_with_key`
  (caller-supplied key, for tests); `demask_event_count`/`mapping_count` helpers; a compile-time
  `Send + Sync` assertion.
- `crates/vg-vault/src/schema.rs` — SQLCipher DDL: `meta`, `mapping` (with a UNIQUE index on the
  per-namespace/type ordinal), `demask_event`.
- `crates/vg-vault/src/keychain.rs` — OS-keychain wrap of the 32-byte DB key via `keyring`
  (generate-on-first-use, hex-encoded), with hex codec unit tests.
- `crates/vg-vault/src/codec.rs` — round-trippable `Namespace`/`EntityType` ↔ column encoding
  (needed so the reseed can reconstruct real keys), with round-trip unit tests.
- `crates/vg-vault/src/random.rs`, `src/error.rs` — CSPRNG helper (`getrandom`) and `VaultError`
  mapping.
- `crates/vg-vault/Cargo.toml` — added `rusqlite` (`bundled-sqlcipher-vendored-openssl`), `keyring`,
  `uuid`, `getrandom`; `tempfile` dev-dep.
- `crates/vg-vault/tests/vault.rs` — integration tests: `assert_vault_roundtrip` conformance,
  stable placeholder, sequential ordinals, **ordinal continuity across reopen** (the T05 hard
  requirement), value persistence, namespace isolation, demask logging, TTL purge, wrong-key open
  failure, session-namespace round-trip.
- `crates/vg-core/src/keying.rs` — added `Keyer::seed_ordinal` (additive; not a frozen-contract
  change) plus three unit tests. This is the reseed hook T04 flagged as required for T05.

### Decisions / assumptions

Nine recorded in `docs/decisions.md` (2026-07-17 T05 entry) — key ones: reseed via a new additive
`Keyer::seed_ordinal`; `intern` uses non-mutating `placeholder_key` for the lookup and only mints an
ordinal via `key_for` for genuinely-new values; `prepare_cached` is the "cache prepared statements"
mechanism; SQLCipher whole-DB encryption is the value-at-rest cipher (no redundant app-level layer);
per-install random salt in an encrypted `meta` table; `resolve` returns `NotFound` for both namespace
mismatch and expiry.

### Risks

- RISK-0006 (vault key mishandling / plaintext at rest): materially advanced — this is the code that
  wraps the DB key in the keychain and never writes it plaintext. Not yet verified by a build/run.

### Next actions

- PR-review compile pass: `cargo build --locked && cargo clippy --all-targets -- -D warnings &&
  cargo fmt --check && cargo test -p vg-core -p vg-vault`. Needs a C toolchain + perl for the
  vendored-OpenSSL/SQLCipher build.
- Consider a cross-model doubt-pass on the reseed/intern ordinal logic (the subtle part), as was
  done for T04.

### Validation status

Not compiled or tested in the dispatch session (no reachable toolchain).

**Verified during PR review (2026-07-17):** `bundled-sqlcipher-vendored-openssl` compiled clean;
full chain green after two fixes (a trivial `.is_multiple_of` clippy lint; a missing — and now
redacting, salt-safe — `Debug` on `Vault`). A Codex cross-model doubt-pass found and fixed one
real correctness bug (`intern` could return an expired-but-unpurged placeholder that `resolve`
rejects — now renewed in place) plus two reconciled design points (`resolve` audits denied
demasks by design; the `UNIQUE` ordinal index defends a cross-process race). 40 vg-core + 6
vg-vault unit + 14 vault integration tests green. Full record in `docs/decisions.md`.
Mind-palace updated: no (proposed — sync at PR merge, as with prior tasks).

## 2026-07-17 - T05b: audit sink implemented in vg-audit (headless dispatch, no compiler reachable)

Implemented `vg_core::traits::AuditSink` in the previously empty `vg-audit` stub crate,
per the T05b task spec: append-only JSON Lines storage (`JsonlAuditSink`, one fsynced
record per line, file never truncated), a versioned on-disk schema (`RecordV1`/`EventV1`
mirrors with explicit fallible conversions from the frozen `vg-core` types, every record
carrying `schema_version`), and the full redaction-safety test battery — conformance
roundtrips for all six `AuditEvent` variants, durability across reopen, torn-write
recovery, unknown-schema-version refusal, concurrent writers, and the acceptance property
test that no raw value ever reaches the persisted bytes (checked verbatim *and*
JSON-escaped, with a negative control proving the helper catches a leaky event).

Like T04, this dispatch had no reachable compiler — every `cargo`/`rustc` call was
permission-blocked — which shaped a real decision: the dependency set was chosen so the
required `Cargo.lock` update stayed a hand-editable dependency-edge list between
already-locked packages (`tempfile` dropped for a std-only test tempdir; uuid's `serde`
feature dropped for a `#[serde(with)]` Display-based adapter). Full rationale in
`docs/decisions.md`'s 2026-07-17 T05b entry.

### Changed / created files

- `crates/vg-audit/src/lib.rs` — `JsonlAuditSink` (open/replay/heal, fsynced append,
  in-memory index), `OpenError`.
- `crates/vg-audit/src/record.rs` — versioned storage schema v1 + conversions + pinned
  wire-format tests.
- `crates/vg-audit/tests/sink.rs` — conformance/durability/recovery/property tests.
- `crates/vg-audit/Cargo.toml` — deps (serde, serde_json, thiserror, uuid) with the
  lockfile-constraint note; `Cargo.lock` — vg-audit's dependency list (hand-edited, see
  decisions entry).
- `docs/decisions.md`, `docs/next-actions.md`, `docs/build-log/2026-07-17-an-audit-log-
  sized-to-fit-its-lockfile.md`, this file.

### Decisions

Full record in `docs/decisions.md`, 2026-07-17: "T05b audit sink: JSONL storage,
versioned schema mirrors, and dependencies chosen to fit a hand-editable lockfile."

### Next Actions

- PR review must run the standard verify chain (`cargo build --locked && cargo clippy
  --all-targets -- -D warnings && cargo fmt --check && cargo test -p vg-audit`) — nothing
  was compiled in-session.
- T07 wires this sink into `mask()`'s pipeline assembly alongside T05's vault.

### Validation status

- **Not compiled or tested in the dispatch session** (toolchain permission-blocked in the
  headless dispatch). Self-review caught three would-be compile errors before handoff.
- **Verified during PR review (2026-07-17):** full verify chain green on the first real
  attempt after one `fmt` pass — `cargo build --locked && cargo clippy --workspace
  --all-targets --locked -- -D warnings && cargo fmt --check && cargo test`.
- **Codex cross-model doubt-pass (2026-07-17):** found and fixed 5 real robustness/security
  issues in the log-recovery path (UTF-8 torn-tail bricking the whole log; any unparseable
  line silently skipped rather than only the torn final one; a malformed `schema_version`
  bypassing the strict path; a duplicate `AuditId` silently shadowing; error text
  Debug-leaking an unknown variant's payload) plus a parent-dir fsync; recovery switched
  from newline-heal to truncation. 4 regression tests added, all green. Two limitations
  reconciled as documented trade-offs (the sink cannot scrub raw values by design;
  single-live-sink index coupling). Full record in `docs/decisions.md`.

## 2026-07-17 - T06: implemented `vg-policy` PolicyEngine (`LayeredPolicyEngine`)

Implemented `vg_core::PolicyEngine` in `crates/vg-policy` (was an empty stub). The engine
loads up to three JSON policy packs (global required; repo/session optional), signature-checks
each (Phase 1 stub), merges them session-over-repo-over-global, then validates and resolves
into a query-ready policy. Answers all six trait methods: `classify_entity`,
`classify_artefact`, `destination_allows_masked_only`, `demask_allowed`, `version`, `load`.

The security-load-bearing rule (`demask_allowed` hard-denies `RemoteModelPrompt` /
`ObservabilitySink` for any actor) is enforced in code above the config layer, so no pack can
override it; verified with `vg_core::conformance::assert_policy_engine_denies_hard_deny_destinations`
and a dedicated malicious-pack regression test.

### Changed / created files

- `crates/vg-policy/Cargo.toml` — added `serde` (derive) + `serde_json` deps.
- `crates/vg-policy/src/lib.rs` — module wiring + crate docs (was stub-only).
- `crates/vg-policy/src/config.rs` — new: serde pack schema, 3-layer merge, resolution,
  signature stub, entity/class string mappings, unit tests.
- `crates/vg-policy/src/engine.rs` — new: `LayeredPolicyEngine` + `PolicyEngine` impl.
- `crates/vg-policy/fixtures/*.policy.json` — new: global/repo/session example packs plus
  invalid-class, malformed, and malicious-hard-deny fixtures for failure-mode tests.
- `crates/vg-policy/tests/policy.rs` — new: behavioural + conformance tests.
- `Cargo.lock` — added the `serde`/`serde_json` edges to `vg-policy` (no new packages; both
  already resolved transitively via `criterion`).

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 T06 entry. Headline: policy-pack format is
**JSON** (not TOML/YAML per ADR-007) because cargo can't run in this dispatch sandbox to
regenerate `Cargo.lock`, and `serde_json` is already locked while `toml`/`serde_yaml` are not.
Format is trivially swappable later; flagged as a follow-up to reconcile with ADR-007.

### Assumptions / constraints

- Could not run `cargo build`/`clippy`/`fmt`/`test` — cargo and rustfmt are blocked in this
  sandbox (every invocation returned "requires approval"). Code and formatting were
  hand-verified against rustfmt 100-col defaults and clippy::all; **CI must run the full
  gate.** This is the same no-toolchain constraint that affected T04 (`vg-core` keying).

### Next Actions

- Run `cargo build --locked` / `clippy -D warnings` / `fmt --check` / `test` in CI to confirm
  the hand-verified gate; fix any drift.
- Reconcile policy-pack format with ADR-007 (switch to TOML, or amend ADR-007 to accept JSON)
  once the lock can be regenerated.
- T07 (`vg-core` pipeline wiring) consumes this engine via `Policy { engine, vault, audit }`.

### Validation status

- **Not machine-validated this session** (no toolchain). Logic, types, and formatting
  hand-verified. Unit + integration tests written but not executed here.


## 2026-07-17 - T08 built: `vg-parsers` (headless dispatch, compiler unreachable)

### What happened

Implemented `vg_core::Parser` across `crates/vg-parsers/src/`: `json.rs`, `yaml.rs`, `toml.rs`,
`csv.rs`, `log.rs`, `diff.rs`, `env.rs`, and `rust.rs` (tree-sitter, Rust as the source
language), a shared `util.rs`, an `all_parsers()` registry in `lib.rs`, and a cross-crate
integration test. Every `parse` is written to the never-panic contract — best-effort spans over
empty/truncated/binary/unbalanced input — and each module carries an
`assert_parser_never_panics` battery of genuinely adversarial buffers, plus a registry-wide
battery in `lib.rs`.

### Changed / created files

- `crates/vg-parsers/Cargo.toml` — added `regex`, `serde_yaml`, `toml`, `tree-sitter`,
  `tree-sitter-rust` deps and a `vg-detectors` dev-dep (for the integration test).
- `crates/vg-parsers/src/{lib,util,json,yaml,toml,csv,log,diff,env,rust}.rs` — new.
- `crates/vg-parsers/tests/detector_integration.rs` — new (cross-crate).
- `docs/decisions.md`, `docs/risks.md`, `.hekton/risk-register.yaml` (RISK-0011),
  `docs/next-actions.md`, `docs/build-log/2026-07-17-parsers-that-refuse-to-panic.md`.

### Decisions

Full record in `docs/decisions.md`'s 2026-07-17 T08 entry: source-language choice (Rust),
hand-rolled JSON tokenizer (serde_json gives no offsets and aborts early), serde_yaml/toml used
as well-formedness gates with hand-rolled line-scan spans, `.env` inline-`#`-is-not-a-comment
rule, and the mandated cross-crate classification below.

### Cross-crate finding (required)

`detector_integration.rs` feeds real parser `Span`s into `vg_detectors::all_detectors()` and
pins that the detectors' `_spans` parameter is a no-op today. Classified as an **expected,
stage-appropriate gap** (not a defect): the T03 detectors scan the whole buffer, which is a
superset of structure-scoped scanning; the span-threading pipeline is T07 (Wave C); and the
no-op is now test-pinned so it can't silently change. Flagged span-awareness as the natural
T07-era fix for the 2026-07-16 entropy/phone false positives.

### Validation status

- **NOT compiled/tested in-session** — every `cargo`/`rustc`/`python` invocation is
  approval-gated with no human in a one-shot dispatch (same constraint as T04). Code written for
  correctness/panic-safety by inspection.
- **Must run at PR review:** `cargo build` to **regenerate and commit `Cargo.lock`** (4 new deps
  — all `--locked` CI jobs fail until then), then `cargo test -p vg-parsers && cargo clippy
  --all-targets -- -D warnings && cargo fmt --check`. Verify the `tree-sitter`/`tree-sitter-rust`
  version pair resolves. See RISK-0011.

### Next actions

- Regenerate `Cargo.lock`, verify build/test/clippy/fmt, confirm tree-sitter pins (RISK-0011).
- Re-run the census ladder's parser+detector rung after T08 lands, per the 2026-07-16 Codex plan.

### Mind-palace updated

- No (vault mutation not authorised; repo-local docs updated).

## Session: T07 — wired the masking pipeline (`scan`/`mask`) + contract v1.1

### What changed

- **`crates/vg-core/src/api.rs`** — replaced the `scan`/`mask` `todo!()` bodies with the real
  pipeline. `scan`: first-`can_parse` parser for spans, then every detector over the full raw
  buffer (spans enrichment only). `mask`: classify artefact (Block short-circuits to an empty
  pack + `AuditEvent::Block`, `blocked_artefacts = 1`, nothing interned) → detect (full buffer,
  latency measured here) → resolve overlaps (specific entity beats generic entropy `Secret`, then
  longer span; never double-mask) → per-entity Mask (`vault.intern`) / IrreversibleRedact /
  entity-Block (`[REDACTED:TYPE]`, never interned) / Pass, applied back-to-front → one
  `AuditEvent::Scan` written and returned. Added helpers `parser_spans`, `resolve_overlaps`,
  `spans_overlap`, `specificity`, `redaction_marker`, `detector_version`. **Signature change:**
  `mask` gained `ctx: &Context`.
- **`crates/vg-core/Cargo.toml`** — dev-deps on `vg-parsers`, `vg-vault`, `vg-policy`, `vg-audit`,
  `tempfile`, `criterion`; a `[[bench]]` for `mask_pipeline`.
- **`crates/vg-core/tests/pipeline.rs`** — e2e mask over a mixed fixture through the real
  detectors/parsers/policy-fixture/temp-keyed vault/temp audit sink: same value → same placeholder;
  raw values excluded (via the conformance helper, incl. a per-value property loop); `.env` Block;
  irreversible-redact never interned (`mapping_count == 0` via a fresh vault handle). Plus a `scan`
  test.
- **`crates/vg-core/tests/pipeline_latency_gate.rs`** — plain-`#[test]` CI latency gate for the
  full pipeline (the `vg-detectors/tests/latency_gate.rs` pattern, looser slack for vault+audit I/O).
- **`crates/vg-core/benches/mask_pipeline.rs`** — criterion bench for `mask` on the reference
  artefact (compile-checked in CI).
- **`docs/architecture/interface-contracts.md`** — bumped to **v1.1**: `mask(input, ctx, policy,
  ns)`, inline §2 contract-change note, Versioning entry.
- **`docs/decisions.md`** — ADR-012 row + full 2026-07-18 T07 entry (contract change rationale,
  pipeline order, recorded assumptions, demask-owner note, validation status).

### Decisions / assumptions

- Contract change via the sanctioned explicit-`ctx` fix (not `Policy`-smuggling, not
  caller-precomputed findings). `detector_version` = sorted detector ids joined `+`. Counts tally
  handled findings only (Pass is a no-op). Non-UTF-8 handled via `from_utf8_lossy` (lossless for
  the ASCII-shaped deterministic detectors). Pipeline emits no `DemaskDecision` — the vault owns
  demask attribution in Phase 1. All recorded in `docs/decisions.md`.

### Risks

- RISK: no in-session compiler (headless dispatch; `cargo`/`rustc` approval-gated). Code written
  for correctness by inspection against the merged implementations — **must be built/tested at PR
  review.**

### Validation status

- Not compiled/run in-session. **At PR review:** `cargo build` (expect `Cargo.lock` unchanged),
  `cargo test -p vg-core`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`.

### Mind-palace updated

- No (vault mutation not authorised; repo-local docs updated).

## Session: T09 — `vg` CLI + Claude Code adapter; contract v1.2 + v1.3; two doubt rounds

**Date:** 2026-07-18

### What happened

- Dispatched T09 under Opus from clean main (worktree `run-20260718-T09`). The dispatch
  died mid-response (`API Error: Connection closed mid-response` — failure mode #4);
  rescued in place per the T02 precedent: Opus's adapter crate (1,254 lines, compiled
  clean) kept, the missing CLI/tests/runbook written by the rescue session.
- Contract v1.2 via protocol: `MaskedPack.bindings` (additive) + `rehydrate` re-signed;
  demask resolves exclusively via pack-minted bindings (T07 banked requirement).
- **Doubt round 1 (Fable, fresh context): 18 findings, 6 High.** Keystone: §8's frozen
  exit-code scheme was inverted vs the real platform — every fail-closed path failed
  open, and the transform path never substituted anything. Verified against the hooks
  docs; fixed as **contract v1.3** (transform = exit 0 + JSON `updatedInput` /
  `updatedToolOutput` / prompt `decision:block` with masked resubmit; block = exit 2).
  11 further findings fixed (quoting, schema drift, denial-only demask audit,
  boundary-aware substitution, partial-restore signal, audit hygiene, busy timeout,
  `--settings=`, schema `!=`, state-dir self-gitignore, key-env warning); 4 documented
  trade-offs routed to T10/T11; keyring CI-fix revert (stale worktree base) neutralised.
- **Doubt round 2 (Codex, cross-model): 7 findings.** Real catch: hook-path errors that
  bubbled *out* of `run_hook` exited 1 = non-blocking = fail-open — now exit 2 + test.
  Hard-deny no longer consults even `version()` pre-decision; `same_shape` guard on
  masked tool payloads; count-based partial-restore detection. One addendum: the
  round-2 hard-deny fix had silently un-audited CLI denials — caught by the demo-plan
  critique, corrected same day.
- Ledger repaired `failed` → `interrupted` (reviewable, accurate); RISK-0017 placeholder
  + real output doc written.

### Validation

Full workspace: build, `clippy -D warnings`, `fmt`, **218 tests / 28 binaries /
0 failures**. Live smoke: round trip byte-perfect; hard-deny DENIED + audited; `.env`
write blocked exit 2.

### Mind-palace updated

- No (vault mutation not authorised; repo-local docs updated).

## Session: T10 — eval harness built (dispatch died mid-response, rescued); NO-GO verdict recorded

**Date:** 2026-07-18/19

Dispatch (Opus) died with connection-drop failure mode #4 after authoring a near-complete
`vg-bench` (~1,300 lines, compiled first try). Rescue: fmt, one clippy lint, renderer
wiring, docs layer. Contract v1.4 (`benchmark` gained `ctx`) via protocol. First harness
run: **NO-GO** — overall FP 16.7% (entropy 13.3%, phone 40%), placeholder-consistency
66.7%, display-collision corruption confirmed 1/3; zero-raw-PII, recalls, and latency
gates all pass. Full detail in decisions.md. Validation: 221 tests / 0 failures; clippy
-D warnings + fmt clean. Doubt rounds next (Fable, then Codex offer), then tollgate.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: FP-reduction graph idea checked against real T10 data; redirected to targeted detector fixes

**Date:** 2026-07-21

A `hekton` factory-repo architecture-review session (masking-proxy pivot follow-up) proposed a
graph-db entity-relationship layer to cut false positives via co-occurrence signal. Checked it
against this repo's actual current T10 numbers before writing it up as a plan: the live NO-GO
driver (T10 doubt-pass round 2, 2026-07-19, un-dilutable benign-slice numerator) is entropy: 1
(a commit SHA) and phone: 2 (ISBN/zip) — format-collision, not entity ambiguity — and there is
no person/name detector in `vg-detectors/src/` yet for a co-occurrence graph to enhance.
Redirected: `docs/decisions.md`, `docs/risks.md` (RISK-0004), and `docs/next-actions.md`
updated with a concrete targeted fix (SHA-shape exclusion in `EntropyDetector`, ISBN-checksum +
zip-shape exclusion in `PhoneDetector`) as the real T10 close-out; the graph idea is documented
as deferred, speculative future work in the `hekton` repo's
`docs/plans/veilgremlin-entity-graph-plan-v1.md`, not built here. No code touched this session.

### Validation
N/A — documentation-only change (`docs/decisions.md`, `docs/risks.md`, `docs/next-actions.md`,
this entry); no code, no build, no `vg bench` run.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: T10 precision fix implemented — vg bench verdict now GO locally; PR open, not merged

**Date:** 2026-07-21

Implemented the fix the previous session's redirect pointed at: `EntropyDetector` now excludes
git-SHA-shaped tokens when corroborated by context (`commit`/`sha`/`rev`/`hash` immediately
before a 7-64 char lowercase-hex token), and `PhoneDetector` now excludes ISBN-13/10 via
checksum validation (expanding the regex's own partial match back out to the full digit/hyphen
run first, since the regex's digit-group cap splits a real ISBN mid-number) and ZIP+4 via
shape. A third, previously-undocumented residual (`LICENSE_KEY=ACME-2026-DEMO-KEY`, a value the
corpus's own manifest already lists as an intentional, accepted entity-detection miss) surfaced
on re-running the harness after the first two fixes and was closed too (`is_structured_identifier`
now splits on `=`). Full reasoning and the safety argument for each (why it doesn't create a new
false-negative class) are in `docs/decisions.md`.

`vg bench` verdict: **GO** (false-positive-rate 0.0%, was 16.7%; every other gate unchanged).
Masking proxy (#1 on the roadmap) and the display-collision corruption are unrelated and still
open — this is not a ship decision. Landed on `agent/claude/t10-fp-detector-fixes`, PR open,
**deliberately not merged** — this repo doubt-passes precision changes before they land, and a
result looking clean isn't a reason to skip that this time.

### Validation
`cargo test --workspace`: all green. `cargo clippy --all-targets -- -D warnings`: clean.
`cargo fmt --check`: clean. `vg bench` (with hook latency): GO, all gates PASS.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Two doubt-driven-development rounds on the T10 fix — 14 findings, all closed

**Date:** 2026-07-22

Human asked whether a doubt pass had run against the T10 fix from the prior session — it
hadn't. Ran the full doubt-driven-development cycle. **Round 1:** single-model fresh-context
review (ARTIFACT + CONTRACT only), then a Codex cross-model second opinion on human request
(`codex exec --sandbox read-only`, prompt piped via stdin). Reconciled together: 8 findings,
including 2 Critical false-negative regressions confirmed with concrete counterexamples —
`is_structured_identifier`'s `=` fix let a bare-alphabetic high-entropy secret value pass, and
`looks_like_isbn10`'s checksum alone collided with ordinary NANP phone numbers (Codex's example:
`415-234-0002`). Also escalated ZIP+4's shape-only exclusion to Critical for the same reason.
All 8 fixed: value/key-side re-decomposition rules tightened, ISBN-10/ZIP+4 now require an
explicit text marker (mirroring the git-SHA context-gate), dead-code `sha1`/`sha256` markers and
the too-generic `hash` marker fixed/removed, `commit=<sha>`'s broken `=`-skip documented as a
named scope limit, and the buffer-expansion helper bounded (`MAX_EXPAND`) against O(n^2)/
cross-match risk on adversarial input.

**Round 2:** targeted the NEW code round 1 introduced (not a full re-review) — single-model
only this round. Found 6 more: the `=`-fix's key-side was still unchecked (symmetric to round
1's finding), the marker search matched `zip` inside `gzip`/`unzip` (no word-boundary check),
`MAX_EXPAND` only shrinks (doesn't eliminate) cross-match merging — documented as a named
residual rather than further redesigned, plus two small correctness/defensive fixes. Every
finding across both rounds got a regression test reproducing the reviewer's own counterexample.

`cargo test --workspace`, `clippy -D warnings`, `fmt --check` all clean after every round; `vg
bench` re-run and reconfirmed GO (FP 0.0%) after each. Still on
`agent/claude/t10-fp-detector-fixes`, still not merged — cross-model was offered again for round
2 per the doubt-driven-development skill's protocol; a third round is the human's call.

### Validation
`cargo test --workspace`: all green (66 vg-detectors tests, up from 63). `clippy -D warnings`:
clean. `fmt --check`: clean. `vg bench`: GO, FP rate 0.0%, unchanged from before this session.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Doubt-driven-development round 3 (Codex) — found a bug in round 2's own fix

**Date:** 2026-07-22

Human, asked to choose between stopping, running Codex on round 2's fixes, or merging as-is,
chose the Codex round. It found 8 more issues, including the sharpest one yet: round 2's own
fix for the key-side `=` gap (`MAX_ASSIGNMENT_KEY_LEN = 24`) was itself insufficient — a flat
length bound couldn't distinguish a real 20-24 byte secret from a real identifier name
(Codex's counterexample: `aB3dE5fG7hI9jK1lM2nP=run-2026-01-01`, entropy 4.53 bits/byte).
Replaced with the same structural check already used everywhere else in the file (key must
also decompose into >=2 word-like segments), closing it by construction rather than a
threshold that needed re-guessing. Also found the round-2 word-boundary fix checked
boundaries against the truncated search-window slice rather than the real buffer (a marker
glued directly onto digits with zero separator could still pass), and that round 2's `.`
addition to the expansion helper — meant as a precision improvement for dot-separated ISBNs —
meaningfully widened the ISBN-13 cross-match-merge residual round 2 had already accepted as
narrow; reverted rather than patched further, since the precision gain wasn't worth the
widened false-negative surface. Full detail and reasoning per finding in `docs/decisions.md`.

Every finding across all three rounds (22 total) has a regression test reproducing the
reviewer's own counterexample. `vg bench` reconfirmed GO (FP 0.0%) after this round too. Still
on `agent/claude/t10-fp-detector-fixes`, still not merged. Three consecutive rounds each
surfacing real, non-trivial findings — round 3 targeted at round 2's own fix code and still
found a genuine regression in it — is itself informative about how much a clean `vg bench`
result alone should be trusted for this class of change; recorded plainly rather than treated
as a reason to stop looking.

### Validation
`cargo test --workspace`: all green (71 vg-detectors tests, up from 66). `clippy -D warnings`:
clean. `fmt --check`: clean. `vg bench`: GO, FP rate 0.0%, unchanged.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Doubt-driven-development round 4 — the STOP signal

**Date:** 2026-07-22

Asked again whether to stop or go once more; human chose one more round on round 3's own fix
code. Single-model this time. Its findings were qualitatively different from rounds 1-3: no
new freely-fixable false-negative gap. One finding restated an already-documented residual
(`is_structured_segments` checks character class, not word-likelihood, so a secret with
exactly one incidental delimiter on a letter/digit boundary still passes) more sharply than
before — closed by correcting an overclaiming doc comment, not by changing the mechanism,
since a real fix would need dictionary/word-likelihood detection this detector is
deliberately not built to do. The other was a defensive bounds-check on an unreachable code
path (every current call site already satisfies the invariant). This is the STOP condition
the doubt-driven-development skill describes — recorded as a genuine signal, not just another
findings count.

23 findings across four rounds, every one that was a real, freely-fixable false-negative gap
now closed with its own regression test. `vg bench` reconfirmed GO (FP 0.0%). Recommended to
the human that this is a reasonable stop point; still on `agent/claude/t10-fp-detector-fixes`,
still not merged — human review and the merge decision are next.

### Validation
`cargo test --workspace`: all green (71 vg-detectors tests, unchanged from round 3 — round 4
added no new tests, only doc/hardening fixes). `clippy -D warnings`: clean. `fmt --check`:
clean. `vg bench`: GO, FP rate 0.0%, unchanged.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: M1 — masking-proxy transport + routing skeleton

**Date:** 2026-07-25

First real code toward `docs/next-actions.md`'s "Now" item #1 (the local masking proxy +
daemon), following `~/hekton/docs/plans/veilgremlin-masking-proxy-plan-v1.md` (v3.1,
doubt-pass reconciled, both blocking spikes closed 2026-07-24 in the `~/hekton` factory repo —
that plan and its spikes are tracked there, not here; this session is the plan's first
implementation milestone landing in this repo). Started on `main` with a clean working tree;
created `agent/claude/vg-proxy-m1-transport-routing` per the git contract before touching
anything.

Built milestone M1 exactly as scoped in the plan's §10.3 item 1: **transport + routing
skeleton, no real upstream, no real credentials.** New `crates/vg-proxy` (sibling of
`vg-adapters-claude`, registered in the workspace root `Cargo.toml`): a plain-HTTP `hyper`
loopback server (`server.rs`, `tokio` + `hyper` 1.x + `http-body-util` + `hyper-util`, no TLS
layer at all) in front of `route.rs`'s deny-by-default classifier, matching the plan's §5
step 2 / §8.7 route table verbatim — MASK: `POST /v1/messages`, `POST
/v1/messages/count_tokens`, `POST /model/{model}/invoke[-with-response-stream]`; PASS: `HEAD
/`, `HEAD /api/hello`, `GET /inference-profiles`, `GET /v1/models`; everything else BLOCKs,
including the routes the plan explicitly named as removed (`/v1/messages/batches` — "the
Batch API," never in Claude Code's real gateway contract — and Bedrock Converse, which Claude
Code never calls). Matching is on path only, query string discarded first, per the plan's
`/v1/messages?beta=true` example. There is no upstream client anywhere in this crate yet — a
matched route gets a fixed test-double response, an unmatched one gets `403`, so egress is
impossible by construction rather than merely policy-denied, exactly the property M1 is
supposed to establish before any credential- or forwarding-bearing milestone builds on it.

Verified end-to-end, not just unit-tested: ran the server standalone (a throwaway
`examples/smoke_server.rs`, deleted afterward — not part of the milestone's scope) and hit it
with real HTTP requests over `curl` for all three verdicts — `POST /v1/messages?beta=true`
(mask, query stripped correctly), `HEAD /` (pass — via `curl -I`; `curl -X HEAD` without
`--head` hangs waiting for a body HTTP correctly omits for HEAD responses, a curl gotcha, not
a server bug), `POST /model/.../invoke-with-response-stream` (mask), and two block cases
(`GET /unknown`, `POST /model/.../converse`). All four behaved as designed.

### Changed / created files
- `Cargo.toml` (workspace root) — added `crates/vg-proxy` to `members` and
  `workspace.dependencies`.
- `crates/vg-proxy/Cargo.toml` — new crate: `tokio`, `hyper` 1.x, `http-body-util`,
  `hyper-util`, `thiserror`.
- `crates/vg-proxy/src/lib.rs`, `route.rs`, `server.rs`, `error.rs` — new.
- `crates/vg-proxy/tests/route_classification.rs` — new, table-driven per plan §10.2.

### Decisions
- See `docs/decisions.md` (2026-07-25 entry) for the two judgment calls made without an
  explicit plan citation: keeping M1's module surface to exactly `route.rs` + `server.rs` +
  `error.rs` (deferring `config.rs`/`daemon.rs`/`session.rs`/`schema/` to M2+ rather than
  stubbing them now), and modeling `Mask`/`Pass` as one HTTP-visible behavior in M1 while
  keeping the enum three-valued for M3's sake.

### Validation
`cargo test --workspace`: all green (M1 adds 1 new integration test; no regressions in the
other 8 crates). `cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo fmt
--check`: clean (after `cargo fmt` auto-wrapped two test-table rows the initial write had
under the line-length limit). Manual `curl` verification against a live instance, see above.

### Assumptions
- `hyper` 1.x + `hyper-util`'s `TokioIo`/HTTP1-server pattern (not `hudsucker`, matching the
  plan's §3.1 call) is the right foundation to carry into M2's daemon core and, later, M6's
  streaming work — not reconfirmed independently this session, taken from the plan as given.

### Risks
- None new. M1 is deliberately zero-egress-risk by construction (no upstream client exists in
  this crate yet); nothing here touches the vault, credentials, or real Claude Code traffic.

### Next actions
- M2 (daemon core: `Vault::open_with_key` opened once, per-session namespace shim, session
  store as a bare data structure) is next per the plan's §10.3 build order. Branch left open,
  not merged — human review and merge decision are next, per the git contract's "close
  branches deliberately" rule.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Doubt-driven-development round 1 on M1

**Date:** 2026-07-25

Ran the `doubt-driven-development` skill against the just-committed M1 artifact, per the user's
request. Single-model adversarial review (general-purpose agent, ARTIFACT + CONTRACT only, no
CLAIM) found 8 issues; offered a Codex cross-model pass, user accepted; Codex found 8 more,
independently converging on the same loopback-enforcement gap as the single-model pass — the
strongest signal of the round. Reconciled both sets against the artifact text and the plan's own
§5 step 2 wording. Full findings-by-findings disposition in `docs/decisions.md` (2026-07-25,
"Doubt-driven-development round 1 on M1").

Fixed six real issues: the accept-loop's fatal-on-any-error bug (now logs and continues),
unenforced loopback binding (new `ProxyError::NotLoopback` + `server::bind()`, `run()` split into
`bind()` + `run_with_listener()`), missing real-wire-path test coverage (new
`tests/server_smoke.rs`, real TCP against a real server instance), missing adversarial/regression
test rows (percent-encoded Bedrock model-ID cases, case/trailing-slash `Block` rows), a dead
`unwrap_or` fallback, and unbounded response-body reflection. Documented three real-but-
out-of-scope-for-M1 observations as doc-comment invariants for future milestones to re-check
(GET-with-body, absolute-form request-target authority, Bedrock model-ID character class) and one
reviewer mis-read (Pass-route query-agnostic matching is deliberate, not an oversight — but
worth a doc comment since two independent models read it the same way). One accepted trade-off,
not fixed: shutdown doesn't drain in-flight connections — real gap, but full lifecycle management
is M2's `daemon.rs` job, not M1's.

### Changed / created files
- `crates/vg-proxy/src/error.rs` — new `ProxyError::NotLoopback` variant.
- `crates/vg-proxy/src/server.rs` — `bind()`/`run_with_listener()` split; accept-loop resilience;
  bounded response-body reflection; new doc-comment invariants.
- `crates/vg-proxy/src/route.rs` — dead-code fix; new doc comments (Pass query-agnostic design,
  raw-bytes matching invariant).
- `crates/vg-proxy/tests/route_classification.rs` — adversarial + regression rows added.
- `crates/vg-proxy/tests/server_smoke.rs` — new, real-HTTP integration test.
- `crates/vg-proxy/Cargo.toml` — dev-dependency-only tokio feature additions (`io-util`, `sync`)
  for the new integration test; no production dependency changed.

### Validation
`cargo test --workspace`: all green, no regressions, 2 new `vg-proxy` tests. `cargo clippy
--workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
`scripts/verify-project.sh`: PASS.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Doubt-driven-development round 2 on M1

**Date:** 2026-07-25

Continued the doubt-pass on M1, per the repo's established pattern of targeting each round at
the *previous* round's own new code (the T10 detector-fix precedent). Single-model review
against round 1's fix code (the `bind()`/`run_with_listener()` split, `NotLoopback`, the
accept-loop fix, the two new tests) found something more serious than anything in round 1: the
fix itself introduced a bypass. `run_with_listener` is `pub` (round 1 made it so for testing)
and took an already-bound listener with no loopback check of its own — any caller binding
`0.0.0.0` directly and calling it would have silently reopened the exact exposure gap round 1
closed. Full disposition in `docs/decisions.md` (2026-07-25, round 2).

Fixed: `run_with_listener` now re-checks `listener.local_addr()?.ip().is_loopback()` itself,
closing the bypass regardless of entry point; accept-loop errors now back off (capped
exponential, 5ms→1s, reset on success) instead of risking a busy-loop under sustained accept
failures (fd exhaustion, rapid connect-then-RST) — this needed the `time` feature added to the
production `tokio` dependency (the crate's first; no HTTP client feature anywhere in the graph
still). Added a test proving `run_with_listener`'s own enforcement independent of `bind()`.
Documented, not fixed: `Ipv6Addr::is_loopback()` doesn't recognize IPv4-mapped IPv6 loopback —
a false-rejection, the safe direction of error, not fixed for M1.

### Changed / created files
- `crates/vg-proxy/src/server.rs` — `run_with_listener` re-checks loopback; accept-loop backoff.
- `crates/vg-proxy/Cargo.toml` — production `tokio` gains the `time` feature.
- `crates/vg-proxy/tests/server_smoke.rs` — new test proving the bypass is closed.
- `docs/decisions.md` — full findings disposition.

### Validation
`cargo test --workspace`: all green, 3 tests in `server_smoke.rs` (up from 2), no regressions.
`cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`: clean.
`scripts/verify-project.sh`: PASS.

### Next actions
Round 2 found a higher-severity issue than round 1 (a bypass of round 1's own fix) — per the
doubt-driven-development stop condition, this is real signal that another round is warranted
before treating M1 as settled, not a trivial-findings stop point. Asking the user whether to run
round 3 or stop here.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: Doubt-driven-development round 3 on M1

**Date:** 2026-07-25

User chose to continue past round 2's higher-severity finding. Single-model review targeted at
round 2's own new code (the loopback re-check, the accept-error backoff, the new test) found two
real issues: the backoff sleep wasn't raced against `shutdown`, so a sustained accept-error
storm could delay shutdown observation by up to 1s per iteration repeatedly; and round 2's own
new regression test had no timeout, so if the loopback re-check it guards were ever removed, the
test would hang forever instead of failing — a false-negative in the test itself. Verified the
second fix directly: temporarily reverted the loopback re-check, confirmed the test now fails
cleanly in ~2s instead of hanging, restored the fix. Full disposition in `docs/decisions.md`
(2026-07-25, round 3).

Fixed both: the backoff sleep now races against shutdown via a nested `select!`; the regression
test now wraps its call in `tokio::time::timeout`, matching its sibling test's existing pattern.
No other issues found in round 2's own code after thorough examination (no TOCTOU in the
loopback re-check, no overflow risk in the backoff doubling, reset-on-success logic correct).

Findings trajectory across three rounds: 6 → 3 → 2 real fixes, genuinely diminishing, with round
3's fixes smaller in scope than round 2's security bypass. Stopping here per the
doubt-driven-development skill's own guidance ("escalate to the user rather than grinding a 4th
alone") — reporting back rather than continuing solo.

### Changed / created files
- `crates/vg-proxy/src/server.rs` — backoff sleep now races against shutdown.
- `crates/vg-proxy/tests/server_smoke.rs` — regression test now timeout-wrapped.
- `docs/decisions.md` — full findings disposition.

### Validation
`cargo test --workspace`: all green, no regressions. `cargo clippy --workspace --all-targets --
-D warnings`: clean. `cargo fmt --check`: clean. `scripts/verify-project.sh`: PASS. Also
manually verified the fixed regression test actually catches the regression it guards against
(reverted the fix, confirmed fast failure, restored it).

### Next actions
Recommending stop here — 3 rounds, diminishing real findings, PR #38 ready for human review
covering all three rounds' fixes on top of the original M1 skeleton.

### Mind-palace updated
- No (vault mutation not authorised).

## Session: M1 merged; M2 — daemon core, hardened by 2 doubt-pass rounds

**Date:** 2026-07-25

PR #38 (M1 + 3 doubt-pass rounds) merged to `main` as `8da9561` on the user's explicit go-ahead
("please emerge" — read as "please merge"); all CI checks green, PR clean/mergeable. Note: a
follow-up plain read-only verification command in the same turn was blocked by Claude Code's own
auto-mode safety classifier ("Merge Without Review" — this project's `CLAUDE.md` requires
explicit human approval before merging a self-authored PR, and the classifier judged the user's
instruction insufficiently explicit about waiving that review step). The merge itself had already
completed successfully before the block; flagged to the user rather than worked around.

Started M2 (daemon core, plan §10.3 milestone 2) on a fresh branch
(`agent/claude/vg-proxy-m2-daemon-core`) off the updated `main`. Read the plan's §5 H2 design,
§8.5 (accumulated binding store / H1's fix), and the actual `vg-core`/`vg-vault` APIs
(`Namespace`, `SessionId`, `PlaceholderBinding`, `Vault::open`/`open_with_key`,
`VaultStore::purge_expired`) before writing anything, per this repo's own operating rules.

Built `Daemon` (`daemon.rs`) and the H2 session-namespace shim (`session.rs`), deliberately
**not** wired into `server::handle` — M2 is tested in isolation via direct calls
(`handle_fake_request`, matching the milestone's own "fake requests" framing), since nothing
schema-aware exists yet to route toward (that's M3+). `Daemon::open`/`open_with_key` mirror
`Vault`'s own two-constructor pattern exactly. The port-fallback path is **registration, not
derivation** — a design call made and documented up front: deriving a `Namespace` deterministically
from a port number would be actively wrong (a reused port would silently resolve to the previous
session's namespace), so `SessionShim` requires an explicit `register_port` call, with the real
per-session-listener caller that would provide registration atomicity left as documented future
work (no milestone builds per-session listeners yet).

Ran two doubt-driven-development rounds before finalizing — full disposition in
`docs/decisions.md` (2026-07-25 entries):

- **Round 1 (single-model):** 7 findings. Fixed: mutex-poisoning blast radius (`.expect()` →
  recover-on-poison, since no critical section leaves a half-applied invariant), a dual-stack
  port-collision bug (keyed registrations by full `SocketAddr`, not bare `u16`), silent-overwrite
  observability (`register_port` returns the previous `Namespace`), an unbounded echoed-header
  length, and added the missing concurrency test. Documented, not fixed: the port-reuse handoff
  race (no real caller exists yet to provide atomicity — `unregister_port` added as the primitive
  a future caller needs) and binding-store lifetime/eviction (already an explicitly open
  plan-level question per `docs/next-actions.md`, not invented here).
- **Round 2 (Codex cross-model):** 9 findings. Fixed: a genuine cross-session correctness bug in
  round 1's own new `unregister_port` — remove-by-address-alone let a stale session's delayed
  cleanup delete a *different*, newer session's live mapping after a port handoff; now
  compare-and-remove, only releasing a mapping if the caller names the `Namespace` it expects to
  be there. Also fixed: loopback enforcement missing at the registration boundary (the same class
  of gap M1's own doubt-pass already closed for the listener bind, recurring here), a
  `record_bindings` doc-comment that overclaimed lock-recovery safety (caller-supplied iterator
  code was running *inside* the critical section — now materialized to a `Vec` before locking),
  and the nil UUID being accepted as a legitimate namespace. Added
  `register_port_if_absent` for a caller that wants conflicts rejected outright rather than
  silently observed. Four findings classified as describing the plan's own already-locked design
  (the header's non-authenticating trust model, spoofing mitigation living in `wrapper.rs` not
  this shim, an integration-time trap for a future `HeaderMap`-extraction caller, and same-display
  binding collisions being an upstream vault-keying guarantee) — documented, not changed.

Stopped after 2 rounds per user decision — the most severe finding class (cross-session
correctness) is closed and tested; remaining open items are genuinely plan-level questions, not
gaps introduced this session.

### Changed / created files
- `crates/vg-proxy/src/daemon.rs`, `session.rs` — new.
- `crates/vg-proxy/src/error.rs`, `lib.rs` — updated for the new modules/error variants.
- `crates/vg-proxy/tests/daemon.rs` — new, 13 tests.
- `crates/vg-proxy/Cargo.toml` — `vg-core`, `vg-vault`, `uuid` (prod); `uuid` v4, `tempfile` (dev).
- `docs/decisions.md`, `docs/next-actions.md` — updated.

### Validation
`cargo test --workspace`: all green, 13 tests in `vg-proxy/tests/daemon.rs`, no regressions
elsewhere. `cargo clippy --workspace --all-targets -- -D warnings`: clean. `cargo fmt --check`:
clean. `scripts/verify-project.sh`: PASS. `cargo tree -p vg-proxy -e normal`: confirmed no HTTP
client dependency anywhere in the graph — M2 remains zero-egress-risk by construction, same as M1.

### Next actions
M3 (request masking, Anthropic direct, non-streaming) per plan §10.3 — the first milestone that
actually wires schema-aware parsing and real `vg_core::mask` calls into the HTTP request path.
Branch left open, not merged — human review and merge decision are next.

### Mind-palace updated
- No (vault mutation not authorised).
---

## Session: M1 + M2 landed: masking-proxy transport, routing, and daemon core

**Date:** 2026-07-25 14:15

### What Changed

Built and merged M1 (transport + routing skeleton, PR #38, 3 doubt-pass rounds, 11 fixes) and M2 (daemon core + H2 session-namespace shim, PR #39, 2 doubt-pass rounds, 12 fixes) of the masking-proxy plan. Both merged to main. crates/vg-proxy now has bind/routing (M1) plus a Daemon opening vg-vault once and a SessionShim resolving per-session Namespace via header or registered loopback address (M2), tested in isolation, not yet wired into the HTTP server.

### Decisions

Port-fallback is registration, not derivation, to avoid silently reusing a prior session's namespace on port reuse. Daemon::open/open_with_key mirror Vault's own two-constructor pattern.

### Assumptions

M3 is the first milestone that wires schema-aware masking and the daemon into the real HTTP request path; M2 deliberately stops short of that.

### Risks

Port-reuse handoff race and binding-store eviction remain open, documented design questions (not new gaps this session) until a real per-session-listener caller and an eviction policy are built.

### Next Actions

- [ ] M3: request masking
- [ ] Anthropic direct
- [ ] non-streaming (schema/anthropic.rs + mask_request.rs wired end-to-end against a mock upstream)

---

## Session: VeilGremlin becomes a product family; a latent leak found

**Date:** 2026-07-26

### What Changed

**Renamed the project identity** `veilgremlin` → `veil-proxy`. VeilGremlin is now the name of the
end-to-end product family; this repo is the masking data plane within it. Scope was deliberately
narrow — `.hekton/*.yaml`, the build-DAG filename, and the four agent-facing docs. Runtime
identity (`.veilgremlin/` state dir, `com.veilgremlin.vault` keychain service, policy version
strings, CLI stderr prefixes) was left untouched: it names the *product*, not the repo, and
renaming it would orphan existing vault keys and state directories. The GitHub repo rename stays
deferred.

**Designed the family** (`docs/architecture/product-family.md`, `implementation-plan.md`) and
**created two sibling repos**, both private, both with merged implementation plans:

- `veil-custodian` — device-pseudonym → user mapping, so a central plane keys on pseudonyms and
  never holds identity.
- `veil-foundations` — Terraform codifying Bedrock as an invocation control plane. Renamed from
  the `veil-walled-garden` concept once inference profiles and cost attribution came into scope.

`veil-observatory` was deliberately **not** created — it is gated behind Phase 1a.

**Resolved the central design tension.** A central plane contradicts "PII never leaves the
machine." The resolution separates *reversal material* (vault, key, raw values — never leaves,
unconditionally) from *telemetry* (masked-shape events — may leave, opt-in only), and proposes
retiring the old claim for weaker wording that is actually true.

**Corrected the record.** The T10 precision NO-GO closed in PR #37 (`vg bench` GO, FP rate 0.0%),
but `README.md`, `.hekton/project.yaml` and `docs/next-actions.md` had advertised the stale 16.7%
failure for over a week. All corrected.

### The leak

Two paths interpolate a policy-declared **custom entity class name** into `MaskedPack.text`, the
artefact sent to the model:

| Path | Handling classes | Renders |
|---|---|---|
| `vg-core/src/api.rs:450` | `IrreversibleRedact`, `Block` | `[REDACTED:CUSTOM:{name}]` |
| `vg-core/src/keying.rs:219` | **`Mask` — the default** | `CUSTOM_{SCREAMING_SNAKE}_001` |

Severity was mis-stated twice before settling: first filed as a footnote, then over-corrected to
"live in shipped code." The verified position is narrower — **not reachable today**, because no
shipped detector emits `EntityType::Custom`, but every other layer is wired for it and the fix is
**not retroactive** (`Vault::intern` returns the persisted display), so it arms on the first
custom detector.

Three models reviewed the remediation and disagreed productively:

- The **proposal** recommended a salted-HMAC fingerprint for the display tag.
- **Opus** rejected it — no domain separation over a message space overlapping `placeholder_key`'s
  would render vault-key-derived bytes into model-bound text; per-vault-random salt makes displays
  install-nondeterministic. It proposed re-keying ordinals on the rendered tag instead.
- **Codex** agreed on rejecting HMAC but overruled Opus twice: its "zero `vg-vault` change" version
  misses that `schema.rs:48-49` keys the unique index on `COALESCE(entity_custom,'')`, so two
  concurrent vaults can both mint `CUSTOM_001`; and landing `api.rs` alone leaves the *default*
  `Mask` path leaking.

Also surfaced: a **separate demask correctness bug** — duplicate displays make `rehydrate` restore
both placeholders to the first secret, and `vg demask`'s partial-restore guard misses it because
the token count drops 2→0 for both bindings, so it exits **0 silently**.

### Validation status

**Nothing was compiled or tested.** `cargo`/`rustc` are unreachable in this environment. All code
findings are read-verified with file:line, and the remediation is planned but **not implemented**
for exactly that reason — it touches SQL indexes, keying ordinals and vault reseeding.

Verified by inspection: no `.veilgremlin` state dir or `vault.db` exists on this machine, so no
real vault holds `entity_kind='custom'` rows and **no migration is needed**.

### Risks

- The leak arms silently on the first custom detector. Nothing in CI guards it.
- Crypto-shredding for post-offboarding erasure must now reach S3 and Glacier copies
  (`veil-custodian` ADR-B) — the main open risk in the retention decision.
- The Hekton scaffolder has two defects found this session: uncommitted local edits making
  scaffolds non-reproducible, and a missing newline that swallows `owner:` into a comment. Both
  outside this repo, untouched.

### Next Actions

See `docs/next-actions.md` — the leak remediation is first and needs a compiler.

### Mind-palace updated

No — proposed. Vault mutation remains disabled for this repo.
