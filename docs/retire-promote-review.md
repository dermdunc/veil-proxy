# Retire / Promote Review: Veilgremlin

**Last updated:** 2026-09-06 (first real review since scaffold).

## Retire / Promote Review

### Current state
Active, factory-output. This is not idle housekeeping — the repo (internally renamed `veil-proxy`
on 2026-07-26; `VeilGremlin` is now the retained name of the end-to-end *product family*, not
this component — see "Naming clarification" below) has 45 commits in the 30 days to 2026-09-06,
real merged features, and a real cross-repo integration proof landed as recently as 2026-09-05.
It is mid-build, not finished: the README's own status box says `vg run` only covers the
tool-call path today, `vg-proxy` (the actual masking proxy) has no CLI subcommand to start it,
and real TLS to `api.anthropic.com` (M5) is not built.

### Evidence gathered
- **Commit volume/recency:** `git log --since="30 days ago"` returns 45 commits (2026-08-07 to
  2026-09-06). Most recent: `0109677` (2026-09-06, PR #66, XREPO-005 ratification).
- **Test suite, verified by actually running it (not just citing docs):** `cargo test --workspace
  --locked` run locally 2026-09-06 → **~462 unit tests, 0 failures**, plus doc-tests, across all
  8 crates (`vg-core`, `vg-detectors`, `vg-parsers`, `vg-vault`, `vg-policy`, `vg-audit`, `vg-cli`/
  `vg-adapters-claude`, `vg-bench`). README's stated "443 passing tests" is now a stale, slightly
  lower snapshot — real count has grown since, not shrunk. No red flag here, just a minor
  doc-currency gap.
- **CI is currently RED on `main`, undetected by the last two merges:** `gh run view 34021108816`
  (triggered by the 2026-09-06 merge of PR #66, currently HEAD) shows `cargo build`, `cargo test`,
  `cargo clippy -D warnings`, `cargo fmt --check`, and `cargo-audit` all green, but **`cargo-deny
  check` fails**: `error[yanked]: detected yanked crate (try 'cargo update -p wnaf')` — `wnaf
  v0.14.0`, pulled in transitively via `primeorder` → `p256` → `vg-core` (the ECDSA-P256 signing
  work from 2026-08-31). This is a real, live, currently-unaddressed CI failure on `main` as of
  this review, not mentioned in `docs/decisions.md` or `docs/next-actions.md`. It is minor (a
  yanked-not-vulnerable crate, one-line fix) but it is evidence that the last two doc-only PRs
  (#64, #65, #66 — all cross-repo ratification bookkeeping) merged to `main` without anyone
  noticing red CI.
- **Eval/Go-No-Go evidence is real and dated, not asserted:** `docs/decisions.md`'s 2026-07-21/22
  entries and `README.md`'s Status section both cite a `vg bench` verdict flip from NO-GO
  (false-positive rate 16.7%) to **GO** (0.0%), reached via four doubt-driven-development rounds
  before merge. Two honest caveats stand undisputed since: 1-of-3 display-collision samples still
  corrupted (re-measured 2026-08-01, unchanged), and one residual class-name leak path in
  `vg-audit`'s stored log format (named, deliberately not fixed).
- **Real cross-repo integration proof, not just a design doc:** `docs/decisions.md`'s 2026-09-05
  entry — `veil-demo`'s `scripts/ecdsa-signing-proof.sh` enrolled a real device against a real
  local `veil-custodian`, obtained a real ADR-S-issued P-256 certificate via the now-built
  `veil-enrol` CLI, and drove this repo's actual production `Engine::open` auto-detect code to
  produce a real ECDSA-signed `veil.edge_event.v1`, independently verified by a from-scratch
  DER-wrapping verifier that also correctly rejected a tampered signature. Two cross-repo
  decisions (XREPO-004, signature encoding; XREPO-005, correlation-contract-gate scope) closed
  2026-09-05/06 on the strength of this and a matching `veil-observatory`-side review.
- **Governance metadata has not kept pace with the build:** `.hekton/project.yaml`'s `version`
  field has never been set (`version: ""`) despite ~2 months of continuous work; `maturity_level:
  1` / `maturity_label: experimental` / `maturity_date: 2026-06-30` and `last_validated:
  2026-07-26` are both over a month stale relative to the real progress recorded above.
  Separately, the same file's comment claims the GitHub rename to `veil-proxy` is "deliberately
  deferred until veil-observatory exists" and still lists `github_remote_url:
  "git@github.com:dermdunc/veilgremlin.git"` — but `git remote -v` and `gh repo view
  dermdunc/veil-proxy` both confirm **the rename already happened** (repo created 2026-06-30,
  currently named `veil-proxy`, not archived, last push 2026-09-06). This is stale documentation
  in the project's own control file, not a hypothetical.
- **`docs/retire-promote-review.md` itself had never been filled in** — prior to this review it
  was the unedited scaffold ("Initial scaffold created." / blank scores), confirming the premise
  of this task.
- **No dormancy risk:** the "Project → Archive" trigger (`no active development for >90 days`)
  in `promotion-rules.md` is nowhere close to being met.

### Naming clarification (requested check)
The name does **not** indicate this repo is a Gremlin/task-automation agent serving the other
`veil-*` projects. Per `.hekton/project.yaml`, `CLAUDE.md`, and `README.md`: this repo was
renamed `veil-proxy` on 2026-07-26; `VeilGremlin` is retained only as the *end-to-end product
family* name (and for runtime identity — `.veilgremlin/` state dir, `com.veilgremlin.vault`
keychain service, `vg` CLI — kept unchanged so existing installs don't break). This repo is one
peer component (the masking data plane) alongside `veil-foundations` (Bedrock control plane),
`veil-custodian` (device-pseudonym registry), and `veil-observatory` (not yet created, gated
behind this repo's telemetry work). It genuinely collaborates cross-repo (ADR-S acceptance,
XREPO-004/005) but is not automation tooling *for* the others.

One likely source of confusion for a parallel reviewer: `docs/gremlin-radar.md` exists in this
repo, but it is the generic Hekton practice of logging automation-opportunity candidates at
session closeout (see `~/hekton/agents/gremlin-model.md`) — unrelated to the product-naming
question. Only one entry exists (2026-07-25, a doubt-driven-development skill-enhancement idea,
explicitly flagged as not this repo's to build).

### Value score
- **Reuse:** Medium — one component in a real, actively-coordinated multi-repo product family
  (veil-custodian, veil-foundations, veil-observatory); interface contracts are versioned and
  frozen (v1.4) specifically to let other repos build against it, and two cross-repo decisions
  (XREPO-004/005) closed this week on real evidence, not just design docs.
- **Clarity:** High — README states its own honest limitations up front (tool-call path only,
  no `vg-proxy` startup command yet), decisions.md and next-actions.md are exhaustively dated and
  cross-referenced, and struck-through corrections are used instead of silent edits when facts
  change (e.g., the 2026-09-05 next-actions.md correction).
- **Automation:** Medium-High — CI runs build/test/clippy/fmt/deny/audit on every PR; `vg bench`
  is a self-contained Go/No-Go eval harness; doubt-driven-development is applied as a matter of
  routine (not occasionally) before merging non-trivial changes.
- **Decision quality:** High — ADRs are specific, dated, cite the finding that drove them (e.g.
  raw `r||s` vs DER encoding decided and later formally signed off), and genuine trade-offs are
  named as open rather than glossed over (display-collision gap, custom-entity-label leak,
  `Envelope::device_ref` unused).
- **Strategic leverage:** Medium — it is the gating dependency for `veil-observatory` ("no
  central plane can be built honestly until the emitter is structurally incapable of carrying a
  raw value") and its ECDSA work directly unblocked two sibling repos' cross-repo ratifications
  this week.

### Cognitive load score
**Medium.** The code itself is well-modularized (8 single-responsibility crates with a
frozen interface contract), but the documentation surface is large — `docs/decisions.md` is
~314 KB, `docs/session-log.md` ~123 KB, `docs/next-actions.md` ~51 KB — all still actively
maintained and internally consistent, but a real onboarding cost for anyone new picking this up
cold. The governance metadata drift found above (unset version, stale maturity fields, stale
rename note) adds a small amount of load on top: someone trusting `.hekton/project.yaml` at face
value would be misled on two counts.

### Recommendation
**Keep.**

### Rationale
Against `promotion-rules.md`'s "Project → Archive" trigger: not applicable — 45 commits in 30
days, most recent same-day as this review, no dormancy. Against "Platform Component → Factory
Standard": not applicable — this is already the terminal factory-output classification for this
product, not a platform component seeking further promotion; `architecture.promotion_candidate:
false` and `promotion_target: none` in its own project.yaml are consistent with that and are not
contradicted by anything found here. Against factory-output versioning
(`promotion-rules.md`'s v0→beta→v1.0 table): the project has never had its `version` field set,
and on the evidence gathered it should stay **v0** for now, not bump to `beta` — the "first real
use" bar for `beta` implies the product's actual value proposition (masking the model's context)
being exercised in a real workflow, and the README's own status box says that is not yet true
end-to-end (`vg run` covers the tool-call path only; no subcommand starts `vg-proxy`; no real TLS
to Anthropic yet). The ECDSA/telemetry cross-repo proof is real production-code exercise, but of
the telemetry side-channel, not the core masking value proposition.

This is not a "Simplify" or "Watch" case either: the complexity present (8 crates, versioned
interface contracts, a formal eval harness) is load-bearing for a privacy-critical tool and is
being actively managed, not accumulating unchecked. The one live problem found in this review —
red `cargo-deny` on `main` from a yanked transitive crate — is small and mechanical, not a sign
of quality decay, but it did slip past two consecutive merges undetected, which is worth a
process note, not a lifecycle change.

### Next action
1. Fix the current CI failure on `main`: `cargo update -p wnaf` (or pin/replace the `p256`
   dependency chain) to clear the yanked-crate `cargo-deny` failure — trivial, but real and
   currently red.
2. Set `.hekton/project.yaml`'s `version` field explicitly to `v0` (it has never been set) and
   refresh `architecture.maturity_date`/`last_validated` (both stuck at 2026-06-30/2026-07-26
   despite two more months of validated work) so the control file reflects reality.
3. Correct `.hekton/project.yaml`'s stale comment/field claiming the GitHub rename to
   `veil-proxy` is "deliberately deferred" — it already happened (confirmed via `gh repo view`).
4. No lifecycle action needed beyond the above — re-review at the next natural milestone (M5 real
   TLS to Anthropic, or `vg-proxy` getting an actual CLI startup path), whichever lands first.
