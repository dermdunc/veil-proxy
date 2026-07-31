# Walkthrough — T01: Cargo Workspace + CI + Supply-Chain Skeleton

**Date:** 2026-07-14

## What changed

Built VeilGremlin's actual Cargo workspace: nine crates (`vg-core`, `vg-detectors`,
`vg-parsers`, `vg-vault`, `vg-policy`, `vg-audit`, `vg-cli`, `vg-adapters-claude`, `vg-bench`)
matching the squad-per-crate ownership plan in `docs/architecture/agent-factory-plan.md`. Each
crate is an empty skeleton — a doc comment describing its eventual role and which task builds
it out — because `docs/architecture/interface-contracts.md` names Task T02 (Squad 0) as the
owner of the canonical shared types and trait definitions everything else implements against.
T01's job was the room to build in, not the building.

Also added: `.github/workflows/ci.yml` (fmt, clippy `-D warnings`, cargo-deny, cargo-audit,
`build --locked`, bench compile-check), `deny.toml` (conservative license/advisory/source
policy), and a release skeleton (`release/README.md`) that names SBOM and signing as explicit,
tracked stubs rather than silently skipping them.

## Why it matters

This is VeilGremlin's actual first line of code, and the factory's first real end-to-end build
event: a task dispatched through `agentic-control-tower`'s DAG orchestrator, routed via
`engine-gateway-lab`, landing as a real PR. Every later task (T02–T11) builds directly on this
workspace's shape and CI — a wrong crate boundary or lint config here would compound across five
parallel squads in Wave B.

## How it fits Hekton

VeilGremlin is a factory-output product; this build is the dogfood for the wider Hekton v1
platform's plumbing (ACT dispatch → engine-gateway → adapter → verify). See
`~/hekton`'s `docs/plans/veilgremlin-v1-dogfood-runbook-v1.md` for that side of the record.

## What is NOT verified yet

- **CI was red on first push** — `cargo-deny-action@v2` is a Docker container action, which
  only runs on Linux-hosted GitHub runners; the `deny` job was set to `runs-on: macos-latest`
  and failed on every push. Caught via doubt-driven-development (fresh-context review that
  independently checked the real GitHub Actions run rather than trusting the "PASS" claims this
  same session had written into `docs/decisions.md`/`docs/session-log.md`/the PR body). Fixed by
  changing that one job to `runs-on: ubuntu-latest`; re-verify the actual CI run goes green after
  this fix lands, don't just trust the YAML looks right.
- No unit tests exist — honestly inapplicable today (every crate is a doc-comment stub with no
  logic), but this is a placeholder, not evidence the code works.
- No Linux CI job for the workspace build itself (only the `deny` job now runs on Linux) — the
  design spec commits to cross-platform (Windows DPAPI, Linux Secret Service) but there's no
  automated coverage for that yet. Not a T01 requirement; flagged as an open gap, not a decision.
- Branch name (`gateway/run-20260714-T01`, from the dispatch tooling's own convention) doesn't
  match `agent-factory-plan.md`'s documented `feat/<squad>-<task-id>-<slug>` convention. Not
  renamed (the branch is already pushed with an open PR) — flagged, not fixed, in
  `docs/decisions.md`.

## What the human should do next

- Confirm the CI fix actually goes green on the real PR (not just "the YAML looks right") before
  merging.
- Review the crate layout against `interface-contracts.md` once more before merging — nothing
  here is load-bearing yet, so this is the cheapest point to catch a wrong boundary.
- After merging, dispatch/build T02.
