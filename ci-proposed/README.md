# Proposed CI changes

`.github/workflows/` is a protected path (`hekton-protected-path-hook`, installed
2026-07-31) — no agent may commit to it without `HEKTON_ALLOW_PROTECTED=1`, which this
loop must never set (safety envelope, `veil-compliance-2026-08-01`). This directory holds
a ready-to-install replacement for human review instead.

## What changed vs. the current `.github/workflows/ci.yml`

The `bench` job is promoted from **compile-only** (`cargo bench --workspace --locked
--no-run`) to a **real gate**: it now actually runs `vg bench` over the embedded seeded
corpus, and lets the command's own exit code gate the job. Per `crates/vg-cli/src/main.rs`'s
`cmd_bench`, the exit code **is** the Go/No-Go verdict — `Go` → success, `NoGo` or
`Incomplete` → failure — so no separate assertion step is needed.

This was previously an explicit gap: `docs/next-actions.md` notes "no baseline management
yet" as the reason `vg bench` wasn't gated, and the eval's own numbers (display-collision,
FP rate) were being banked by hand in prose (`README.md`, `docs/risks.md`,
`docs/decisions.md`) rather than continuously checked. Promoting the job doesn't remove
that manual banking discipline — the numbers still need a human to update the prose when
they move — but it does mean a regression that flips the verdict to NoGo is caught on the
next PR, not the next time someone happens to run `vg bench` by hand.

**Everything else in the file is unchanged** — same jobs, same runners, same toolchain pin.

## To install

```bash
HEKTON_ALLOW_PROTECTED=1 cp ci-proposed/ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: promote vg bench from compile-only to a gating job"
```

Setting `HEKTON_ALLOW_PROTECTED=1` **is** the human approval record for this change
(`.git/hooks/pre-commit`'s own convention) — this command is written for a human to run,
not for this loop to run itself.
