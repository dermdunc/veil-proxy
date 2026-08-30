# Contributing to veilgremlin

Thanks for your interest — this is a solo-maintainer project, so please read the honesty
section below before opening anything, it'll save you a confusing wait.

## Solo-maintainer honesty

This repo has one maintainer working on it alongside other projects. Response times on
issues and PRs are irregular — could be days, could be weeks. Silence isn't rejection; it
usually just means the maintainer hasn't gotten to it yet. If something's urgent or you
want a faster read, say so in the issue/PR itself.

## Reporting a bug

Open an issue using the bug report template. Include:
- What you expected to happen vs. what actually happened.
- The exact command you ran (`vg ...`) and its output.
- Your OS and the output of `vg --version` (or `cargo pkgid -p vg-cli` if building from
  source).

## Proposing a change

1. Open an issue first for anything non-trivial (a new detector, a CLI subcommand, a
   architecture change) so we can align before you invest time in an implementation.
2. Fork the repo, create a branch, make your change.
3. Before opening a PR, run the same commands CI runs (`.github/workflows/ci.yml`):
   ```bash
   cargo build --workspace --locked
   cargo test --workspace --locked
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo fmt --all --check
   ```
4. Open a PR against `main` using the PR template. Keep it scoped — one logical change per
   PR is much easier to review than a bundle of unrelated fixes.

## What a good PR looks like here

- Tests for new behavior (this repo takes its own eval harness seriously — `vg-bench`'s
  Go/No-Go gate is not decorative, see `docs/architecture/`).
- No new PII/secret detection logic without a corresponding fixture in `corpus/seeded/` and
  an explanation of the detection approach.
- Clippy and fmt clean — CI enforces both.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're
expected to uphold it.
