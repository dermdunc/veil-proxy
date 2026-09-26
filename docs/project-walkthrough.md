# VeilGremlin: Plain-English Project Walkthrough

## What this project is in one paragraph

VeilGremlin is a local-first privacy shield for "vibe coding". When a developer uses an AI coding agent (like Claude Code) that sends code, logs, and tickets to a cloud model, VeilGremlin sits on the laptop *in front of* that model. It automatically swaps real personal data and sensitive company identifiers for stable placeholders before anything leaves the machine, then lets the developer put the real values back locally, explicitly and auditably, after the model replies. The cloud model works against placeholders instead of the real values behind them.

## The simple analogy

It is a translation booth at the door. Outgoing messages get their secrets swapped for code-words (`EMAIL_001`, `ACCOUNT_ID_014`) on the way out; the reply comes back in code-words; and only you, standing inside the booth, hold the key to translate the code-words back, and only into local files, never back out to the cloud.

## What problem we are solving

AI coding agents pull in far more than a chat prompt: files, diffs, terminal output, logs, tickets, MCP resources. Any of those can contain real customer or employee data. Guardrails and DLP scanners inspect data *after* the provider already has it. VeilGremlin changes *what leaves the laptop in the first place*, which is what privacy and risk teams actually care about, and which aligns with data-minimisation and privacy-by-design expectations (without claiming "compliance").

## What it does today

The product is built and working end to end. A hardened Rust core does the masking on the local hot path, backed by:

- **Five deterministic detectors** (email, phone, IP, IBAN/sort-code, and an entropy-based secret detector).
- **Parsers** for logs, diffs, JSON/YAML/TOML/CSV, `.env`, and Rust source (tree-sitter), so detection is span-aware and structure-aware.
- **An encrypted SQLCipher vault** that holds the reversible placeholder↔value mappings, with the database key wrapped by the OS keychain.
- **A three-layer policy engine** that decides, per entity and per artefact, whether to mask, irreversibly redact, block, or pass, with two remote destinations hard-denied for raw values by design.
- **An append-only audit log** that records what was masked, blocked, and demasked, without storing raw values.
- **A Claude Code adapter and the `vg` CLI**, so the same engine the hooks use is also driveable by hand (`vg run`, `vg inspect`, `vg diff`, `vg demask`, `vg audit`).
- **A Go/No-Go eval harness** (`vg bench`) that runs the whole thing over a synthetic corpus and prints a verdict.
- **A local masking proxy** (`vg-proxy`) that sits between Claude Code and the model API: it masks each request before it leaves the machine and puts the real values back into the reply. As of 2026-09-26 it handles real multi-turn, tool-using sessions: the model's own "thinking" is carried back and forth untouched, tool calls come back with real values so edits land on the real file, and ordinary file paths are no longer mistaken for secrets (issue `veil-proxy#86`). A live re-run by veil-demo is still the final check.

## How the pieces fit together

The core does the work on a deterministic "hot path": parse → detect → vault → policy → masked pack, all locally, with no network and no LLM, measured in tens of milliseconds and gated in CI. Thin adapters wire it into Claude Code (hooks plus a `vg run` wrapper) and, later, into LiteLLM gateways and cloud-agent worktrees. The encrypted vault holds the reversible mappings; the audit log records what happened without storing raw values.

## What it does NOT do yet, and what it does not claim

- **Detection is measured, not perfect.** The eval harness returned a NO-GO on precision: too many false positives (see "Current confidence"). Separately, there is a known false-negative class: low-entropy or prose-style passwords, structured licence keys, and dotenv-shaped content with no filename hint can currently pass through undetected. So the plain promise is "the cloud model sees placeholders instead of the values the detectors caught", not "no real value can ever leak". One concrete case, seen in a real session: if a tool prints a file one character at a time (`od -c`), no detector recognises the pieces, and the model can reassemble the value (`RISK-0015`).
- **Demask authorisation is attribution, not authentication.** Reversal is explicit, local, and audited, but in this single-user Phase 1 the `--actor`/`--role` labels are self-asserted for the audit trail, not an enforcement gate. The genuine boundary is the hard-deny on sending raw values to a remote model or observability sink. Tightening the actor gate is a follow-up.
- **Warm-path local NER** (GLiNER) is designed but off by default.
- **LiteLLM gateway, MCP server mode, CI/CD mode, cloud-agent packaging** are later phases.
- **Synthetic-data generation and quasi-identifier leakage scoring** are later phases.

## Current confidence level

Design: high, grounded in the research report and an explicit Go/No-Go bar. Implementation: the build is complete through the T10 eval, reviewed, and measured against a synthetic corpus. The open item is a measured false-positive rate above the Go/No-Go bar (16.7% overall; entropy 13.3%, phone 40%), plus a display-collision corruption seen in 1 of 3 round-trips. Both are being remediated before T11 review and sign-off. The eval harness itself is green and honest: it reports the product's red numbers rather than hiding them, which is exactly what it is for.

## Open questions

- Multilingual entity coverage; quasi-identifier leakage; screenshot OCR boundary; graph-based context preservation; exact Cedar/OPA choice for enterprise policy; repo- vs session-scoped placeholder stability default. (See spec § Open Questions.)

## Where the detailed history lives

For the same story told as a readable, dated narrative rather than a technical changelog, see **`docs/build-log/`**, starting at [`docs/build-log/README.md`](build-log/README.md). The full technical record is in [`docs/decisions.md`](decisions.md) and [`docs/session-log.md`](session-log.md).
