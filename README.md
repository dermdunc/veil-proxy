# Veil Proxy

**The masking data plane of [VeilGremlin](#the-veilgremlin-product-family).** Veil Proxy keeps real PII and sensitive enterprise identifiers out of an AI coding agent's cloud context. It masks automatically on your laptop in milliseconds and reverses only locally, explicitly, and auditably, so the cloud model works against placeholders instead of real values.

> **Invisible governance for AI coding agents. The cloud model sees placeholders, not the values behind them.**

**Classification:** factory-output (Hekton) · **Owner:** dermdunc · **Status:** built through T10, contract v1.4, 221 passing tests · eval verdict: **honest NO-GO on precision** (false-positive rate 16.7%), remediation in progress before T11 sign-off.

> **Naming:** this repo was called `veilgremlin` until 2026-07-26. VeilGremlin is now the name of the **end-to-end product family**, and this repo is `veil-proxy`, the component that does the masking. The product's runtime identity is deliberately unchanged — the state directory is still `.veilgremlin/`, the macOS keychain service is still `com.veilgremlin.vault`, and the CLI is still `vg`. Those name the product, not the repo, so existing installs and vaults keep working.

## The problem

Agentic coding tools (Claude Code, Codex, Cursor, Cline) pull in far more than a prompt: files, diffs, terminal output, logs, tickets, MCP resources. Any of it can carry real customer or employee data. Guardrails and DLP scanners inspect data *after* the provider already holds it. VeilGremlin changes *what leaves the laptop in the first place*, which is what privacy and risk teams actually care about.

## What Veil Proxy is

Veil Proxy is **not** another guardrail or DLP scanner. It is a file-aware, **reversible-pseudonymisation** layer that sits on the local hot path of a coding-agent turn and keeps the reversal material on your laptop.

**The one hard rule (as designed):** *unless the model is local and explicitly approved, Veil Proxy does not hand it real PII or sensitive enterprise identifiers that its detectors have caught.*

That rule is scoped to what the detectors catch, and that is the honest boundary. Detection is deterministic and measured, not perfect: low-entropy or prose-style passwords, structured licence keys, and dotenv-shaped content with no filename hint can currently pass through undetected, and the T10 eval returned a **NO-GO** on precision (see [Status](#status)). Treat Veil Proxy as a strong data-minimisation control, not an absolute guarantee that no real value can ever reach the model.

> **Positioning:** a technical and governance control **supporting** data minimisation, privacy by design, auditability, and risk-based adoption. Not a GDPR or EU AI Act "compliance" guarantee.

## How it works

A small hardened **Rust core** runs entirely on the developer laptop: parse → detect → vault → policy → masked pack. The path is deterministic and local, with no network and no LLM, and is gated in CI against a latency budget (measured tens of milliseconds end to end). Thin adapters wire it into **Claude Code on Amazon Bedrock** through hooks plus a `vg run` wrapper. An encrypted **SQLCipher vault** holds the reversible mappings; an audit log records what was masked, blocked, and demasked without storing raw values.

Handling is policy-driven, with four classes: **Mask** (reversible), **IrreversibleRedact** (one-way, never vaulted), **Block** (content never sent), and **Pass**. Two destinations, `remote-model-prompt` and `observability-sink`, are hard-denied for raw values by design and are conformance-tested.

**On demask authorisation (be precise):** demasking is explicit, local, and audited. In Phase 1 it is a single-user local trust model, so `--actor`/`--role` are **self-asserted attribution recorded in the audit trail, not authentication**. Any local process (including the wrapped agent's own shell) could invoke `vg demask`. The genuine enforcement boundary is the hard-deny on remote/observability destinations; the actor gate is an honest audit label, and hardening it is tracked for T11.

## Quickstart (the `vg` CLI)

```
vg run -- claude "Debug this incident and propose a regression test"   # wrap an agent with masking hooks
vg inspect incident.log                    # preview what WOULD be masked (classes + spans, never values)
vg diff --masked incident.log              # show the masked rendering and stats, and store a reversible pack
vg demask --from pack.json --to local-patch   # reverse a stored pack into a local destination
vg audit last                              # most recent audit event (refs/counts only)
```

`vg demask --from` takes a **stored pack JSON** written by the hooks or by `vg diff`, not a raw `.patch`. Destinations are kebab-case: `local-patch`, `local-test-fixture`, `local-explanation-buffer` (the two remote destinations are hard-denied). Run `vg --help` for the full surface (`vg policy check`, `vg vault stats`, `vg bench`).

## Status

Built through task T10; interface contract at v1.4; 221 tests passing.

VeilGremlin runs its own Go/No-Go eval harness (`vg bench`) over a synthetic seeded corpus, and the current verdict is an honest **NO-GO on false-positive rate: 16.7%** against a `<3%` gate (entropy 13.3%, phone 40%), plus a display-collision corruption found in 1 of 3 mask→demask round-trips. Passing gates in the same run: zero raw PII leaked (11/11), secret recall 5/5, PII recall 15/15, placeholder consistency 10/10, and cold-hook end-to-end p95 of 17.0 ms under the 50 ms budget.

We publish that failing number on purpose. A privacy tool that measures itself against a bar and tells you it has not cleared it yet is a privacy tool you can check. The green harness reporting red product numbers is the tool working. **Next:** close the precision NO-GO (entropy and phone false positives, and collision-avoiding minting) ahead of T11 review and sign-off.

## The VeilGremlin product family

VeilGremlin is the end-to-end product. This repo is one component of it.

| Component | What it is | Status |
|---|---|---|
| **veil-proxy** (this repo) | The masking data plane: on-laptop parse → detect → vault → policy → masked pack, plus the agent adapters and the `vg` CLI | Built through T10 / M2 |
| **veil-observatory** | Telemetry, audit and evidence plane — what a fleet of proxies reports centrally, and what it provably never reports | In design |
| **Dashboard** | Sits on proxy + observatory. Two audiences: CSOC for near-real-time usage monitoring, and legal/risk/privacy for after-the-fact audit and evidence | In design |
| **veil-walled-garden** | Terraform for Amazon Bedrock as an LLM invocation control plane — which models can be invoked, by whom, under what guardrails and logging | In design |

The proxy minimises what leaves the laptop; the walled garden constrains what can be invoked at all. They are intended as defence in depth, not alternatives.

See [Product family architecture](docs/architecture/product-family.md) for component boundaries, trust boundaries, and the open questions — including how a central observatory is reconciled with this repo's local-first promise.

## Documentation

| Doc | What |
|---|---|
| [Requirements & Design Spec](docs/spec/requirements-and-design-spec.md) | Canonical spec: threat model, vault, policy, latency budget, diagrams, Go/No-Go |
| [Interface Contracts](docs/architecture/interface-contracts.md) | The crate seams, version-controlled under a change protocol (v1.4) |
| [Work Breakdown (T01–T11)](docs/architecture/work-breakdown.md) | Task DAG with owners and acceptance criteria |
| [Agent Factory Build Plan](docs/architecture/agent-factory-plan.md) | How teams of agents build it: squads, waves, gates |
| [Architecture index](docs/architecture.md) · [Decisions](docs/decisions.md) · [Risks](docs/risks.md) · [Next Actions](docs/next-actions.md) | Reference and receipts |
| [Deep Research Report](docs/research/deep-research-report.md) | Source analysis |
| [Build Log](docs/build-log/README.md) | The same history, told as a readable, dated narrative |

## Project conventions

Built inside the Hekton agentic factory. Agents follow the repo's `CLAUDE.md` / `AGENTS.md`: inspect `.hekton/project.yaml` before structural changes, record decisions in `docs/decisions.md`, keep `docs/session-log.md` current, and use session-scoped commits. Vault mutation is not allowed by default.
