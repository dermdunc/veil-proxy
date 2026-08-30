# Veil Proxy

**The masking data plane of [VeilGremlin](#the-veilgremlin-product-family).** Veil Proxy keeps real PII and sensitive enterprise identifiers out of an AI coding agent's cloud context. It masks automatically on your laptop in milliseconds and reverses only locally, explicitly, and auditably, so the cloud model works against placeholders instead of real values.

> **Invisible governance for AI coding agents. The cloud model sees placeholders, not the values behind them.**
>
> That's the product's target state. **Today, `vg run` delivers it on the tool-call path only** —
> file reads, diffs, and terminal output the agent's tools touch. It does not yet mask the
> prompt/context path (typed input, conversation history, MCP context) or sit at model egress,
> so those aren't guaranteed masked yet. The local masking proxy that closes this gap exists in
> `vg-proxy` and, through M4, masks requests and demasks responses end-to-end — but only
> against a mock upstream over plain HTTP; real TLS to `https://api.anthropic.com` is M5, not
> yet built, and **no `vg` subcommand starts the proxy at all yet** — `vg run` still only wires
> the hooks. See [Status](#status).

**Classification:** factory-output (Hekton) · **Owner:** dermdunc · **Status:** built through T10, M1-M4 merged, contract v1.4, 443 passing tests · eval verdict: **GO** — the precision NO-GO that stood here for weeks is closed (false-positive rate **0.0%**, was 16.7%).

> **Naming:** this repo was called `veilgremlin` until 2026-07-26. VeilGremlin is now the name of the **end-to-end product family**, and this repo is `veil-proxy`, the component that does the masking. The product's runtime identity is deliberately unchanged — the state directory is still `.veilgremlin/`, the macOS keychain service is still `com.veilgremlin.vault`, and the CLI is still `vg`. Those name the product, not the repo, so existing installs and vaults keep working.

## The problem

Agentic coding tools (Claude Code, Codex, Cursor, Cline) pull in far more than a prompt: files, diffs, terminal output, logs, tickets, MCP resources. Any of it can carry real customer or employee data. Guardrails and DLP scanners inspect data *after* the provider already holds it. VeilGremlin changes *what leaves the laptop in the first place*, which is what privacy and risk teams actually care about.

## What Veil Proxy is

Veil Proxy is **not** another guardrail or DLP scanner. It is a file-aware, **reversible-pseudonymisation** layer that sits on the local hot path of a coding-agent turn and keeps the reversal material on your laptop.

**The one hard rule (as designed):** *unless the model is local and explicitly approved, Veil Proxy does not hand it real PII or sensitive enterprise identifiers that its detectors have caught.*

That rule is scoped to what the detectors catch, and that is the honest boundary. Detection is deterministic and measured, not perfect: low-entropy or prose-style passwords, structured licence keys, and dotenv-shaped content with no filename hint can currently pass through undetected. Precision now clears its gate (see [Status](#status)), but recall gaps are a separate axis and some remain. Treat Veil Proxy as a strong data-minimisation control, not an absolute guarantee that no real value can ever reach the model.

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

**Before / after** — `vg diff --masked` run against the `incident-log-multi-entity` sample's `content` from `corpus/seeded/manifest.json` (the anchor fixture above), saved locally as `incident.log` (there's no such file checked into the repo — the corpus stores every sample inline in `manifest.json`, see `corpus/seeded/README.md`). Real output, not illustrative:

```
$ vg diff --masked incident.log
2026-07-18T09:14:02Z ERROR customer EMAIL_001 (acct IBAN_001) failed login from INTERNAL_IP_001
escalated to EMAIL_002 callback PHONE_001 sort code SORT_CODE_001
session token [REDACTED:SECRET] flagged for rotation

--- veilgremlin ---
original: 268 bytes; masked: 215 bytes
masked 2 x EMAIL
masked 1 x PHONE
masked 1 x IBAN
masked 1 x SORT_CODE
masked 1 x INTERNAL_IP
masked 1 x SECRET
pack saved: .veilgremlin/packs/43cc9542-f3be-4bc0-8f9b-e2de0e205ab7.json (use `vg demask --from` to reverse)
```

The emails, IBAN, phone number, sort code, and internal IP are reversibly masked to stable placeholders; the session token is irreversibly redacted (never vaulted). `vg demask --from <pack>` restores the original values locally.

## Status

Built through task T10, with M1-M4 merged; interface contract at v1.4; 443 tests passing.

Veil Proxy runs its own Go/No-Go eval harness (`vg bench`) over a synthetic seeded corpus. The verdict is **GO**. The false-positive rate is **0.0%** against a `<3%` gate, down from 16.7% — closed by targeted detector fixes (git-SHA context exclusion in the entropy detector, ISBN-13/10 checksum and ZIP+4 shape exclusion in the phone detector) that went through four adversarial review rounds before landing. Also passing: zero raw PII leaked (11/11), secret recall 5/5, PII recall 15/15, placeholder consistency 10/10, and cold-hook end-to-end p95 of 17.0 ms under the 50 ms budget.

**This section previously advertised that 16.7% failure for weeks, on purpose.** A privacy tool that measures itself against a bar and tells you when it has not cleared it is a privacy tool you can check. That is still the policy — the number moved because the bug was fixed, not because the bar moved.

**Two honest caveats on the current state:**

- The **display-collision measurement** is a banked measurement rather than a gate: **1 of 3 collision samples still corrupted** (re-run 2026-08-01, unchanged from the 2026-07-22 measurement — the false-positive-rate fix did not touch this code path). `vg bench`'s own recommendation stands: collision-avoiding minting at intern time (skip an ordinal whose display already occurs in the raw buffer), not yet implemented. See `docs/next-actions.md`.
- A **latent leak is partially closed, one path still open**: the two sites that could interpolate a policy-declared custom entity class *name* into text sent to the model (`vg-core/src/api.rs`, `vg-core/src/keying.rs`) were fixed 2026-08-01 — `redaction_marker` now returns a fixed `[REDACTED:CUSTOM]` marker regardless of the class name, with a dedicated regression test. A third, distinct path stays open: `vg-audit` stores the class name verbatim in its versioned log format, and `vg audit` pretty-prints stored events without re-deriving safe display text — so a wrapped agent shelling out to `vg audit` can still read a `Custom` class name back. Not fixed yet, deliberately (the on-disk format is versioned and may already have historical data depending on it). See `docs/next-actions.md`.

## The VeilGremlin product family

VeilGremlin is the end-to-end product. This repo is one component of it.

| Component | What it is | Status |
|---|---|---|
| **veil-proxy** (this repo) | The masking data plane: on-laptop parse → detect → vault → policy → masked pack, plus the agent adapters and the `vg` CLI | Built through T10 / M4 |
| **veil-foundations** | Terraform for Amazon Bedrock as an LLM invocation control plane — which models can be invoked, by whom, under what guardrails, logging and cost attribution | Repo created, plan merged |
| **veil-custodian** | Holds the device-pseudonym → user mapping, so the observatory can key on pseudonyms and never hold identity. Resolution is an explicit, authorised, audited act | Repo created, plan merged |
| **veil-observatory** | Telemetry, audit and evidence plane — what a fleet of proxies reports centrally, and what it provably never reports. Includes the CSOC + legal/risk dashboard | Designed, deliberately not yet created |

The proxy minimises what leaves the laptop; `veil-foundations` constrains what can be invoked at all. They are defence in depth, not alternatives.

`veil-observatory` is gated behind the telemetry-type work in `veil-proxy` — no central plane can be built honestly until the emitter is structurally incapable of carrying a raw value.

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
| [Hooks Runbook](docs/runbook-hooks.md) | How to actually build, install, and run the `vg run`/hook path locally |

## Contributing

Built inside the Hekton agentic factory (internal build-process scaffolding is intentionally not part of the public tree). To contribute here, see [CONTRIBUTING.md](CONTRIBUTING.md).
