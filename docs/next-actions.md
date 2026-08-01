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
- [ ] **Audit-log third path**: `vg-audit/src/record.rs:212` serialises `{"custom":"<name>"}`, and
      `vg-cli/src/main.rs:476-478` claims in a doc comment that audit events "leak nothing" —
      false for the `Custom` arm. Local-only today (never reaches a remote-model-prompt or
      observability-sink destination, so out of scope for *this* fix, which was specifically
      about text reaching the model); a hard prerequisite for v1.5 telemetry. Still open.
- [ ] **Phase 1a** — close the six raw-capable `String` surfaces, land the `interface-contracts`
      v1.4 → v1.5 bump (first bump in the project's history with real downstream callers: 7
      crates, ~221 tests), then `TelemetryEvent` + `TryFrom` in `vg-core`.

M3 (request masking) remains the standing product priority; the leak fix is small and should not
displace it for long.

## Session Update: 2026-08-01 — Close the custom-entity-label leak

- [ ] Human reviews and merges PR; A3 still needs to bank vg bench's display-collision number; audit-log third path (record.rs:212) remains open
