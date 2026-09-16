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
- [x] ~~**Local masking proxy + daemon — M3, request masking (Anthropic direct,
      non-streaming).**~~ **Built 2026-08-24** — `vg-proxy` now actually does the job: parses a
      real Anthropic Messages API body (`schema/anthropic.rs`'s `ContentBlockKind` +
      `mask_request.rs`'s generic-`Value` walk — deliberately not a typed struct, so every field
      it doesn't name round-trips untouched instead of silently dropping), masks every
      text-bearing field through the real `vg_core::mask` pipeline (`tool_use.input`/
      `tool_result.content` recursively; `document`/`image`/anything unrecognized blocks the
      *whole* request), forwards the masked body to an upstream over plain HTTP
      (`upstream.rs`, explicit header allow-list), and returns the response verbatim — response
      *de*masking is M4, not this milestone. `Daemon` (`daemon.rs`) now holds a full `Policy` +
      detector/parser registries, mirroring `Engine::open`'s assembly, but deliberately **not**
      real production state-dir/keychain discovery (a real `vg-proxy` daemon binary is separate,
      unscoped, later work — see below). `vg run` (`vg-cli/src/main.rs`) now injects
      `CLAUDE_CODE_ATTRIBUTION_HEADER=0` into every launch. Two doubt-driven-development rounds
      (a stalled-but-still-useful single-model pass, then Codex cross-model) found and fixed
      five real issues — most notably a present-but-invalid `X-VG-Namespace` header silently
      falling back to port-resolution instead of failing closed, which M2's own doubt-pass round
      had explicitly warned "whichever milestone adds header-extraction code" would hit — see
      `docs/decisions.md`'s 2026-08-24 entry for the full list. `cargo build/clippy -D
      warnings/fmt --check/test` all clean, workspace-wide.
      **Named gaps, not solved by this milestone:** response demasking (M4, now built, see
      below); streaming (M6); real production state-dir/keychain discovery for a `vg-proxy`
      daemon *binary* (this milestone's `Daemon` constructors take already-resolved config,
      matching what tests need, not a real running service); reaching the real
      `https://api.anthropic.com` over TLS (`upstream.rs` is plain-HTTP-only, M5's job);
      `document` content-block real handling (text vs. base64 vs. url); a block partway through
      a request doesn't roll back vault interning already done by earlier fields in the same
      request (not a leak — the vault is local and encrypted — but real audit-trail untidiness,
      named not fixed).
- [x] ~~**Local masking proxy + daemon — M4, response demask (non-streaming).**~~ **Built
      2026-08-24** — closes the "mask outbound, demask inbound" loop: `vg-proxy` now demasks the
      model's response before it reaches the wrapped client, real end-to-end for the first time.
      New `Destination::ProxyResponse` (`vg-core`, additive/`#[non_exhaustive]`) + a matching
      `proxy-response` policy fixture entry. `demask_response.rs` (new) walks a response's
      `content[]`, reusing `vg_core::rehydrate` as a black box (one call per leaf, a synthetic
      `MaskedPack` per call — no `vg_core` internals touched). **Deliberately infallible** (the
      opposite risk shape from request masking): a malformed response or a denied/unresolvable
      binding leaves that leaf's placeholder in place rather than blocking a successful response.
      **Session-store-backed**, not pack-backed — demasks against the namespace's *full*
      accumulated binding store (`SessionShim::bindings_for`), so a placeholder minted by an
      earlier request in the same conversation still resolves in a later response (the plan's
      "H1" case, proven end-to-end with a real two-request HTTP test). `server.rs` recomputes
      `Content-Length` on the rewritten response (verified by an explicit test assertion, not
      just body content). Two doubt-driven-development rounds found and fixed five real issues —
      most notably (round 2, Codex) that round 1's own "demask every content block
      unconditionally" fix (needed because a non-streaming response can carry `thinking`/
      server-tool blocks `ContentBlockKind` never named) was itself too broad: it recursed into
      a block's own structural fields (`type`/`id`/`name`/`signature`) too, and a minted
      placeholder's low-entropy shape (`EMAIL_001`) can plausibly collide with a real tool name
      over a long session, silently corrupting it — closed with a structural-key skip-list and a
      regression test constructing the exact collision. Full findings in `docs/decisions.md`'s
      2026-08-24 M4 entry. `cargo build/clippy -D warnings/fmt --check/test` all clean,
      workspace-wide. **Named gaps, not solved:** unbounded binding-store growth/cloning over a
      long conversation (a real, deferred perf cost — fixing it touches already-merged M2 code);
      everything M3 already named that M4 doesn't touch (streaming, real TLS upstream, production
      daemon bootstrap, `document` real handling, the partial-vault-interning trade-off). **Next
      up: M5 — real Claude Code, Anthropic API-key mode, non-streaming** (first real contact —
      `ANTHROPIC_BASE_URL` pointing at the daemon, a real API key swap, a real sandboxed session;
      also where `upstream.rs` needs real TLS support), per the plan's §10.3 build order.
- [x] **M5/A2 — real TLS client + real Claude Code session — CLOSED 2026-09-14 (veil-ecosystem
      intent `INT-2026-09-13-001`, branch `agent/claude/a2-real-tls-client`).** Built: a real
      `rustls`/`tokio-rustls` TLS client in `upstream.rs` (`UpstreamConfig::real_anthropic()`,
      trust via `rustls-native-certs` — the real OS trust store, not a bundled CA list — switched
      from `webpki-roots` after `cargo deny check licenses` rejected its CDLA-Permissive-2.0
      license), with real WebPKI certificate chain + hostname verification proven against a real
      local TLS server in three new tests (`tests/tls_upstream.rs`: accepts a validly-signed
      right-hostname cert, refuses a right-CA-wrong-hostname cert, refuses an untrusted-CA cert —
      no disabled/bypassed verification anywhere). Also built, pulled forward from M6 mid-mission
      after the live-run proof found the real `claude` CLI always sends `stream: true` (no flag
      forces non-streaming): a minimal, buffer-first SSE response demasker (`stream_demask.rs`,
      selected by `server.rs` on the upstream response's own `content-type: text/event-stream`
      header) that reconstructs each content block's full text across the whole buffered stream
      before ever demasking — sidestepping the SSE chunk-boundary/partial-placeholder question
      this same file named as unanswered, proven with a dedicated regression splitting a real
      placeholder across two delta chunks. `mask_request.rs`'s earlier `stream: true` block is
      removed (superseded). `cargo build/clippy -D warnings/fmt --check/test --locked`,
      `cargo deny check`, and `cargo audit` all clean, workspace-wide.

      **The live-run proof itself then found a real, external blocker (RISK-0014) — and a real,
      cheap fix.** Running `scripts/a2-live-proof.sh` against the real, unmodified `claude` CLI
      found the CLI's own system prompt embeds
      `x-anthropic-billing-header: [REDACTED:SECRET]; cc_entrypoint=sdk-cli;` whenever
      `ANTHROPIC_BASE_URL` points away from the default Anthropic endpoint, which the real API
      then rejects outright. A Codex cross-model consultation (asked to weigh in on the broader
      "sit in front of multiple harnesses" architecture question) surfaced the actual fix: that
      line is Claude Code's own *attribution* block, and Anthropic's own gateway-compatibility
      docs name `CLAUDE_CODE_ATTRIBUTION_HEADER=0` as the documented way to have the CLI omit it
      entirely — which `vg run` (`vg-cli/src/main.rs`) already injects into every launch, for
      exactly this reason, since before this session started; the live-run proof had simply never
      been run through `vg run`, only a direct `claude -p` invocation. Set on the proof script's
      own invocation instead, and **the full live-run proof now passes end to end** against the
      real, unmodified CLI: real TLS, real streaming, real masking/demasking, real subscription
      auth, a synthetic secret correctly masked before egress and demasked in the real response.
      `RISK-0014` closed same day. The bigger "sit in front of Claude Code *and* Codex generally"
      question Codex was actually asked about is still open — its own recommendation (a
      process-scoped explicit forward proxy over system-wide TLS interception, architected around
      a generic transport + per-provider codec) is real follow-on design work, not yet started,
      and Codex named concrete gaps in the current code for that direction (a TLS-terminating
      listener is materially new work; routing/headers/masking are all still Anthropic-specific).
- [x] **Track H, H2b — codec trait extraction — BUILT 2026-09-15** (intent
      `INT-2026-09-14-001`, veil-ecosystem). The Codex-generality gap the M5/A2 entry above
      named ("routing/headers/masking are all still Anthropic-specific") is now closed for the
      routing/masking/demasking/header-forwarding seam specifically: a new
      `crates/vg-proxy/src/codec` module holds a `Codec` trait (route classification,
      request-mask walk, response/SSE demasking, header-forwarding policy), with everything
      previously scattered across `route.rs`/`upstream.rs`/`mask_request.rs`/
      `demask_response.rs`/`stream_demask.rs` now living under `codec::anthropic` as that
      trait's sole implementation. `route.rs`, `upstream.rs`, and `server.rs` hold zero
      Anthropic-shaped identifiers at the top level (grep-verified). **Track H fork F4
      (header-forwarding policy) decided as part of this milestone**: prefix allowlist
      (`anthropic-*`, `x-claude-code-*`) + five named singletons (the pre-existing fixed list,
      unchanged) + a credential-shaped denylist that wins over any prefix match — see this
      file's own `docs/decisions.md` entry for the full record. `scripts/a2-live-proof.sh`
      still passes end to end, unregressed. Two review rounds (fresh-context single-model,
      then Codex cross-model) found and fixed real issues: a header-misclassification bug that
      would have spammed the F4 review-candidate log on every real request; a denylist gap
      missing "key"/"auth" substrings despite the codec's own named singletons being
      `x-api-key`/`authorization`; a real defense-in-depth regression in `upstream::forward`
      (now documented rather than silently accepted, since fixing it would mean putting
      codec-shaped policy back into the transport layer, contradicting D-H-1); and a missing
      observability path for headers silently denied by the credential-shaped pattern (now
      surfaced via `SelectedHeaders::denied_by_credential_pattern`). `cargo build/clippy/fmt/
      test --locked` and `cargo bench --workspace --locked --no-run` clean, both locally and
      in this PR's own CI. `cargo deny check`/`cargo audit` FAIL in this PR's real CI on the
      same pre-existing `RUSTSEC-2026-0285` (rustls 0.23.44) finding a separate branch already
      fixes but hasn't merged — not a regression this milestone introduced (see
      `docs/decisions.md`'s 2026-09-15 entry for the full correction). **Named, not solved by
      this milestone:** `MaskedRequest`/
      `MaskRequestError` are reused as-is by the `Codec` trait rather than pre-generalized for
      a second codec (H3's own open question); `upstream::forward`'s new header parameter is a
      caller-trusted slice with no self-enforced policy, unlike the pre-H2b fixed constant
      (named explicitly in `upstream.rs`'s own doc comment, not silently accepted). H2c (bounds
      and timeouts) and H1 (Codex interception spike) remain open under the same intent.
- [x] **Track H, H2c — request/response bounds and five named timeouts — BUILT 2026-09-15**
      (same intent `INT-2026-09-14-001`, built on H2b's own branch to avoid a conflict since
      both touch `upstream.rs`/`server.rs`). Closes plan §1.2 item 9 in both directions:
      `server.rs::collect_body` (previously an unbounded `.collect()`) and
      `upstream.rs::buffer_response` are both now bounded (`MAX_REQUEST_BODY_BYTES` 32 MiB,
      `MAX_RESPONSE_BODY_BYTES` 64 MiB, the latter configurable per `UpstreamConfig` for
      testing) — an oversized body fails closed (413 request-side, mapped-502 response-side),
      never OOMing. Five separately-named timeouts (`upstream.rs::Timeouts`): `connect`,
      `response_headers`, `idle_body`, `streaming_idle` (300s, matching GROUND-13/14's real
      Claude Code/Codex vendor numbers so a genuinely slow-but-alive stream survives),
      `total_request` — each with its own dedicated, fast (no real multi-minute wait) test in
      the new `crates/vg-proxy/tests/upstream_timeouts.rs` (8 tests), plus a "survives" test
      proving a real mid-length pause under `streaming_idle` doesn't get killed. A
      fresh-context single-model review found and fixed two real bugs, both in the test suite
      itself, not the production code: a near-zero connect-timeout test that flaked under load
      (raced against a real fast connect, non-deterministically), fixed by switching to a
      real, reliably-unanswered target (`192.0.2.1`, RFC 5737 TEST-NET-1); and a classic
      async-Rust footgun (an `_stream`-named closure parameter never referenced inside its
      `async move` body, so it dropped — closing the connection — before the future was ever
      polled). A following Codex cross-model pass found and fixed four more real issues (full
      account in `docs/decisions.md`'s 2026-09-15 entry): the strengthened slow-stream test's
      original single-pause design didn't actually distinguish correct per-frame idle-reset from
      a fixed-deadline regression (rewritten to two gaps summing over the budget, each
      individually under it); `response_headers`'s own doc/error wording overclaimed its scope
      (it also covers request upload, not just waiting for headers); the revised connect-timeout
      test's TEST-NET-1 approach was itself non-hermetic (RFC 5737 only recommends, doesn't
      guarantee, silent dropping — the critique's own sandbox got an immediate
      `PermissionDenied` there) — replaced with a deterministic loopback TLS-stall design that
      also newly covers `connect`'s TLS-handshake half; and SSE content-type matching was
      neither exact nor case-insensitive, and duplicated between `upstream.rs` and `server.rs`
      (a pre-existing A2 bug this milestone copied into a second location) — now one shared,
      correct implementation. `scripts/a2-live-proof.sh` re-run and passing; `cargo
      build/clippy/fmt/test --locked` (three repeated full runs, no flakes, both before and
      after the Codex fixes) and `cargo bench --workspace --locked --no-run` all clean. Same
      `cargo deny check`/`cargo audit` caveat as H2b's own entry: local runs are clean only
      because of an unrelated, uncommitted `RUSTSEC-2026-0285` fix carried in the working tree —
      this branch's own committed `Cargo.lock` is untouched and will show the same pre-existing,
      separately-tracked failure in real CI. H1 (Codex interception spike) remains open under
      the same intent.
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
- [ ] **Audit-log third path — reachability corrected 2026-08-01, this is a real gap, not
      "local-only."** `vg-audit/src/record.rs:212` serialises `EntityType::Custom(name)` as
      `{"custom":"<name>"}`, and `vg-cli/src/main.rs:476-478` claims in a doc comment that
      audit events "leak nothing" — false for the `Custom` arm. A same-model + Codex review
      of the 2026-08-01 leak fix (docs/decisions.md) found this reachable by the *same*
      mechanism just closed for `vg diff`/`vg inspect`: a wrapped agent invoking `vg audit`
      as a shell command reads back whatever JSON is in the log — including the raw class
      name — as `vg audit` pretty-prints already-serialized log lines verbatim
      (`vg-cli/src/main.rs:~502`) rather than re-deriving safe display text. Not fixed here,
      deliberately: `EntityTypeV1` (`vg-audit/src/record.rs`) is a *stored, versioned*
      serialization format historical audit logs may already depend on, and a same-day
      change to it under this fix's time pressure risks exactly the kind of undercoordinated
      addition doubt-driven-development's STOP-and-decompose guidance warns against. Needs
      its own reviewed change: likely a `CUSTOM` collapse in the serialised form itself (not
      just at print time, matching the vg-core Display fix's approach) plus an explicit
      decision on backward-compatibility with any already-written `{"custom":"<name>"}` log
      lines. A hard prerequisite for v1.5 telemetry regardless. Raised as decision packet
      material for the launching session's compliance loop.
- [x] ~~Phase 1a, `TelemetryEvent` + `TryFrom` in `vg-core`~~ **Built 2026-08-23, merged to
      `main` via PR #47 (`https://github.com/dermdunc/veilgremlin/pull/47`).** —
      `crates/vg-core/src/telemetry/` (envelope + `Receipt`/`Alert`/`EdgeEvent`, the §3.2a type
      inventory, `TryFrom<&AuditEvent>` exhaustive with no wildcard arm), `interface-contracts.md`
      bumped to v1.5 (§7a), `implementation-plan.md` §3.2-3.4 rewritten to match what was actually
      built. Reviewed across **four** rounds of adversarial review (single-model → Codex →
      single-model → Codex+Opus in parallel) — see `docs/decisions.md`'s 2026-08-23 entries for
      the full findings list; most severe was a **proven** `#[derive(Hash)]` side-channel on the
      `String`-backed token types (an external-crate exploit recovered raw strings byte-for-byte
      through a custom `Hasher`), closed by removing `Hash` from every type wrapping variable
      content. `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide,
      311 tests passing, zero regressions.
      **Every `TryFrom<&AuditEvent>` arm still rejects** — this is the honest, reviewed state, not
      an oversight (see `telemetry::mod`'s module doc). What's still needed before any arm can
      return `Ok`, in the order the reject reasons name:
      - [x] ~~**`ActorId` pseudonymization** (keyed HMAC, computed locally)~~ **Built
        2026-08-23, merged to `main` via PR #48
        (`https://github.com/dermdunc/veilgremlin/pull/48`).** —
        `crates/vg-core/src/telemetry/pseudonymize.rs`
        (`ActorPseudonymKey`, `pseudonymize_actor`), `crates/vg-vault/src/keychain.rs`
        (`load_or_create_actor_pseudonym_key`, per-device OS-keychain-backed, fixed
        `account = "default"`), `EdgeEvent::try_from_audit_event` (a **second**,
        key-carrying conversion entry point alongside the frozen, keyless
        `TryFrom<&AuditEvent>` — the ratified signature at `docs/decisions.md:2883` can
        never take a key, so it stays reject-only forever; this new function is what
        actually unblocks `DemaskRequest`/`DemaskDecision` in practice). Two rounds of
        adversarial review (single-model, then Codex cross-model). See
        `docs/decisions.md`'s 2026-08-23 pseudonymization entry for the full findings
        list and the residual risks recorded below, still open:
        - **Env-var test seam (`VG_ACTOR_PSEUDONYM_KEY_HEX`) can silently defeat the
          "no cross-device correlation" guarantee** if the same value is ever set on two
          machines — no structural fix found within this codebase's existing test-seam
          architecture (same shape as `VAULT_KEY_ENV`); mitigated with a loud stderr
          warning naming the specific consequence, not solved.
        - **`ActorPseudonymKey::from_bytes` is unrestricted `pub`** (needed so
          `crates/vg-core/tests/telemetry.rs`, a separate compiled crate, can construct
          test keys) — nothing in the type system stops a production caller from
          fabricating a fixed/weak/shared key instead of using
          `vg_vault::load_or_create_actor_pseudonym_key`. A sealed-trait/capability-token
          redesign could close this; not attempted here as disproportionate to this
          slice. Candidate hardening item for a future session.
        - **Keychain create-race, inherited from `load_or_create_db_key`, widened for
          this key**: two `vg-*` processes launched near-simultaneously on a device's
          first-ever run can each mint a different key (no atomic compare-and-set
          available via the `keyring` crate). Wider than the DB key's version of the
          same race because every vault on a device shares one fixed
          `(service, account)` pair. Not fixed.
      - **The versioned reason dictionary** — unblocks `Block` → `EdgeEvent::BlockedAttempt`.
        Distribution mechanism deliberately unscoped (reconciliation plan §5).
      - **The in-emitter aggregator** (groups `AuditEvent`s by trace before minting a
        `Receipt`) plus **Bedrock `requestMetadata` trace stamping** — unblocks
        `Scan`/`PolicyDecision`. No trace id exists anywhere upstream in `vg-core` today; this
        is the biggest remaining gap. Must also implement the Q3 5-minute replay-window
        consequence flagged in the reconciliation plan's §4a (an offline device reconnecting
        after the window elapses needs a drop/re-mint/queue decision, not made yet).
      - JSON Schema generation (no `serde`/`schemars` dependency exists in `vg-core` yet) —
        needed before the "schema published as a versioned artifact" exit gate is met.

### Telemetry roadmap sequencing (planned 2026-08-23, revised after adversarial review; not yet built)

Sequences the items above by what's genuinely blocking what, not by the order they're listed —
worked out in a dedicated planning session after PR #47/#48 merged, then reconciled against a
heavy fresh-context critique the same day (every claim below re-verified against the code, both
directions). Full context in that session's plan (not committed to this repo; summarised here so
it isn't lost).

**Three findings from reading the code, not assumed, that reorder the obvious sequencing:**
- **Bedrock `requestMetadata` trace stamping is blocked on there being a Veil-owned Bedrock
  request body at all** — not on M3 as a universal truth. Stamping needs whoever serialises the
  final Bedrock request; today nothing in this workspace does. `vg-proxy` has "no upstream client
  anywhere in this crate" (`vg-proxy/src/lib.rs:11`), and the Claude adapter deliberately builds
  none either, leaving transport to the wrapped Claude Code CLI
  (`vg-adapters-claude/src/wrapper.rs:4`). **For the proxy path — the only planned owner — that
  owner is M3**, this file's own stated **#1 priority**, which hasn't started. A future
  direct-Bedrock adapter path would be an alternative owner and would unblock stamping
  independently; no such path is planned, so plan on M3.
- **No first-party production path emits `AuditEvent::PolicyDecision`.** The workspace has exactly
  three production `policy.audit.write` call sites (grep-verified): `api.rs:173` (`Block`),
  `api.rs:306` (`Scan`), `api.rs:627` (`DemaskDecision`). The type is `pub` and `vg-audit` still
  *reconstructs* `PolicyDecision` when reading back historical records
  (`vg-audit/src/record.rs:420`), so "never constructed anywhere" was too strong — but nothing we
  ship *mints* one. Scope the aggregator to what our own code emits, and see the next finding for
  why dropping it isn't free.
- **`AuditEvent`s alone cannot build a `Receipt`** (this is the finding that actually changes the
  plan). `Controls` requires policy version, outcome, per-entity `Detection { class, count,
  action }`, a `ReasonCode` block reason, and exceptions (`telemetry/receipt.rs:235`,
  `receipt.rs:167`). `Scan` carries only aggregate counts, detector version and latency
  (`audit.rs:21`); `Block` carries an artefact kind and a free-text reason. Some of the missing
  data is closer to hand than that gap implies — `mask()` returns `(MaskedPack, Vec<MappingRef>,
  AuditEvent)`, and `MaskedPack` already carries `policy_version` and per-type `EntityCounts`
  (`types.rs:182`, `:166`) — but `outcome`, per-detection `action`, `block_reason`, and
  `exceptions` have no source today, not even inside `mask()`. So a decision is owed before
  Phase 3: either mint a real per-decision control event (the role `PolicyDecision` was shaped
  for), or define the aggregator over a richer `mask()` outcome plus newly-derived fields rather
  than over bare `AuditEvent`s. Not decided here; recorded as a Phase 3 prerequisite.

**Recommended phases** (same-phase items have no hard dependency on each other):
- **Phase 0 — zero dependencies:** the Q10 privacy write-up (below); the fieldless-enum `Hash`
  cleanup (below). Cheapest items, no reason to wait.
- [x] ~~**Phase 1 — the emitter.**~~ **Built 2026-08-23** — `crates/vg-audit/src/telemetry_sink.rs`
  (`TelemetryCountingAuditSink`/`SharedTelemetrySink`/`TelemetryConversionCounts`, a decorator
  around any `AuditSink`, attempts `EdgeEvent::try_from_audit_event` on every write and counts
  the outcome per `AuditEvent` variant — intercepts at the `AuditSink` boundary as planned, not
  inside `mask()`), wired into `Engine::open` (`crates/vg-adapters-claude/src/runtime.rs`) behind
  a new opt-in policy flag (`RawPack.telemetry_enabled`, `crates/vg-policy/src/config.rs`, reached
  via a new default `PolicyEngine::telemetry_enabled()` trait method,
  `crates/vg-core/src/traits.rs`) — **not originally scoped in this phase's sketch above**,
  added because wiring into real production construction (a scope decision made in this
  session's interview, since the two earlier telemetry PRs deliberately stayed unwired) meant
  ADR-015's "opt-in, never opt-out" ratification needed an actual config surface, which
  previously didn't exist anywhere in the code.
  **A second, more consequential scope addition, found only during review, not planned going
  in:** `StatePaths` (`crates/vg-adapters-claude/src/state.rs`) now carries its own
  `Provenance`, and `Engine::open` refuses to honor `telemetry_enabled()` when the state dir's
  provenance is `Discovered` (F3 — a `.veilgremlin/` adopted wholesale from a cloned repo's
  ancestor directory). Before this fix, a hostile repo could silently trigger real OS-keychain
  secret generation via a committed `repo.policy.json`, with zero operator-facing signal, on the
  automatic `vg hook` path Claude Code invokes on every tool call. Found by a fresh-context
  adversarial reviewer during this session's doubt-driven-development pass, confirmed by a
  second, Codex cross-model round after the fix. See `docs/decisions.md`'s 2026-08-23 Phase 1
  entry for the full findings list (this and two smaller fixes: mutex-poison recovery so a
  telemetry-only fault can never block the real audit-log write; an env-var test-cleanup guard).
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
  **Scope, still accurate:** Phase 1 buffers **unsigned payload candidates** (`EdgeEvent` values
  and conversion outcomes), *not* `TelemetryEvent`s — full records stay custodian-blocked (see
  the still-open `veil-custodian` item below), and nothing here transmits anywhere; counts are
  in-memory only, inspectable via `Engine::telemetry_counts()`.
- [x] ~~**Phase 2 — the reason dictionary.**~~ **Built 2026-08-23** —
  `crates/vg-core/src/telemetry/block_reason.rs` (new: `BlockReason`, a small
  **code-defined** registry, `ARTEFACT_POLICY_BLOCK_TEXT` constant, `classify()` exact-match
  lookup). **Scope changed from this entry's own original sketch, by explicit choice made in
  this session's interview, after checking the actual code first**: there is exactly one
  production `AuditEvent::Block` construction site in the whole workspace
  (`crates/vg-core/src/api.rs`'s `mask()`), and `vg-policy`'s `ResolvedPolicy` has no separate
  "reason text" concept anywhere — building the full policy-pack-distributed mechanism this entry
  originally sketched (a `PolicyEngine` contract change, merge semantics for reason ownership,
  inheriting the still-stubbed `verify_signature` risk) for one fixed reason string was judged
  premature. The registry is versioned like `detector_version`/`policy_version` strings are —
  shipped with the code — not operator-editable; nothing in `vg-policy` changed.
  `EdgeEvent::try_from_audit_event`'s `Block` arm now resolves a recognized reason to `Ok` in
  production for real (`crates/vg-core/tests/pipeline.rs` proves this against the actual
  `mask()`-emitted event, not a hand-built fixture). New `TelemetryReject::UnrecognizedReason`
  (an unregistered reason string) and `TelemetryReject::RequiresEnvelopeConstruction` (the frozen,
  keyless `TryFrom<&AuditEvent>`'s now-accurate reject for a *recognized* `Block` reason, since
  that entry point still can't build `Envelope`/`Integrity`) — the now-permanently-dead
  `RequiresReasonDictionary` variant was removed rather than left stale.
  Two rounds of adversarial doubt-driven-development review (single-model, then Codex
  cross-model), both offered and accepted — see `docs/decisions.md`'s 2026-08-23 Phase 2 entry
  for the full findings list. Most notable: round 2 caught that round 1's own fix for the frozen
  `TryFrom`'s `Block` arm was itself incomplete (it unconditionally claimed "would resolve,"
  which was false for an unrecognized reason) — fixed by having that arm classify the reason
  first, the same way the newer entry point does. **Named risk, deliberately not solved:** "every
  `Block` construction site uses a registered constant" is enforced by review discipline, not the
  type system — `AuditEvent` being `#[non_exhaustive]` restricts cross-crate matching, not
  cross-crate *construction* (confirmed: `crates/vg-audit/tests/sink.rs` already constructs
  `AuditEvent::Block` from a different crate with its own reason strings).
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
- [x] ~~**Phase 3 (partial) — trace-id threading + aggregator skeleton.**~~ **Built 2026-08-24** —
  `mask()` (`crates/vg-core/src/api.rs`) now mints a fresh `TraceId::from(Uuid::new_v4())`
  internally on every call and returns it as a 4th tuple element, rather than accepting one as a
  parameter — verified against every real call site in the workspace (`Engine::mask_text` in
  `vg-adapters-claude/src/runtime.rs`, `crates/vg-core/benches/mask_pipeline.rs`, and
  `Harness::mask_sample` in `crates/vg-bench/src/report.rs` — a doubt-driven-development round
  caught an earlier version of this claim undercounting the third one), none of which has any
  other correlation id available to supply. New `TraceBuffer`
  (`crates/vg-core/src/telemetry/aggregator.rs`, `pub(crate)`) buffers `AuditEvent`s by trace,
  tracks a per-trace age baseline, and exposes `insert`/`events_for`/`aged_before`/`remove` —
  deliberately no completion detection and no eviction policy, matching Phase 1/2's own precedent
  for a real, tested, **not-yet-wired** piece. Two rounds of doubt-driven-development review
  (single-model, then Codex), both accepted — see `docs/decisions.md`'s 2026-08-24 entry for the
  full findings list, most notably a real security regression caught and fixed: an earlier version
  derived `Ord`/`PartialOrd` on `TraceId` reasoning a single comparison "only returns an
  `Ordering`," missing that a *public* `Ord` lets any holder binary-search the wrapped `Uuid` out
  bit-for-bit via ~128 adaptive comparisons — the same class of channel `telemetry::ids` already
  treats as serious for `Hash`. Fixed by confining ordering to a `pub(crate)`-only
  `TraceId::ordering_key() -> u128`, used only inside `TraceBuffer`'s own `BTreeMap`.
  `cargo build/clippy -D warnings/fmt --check/test` all clean, workspace-wide.
  **Two open decisions still gate the real aggregator, not the skeleton just built:** the receipt
  data source (third finding above), and the Q3 replay-window drop/re-mint/queue question, which
  blocks the buffer-eviction policy specifically. **Also named, not solved:** `mask()`'s
  `trace_id` is unreachable on every `Err` return (including the one partial-audit-write path that
  would most benefit from it) — fixing this means redesigning `MaskError`, which currently leans
  on `#[from]` auto-conversion incompatible with also carrying a mandatory field; a real, separate
  change. Bedrock stamping stays split into a future session, blocked on M3 (`vg-proxy` has no
  upstream client yet).
- **Phase 4 — JSON Schema generation + publish.** *Publishing* is sequenced last on purpose:
  regenerating a published schema after Phase 3 changes `Receipt`'s shape is worse than
  generating it once after that shape is real. The **generator machinery and its local tests
  should start early** (alongside Phase 1/2) — it's the first mechanized proof that the Rust
  shapes emit closed JSON objects with no surprise strings, and that feedback is worth having
  before Phase 3, not after. **Named trade-off, accepted:** the harness will need rework when
  Phase 3 moves `Receipt`'s shape; that cost is cheaper than discovering an open-object leak at
  publish time. `additionalProperties: false` at every object boundary is a generator test
  (reconciliation plan §3.3 item 4), not a review checklist item.
- **Phase 5 — delivery, named but not designed.** The reconciliation plan defers transport and
  delivery (§5: HTTPS ingest vs. SQS, batching windows, retry/backfill, fail-open/fail-closed)
  and explicitly notes it interacts with Q3's replay window, "so the two should not be settled in
  isolation." That deferral is fine for a schema plan; it is not fine for a roadmap whose stated
  goal is one real, signed `TelemetryEvent` reaching `veil-observatory`. Phase 1's local buffer is
  a placeholder, not a delivery story: with a fixed 5-minute freshness window, buffering policy
  and delivery policy are the same decision. Owns its own scoping session; sequenced after
  Phase 3 only because record shape should stop moving first.
- **Not phase-gated:** the six-raw-capable-`String`-surfaces item (below) deserves its own scoping
  pass, bigger than a cleanup item; the `ActorPseudonymKey::from_bytes` provenance hardening item
  (below) needs its own design decision before implementation; the env-var cross-device-
  correlation residual (below) likely stays an accepted, documented risk rather than a plannable
  item unless the test-seam architecture itself changes.

`veil-custodian` (device enrolment + signing-key issuance, below) blocks `Envelope`/`Integrity`
construction regardless of how much of the above lands — no `TelemetryEvent` can be fully
assembled and signed without it, which is why Phase 1 is scoped to unsigned candidates above.
Deliberately not planned in detail here — that's a separate repo's own session; what `veil-proxy`
needs from it is named in the item below.

- [ ] **Close the six raw-capable `String` surfaces at their source** (`docs/architecture/implementation-plan.md`
      §3.1) — **still open, not done by the `TelemetryEvent` build above.** `ActorId(pub String)`,
      `DetectorId(pub String)`, `Block.reason: String`, `policy_version: String`,
      `EntityType::Custom(String)`, `ArtefactKind::SourceCode(String)` are all still raw in
      `vg-core`'s own base types; the telemetry layer works around this by rejecting or
      collapsing at the telemetry boundary (e.g. `EntityClassId::Custom` collapses the name).
      `ActorId` pseudonymization (built 2026-08-23, above) unblocks conversion for
      `DemaskRequest`/`DemaskDecision` via the second entry point, but does not touch
      `ActorId`'s own `pub String` field — the underlying type is still raw.
- [ ] **Minor consistency cleanup: several fieldless `telemetry::` enums still derive `Hash`**
      (`SchemaVersion`, `SigningAlgorithm`, `DeploymentStage`, `Action`, `Outcome`,
      `EdgeOutcome`, `Severity`) — found by a Codex cross-model doubt-driven-development
      round during the 2026-08-23 pseudonymization work, out of scope for that change (all
      pre-existing, merged in PR #47). Not an active leak (they carry no fields, so a derived
      `Hash` has no raw bytes to expose) — the concern is purely convention consistency with
      the rest of `telemetry::`'s "no `Hash`" rule. Small, low-risk, self-contained cleanup for
      a future session.
- [x] ~~**`veil-custodian`: build the device enrolment registry and signing-key issuance**~~
      **Signing-key half designed 2026-08-30, reviewed 2026-08-31, BUILT 2026-08-31** —
      `veil-custodian` proposed ADR-S (per-device telemetry signing-key issuance) on 2026-08-30;
      this repo completed the acceptance review ADR-S's own text names as blocking its flip to
      Ratified (accepted, with edits — see `docs/decisions.md`'s 2026-08-31 entry); and
      `veil-custodian`'s own PR #19 (merged 2026-09-02) then built the real issuance/lookup
      endpoints, the `signing_keys` migration, the CSR P-256/signing-cert-profile validation in
      its CA, and the revocation cascade — ADR-S is no longer docs-only on the custodian side.
      ~~**Still open:** this repo's `telemetry::signing::DeviceSigningCredential`/
      `SigningCredential::EcdsaP256` consume the *contract* and are proven end-to-end only via
      the `VG_DEVICE_SIGNING_KEY_HEX`/`VG_DEVICE_SIGNING_CERT_PEM` test seam — no real device has
      actually called the now-real endpoints, since the small operator tool that would do so
      (`veil-custodian`'s `veil-enrol`) still doesn't exist.~~ — **done, corrected 2026-09-05:**
      `veil-enrol` now exists and was used for real (`veil-enrol` repo, merged through PR #4)
      — `veil-demo`'s `scripts/ecdsa-signing-proof.sh` enrolled a real device against a real
      local `veil-custodian`, obtained a real ADR-S-issued signing key/certificate via real
      `veil-enrol` CLI calls, and fed that real credential into this repo's actual production
      `Engine::open` auto-detect path (via the same `VG_DEVICE_SIGNING_KEY_HEX`/
      `VG_DEVICE_SIGNING_CERT_PEM` seam named above — no code that writes an enrolled credential
      into the OS keychain exists yet, so the seam is still how the real credential reached `vg`,
      not the OS keychain itself) to produce a real ECDSA-P256-signed `veil.edge_event.v1`,
      independently verified by a from-scratch DER-wrapping verifier that also correctly rejected
      a tampered signature. See `docs/decisions.md`'s 2026-09-05 entry. The
      enrolment-**registry** half (Q1) is still untouched, and nothing yet writes a device's
      enrolled credential into its OS keychain automatically — see the corrected entry below.
- [x] **Build the policy/config surface to select `EcdsaP256` over the current `Hmac` default
      (2026-08-31).** Auto-detect from credential presence, no explicit flag: `Engine::open`
      (`vg-adapters-claude::runtime`) calls `vg_vault::load_device_signing_credential()` — gated
      on `VEIL_OBSERVATORY_ENDPOINT` actually being set, so a process that never opted into
      transport never touches the OS keychain for this — and passes the result down through a
      new `OwnedSigningCredential` (owned-storage counterpart to the borrowing
      `SigningCredential<'a>`) into `TelemetryCountingAuditSink::new`. `Ok(Some(cred))` signs
      ECDSA; `Ok(None)` (not yet enrolled — today's universal case) or `Err` (genuine
      misconfiguration, logged and never fatal to `Engine::open`) falls back to the existing
      `VEIL_RECEIPT_KEY`-sourced HMAC path unchanged. Hardened by a single-model +
      Codex doubt-driven-development round (4 + 5 findings, all fixed) — see `docs/decisions.md`'s
      2026-08-31 entry.
- [x] ~~**Wire the ECDSA signing path into production against a *real* issued credential**, once
      a device signing key/certificate can actually be enrolled. The auto-detect plumbing above is
      real and tested (via the existing `VG_DEVICE_SIGNING_KEY_HEX`/`VG_DEVICE_SIGNING_CERT_PEM`
      env-var test seam), but no enrolment flow exists yet, so `Ok(None)` — HMAC fallback — is
      still every real device's outcome today.~~ — **done, corrected 2026-09-05:** proven for
      real. `veil-demo`'s `scripts/ecdsa-signing-proof.sh` enrolled a real device via a real,
      local `veil-custodian` and the now-real `veil-enrol` CLI, and that real ADR-S-issued
      credential drove this repo's actual production `Engine::open` auto-detect code path
      (`vg-adapters-claude::runtime`) end-to-end: a real ECDSA-P256-signed `veil.edge_event.v1`
      was produced and sent over real HTTP, then independently verified (including a negative
      control that correctly rejected a tampered signature). This is what grounded the
      raw-`r||s`-encoding sign-off recorded in `docs/decisions.md`'s 2026-09-05 entry.
      ~~**Still genuinely open, not resolved by this:** nothing yet writes a real enrolled
      credential into a device's OS keychain automatically — the proof reached `Engine::open`
      via the same `VG_DEVICE_SIGNING_KEY_HEX`/`VG_DEVICE_SIGNING_CERT_PEM` test seam, with the
      raw key scalar extracted by hand from `veil-enrol`'s output, not stored in the keychain by
      any tool. `vg-vault::keychain::load_device_signing_credential` is load-only by design
      (enrolment itself is out of scope here, per ADR-D/ADR-N: "a device never calls this API"),
      so until something — `veil-enrol` or a separate device-side tool — writes the credential
      into the OS keychain, `Ok(None)`/HMAC fallback remains the outcome for any device that
      hasn't had a credential manually threaded in via the env-var seam.~~ — **done,
      2026-09-12 (`XREPO-009`, ADR-017):** `vg-vault::enrol` is now a real device-side keychain
      *writer* (`request_device_signing_csr`/`install_device_signing_certificate`), and
      `vg enrol request-csr`/`install-cert` are real `vg-cli` commands. Live-run proven
      zero-seam in `veil-demo/scripts/xrepo-009-device-credential-install-proof.sh`: a real
      credential is written to the real macOS keychain, then loaded back by two further,
      independent `vg` processes with `VG_DEVICE_SIGNING_KEY_HEX`/`VG_DEVICE_SIGNING_CERT_PEM`
      asserted unset, the second reaching veil-observatory's `accepted` disposition — the first
      time organic, un-seamed traffic has ever reached it. Five closure limitations (no CA
      trust-anchor distribution, macOS-only, no renewal automation, not an MDM path, the anchor's
      algorithm constraint proven only against the dev CA) are filed as `XREPO-010`–`XREPO-013`
      in `veil-ecosystem/.hekton/cross-repo-deps.yaml`, not silently accepted. The other gap this
      bullet named when written — `veil-observatory` had no real ECDSA verification path — is
      now **also closed** (`XREPO-008`, 2026-09-11, ADR-0022 on veil-observatory's side); the
      enrolment-registry half (Q1) remains untouched.
- [ ] **Decide whether `Envelope::device_ref` should be populated from
      `DeviceSigningCredential::device_ref()` when signing with ECDSA**, rather than staying tied
      to the separate, still-always-`None` `EdgeEventRecordInput::device_ref` (ratified Q1 gates
      that field on the enrolment registry existing). A doubt-driven-development review round
      (2026-08-31) flagged that the credential now carries a cryptographically-verified device
      identity that signing never uses — not a bug (nothing currently depends on it), but a real
      design question once the ECDSA path is actually wired into production (item above).
      `docs/decisions.md`'s 2026-08-31 entry has the full finding.
- [x] **Report two findings back to `veil-custodian`**, surfaced during ADR-S's acceptance review
      (2026-08-31): `docs/api/openapi.yaml`'s 201 example `certificate_fingerprint` value doesn't
      match its own `^[a-f0-9]{64}$` pattern (will fail an example-validating linter); and
      `src/domain/pseudonym.rs`'s module docstring still claims the `dev_`-prefixed wire form
      "matches veilgremlin's `DeviceRef` exactly" — the 2026-08-30 correction pass fixed this
      claim in `decisions.md` and `docs/api/README.md` but missed this file. Both cosmetic, not
      blocking, no urgency. Fixed in `veil-custodian` PR #18 (branch
      `agent/claude/adr-s-cosmetic-fixes`), open as of 2026-08-31, not yet merged.
- [x] ~~**Get ADR-S's signature encoding decided jointly, not unilaterally.**~~ — **sign-off
      given 2026-09-05** (tracked as `XREPO-004` in veil-ecosystem's
      `.hekton/cross-repo-deps.yaml`, now `status: closed`), on the strength of a real ECDSA
      signing proof built in veil-demo: a from-scratch DER-wrapping verifier (the exact
      `utils.encode_dss_signature(r, s)`-shaped conversion this entry itself named as the
      real integration cost) independently confirmed the raw `r||s` encoding is
      cryptographically sound, including correctly rejecting a tampered signature. Raw
      `r||s` is accepted as this repo's ECDSA wire encoding for cross-repo signing. **Not
      resolved by this**: `veil-observatory` still has no real ECDSA verification path built
      (KMS Verify or a native P-256 library) — the encoding question is settled, that
      integration work is separate and still unscheduled.
- [x] ~~**Write the Q10 telemetry-metadata privacy section** (retention, residency, permitted
      joins, re-identification path) into the ratification packet, alongside the Q1 registry
      work — the plan explicitly deferred this write-up, it is not yet done
      (`docs/architecture/telemetry-receipt-reconciliation-plan.md` §4a).~~ — **done 2026-09-07**,
      as Phase 0 (P0-2) of `XREPO-007`'s device_ref work
      (`docs/architecture/telemetry-receipt-reconciliation-plan.md` §4b). **Real finding, corrected
      once by a Codex adversarial round before being confirmed:** a first draft claimed no built
      re-identification mechanism existed anywhere in this family — false; `veil-custodian`
      already implements a gated, audited `POST /v1/resolutions` (device_binding/user_binding,
      `Role::ResolutionAuthority`, fail-closed audit-before-disclosure). The real gap is narrower:
      no production-grade authenticator exists yet (default build denies everyone;
      `stub-authn` trusts a caller-supplied header — `RISK-0004`), and sealing is a documented
      Milestone-1 plaintext placeholder (ADR-H defers real encryption to Milestone 5). §4b
      recommends gating production enablement of real `device_ref` emission on either those
      landing or an explicit human decision to accept the current posture for a defined interim. See ADR-016.
- [x] ~~Get the `veil-observatory` ADR-0004 scope note actually accepted on that side.~~
      **Reviewed and accepted-with-edits 2026-08-23** by a dedicated `veil-observatory`-side
      session (own judgment, not a rubber stamp — see that repo's `docs/session-log.md`). Marker
      flipped from "Proposed amendment" to "Amended." Merged to `main` via PR #8
      (`https://github.com/dermdunc/veil-observatory/pull/8`, fast-forward `835d083..457105c`),
      branch deleted.
- [x] ~~New cross-repo decision surfaced by the veil-observatory-side review: should ADR-0014's
      correlation/determinism suite get the same formal CI-veto status ADR-0012's fuzz test has
      under Q5?~~ **Resolved by `codex` critique (`xhigh` effort, 2026-08-23): no, not as
      proposed.** ADR-0012's fuzz test is genuinely schema-shaped (canaries in string fields,
      checkable against arbitrary schema-conformant instances) and maps cleanly onto a
      producer-schema veto. ADR-0014's guarantees (exact-match `veil_trace_id` correlation, no
      fuzzy fallback, replay determinism) live in pipeline/adapter *behavior*
      (`correlator.py`, `bedrock.py`, `receipt.py`), spread across three test files, not the one
      suite named in the ADR-0004 scope note — a schema can protect the *fields* correlation
      needs but can't prove the *behavior*. Wiring the whole existing `test_pipeline.py` in as a
      schema-level veto would be a category error. **Deferred, not ratified**, until a first
      generated schema artifact exists. When it does, build a narrow, purpose-built
      **correlation-contract gate** instead of reusing the broad suite: stable field-name/pointer
      checks on the `linkage` block, plus a synthetic fixture matrix (valid pair / missing trace /
      mismatched trace / duplicate trace / account-region mismatch / `bedrock-mantle`
      unmonitored-path) that `veil-proxy` CI can run against `veil-observatory`'s adapters without
      needing live pipeline data. Not blocking anything today — no schema artifact exists on
      either side yet.
      **Ratified on both sides 2026-09-06** (`XREPO-005` closed) — see `docs/decisions.md`'s
      2026-09-06 entry: `veil-observatory`'s ADR-0019 built exactly this gate. Cross-repo CI
      wiring remains deferred on the same still-unmet schema-artifact precondition.

M3 (request masking) remains the standing product priority; the leak fix is small and should not
displace it for long.

## Session Update: 2026-08-01 — Cross-link unified regulatory control register

- [ ] Human reviews and merges PR #44; Lane B decision packets B1-B9 follow

## Session Update: 2026-08-01 — Close the custom-entity-label leak — full doubt-cycle

- [ ] Human reviews and merges PR #45; audit-log serialization fix needs its own scoped session

## Session Update: 2026-08-01 — Bank display-collision measurement, propose vg-bench CI gate

- [ ] Human reviews and merges PR; install ci-proposed/ci.yml when ready (see its README for the exact command)

## Session Update: 2026-08-29 — `EdgeEvent`/`Envelope`/`Integrity` wire-serialization + HMAC signing contract built

- [ ] Human reviews and merges the PR; hand the golden vector
      (`crates/vg-core/tests/fixtures/edge_event_v1_golden.json`) to the `veil-observatory` team
      building the Python-side verifier.
- [x] ~~Build the network emitter / HTTP client~~ — done: `crates/vg-core/src/telemetry/emitter.rs`,
      fire-and-forget over a dedicated thread + single-threaded Tokio runtime, structurally
      opt-in on both `VEIL_RECEIPT_KEY` and a new `VEIL_OBSERVATORY_ENDPOINT` env var.
- [x] ~~Wire the signer into `TelemetryCountingAuditSink::write`~~ — done, same session.
- [x] ~~Merge this branch (and veil-observatory's ingestion branch)~~ — both fast-forward
      merged to local `main` in their respective repos, 2026-08-29. Not pushed to GitHub yet.
- [x] ~~Point a real `VEIL_OBSERVATORY_ENDPOINT` at a running `veil-observatory serve` instance
      and confirm one genuine end-to-end delivery~~ — done, 2026-08-29. Real
      `TelemetryCountingAuditSink` write, over the real `JsonlAuditSink`, through the real
      signer and emitter, to a real separately-running `veil-observatory serve` process:
      server logged `POST /ingest HTTP/1.1" 202`, and the record persisted in its real
      evidence store (`raw/<hash>.json`) with `edge_event.actor` as a genuine 64-hex-char
      HMAC pseudonym, never the raw actor string used to build it. See
      `crates/vg-audit/tests/live_edge_event_integration.rs` (checked in, `#[ignore]`d by
      default — requires a real running observatory) for the exact repeatable invocation.
      **Caught in the process, worth keeping visible**: veil-proxy's `VEIL_RECEIPT_KEY`
      hex-decodes; veil-observatory's UTF-8-encodes the same env var name directly. The
      same 32-byte key needs two DIFFERENT string values, one per side — using one string
      for both silently produces two different keys. Documented in the test's own module
      doc; worth a matching note in `veil-ecosystem/docs/architecture.md` if this hasn't
      already been flagged there.
- [ ] Follow-up: source `VEIL_RECEIPT_KEY` from the OS keychain via a `vg-vault`-style loader
      (`// TODO` left in `crates/vg-core/src/telemetry/signing.rs`'s module doc), matching
      `load_or_create_actor_pseudonym_key`'s precedent, instead of the env var.
- [ ] `Receipt`/`Alert` serialization is still unbuilt — deferred until `Receipt` is actually
      producible (the aggregator, `telemetry::aggregator`, is still a documented skeleton).

## Session Update: 2026-08-30 — fixed two review-found defects in the emitter

- [x] ~~`EdgeEventEmitterHandle::connect` panics on thread-spawn failure~~ — fixed:
      now returns `Result<Self, std::io::Error>`, propagated through
      `EmitterInitError::ThreadSpawnFailed` into the same log-and-disable path
      `TelemetryCountingAuditSink::new` already has for other misconfigurations.
- [x] ~~No flush/join path — the short-lived CLI hook process can race process exit and
      silently drop telemetry~~ — fixed: `EdgeEventEmitterHandle` now has a `Drop` impl
      doing a bounded (500ms + 200ms grace) flush-then-join, so a normal-return exit path
      (no `std::process::exit`) delivers already-`try_emit`ted records before the process
      goes away, without meaningfully slowing down the common case. New test
      (`dropping_the_handle_right_after_emit_still_delivers_the_record`) exercises exactly
      the race the other tests' `wait_for` polling never touched.

## Session Update: 2026-09-06 — Retire/promote review; fix yanked crate and a real test race

- [ ] No action needed right now; CI is green

## Session Update: 2026-09-15/16 — Track H, H1: Codex interception + auth spike (SPIKE COMPLETE, with four named, user-accepted scope deviations)

- [x] ~~H1 entry gate (fork F15): scrub step + test, `.gitignore`, chained pre-commit guard~~ —
      built and demonstrated live (a force-added raw-looking file was shown blocked from
      commit) before any real Codex capture, per the intent's own strengthened criterion.
- [x] ~~H1 live-run spike: `openai_base_url` override and custom `model_providers.veil` +
      `requires_openai_auth`, against the real `codex` CLI (0.153.4) under real ChatGPT
      subscription auth~~ — both mechanisms confirmed working end to end, each reproduced
      twice (real "pong" responses, real "tokens used" CLI output). See `docs/decisions.md`,
      "Track H, H1" for the full mechanism decision, and
      `docs/architecture/multi-harness-proxy-plan.md` for F7/F11/F12's answers.
- [ ] **Not working, recorded as a real finding, not silently dropped:** plain `HTTPS_PROXY`
      env vars alone did not reliably work — on reproduction, `codex` issues a genuine
      `CONNECT` tunnel request that this spike's relay (no `CONNECT` support) can't satisfy,
      and `codex` retries indefinitely with no observed fallback. A real transparent-proxy
      interception layer needs genuine `CONNECT` handling; this spike didn't build one. Note
      this is a *different* thing from test-order item (d) below, not the same mechanism.
- [ ] **Two rounds of adversarial review (a fresh-context subagent, then Codex cross-model)
      found the first write-up and its retained corpus had real, serious problems** — most
      seriously, a real ChatGPT account id and real session/environment data almost reached
      a commit (once via an under-scoped scrubber, once via a regression test that
      accidentally hardcoded the real captured value as "example" data). Full account in
      `docs/decisions.md`'s "Corrections from review" sections; both are fixed. The retained
      corpus is now a 5-entry, hand-authored, provenance-labeled **synthetic** artifact —
      real-capture retention was abandoned as too risky to do safely, on Codex's own
      recommendation, independently checked by a third model (Fable) before implementation.
- [ ] **Four named scope deviations from H1's original confirmation criteria, put to the
      human operator explicitly and accepted this session** (recorded as a real amendment
      to `veil-ecosystem`'s `INT-2026-09-14-001`, "UPDATE 2026-09-16" — not merely asserted
      in this repo's own docs): (1) API-key auth mode (`env_key`) untested — no
      `OPENAI_API_KEY` authorized, F7 narrowed to ChatGPT-subscription-only; (2) F12's
      specific `supports_websockets=false` pin mechanism untested, deferred to H3; (3)
      test-order item (d) — the `network_proxy`/`respect_system_proxy` config keys — not
      performed at all; (4) the corpus is synthetic-structure, not a redacted real capture.
      Revisit each if a later milestone needs the fuller original scope.
- [ ] Real follow-up work named in the decision, not yet done: a Codex header-forwarding
      policy (H2b's `AnthropicCodec::select_headers` has no Codex counterpart yet), the
      `prefer_websockets`-pinning mechanism for F12, a real `CONNECT`-capable relay/proxy to
      actually test the `network_proxy`/`respect_system_proxy` config keys, and the
      CA/trust-bundle path ((e) in H1's test order, not attempted since (a)/(b) succeeded).
      `scrub.py`'s own module doc now names a real, unfixed structural blind spot (real
      environment data embedded in request bodies as ordinary JSON, not token-shaped) —
      any future real-capture attempt needs a genuinely different approach, not a bigger
      regex.
