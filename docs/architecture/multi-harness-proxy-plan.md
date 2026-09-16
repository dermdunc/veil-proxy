# VeilGremlin — Multi-Harness Proxy Plan (Track H)

**Status:** proposed, not ratified. Supersedes nothing until reviewed; see `docs/decisions.md`.

**Update 2026-09-14 (same day, later session):** fork **F1** (§7) is decided — the user chose to
widen the beta bar to require Codex parity, against this plan's own recommendation. Ratified as
`D-BETA-8` in `veil-ecosystem/docs/decisions.md`, which is now the source of truth for whether
Track H gates the beta; every other statement in this document assuming F1 resolved to "no" (the
§0 summary line, §6's "nothing in this track gates the ratified beta bar") is stale and not
edited to match, per this document's own evidence-trail discipline — see §7's F1 row for the
decision record.

**Date:** 2026-09-14 (consolidation pass; draft 2026-09-14)

**Provenance — this is the third and final stage of a three-stage pipeline**, deliberately the
same shape as `veil-ecosystem/docs/beta-implementation-plan.md`'s own provenance: a **Fable
draft** of this document, an independent **Codex cross-model adversarial critique** of that draft
(25 numbered findings, with its own repo read access and live vendor-doc fetches), and this
**Opus consolidation**, which re-verified every contested point directly against repo source and
live vendor documentation before merging — accepting neither prior document's prose on faith.

**What changed from the draft, in one line:** the draft's central claim that Claude Code ships on
"mechanism A today" was false at product level — `vg-cli` has no dependency on `vg-proxy` at all,
so a real production launch path is a new, explicit milestone (**H0**) with a hard dependency on
Track 1's **A3** — and alongside that, the fail-open tunnel default was inverted, the CA lifecycle
contradiction resolved, four dependency-graph ordering errors fixed, six new decision forks named,
the sizing roughly doubled to 16-26 sessions (22-35 with H5), and two shared factual errors
corrected: the Codex CA variable is **singular** (`CODEX_CA_CERTIFICATE` — both the draft and the
critique misread a concatenated string table), and `wire_api = responses` is **one protocol over
two transports** (HTTP/SSE *and* WebSocket), not one homogeneous codec surface.

---

## 0. The one-line answer

**Build the production launch path first, spike the Codex interception mechanism before choosing
it, build a per-provider codec seam around a canonical origin identity, and keep the
process-scoped-CA CONNECT transport as a gated, conditional subsystem — not the default path.**

Claude Code's proven redirect stays the mechanism for beta; nothing in this track gates the
ratified beta bar.

The product goal (stated by the user directly): vg-proxy "sits in front of harnesses such as
Claude Code and Codex" — generically. The honest version of that promise, adopted from the Codex
consultation verbatim because it survives contact with the evidence below:

> Any **explicitly supported** harness for which Veil has verified an interception mechanism, an
> authentication mode, a provider codec, and a streaming implementation.

Not "any harness." Every harness added is four verified things, and this plan budgets them as
such. **Correction adopted from the critique:** "verified" must mean verified *in the shipped
product path*, not verified in a development proof harness. §1 states exactly how far short of
that the repo currently is.

**Beta-relevant constraint:** the ratified beta bar (`veil-ecosystem/docs/beta-implementation-plan.md`
§1) is a cohort of **3-10 real, non-author users on their own macOS machines**, and its condition
1 names only "real Claude Code / Anthropic API." Track H is therefore Track 1 *follow-on* work:
it must never regress the passing A2 live proof, and it must not silently become a beta blocker
(open fork F1, §7).

---

## 1. What is true today — verified against the code, not remembered

### 1.1 The production-integration gap, stated first because the draft got it wrong

The A2 live proof is real and it passes: `scripts/a2-live-proof.sh` drives a real, unmodified
`claude` CLI through a real vg-proxy TLS connection to the real `api.anthropic.com` — real
streaming, real masking/demasking, real subscription auth. That is a genuine achievement and
nothing below diminishes it.

**But it is a development proof, not a shipped mechanism.** Verified by direct reading:

| Claim | Verified state |
|---|---|
| `vg run` starts vg-proxy | **False.** `crates/vg-cli/Cargo.toml` lists no `vg-proxy` dependency at all. The gap is structural, not a missing line. |
| `vg run` allocates a listener, registers a namespace, injects `ANTHROPIC_BASE_URL` | **False.** `cmd_run` (`crates/vg-cli/src/main.rs:259-337`) writes hook settings, prints the pre-send summary, appends `--settings` for `claude*`, and execs the child with exactly one added env var: `CLAUDE_CODE_ATTRIBUTION_HEADER=0` (`main.rs:335`). |
| The live proof runs through `vg run` | **False.** `scripts/a2-live-proof.sh` sets `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_ATTRIBUTION_HEADER=0` **itself**, on a direct `claude -p` invocation, against a `cargo run --example` harness. |
| The proof harness is production-shaped | **False, and it says so.** `crates/vg-proxy/examples/live_proof_harness.rs:18` — "**Not production daemon bootstrap (A3)**": temp state dir deleted on exit, vault opened with the fixed dev constant `TEST_KEY = [7u8; 32]`, not the OS keychain. |
| Anyone else knew this | **Yes — the beta plan already did.** `veil-ecosystem/docs/beta-implementation-plan.md` §0 item 2: "There is no shippable proxy daemon today." That is why **A3** exists (1-2 sessions, Track 1). |

**Consequences, each corrected downstream in this document:**

- "Claude Code = mechanism A today" (draft §2, D-H-1) is false at product level. Corrected.
- GROUND-11's "a working mechanism" needs the qualifier **development live-proof mechanism**.
- GROUND-12's "moot by construction" is wrong in a subtle way: `vg run` *does* inject the
  attribution opt-out unconditionally, but `vg run` does not construct a proxy path, so the
  invariant it claims to establish is established for the wrong process. Corrected.
- H4 as drafted silently contained the missing production daemon bootstrap and launcher↔daemon
  integration. Split out as **H0** and a hard **A3** dependency.

This is critique finding #2, confirmed in full. It is the single most consequential correction in
this pass.

### 1.2 Single-harness assumptions baked into the current code

Each verified by reading the file (these are the work items, so they are stated precisely):

| # | Assumption in the code | Where (verified) |
|---|---|---|
| 1 | Every accepted TCP connection is plaintext HTTP/1.1, immediately — no CONNECT parsing, no TLS acceptance, no server-side certificate machinery anywhere in production code | `crates/vg-proxy/src/server.rs:106-122` (`TokioIo::new(stream)` straight into `http1::Builder::serve_connection`). Server-side TLS (`rustls::ServerConfig`, `TlsAcceptor`, `rcgen` cert generation) exists **only** in `tests/tls_upstream.rs`; `rcgen 0.13` is a `[dev-dependencies]` entry in `crates/vg-proxy/Cargo.toml` |
| 2 | One `UpstreamConfig` fixed for the whole listener, and its single `host: String` plays four roles at once: TCP connect target, TLS SNI, hostname-verification name, and `Host` header. **There is no base-path component at all** — `forward()` reconstructs the upstream URI from the inbound `path_and_query` verbatim | `crates/vg-proxy/src/upstream.rs:53-65` (the struct + its own doc: "the same string serves both roles"), `:204-210` (connect), `:215-224` (SNI/verify), `:246-262` (`Host` + URI) |
| 3 | The forwarded-header set is a hardcoded five-entry const: `content-type`, `x-api-key`, `authorization`, `anthropic-version`, `anthropic-beta` | `crates/vg-proxy/src/upstream.rs:131-138` (`FORWARDED_HEADERS`) |
| 4 | The route table is Anthropic-Messages + Bedrock-InvokeModel only, deny-by-default | `crates/vg-proxy/src/route.rs:30-51` |
| 5 | The request mask walk is shaped exactly like an Anthropic Messages body: `system` (string or text-block array), `messages[].content`, `tool_use.input`, `tool_result.content` | `crates/vg-proxy/src/mask_request.rs:95-134`, content-block dispatch at `:194-236` |
| 6 | Response demask is Anthropic-shaped in both modes; the SSE path rewrites only Anthropic `content_block_delta`/`text_delta` events | `crates/vg-proxy/src/stream_demask.rs:174-184` (`text_delta_text`), module doc lines 17-23 |
| 7 | Every response is fully buffered before demask — non-streaming and SSE alike | `crates/vg-proxy/src/upstream.rs:278-286` (`buffer_response`), `stream_demask.rs` module doc ("buffers the *entire* upstream SSE stream") |
| 8 | The H2 namespace fallback keys off the listener's own bound local address, so one shared listener collapses every header-less client into one namespace; per-session listeners are the documented intended fix, with the port-reuse handoff race explicitly left open for "the real caller that would provide that atomicity" | `crates/vg-proxy/src/server.rs:127-137` (doc on `handle`), `crates/vg-proxy/src/session.rs:33-88` |
| 9 | No connect/request timeout, and **no bound on buffering in either direction** — a named, accepted A2 gap for responses, and an unnamed one for requests | `crates/vg-proxy/src/upstream.rs:27-33` (module doc, "Named gap, not solved by this milestone") for responses; `crates/vg-proxy/src/server.rs:304-320` (`collect_body`) reads the entire inbound request body with no limit, and its own doc explicitly declines to bound it |
| 10 | `Daemon` owns **one** vault, **one** `Policy`, **one** detector/parser set and **one** audit sink for its whole process lifetime, and takes already-resolved paths — never discovering a `.veilgremlin` state dir | `crates/vg-proxy/src/daemon.rs:49-68` (the struct + its own "**Not production state-dir/keychain discovery**" doc), `:71-107` (`open`/`open_with_key`/`from_vault`) |

Item 9's request half and item 10 are **new to this consolidation** — the draft carried neither.

**What is genuinely reusable as-is** (verified): the outbound TLS client (`upstream.rs:100-126` —
real WebPKI verification against the OS trust store via `rustls-native-certs`, proven by three
real-local-TLS-server tests in `tests/tls_upstream.rs`), and the entire mask/vault/policy/demask
engine underneath `Daemon` (nothing in `vg-core`'s `mask()`/vault/policy path knows what transport
or provider called it). The provider-*shaped* parts are exactly items 3-6 — the codec seam of §2 is
drawn precisely around them. Item 10 is the part that **does not** generalise and is treated as a
first-class design problem in F5/F10, not as an asset.

---

## 2. Chosen architecture

```
harness launch profile    (vg run claude / vg run codex — env, config, flags, trust bundle)
        ↓
launcher ↔ daemon control plane   (session create/destroy, port + CA handoff — H0, NEW)
        ↓
interception transport    (mechanism A: loopback base-URL/config redirect — proven in a dev
                           harness, productionised by H0
                           mechanism B: explicit CONNECT proxy + process-scoped CA — H5, gated)
        ↓
per-provider protocol codec   (Anthropic Messages — EXISTS as mask_request/demask_response/
                               stream_demask; OpenAI Responses — H3, new)
        ↓
shared mask/vault/policy/demask engine   (vg-core + Daemon — reused, contract unchanged)
        ↓
verified-TLS upstream client  (upstream.rs — reused, config split per H2a)
```

The structural decisions, stated as decisions:

**D-H-1: Transport and codec are independent axes, and a harness binds one of each.** Claude
Code = (mechanism A, Anthropic codec) **once H0 ships**; today it is (mechanism A *in a dev
harness*, Anthropic codec). Codex = (mechanism decided by H1's spike, OpenAI Responses codec).
Neither axis may import the other's types: the codec sees "a request body + headers for provider
P," never "a CONNECT target"; the transport sees "an origin and bytes," never a `messages` array.

**D-H-1b (NEW): transport has a third sub-axis — the wire transport.** Verified: the Codex config
reference documents a provider capability `supports_websockets` ("Whether that provider supports
the Responses API WebSocket transport"), and the installed 0.153.4 binary contains a `wire_api`
value `responses_websocket` alongside `responses_http`, plus `websocket_connect_timeout_ms`,
`wss://`, and `codex.transport.fallback_to_http`. **One protocol schema, two wire transports.**
The Responses codec is written against the schema; SSE-vs-WebSocket is a transport decision
(fork F12).

**D-H-2: The CONNECT/process-scoped-CA transport is built only if the H1 spike shows the cheap
mechanism fails for Codex** — because for Codex a *configuration-level* redirect exists and is
documented (GROUND-8). The CA subsystem is the single riskiest component in this plan (a locally
generated CA that terminates TLS for real model traffic); this plan refuses to build it on spec.
If built, it is built to the §5 security bar, and it also becomes available as a second,
hostname-preserving mechanism for Claude Code (fork F3).

**D-H-3 (NEW, replacing the draft's `Origin` sketch): one canonical logical origin, one derived
identity.** The draft proposed `{connect_target, sni_name, verify_name, host_header}` as four
independently configurable values. Accepting critique finding #8: four free variables permit
identity splitting — an allowlisted CONNECT authority forwarded or authenticated as a different
origin. The corrected type is:

```
Origin {
    canonical: CanonicalOrigin,   // scheme + lowercased IDNA-normalised host + explicit port
    base_path: String,            // NEW — see below
    connect_target: SocketAddr-or-name,  // the ONLY field allowed to differ from `canonical`
}
```
SNI, certificate-verification name, and outbound `Host`/`:authority` are all **derived from
`canonical`**, never set independently. Only the socket destination may differ (and only to a
loopback or explicitly configured address).

`base_path` is required, not optional: verified in the 0.153.4 binary, Codex's two authentication
modes use **different hosts and different base paths** — `https://api.anthropic.com`-style
`https://api.openai.com/v1/responses` for API-key auth, and `https://chatgpt.com/backend-api/codex`
for ChatGPT sign-in (the config reference documents `openai_base_url` and `chatgpt_base_url` as
separate keys). Reconstructing only host + inbound request path, as `upstream.rs` does today,
produces the wrong upstream URL for the ChatGPT-backend case.

**Binding rule (H2a acceptance criterion).** For every request the implementation must bind and
compare, before any byte is forwarded: CONNECT authority (mechanism B only) · TLS SNI · inner
HTTP `Host`/`:authority` · matched codec route · selected upstream origin. A mismatch on any pair
fails closed. Canonicalisation rules are named explicitly and tested: ASCII case folding, trailing
dot stripping, default-port elision, IPv6 bracket forms, IDNA/punycode normalisation, rejection of
userinfo in an authority, and rejection of absolute-form request targets whose authority disagrees
with the connection's.

What this architecture explicitly is **not** (named, so scope can't silently creep back):

- **Not system-wide interception.** No `/etc/hosts` mutation, no OS-trust-store CA install, no
  port-443 listener. That is a possible later "managed enterprise" mode, out of scope for a
  3-10 person beta.
- **Not a general local signing oracle.** Under mechanism B, only an exact allowlist of real
  model-API origins is ever TLS-terminated; everything else is **rejected unless it is on a
  separately verified non-model-bearing tunnel allowlist** (F2, inverted from the draft).
- **Not "any harness."** A supported-harness matrix (harness × mechanism × auth mode × wire
  transport × codec), maintained in this document, is the product claim.

---

## 3. GROUND notes — evidence trail

This repo's culture is allergic to unverified claims stated as fact, and **both** prior stages'
findings were inputs to verify, not conclusions to copy. Each note says what was checked and how.
Notes marked **(consolidation)** are new or materially rewritten in this pass.

- **GROUND-1 (verified):** every "materially new work" claim about `server.rs`, `upstream.rs`,
  `route.rs`, and the codecs is accurate against the current files — §1.2's table is an
  independent re-derivation with exact line numbers, re-checked this pass.

- **GROUND-2 (verified, superseded by D-H-3) (consolidation):** `UpstreamConfig` does conflate
  TCP destination, DNS name, SNI, verification name and `Host`. The draft's four-field `Origin`
  fix was itself unsafe; D-H-3 replaces it with a canonical-origin-plus-derived-identity model
  and adds the missing `base_path`.

- **GROUND-7 (corrected this pass) (consolidation):** the draft quoted OpenAI's config reference
  correctly — for `model_providers.<id>.wire_api`, "**`responses` is the only supported value**,
  and it is the default when omitted" (re-fetched live 2026-09-14,
  `learn.chatgpt.com/docs/config-file/config-reference`, via a 308 from
  `developers.openai.com/codex/config-reference`). **But the draft's conclusion — "H3 is therefore
  one codec, not two" — overclaims the scope reduction**, exactly as critique finding #9 argues.
  The same reference documents `supports_websockets`: "Whether that provider supports the Responses
  API WebSocket transport," and the installed 0.153.4 binary contains `responses_websocket`,
  `websocket_connect_timeout_ms`, `wss://` and `codex.transport.fallback_to_http`. **What survives:**
  there is no Chat Completions wire mode, so H3 builds one *schema*. **What does not:** SSE-versus-
  WebSocket, auth-specific origins/paths, and versioned event variants remain real work. Fork F12.

- **GROUND-8 (verified, and its build order revised) (consolidation):** the live config reference
  documents `model_providers.<id>.base_url` ("API base URL for the model provider"), `env_key`
  ("Environment variable supplying the provider API key"), `requires_openai_auth` ("The provider
  uses OpenAI authentication (defaults to false)"), `http_headers`, `query_params`, and that
  "Codex ignores `openai_base_url`, `chatgpt_base_url` … `model_provider`, `model_providers` …
  when they appear in a project-local `.codex/config.toml`; put provider … keys in user-level
  config instead." So a redirect must live in user-level `~/.codex/config.toml` or `-c` CLI
  overrides — both injectable per-launch by `vg run codex`, `-c` being the cleaner per-session seam.
  **Revision accepted from critique finding #10:** OpenAI's own guidance is to prefer the *built-in*
  provider: "If you just need to point the built-in OpenAI provider at an LLM proxy, router, or
  data-residency enabled project, set `openai_base_url` in config.toml instead of defining a new
  provider." H1 therefore tests `openai_base_url` **first**, because it preserves built-in provider
  identity and capabilities; a custom `model_providers.veil` entry is the *second* case, valuable
  precisely because it may silently downgrade capabilities. Fork F11.
  *Accuracy note:* the critique is also right that the draft mischaracterised the original
  consultation. Re-read of the transcript (`tasks/bxk4147k6.output`) confirms it said CONNECT was
  "the largest omission from A–D" — i.e. from the user's own option list — not that CONNECT should
  be built before testing Codex configuration; and `openai_base_url` appears nowhere in it. Not
  material to the plan, recorded for accuracy.

- **GROUND-9 (CORRECTED — both prior stages were wrong) (consolidation):** the draft wrote the
  Codex custom-CA variable as plural `CODEX_CA_CERTIFICATES`, and the critique built finding #12
  on top of that, asserting a doc-versus-binary version conflict. **Both are wrong, from the same
  parse error.** A raw byte search of the installed 0.153.4 binary shows the string-table entries
  concatenated without separators: `…CODEX_CA_CERTIFICATE` + `SSL_CERT_FILE` + `REQUESTS_CA_BUNDLE`
  + `CURL_CA_BUNDLE…`. A `strings | grep` for the plural matches the singular plus the leading `S`
  of `SSL_CERT_FILE`. Decisive counter-evidence in the same binary: a human-readable message
  reading "**If you set `CODEX_CA_CERTIFICATE` or `SSL_CERT_FILE`, ensure it points to a…**"
  (singular). This matches the official docs exactly: "`CODEX_CA_CERTIFICATE` — Points to a PEM CA
  bundle… Takes precedence over `SSL_CERT_FILE`"; "`SSL_CERT_FILE` — Fallback PEM CA bundle path
  when `CODEX_CA_CERTIFICATE` is unset." **There is no version fork here.** The name is singular in
  both doc and binary; every occurrence of the plural in the draft is corrected throughout.
  **What the critique got right in the same finding, and is adopted:** the docs state "The same
  custom CA settings apply to **login, normal HTTPS requests, and secure WebSocket connections**"
  — so trust-bundle composition and auxiliary traffic must be tested, not just the model path.

- **GROUND-9b (new evidence, neither prior stage had it) (consolidation):** Codex 0.153.4 ships an
  entire **`network-proxy` subsystem of its own** — `network-proxy/src/mitm.rs`, `certs.rs`,
  `network_policy.rs`, `credential_broker/providers/openai.rs` — with CONNECT allow/block policy
  ("CONNECT blocked; MITM required to enforce HTTPS policy (client=…, host=…, mode=…)"), a
  **managed MITM CA** it generates and persists itself, and config keys `allow_upstream_proxy`,
  `dangerously_allow_non_loopback_proxy`, `features.network_proxy.enabled`,
  `features.respect_system_proxy`. Two consequences: **(a)** an interaction risk — if Codex's own
  network proxy is enabled, `HTTPS_PROXY` injection by Veil meets a harness that already has
  opinions about upstream proxies; H1 must test this explicitly. **(b)** prior art — its file
  discipline ("refusing to use symlink lock file", "refusing to overwrite existing file", atomic
  rename, lease pruning) is precisely the discipline §5 now requires of H5, and is cited there.
  This substantially firms up the draft's own "some proxy strings belong to Codex's sandbox
  network-proxy subsystem" hedge: that hedge was correct and is now concrete.

- **GROUND-10 (verified live, and sharpened into a safety requirement) (consolidation):** Claude
  Code's enterprise-network doc (`code.claude.com/docs/en/corporate-proxy`, fetched 2026-09-14)
  documents `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`, `NODE_EXTRA_CA_CERTS`, OS-trust-store reading,
  and mTLS client-cert vars — so mechanism B is inside Anthropic's documented support envelope.
  **Critique finding #13 verified verbatim and adopted:** "Lowercase variants also work, and
  Claude Code uses the first one that's set in the order **`https_proxy`, `HTTPS_PROXY`,
  `http_proxy`, `HTTP_PROXY`**." Injecting only uppercase is therefore unsafe — an inherited
  lowercase `https_proxy` wins and routes Claude Code around Veil. Launch profiles need an explicit
  collision policy for every case variant plus `ALL_PROXY`/`all_proxy` and `NO_PROXY` (F14).
  Also verified, as the draft claimed: "Claude Code never sends its WebSocket connections to
  `localhost`, `::1`, or `127.0.0.0/8` through the proxy."
  **Two details neither prior stage had:** (i) `CLAUDE_CODE_CERT_STORE` (comma-separated
  `bundled`/`system`, default `bundled,system`) is a separate trust-composition knob, and
  `NODE_EXTRA_CA_CERTS` *appends* ("CA certs: Appended extra certificates from
  NODE_EXTRA_CA_CERTS") rather than replacing the bundled+system set — so the critique's
  "broadening trust" concern is narrower than stated, but its *collision* concern is real: there is
  one `NODE_EXTRA_CA_CERTS` path, so overwriting a corporate value breaks that user. The fix is a
  merged bundle file, not an overwrite (F14). (ii) See GROUND-13 for the streaming watchdogs.

- **GROUND-11 (revised — the draft overclaimed) (consolidation):** the consultation's recommended
  order was "(1) test `CLAUDE_CODE_ATTRIBUTION_HEADER=0` on the existing base-URL path; (2) if that
  fails, CONNECT proxy." Step (1) succeeded — **in a development live-proof harness driven by a
  shell script**, per §1.1. So the fork for Claude Code is no longer "which mechanism works"; it is
  **"productionise the proven-in-dev mechanism" (H0) and, separately, "is there any reason to
  migrate off it" (F3)**. Critique finding #14 confirmed.

- **GROUND-12 (revised — "moot by construction" was wrong) (consolidation):** verified against
  `mask_request.rs:139-161`: `mask_system` walks every `system` text block indiscriminately;
  there is no attribution-block recognition, and any non-`text` entry fails closed
  (`MalformedSystemEntry`). The draft called the risk "moot by construction" because `vg run`
  injects `CLAUDE_CODE_ATTRIBUTION_HEADER=0` unconditionally (`main.rs:326-335`). That is true of
  `vg run` and false of the proxy path, because §1.1: nothing launched by `vg run` currently goes
  through vg-proxy at all, and the thing that does (the proof script) sets the variable itself.
  Critique finding #15 confirmed. **Standing invariant, restated:** every supported harness profile
  must pin the vendor-metadata story as part of its launch profile, and the live proof must assert
  it. **Adopted from finding #15:** "suppress, or byte-preserve" is not a design. This plan chooses
  **suppress** and states the residual plainly: a direct proxy user who bypasses the launcher, or a
  vendor semantics change, re-opens it. Byte-preservation would require an actual
  metadata-recognition design and tests and is explicitly **not** scoped here (§6).

- **GROUND-13 (new — the concrete bound on buffered streaming) (consolidation):** the draft's F6
  gestured at "Anthropic's documented stall warning" without a number. The corporate-proxy doc's
  "Streaming idle watchdogs" table gives real ones. An **event-level watchdog** ("No response
  events parse", **runs on every provider**, default **300 seconds**) and a **byte-level watchdog**
  ("No bytes arrive on the wire, including SSE keep-alive pings", runs on "gateway connections,
  including a custom `ANTHROPIC_BASE_URL`", default **300 seconds** for non-direct endpoints) both
  abort the stream. **vg-proxy's full buffering means zero bytes reach the client until the entire
  upstream response is buffered.** Any upstream response taking longer than ~300s to complete is
  therefore aborted client-side today. That converts F6 from a vibe into a measurable entry
  criterion, and it is the strongest single argument for H6.

- **GROUND-14 (new — Codex's own retry/timeout contract) (consolidation):** the config reference
  documents `request_max_retries` (default 4), `stream_max_retries` ("Retry count for SSE streaming
  interruptions", default 5) and `stream_idle_timeout_ms` (default 300000). Adopted from critique
  finding #18: repeated masking across retries must not create inconsistent placeholder bindings or
  duplicated output, and Veil's own timeouts (H2c) must be compatible with these, not shorter in a
  way that induces a retry storm. Explicit tests required in H3/H4.

- **GROUND-15 (new — `requires_openai_auth` is documented, not unknown) (consolidation):** the
  draft's evidence register said there is "no direct evidence at all" that ChatGPT-subscription
  auth flows to a custom provider. That is wrong. Verified in the official authentication docs:
  "Set `requires_openai_auth = true` to use OpenAI authentication. **You can then sign in with
  ChatGPT or an API key.**" and "This is useful when you access OpenAI models through an LLM proxy
  server." Critique finding #11 confirmed. The honest remaining unknown is narrower and is what H1
  must convert to evidence: whether it *behaves as documented for 0.153.4 against a loopback
  plain-HTTP redirect*, and whether ChatGPT-backend traffic then targets `chatgpt.com/backend-api/
  codex` rather than the configured base URL.

---

## 3b. Disposition of the 25 critique findings

Held to the same bar the draft held its own input to. "Confirmed" means re-verified independently
this pass, not accepted on the critique's authority.

| # | Subject | Verdict | Where handled |
|---|---|---|---|
| 1 | F2 fail-open tunnel | **Confirmed, material** | F2 inverted; §2; §5 |
| 2 | Dev proof ≠ shipping path | **Confirmed, most material** | §1.1; new H0; A3 dependency |
| 3 | Four dependency-graph errors | **Confirmed** (3 exact; the 4th, E1-vs-"Track 1", is a real omission though not a literal contradiction — E1 is Phase E, not Track 1) | §4 table + graph |
| 4 | F5 vs per-session CA; one-vault overread | **Confirmed, material** | F5 rewritten; F10 new; H0 control plane |
| 5 | "CA key dropped from memory" unenforceable | **Confirmed** | §5 restated precisely + audit checklist; F13 |
| 6 | Leaf key not dominated by memory compromise | **Confirmed** | §5 row rewritten |
| 7 | SIGKILL cleanup impossible | **Confirmed** (and it is *conditional* on F5's answer — true under one-process-per-session, false under a persistent daemon) | §5; H0 orphan reaping |
| 8 | `Origin` identity splitting; missing base path | **Confirmed, strengthened** — two auth modes use different hosts *and* base paths | D-H-3 |
| 9 | GROUND-7 overclaims | **Confirmed, strengthened** — `responses_websocket` found in the binary | GROUND-7; F12 |
| 10 | `openai_base_url` should be tested first | **Confirmed, doc-verified verbatim** | GROUND-8; H1; F11 |
| 11 | `requires_openai_auth` is documented | **Confirmed, doc-verified verbatim** | GROUND-15; §8 |
| 12 | Plural-vs-singular CA var version fork | **REJECTED — the critique's central factual claim is wrong.** Both doc and binary use singular `CODEX_CA_CERTIFICATE`; the "plural" is a string-table concatenation artifact the draft made first and the critique repeated. No version fork exists. Its *second* half (CA applies to login/HTTPS/WSS) is **confirmed** and adopted. | GROUND-9 |
| 13 | Lowercase proxy precedence | **Confirmed, doc-verified verbatim** | GROUND-10; F14 |
| 14 | GROUND-11 too broad | **Confirmed** | GROUND-11 |
| 15 | GROUND-12 overstates invariant | **Confirmed** | GROUND-12 |
| 16 | H1 bare listener can't meet its gate; fixture governance | **Confirmed** | H1 rewritten; F15 |
| 17 | H2 is not no-behavior-change; request body unbounded | **Confirmed** — `server.rs:304-320` verified unbounded | H2a/b/c split; §1.2 item 9 |
| 18 | Fail-closed contract underspecified for responses; retries | **Confirmed, strengthened** by GROUND-14 | H3; F16 |
| 19 | Anthropic header-prefix claim overstated | **Confirmed in substance** — prefix-forwarding is a design choice, not a vendor requirement | F4 rewritten |
| 20 | H4 doesn't close namespace lifecycle | **Confirmed in substance; one sub-claim rejected.** Its positive suggestion is better than the draft's design and is adopted (per-session listener carries its namespace on the connection; no global registry). **Rejected:** binding-store eviction framed as an unresolved Track H gap — it is pre-existing, named in `session.rs`'s own doc and `docs/next-actions.md`'s open questions, and owned there; Track H neither creates nor is blocked by it. | H0/H4 |
| 21 | `tls_upstream.rs` has 2 reject tests, not 3 | **Confirmed, minor.** The draft's §1 "three tests" was *correct* (1 accept + 2 reject); only H5's exit-gate wording was wrong. Corrected, and the real inbound reject list expanded. | H5 gate |
| 22 | Process-scoped trust is propagation scoping | **Confirmed** | §5 rewritten; GROUND-9b cited as prior art |
| 23 | E1 credited with the wrong security effect | **Confirmed** | §5 rows split |
| 24 | Missing forks | **Mostly confirmed** — F9-F14 added. **One sub-item rejected:** "per-harness/provider provenance in audit events" is not a missing fork; the draft explicitly declared it out of scope with a named owning document (`telemetry-receipt-reconciliation-plan.md`), which the critique missed. | §7; §6 |
| 25 | Sizing substantially low | **Confirmed** | §4 |
| — | Artifact untracked in git | **Confirmed** (`git status`: `?? docs/architecture/multi-harness-proxy-plan.md`) | Commit this file as the first act of Track H |

---

## 4. Milestones — Track H

**Naming:** a new track, deliberately. The M-series (M1-M6, M10) belongs to the masking-proxy plan
(`<hekton-machinery>/docs/plans/veilgremlin-masking-proxy-plan-v1.md` §10.3) with M6/M10 still
reserved there; the A-series is the beta plan's Track 1, allocated through A8 with ratified sizes.
Reusing either numbering would imply this work sits inside a plan whose scope it exceeds.
"H" = harness. Session-size estimates follow Track 1's convention.

| ID | Milestone | Sessions | Blocks on | Exit gate |
|---|---|---|---|---|
| **H0** | **Production launch path (NEW — was hidden inside the draft's H4).** `vg run` actually starts the masking path: `vg-cli` gains a `vg-proxy` dependency; per-session listener bound on an ephemeral loopback port; namespace carried **on the connection**, not via a global address registry (adopted from critique #20 — a per-session listener knows its own namespace, so `register_port_if_absent`'s crash/port-reuse staleness never arises); env/config injection (`ANTHROPIC_BASE_URL` + the F14 proxy/CA collision policy); an **authenticated launcher↔daemon control plane** (F9) carrying session create/destroy, the listener port, and — under H5 — the CA path; child-exit and orphan reaping (parent-death detection, not only shell traps, per critique #7). The existing `session.rs` registry is retained only as the compatibility path for callers that send `X-VG-Namespace`. | 2-3 | **A3** (Track 1: production daemon bootstrap — real state-dir/keychain discovery; `daemon.rs:49-68`'s own named gap) | `vg run -- claude -p …` masks and demasks a real session end to end **with no script-level env injection**; `scripts/a2-live-proof.sh` re-expressed against `vg run` and still passing; killing the launcher leaves no live listener and no orphaned session state |
| **H1** | **Codex interception + auth spike.** Live-run, throwaway-code-allowed, in this order: (a) `openai_base_url` pointed at a loopback listener via `-c` override — the vendor-recommended LLM-proxy path (GROUND-8); (b) custom `model_providers.veil` with `base_url` + `requires_openai_auth = true`; test **both** auth modes for each — ChatGPT sign-in and API key (`env_key`) — and record which upstream origin/base path each actually targets (`api.openai.com/v1/responses` vs `chatgpt.com/backend-api/codex`); (c) whether `wire_api` negotiates SSE or WebSocket, and whether `codex.transport.fallback_to_http` triggers; (d) interaction with Codex's own `network_proxy`/`respect_system_proxy` features (GROUND-9b); (e) **only if (a)-(b) fail:** `HTTPS_PROXY` + `CODEX_CA_CERTIFICATE` (singular — GROUND-9) with a throwaway local CA, testing `SSL_CERT_FILE` fallback too. Look specifically for Claude-Code-style defensive behaviours against non-default base URLs (GROUND-12 precedent). The listener is a **throwaway record-and-relay**, not a bare recorder (critique #16: a bare listener cannot capture an upstream SSE corpus or validate auth end to end). | 2-4 | — (F15 must be answered first — it is a governance answer, not a session) | A written mechanism decision recorded in `docs/decisions.md` with live-run evidence; a **sanitised** Responses traffic corpus meeting F15's fixture-governance rules; F7 (auth mode), F11 (provider mode) and F12 (wire transport) answered or escalated |
| **H2a** | **Canonical `Origin` + per-origin routing.** Replace `UpstreamConfig`'s four-roles-one-string with D-H-3's canonical origin + derived identity + explicit `base_path`; per-origin routing table selected from the transport's trusted identity, never the client `Host`; the full binding/canonicalisation rule set and its adversarial tests. | 2-3 | **H1's verdict** (not all of H1) — H1 determines the real origin/base-path shapes the type must express | Every canonicalisation case in D-H-3 has a passing reject test; `a2-live-proof.sh` (via H0) still passes |
| **H2b** | **Codec trait extraction.** Extract the codec trait pair (request-mask walk, response demask, SSE demask, route classification, per-codec header policy); items 3-6 of §1.2 become the Anthropic impl; `FORWARDED_HEADERS` moves into the Anthropic codec under F4's resolved policy. | 1-2 | — (starts immediately, parallel to H1) | Zero Anthropic-shaped types outside the Anthropic codec module; all existing tests green |
| **H2c** | **Bounds and timeouts.** Close §1.2 item 9 in **both** directions: a request-body bound (`server.rs:304-320`, currently unbounded — critique #17) and a response-body bound, plus **five separately named timeouts**: connect, response-headers, idle-body, total-request, and streaming-idle. Defaults chosen against GROUND-13/14's real vendor numbers so a valid long stream is never killed by a generic "request timeout." | 1-2 | — (starts immediately) | A long-running real stream survives; an oversized body in either direction fails closed with a 4xx/5xx, not an OOM; each timeout has a test that trips only it |
| **H3** | **OpenAI Responses codec.** Route table, request-tree mask walk, response + SSE-event demask for the Responses schema, built against H1's captured real corpus, not the docs alone. Same fail-closed discipline as the Anthropic codec on the **request** side (unrecognised item types block; image/file inputs block; malformed shapes block). On the **response** side, the contract the draft left unspecified is now stated (F16's recommendation): an **unrecognised event in a stream terminates the stream with an explicit error**, never passes through — a placeholder that reaches the user un-demasked is a worse failure than a truncated response. Retry/resumption tests per GROUND-14. | 3-5 | H1, H2a, H2b | Codec unit tests against sanitised real fixtures; masked-request shape-preservation tests matching `mask_request.rs`'s own discipline; a replayed retry produces identical placeholder bindings and no duplicated output |
| **H4** | **Codex harness launch profile + live proof.** `vg run codex …` on H0's launch machinery: config/env injection per H1's mechanism, vendor-metadata invariant pinned (GROUND-12), trust-bundle composition per F14. A real `a2`-style live proof: real Codex CLI, real OpenAI API, real auth, real masking/demasking round trip. | 2-3 | H0, H1, H2a, H2b, H3, **and H5 iff H1's verdict is "config redirect fails"** | The Codex live proof passes end to end and joins the proof-script set; the Claude proof still passes; the supported-harness matrix in §2 is updated with real rows |
| **H5** | **CONDITIONAL — CONNECT transport + process-scoped CA.** Built only if H1 eliminates the config-redirect mechanism (D-H-2), to §5's security bar in full: CONNECT parsing + exact-origin allowlist + the D-H-3 binding rule; inbound TLS acceptance with pre-issued per-origin leaves; **reject-unknown by default** with a separately verified non-model-bearing tunnel allowlist (F2, inverted); CA key-lifecycle to §5's audit checklist; `NODE_EXTRA_CA_CERTS`/`CODEX_CA_CERTIFICATE` injection under F14's merge policy; ALPN, backpressure, and the H2c timeout set on the inbound path; corporate-proxy compatibility (an upstream corporate proxy already present). `rcgen` and any CONNECT/zeroize dependency move to production dependencies — governance-gated (F8). | 6-9 | H1's verdict, H2a, H2c, **and E1 for any cohort distribution** (§5) | The inbound reject list of §5 each has a passing test; a non-allowlisted CONNECT target is demonstrably never terminated **and never tunnelled unless explicitly allowlisted**; §5's checklist items each either done or waived by name in `docs/decisions.md` |
| **H6** | **Streaming decision + incremental demask.** Today both directions are fully buffered (§1.2 item 7), which GROUND-13 shows breaks any response exceeding ~300s under Claude Code's own watchdogs. One design covering **both** codecs' event formats, with the bounded-window partial-placeholder question (a placeholder split across a chunk boundary, currently solved only by full buffering) answered without buffering. Overlaps beta item A4/M6 — **coordinated, not duplicated**. | 3-4 | H2b, **H3** (the Responses event corpus must exist before a design claims to cover both codecs — critique #3), A4 coordination | Incremental delivery under a real long-response live run exceeding the 300s watchdog; the split-placeholder regression test passes without full buffering; bounded memory under a hostile long stream |

**Dependency graph (corrected):**

```
A3 (Track 1, 1-2) ──> H0 (launch path, 2-3) ──────────────────────────┐
                                                                      │
H2b (codec trait) ──┬──────────────────────────────┐                  │
H2c (bounds/timeouts)┤                             │                  │
                     │                             ├──> H4 (Codex live proof)
H1 (spike) ──┬──> H2a (canonical Origin) ──────────┤                  │
             │                                     │                  │
             └──[if H1 rejects config redirect]──> H5 ────────────────┘
                                                    │
                                          H5 also needs E1 (Phase E)
                                             for ANY cohort distribution
H1 ──> H3 (Responses codec) ──┬──> H4
H2b, H3 ──> H6 (streaming; coordinate with A4/M6)
```

**Sizing (revised upward, accepting critique #25).**

| Path | Sessions |
|---|---|
| Track H without H5 (H0+H1+H2a+H2b+H2c+H3+H4+H6) | **16-26** |
| Track H with H5 | **22-35** |
| Prerequisite already budgeted in Track 1 | A3: 1-2 (not double-counted above) |
| Prerequisite on the beta critical path, only for H5 cohort distribution | E1: 3-4 (Phase E) |

The draft's 6-10 / 9-14 were not reliable: they excluded H0/A3 entirely, treated H2 as one
milestone when it is at least three risky changes, assumed one captured exchange establishes the
Responses schema, and sized H5 — a subsystem comprising CONNECT parsing, tunnels, inbound TLS,
certificate lifecycle, origin binding, ALPN, backpressure, timeouts, control-plane integration,
corporate-proxy compatibility, governance and adversarial tests — as one milestone-sized feature.

**Start order.** H2b and H2c start immediately (neither depends on H1's findings). H1 starts as
soon as F15 is answered. H0 starts as soon as A3 lands. H2a's type shape is **frozen only after
H1's verdict** — the draft's "H1 and H2 start in parallel" was right about the work and wrong
about the freeze point, since H1 is exactly what discovers the origins, base paths, auth modes and
wire transport the `Origin` type must express.

---

## 5. Security and trust-boundary analysis: the process-scoped local CA (H5)

This section binds H5 whether or not it is ever built; if H5 is skipped, it stands as the recorded
reason the cheaper mechanism was preferred.

**Trust model, stated honestly (critique #22, adopted).** The CA is reachable by the wrapped
harness and its children via `NODE_EXTRA_CA_CERTS` (Claude Code) / `CODEX_CA_CERTIFICATE` (Codex).
**This is environment-propagation scoping, not an OS security boundary.** Children inherit it;
same-user processes can inspect process state; the wrapped agent can modify files in its own state
directory; mode 0600 does not protect anything from a compromised child running as the same UID.
The CA is never written to the OS trust store — `vg` must **refuse** such a request outright, not
merely omit the feature (a testable behaviour, like `server.rs`'s double loopback check).

| Concern | Design position |
|---|---|
| **Key generation** | Per-session, in-memory, at session start. No cross-session CA, no per-device CA. `rcgen` (exercised today by `tests/tls_upstream.rs:39-63`, `make_ca_and_leaf`) generates CA + leaves in one pass. |
| **Issuance scope** | Leaves are **pre-issued at session start for the fixed origin allowlist only**, then the signing capability is retired. **Claim restated precisely (critique #5, adopted):** what is enforceable and testable is "**after setup, no code path in the process retains a signing API or an issuer key handle**" — that is a real structural reduction and stays as an acceptance gate. What is **not** claimed, because it is not established by dropping an `rcgen` value: that every copy of the secret bytes has been erased. |
| **Key destruction — audit checklist, not an assertion** | H5 review must answer each in writing: does `vg-proxy` take a `zeroize` dependency (it does not today — verified, `crates/vg-proxy/Cargo.toml`) and wrap issuer key material in a zeroizing type; does `rcgen 0.13`'s internal key representation permit zeroization or must material be handled pre-`rcgen`; do DER/PKCS#8 serialisation steps create additional copies; what is the posture on allocator reuse, swap, and core dumps (at minimum: disable core dumps for the process); how do failure paths erase partially constructed material. Any item may be **waived by name** in `docs/decisions.md` — none may be silently assumed. `vg-vault`'s use of `zeroize` elsewhere is not evidence about `vg-proxy`. |
| **Certificate parameters** (critique #22, adopted) | Named explicitly, not left to implementation: key algorithm (P-256/ECDSA-SHA256, matching this repo's ADR-S/ADR-017 discipline); validity **bounded to a few hours**, not a year, so a stolen leaf's capability expires (see the leaf-key row); SANs limited to the exact allowlisted origins; EKU `serverAuth` only; CSPRNG serial numbers; explicit tolerance for clock skew and for sleep/resume crossing a validity boundary (behaviour on expiry mid-session: re-issue from a retained *leaf* keypair is impossible once the issuer is retired, so the session must fail closed with a clear error — an accepted cost of retiring the issuer, named here rather than discovered later). F13. |
| **Storage** | Only the CA *certificate* (public) touches disk, for env-var injection: in a 0700 session directory, created **atomically and symlink-safely** (`O_NOFOLLOW`/`O_EXCL` + rename, refusing to overwrite or reuse a mismatched or symlinked path — exactly the discipline Codex's own `network-proxy/src/certs.rs` implements, GROUND-9b). The plan must state whether clients re-read the bundle mid-session (Claude Code does re-read mTLS material on connection errors; CA behaviour must be tested) and what happens if the path is replaced during a long session. Leaf private keys and (until retired) the issuer key exist in process memory only. Nothing enters the macOS keychain: unlike `vg enrol`'s device credential (ADR-017), this material is worthless past the session. |
| **Lifecycle / cleanup** | **Conditional on F5, and the draft's claim was wrong under its own recommendation (critique #7, adopted).** Under one-process-per-session, "key material died with the process" holds. Under a persistent daemon — the draft's own recommendation — killing the launcher does **not** kill the process holding the keys, so the claim is false. Required either way: daemon-side orphan detection (parent-death watch, not only shell traps, which cannot run after SIGKILL), explicit session teardown that zeroizes and drops per-session TLS configs, draining of detached connection tasks (`server.rs`'s documented detached-task trade-off makes this real work), and defence against PID reuse. Shell traps are a convenience, never the mechanism. |
| **If the CA cert leaks** | Harmless alone: public material, and nothing outside the session's env trusts it. |
| **If a leaf private key leaks** | **Treated as an independent capability, not dominated (critique #6, adopted — the draft was wrong here).** The counterexample is sound: a one-time memory snapshot, crash dump or swap fragment yields a leaf key without ongoing code execution and without observing current plaintext; later, if the proxy dies or its port becomes reusable while the harness lives, the attacker binds the expected endpoint, presents the still-valid leaf, and captures newly refreshed credentials and all future prompts. "Can read selected memory once" is strictly weaker than "can observe every future request." Mitigations, which is why the parameters above are what they are: short certificate validity bounds the window; binding the leaf to the session's ephemeral loopback port narrows the rebind opportunity; the port must not be rebindable by another process while the session lives. Residual risk accepted and disclosed, not argued away. |
| **If the wrapped harness is compromised** | It holds the real bearer token and sees all plaintext regardless of vg-proxy. The inherited-env hazard is the real one: shell children inherit the proxy and CA variables, so `curl` inside an agent session routes through vg-proxy trusting the session CA. Mitigations: (1) non-allowlisted CONNECT targets are **rejected**, never terminated and never tunnelled unless explicitly allowlisted as non-model-bearing (F2); (2) allowlisted tunnel bytes are never parsed, logged, or buffered beyond copy loops; (3) allowlists are exact origins, no wildcards. |
| **If vg-proxy itself is compromised (concentrated trust)** | Bounded by: loopback-only listening enforced twice (`server.rs:27-34`, `:71-73` — keep both); per-session ephemeral ports; per-session CA (compromising one session's daemon yields that session, not a device-wide interceptor); short certificate validity; issuer retirement after setup. **E1 is NOT a mitigation for this row (critique #23, adopted — the draft mis-credited it).** Signing/notarisation bounds *distribution integrity*: it does not bound a runtime daemon compromise, a parser exploit, a malicious dependency, or a correctly signed but vulnerable release. |
| **Distribution integrity (separate row)** | E1 (signed/notarised binary, SBOM, versioned artifact — beta plan Phase E, 3-4 sessions) is the control here, and **H5 hard-depends on it for any cohort distribution**: asking beta users to trust locally generated interception material shipped by an unsigned binary inverts the trust story. |
| **Logging** | `Authorization`/`x-api-key` values and plaintext bodies never reach any log. Standing risk: this crate's error-logging convention is bare `eprintln!` with error context (`upstream.rs:241`, `server.rs:94`, `:114`); H5 review must re-audit every such site on the new inbound path — an inbound TLS error echoing ClientHello or header bytes would be a new leak class. |
| **User consent** | Beta users under H5 acknowledge in the participation agreement that vg-proxy terminates TLS for the named origins and holds their model bearer token in memory — extending the beta plan's "security gaps accepted in writing, not latent" bar, consistent with the A5/F4 disclosure discipline. |

**Inbound must-reject list (H5 exit gate; replaces the draft's incorrect "three `tls_upstream.rs`
must-reject properties" — that file has three tests total, one accept at `:117` and two reject at
`:134`/`:155`).** Each needs its own passing test on the *inbound* path: CONNECT authority not on
the allowlist · CONNECT authority ≠ TLS SNI · TLS SNI ≠ inner `Host`/`:authority` · codec route
disagreeing with the selected origin · every canonicalisation bypass in D-H-3 (case, trailing dot,
default port, IPv6 form, IDNA, userinfo, absolute-form target) · disallowed port · leaf presented
with an invalid SAN/EKU/key usage · expired or not-yet-valid leaf · unsupported ALPN · a
model-bearing origin reached via the tunnel path.

---

## 6. Named trade-offs and out-of-scope items

Trade-offs made (not discovered later):

1. **Claude Code stays on the base-URL redirect for beta**, productionised by H0 rather than
   migrated to mechanism B — the vendor's documented opt-out closed the attribution defence, the
   proof passes, and migrating a working mechanism mid-beta adds risk for symmetry's sake alone
   (GROUND-11, fork F3 for later).
2. **The Codex mechanism is decided by evidence, not architecture aesthetics.** The layered
   architecture is prettier if both harnesses use mechanism B; this plan accepts a lopsided
   (A, A) or (A, B) matrix to avoid building the CA subsystem before it is provably needed.
3. **H2 is split into three milestones and is explicitly not a "no behavior change" refactor**
   (critique #17, adopted). It changes routing identity, header policy, timeout behaviour and
   response-size behaviour; a prefix allowlist is an observable expansion, and bounds can terminate
   previously-succeeding long requests. The honest bar is **"live-proof-preserving"**, asserted by
   re-running the proofs, not "behaviour-identical."
4. **Buffered streaming survives until H6, with a now-quantified cost.** GROUND-13 gives the real
   bound (~300s of client-side watchdog). Accepted for beta because real sessions work today, but
   it is a known correctness cliff, not merely a latency preference (F6).
5. **Per-codec header policy over both alternatives**: a fixed enum (today; breaks as vendors
   evolve their header sets) and a blind copy (forwards anything a compromised client sets).
   Prefix-allowlist per codec plus named singletons, **plus an explicit rule for unknown prefixed
   headers** (F4) — because, as critique #19 correctly says, prefix-forwarding is Veil's design
   choice and not a vendor requirement, so a future prefixed credential would otherwise be
   forwarded automatically.
6. **Vendor metadata is suppressed, not byte-preserved** (GROUND-12). Byte-preservation would need
   a real metadata-recognition design and tests; naming it as an option does not create one, so it
   is out of scope rather than half-promised.

Out of scope for Track H, by name:

- System-wide DNS/hosts interception, OS-trust-store CA, transparent port-443 capture — the
  possible "managed enterprise" mode, unscoped and unscheduled.
- Any third harness (Gemini CLI, Cursor, aider, …) — each is a new H1-style spike + profile.
- Codex-over-Bedrock or any non-default Codex provider chain; Anthropic-Bedrock route changes.
- Integrating with, or depending on, Codex's own `network_proxy`/managed-MITM-CA subsystem
  (GROUND-9b) — H1 tests for *interference*; using it is a separate, unscoped question.
- Windows/Linux anything (beta bar is macOS-only).
- A byte-preserving vendor-metadata design (trade-off 6).
- The `document`-content-block sub-case deferred by `mask_request.rs` — unchanged by this track.
- The session binding-store lifetime/eviction question — **pre-existing and owned elsewhere**
  (`session.rs`'s own doc; `docs/next-actions.md` open questions). Track H neither creates nor
  resolves it; H0's per-connection namespace design does not depend on its answer.
- MCP-server mode, LiteLLM-style gateway hosting, GLiNER warm path.
- Telemetry schema changes: masking events from a Codex session reuse the existing
  `AuditEvent`/telemetry path untouched. If per-harness provenance in telemetry is ever wanted,
  that is a `telemetry-receipt-reconciliation-plan.md` amendment, not Track H scope. (Retained
  against critique #24, which listed this as a missing fork; it is a named out-of-scope item with
  a named owner, which is the stronger form.)

---

## 7. Open forks needing a human decision before the affected milestone starts

Per ADR-017's precedent (design forks named and settled with a human before code). F9-F16 are new
in this consolidation, mostly from critique #24.

| # | Fork | Options | Plan's recommendation | Decide before |
|---|---|---|---|---|
| **F1** | Does Track H gate the beta? **DECIDED 2026-09-14 — (b), overriding this plan's own recommendation.** | (a) beta ships Claude-only, Track H lands after; (b) Codex support joins the beta bar | **(a)** was this plan's recommendation — the ratified bar's condition 1 named Claude Code only; widening it re-opens a ratified decision and adds 16-35 sessions to the critical path. **The user chose (b) instead**, via explicit `AskUserQuestion`, specified as full Codex parity: Track H's H0 through H4 complete (H5 only if H1's own spike verdict forces it) before any beta user is onboarded. Ratified as `D-BETA-8` in `veil-ecosystem/docs/decisions.md` (2026-09-14), which also reworks `beta-implementation-plan.md` §1 condition 1 and §5's critical path — see that entry for the schedule consequence, not re-derived here. This plan's own out-of-scope framing in §6 ("nothing in this track gates the ratified beta bar") and the summary line in §0 are now stale and superseded by that ratification; left as originally written elsewhere in this document as a record of the plan's own reasoning at merge time, not silently edited to match. | ~~H1 start~~ — decided |
| **F2** | Non-allowlisted CONNECT targets under H5 | (a) **reject unknown by default**, with a *separately verified* allowlist of destinations proven not to carry model context; (b) tunnel raw everything non-terminated | **(a) — inverted from the draft** (critique #1, accepted). Tunnelling every unknown target is fail-open for the product's whole purpose: if a vendor moves model traffic to a new hostname, WebSocket endpoint, regional origin, or auth-dependent backend, Veil forwards the prompt unmasked and per-target counts only report the leak afterwards. Verified as a live hazard, not hypothetical: Codex 0.153.4 carries model context to **two** distinct origins depending on auth mode (`api.openai.com`, `chatgpt.com/backend-api/codex`). The invariant is not "terminate only exact origins" but **"model-bearing traffic never tunnels."** Operability cost is paid by curating the tunnel allowlist from H1's real observations, with per-target counts (never contents) in the local audit log. | H5 build |
| **F3** | Migrate Claude Code onto mechanism B eventually? | (a) keep base-URL redirect indefinitely; (b) converge both harnesses on B post-beta | Defer — no evidence yet that B is strictly better in practice; re-open after H4/H5 with two live proofs in hand | Not before H5 exists |
| **F4** | Header-forwarding policy shape, **including unknown prefixed headers** | (a) fixed enum per codec; (b) prefix allowlist + named singletons; (c) forward-all minus denylist | **(b)**, with two additions per critique #19: an explicit **denylist of credential-shaped names** that wins over any prefix match, and unknown-but-prefix-matching headers **counted (never logged by value)** with a per-release review of what actually appeared. Exact lists: `anthropic-*`/`x-claude-code-*` for the Anthropic codec; the OpenAI-side list from H1's real captured traffic, not guessed. Anthropic names specific required headers; it does not warrant a whole prefix as safe — that is Veil's choice and Veil owns the residual. | H2b merge |
| **F5** | Process model for per-session listeners | (a) one daemon, N listeners; (b) one vg-proxy process per session; (c) hybrid — one supervisor daemon, one worker process per session | **(c), replacing the draft's (a)** (critique #4, accepted). The draft's argument for (a) — "`Daemon`'s one-open-vault design exists precisely for this" — overreads the code: `daemon.rs:49-68` gives one process **one** vault, policy, detector set and audit path for its whole lifetime, so a single daemon cannot serve two repositories with different `.veilgremlin` policy/state dirs without a new per-session configuration model (F10). (c) keeps a single supervisor for the control plane and lifecycle while giving each session its own vault/policy/audit and its own key material, which also makes §5's "keys die with the process" true again rather than conditionally false. Cost: N vault opens — measure it in H0 before committing. | H0 build |
| **F6** | True incremental streaming — and does an explicit proxy change when it's needed? | Grounded in §1.2: **no** — buffering happens in `upstream::forward`/`stream_demask`, transport-independent. The real drivers, now quantified (GROUND-13): Claude Code aborts a stream after ~300s with no parsed event or no bytes, and vg-proxy emits **nothing** until the upstream response is fully buffered | Fix in H6; do not treat as a Track H entry criterion, but record it as a known correctness cliff, not a latency preference | H6 scoping (jointly with A4's owner) |
| **F7** | Which Codex auth mode does Veil support first? | (a) ChatGPT subscription; (b) API key; (c) both | Evidence-gated: H1 tests both. Note the modes are **not** interchangeable for interception — they target different hosts and base paths (D-H-3). If subscription auth fails through every interception mechanism, **(b)** is the honest launch scope | End of H1 |
| **F8** | `rcgen`, `zeroize`, and any CONNECT-parsing dependency as production dependencies | Per veil-ecosystem `governance.yaml` `dependency_changes: human_required` | Present at H5 start with license/`cargo-deny` results in hand (precedent: A2's `webpki-roots`→`rustls-native-certs` license swap) | H5 build |
| **F9** | **(NEW)** Launcher↔daemon control plane: ownership and authentication | (a) launcher generates certificates and sends private leaf keys to the daemon; (b) daemon generates and returns port + CA path to the launcher; (c) no daemon — launcher owns everything in-process | **(b)**, over a 0700 unix domain socket with peer-credential checks (same-UID, expected PID lineage) — (a) moves private keys across a process boundary for no benefit. Whichever is chosen, the launcher needs a trustworthy response carrying the correct port and CA path, and neither side may accept an unauthenticated session-create | H0 build |
| **F10** | **(NEW)** One global policy/vault vs per-repository session configuration | (a) one global `.veilgremlin` per machine; (b) per-repository state dir resolved per session | **(b)** — it is what users will expect and what `Engine::open` already does for the hook path; but it is the concrete reason F5 lands on (c), and it is real new work in A3/H0, not a free property of today's `Daemon` | H0 build (jointly with F5) |
| **F11** | **(NEW)** Codex redirect mode | (a) `openai_base_url` on the built-in provider; (b) custom `model_providers.veil`; (c) support both | **(a) first, (c) eventually.** OpenAI's own guidance prefers (a) for LLM proxies, and it preserves built-in provider identity; (b) may change capabilities and hide problems behind feature downgrades — which makes it a valuable *second* test case, not the first | End of H1 |
| **F12** | **(NEW)** SSE-only support vs WebSocket/capability parity | (a) SSE only, with `supports_websockets = false` pinned in the injected provider config and the downgrade disclosed; (b) full parity | **(a) for beta**, explicitly disclosed as a capability restriction Veil imposes — with H1 confirming whether pinning it actually prevents the WebSocket transport and whether `codex.transport.fallback_to_http` behaves. (b) is a real second transport implementation, unsized here | H3 scoping |
| **F13** | **(NEW)** Certificate policy under H5: algorithm, validity, clock skew, long sessions | (a) short validity (hours) + fail-closed on expiry; (b) long validity (session-length-plus-margin); (c) re-issuance (requires retaining the issuer, defeating issuer retirement) | **(a)** — it is the only option that bounds the leaf-theft window (§5, critique #6), and its cost (a very long session failing closed at the boundary) is visible and recoverable | H5 build |
| **F14** | **(NEW)** Environment composition: proxy variables and existing corporate trust bundles | (a) set only the variables Veil needs, error out on any pre-existing conflicting value; (b) set Veil's values and merge/preserve existing ones; (c) overwrite silently | **(b) for CA bundles, (a) for proxy variables.** CA: write a merged bundle (Veil's CA + whatever the existing `NODE_EXTRA_CA_CERTS`/`CODEX_CA_CERTIFICATE` pointed at) so corporate networking keeps working — overwriting breaks login/updates, and Claude Code appends rather than replaces its bundled+system set, so the risk is collision, not trust broadening. Proxy: the launch profile must set **every** case variant Claude Code consults, in its documented precedence order `https_proxy, HTTPS_PROXY, http_proxy, HTTP_PROXY`, plus `ALL_PROXY`/`all_proxy` and a `NO_PROXY` that does not exclude the target origin — and must **fail loudly** on a pre-existing conflicting proxy rather than quietly losing to a lowercase variant (GROUND-10) | H0 build (Claude), H4 build (Codex) |
| **F15** | **(NEW)** Live-corpus and fixture governance | (a) capture real traffic freely into local fixtures; (b) synthetic seeded prompts only, captured artifacts scrubbed before persistence, raw captures never committed | **(b)**, and this is a **precondition for H1 starting**, not a review-time cleanup (critique #16). Real captures can contain bearer tokens, prompts, secrets, account identifiers, conversation metadata and model output; persisting them conflicts with this repo's own rule that raw bodies never reach logs. Required: synthetic seeded prompts under a disclosed-test framing (as `a2-live-proof.sh` already does), a scrub step with its own test, retention limited to the spike, and a `.gitignore` entry plus a pre-commit check for the capture directory | **H1 start** |
| **F16** | **(NEW)** Unknown response events and unknown upstream shapes | (a) block/error the whole response; (b) pass through; (c) buffer and inspect; (d) strip the event; (e) terminate an active stream with an explicit error | **(e) for streams, (a) for non-streaming.** (b) risks an un-demasked placeholder reaching the user — the worst outcome available; (d) silently changes model output; (c) re-introduces the buffering H6 exists to remove. A single captured corpus cannot establish schema completeness, so the default must be safe rather than permissive | H3 build |

---

## 8. Evidence register

Everything above traces to one of the following. Claims resting on another document's *citations*
rather than a direct check are marked as such in place; this pass deliberately re-verified rather
than inherited.

**Repo source, read directly this pass** (paths/lines cited inline): `crates/vg-cli/src/main.rs`,
`crates/vg-cli/Cargo.toml`, `crates/vg-proxy/src/{server,upstream,daemon,session,route,mask_request}.rs`,
`crates/vg-proxy/Cargo.toml`, `crates/vg-proxy/examples/live_proof_harness.rs`,
`crates/vg-proxy/tests/tls_upstream.rs`, `scripts/a2-live-proof.sh`, `docs/risks.md` (RISK-0014),
`docs/decisions.md`.

**Sibling repo:** `veil-ecosystem/docs/beta-implementation-plan.md` (§0 progress tracker and
verification list; Track 1 A2/A3/A4 rows; Phase E E1 row; §5 dependency graph),
`veil-ecosystem/.hekton/governance.yaml` (`dependency_changes: human_required`).

**Installed binary, inspected locally** — `codex-cli 0.153.4`
(`~/.codex/packages/standalone/releases/0.153.4-aarch64-apple-darwin/bin/codex`), by raw byte
search rather than `strings | grep`, **specifically because the latter produced the shared
plural/singular error corrected in GROUND-9**. Machinery-level evidence only: the presence of a
string proves the machinery exists, not that the model-API request path exercises it. Findings:
`CODEX_CA_CERTIFICATE` (singular) + `SSL_CERT_FILE` + `REQUESTS_CA_BUNDLE` + `CURL_CA_BUNDLE`;
`wire_api` values `responses_http` / `responses_websocket`; `supports_websockets`,
`websocket_connect_timeout_ms`, `wss://`, `codex.transport.fallback_to_http`; `openai_base_url`,
`chatgpt_base_url`, `requires_openai_auth`, `env_key`, `http_headers`, `query_params`;
`https://api.openai.com/v1/responses` and `https://chatgpt.com/backend-api/codex`;
`features.respect_system_proxy`, `features.network_proxy.enabled`,
`network-proxy/src/{mitm,certs,network_policy}.rs`, `credential_broker/providers/openai.rs`.

**Live vendor-doc fetches, 2026-09-14** (verbatim quotes in the GROUND notes):
- `learn.chatgpt.com/docs/config-file/config-reference` (via 308 from
  `developers.openai.com/codex/config-reference`) — `wire_api`, `supports_websockets`,
  `openai_base_url`, `model_providers.*`, retry/timeout defaults, project-local restriction.
- `learn.chatgpt.com/docs/config-file/environment-variables` — `CODEX_CA_CERTIFICATE` /
  `SSL_CERT_FILE` and their precedence.
- `learn.chatgpt.com/docs/auth.md` — `requires_openai_auth` with ChatGPT sign-in or API key;
  LLM-proxy intent; custom CA applying to login, HTTPS and secure WebSockets.
- `code.claude.com/docs/en/corporate-proxy` — proxy variable precedence, `NO_PROXY`,
  `NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_CERT_STORE`, loopback WebSocket bypass, streaming watchdogs.

**Prior-stage inputs, treated as claims to test:** the original Codex architectural consultation
(`tasks/bxk4147k6.output` — re-opened this pass to adjudicate GROUND-8's attribution dispute), the
Fable draft of this document, and the 25-finding Codex critique of that draft (disposition table,
§3b).

**What this document still asserts on no live-run evidence** — exactly what H1 exists to convert
into evidence before anything is built on it:
1. Whether `openai_base_url` (or a custom provider) actually accepts a plain `http://127.0.0.1:<port>`
   value in 0.153.4, and whether ChatGPT sign-in then still routes to `chatgpt.com/backend-api/codex`
   rather than the configured base URL. (Documented behaviour is known — GROUND-15 — live behaviour
   is not. The draft's "no direct evidence at all" was wrong; this is the corrected, narrower claim.)
2. Whether Codex has a Claude-Code-style defensive behaviour against non-default base URLs.
3. Whether `supports_websockets = false` actually suppresses the WebSocket transport.
4. Whether Codex's own `network_proxy` subsystem interferes with an injected `HTTPS_PROXY`.

**Housekeeping:** this file was untracked at the time of the critique (`git status`:
`?? docs/architecture/multi-harness-proxy-plan.md`), so its traceability was not yet durable.
Committing it is the first act of Track H.
