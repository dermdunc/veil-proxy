//! Masks an Anthropic Messages API request body (plan §10.2/§10.3 milestone M3) — the piece
//! that turns `vg-proxy` from a routing skeleton into the thing that actually does the job.
//!
//! **No structured entry point exists in `vg_core` for this** (confirmed by exploration before
//! writing this module): `vg_core::mask` takes a flat `Input { buf: Vec<u8>, hint }` and
//! returns one `MaskedPack` — one call per leaf text field, nothing that understands a JSON
//! tree. This module parses the body as a generic [`serde_json::Value`] and mutates only the
//! specific fields it knows about (`system`, `messages[].content`) in place; every other field
//! — `max_tokens`, `temperature`, `metadata`, `stream`, and anything else a real request
//! carries that this module doesn't name — round-trips through untouched, because nothing here
//! ever re-types the body into a narrower struct that could silently drop it.
//!
//! **`stream` history, A2:** an earlier version of this module blocked `stream: true` outright,
//! reasoning that M4's response demasking couldn't handle a streaming response. Running the
//! real live-run proof against the real, unmodified `claude` CLI found that it always sends
//! `stream: true` (no flag forces non-streaming) — blocking it made every real CLI session fail
//! closed, not just an edge case. `amendment-2026-09-14-001.yaml` pulled a minimal SSE-response
//! demask path forward from M6 instead (`crate::codec::anthropic::stream_demask`, selected by `server.rs` on the
//! upstream response's own `content-type: text/event-stream` header); `stream` no longer needs
//! special-casing on the request side at all.
//!
//! `tools[]` (the top-level tool *definitions*) is never read or touched by anything in this
//! module — masking only walks `system`/`messages`, so `tools[]` survives by construction, not
//! by an explicit skip.
//!
//! **Two consequences of "one `vg_core::mask()` call per leaf field," named not hidden:** each
//! call mints its own `TraceId` and its own `AuditEvent::Scan` — one request with N text fields
//! produces N traces/events, not one, a finer-grained version of the telemetry roadmap's
//! already-accepted "one trace per masked artefact, not per invocation" limitation. Vault-level
//! ordinal dedup still works correctly across calls (it's namespace-scoped in the vault, not
//! call-scoped): the same raw value reused across two fields in one request still gets the same
//! placeholder, proven in this module's own tests.
//!
//! **Content-block handling, per this session's interview:** `tool_use.input` and
//! `tool_result.content` are masked recursively — every string leaf, regardless of nesting —
//! matching what the existing hook-based mechanism already does for `tool_input`/`tool_response`
//! today (stringify-the-whole-blob-and-mask), done here as a real tree-walk instead. `document`
//! and `image` content blocks block the whole request (real `document` sub-case handling —
//! text vs. base64 vs. url — is a named, deferred gap, not built here). Any other/unrecognized
//! content-block `"type"` also blocks the whole request — fail-closed, per plan §10.2.
//!
//! **Thinking blocks (veil-proxy#86 finding 1).** A real default Claude Code session replays
//! the model's own `thinking`/`redacted_thinking` blocks in `messages[]` history on every later
//! turn (the CLI keeps them via `context_management` `clear_thinking_… keep: all`). Classifying
//! them `Unknown` failed every such session closed at the first request after a thinking turn.
//! The round-trip design, chosen so that **no raw value can egress whichever way the API treats
//! an altered block**:
//!
//! - The response side never demasks thinking text (`stream_demask.rs` never touched
//!   `thinking_delta`; `demask_response.rs` now skips `thinking`/`redacted_thinking` blocks to
//!   match). So the client's copy of a thinking block is exactly what the API issued:
//!   placeholder-bearing, byte-identical to what its `signature` covers.
//! - Every thinking block a response carries is recorded per session as a keyed fingerprint
//!   (`IssuedThinking`, filled by `Daemon` from both demask paths). A replayed block that
//!   matches the record is forwarded verbatim: the upstream wrote those bytes, so returning them
//!   discloses nothing new, and its signature stays valid even when the model's own thinking
//!   holds text a detector would flag. Without this, re-masking that text would change the
//!   signed bytes on every later turn (the CLI replays all thinking), a plausible way for a
//!   session to fail permanently, raised by the fresh-context review of this change.
//! - A block not on the record (the proxy restarted, or the client built it) falls back to
//!   masking: the `thinking` text is masked like any other leaf and the `signature` must pass
//!   `check_opaque_token` (base64 shape). At worst the API rejects the altered block with a 4xx; no raw value
//!   goes upstream through the text.
//! - Thinking blocks are accepted only in `assistant` messages and only with their own fields
//!   (`type`/`thinking`/`signature`, `type`/`data`). `redacted_thinking.data` is API-encrypted
//!   ciphertext: forwarded unchanged if issued, otherwise it must pass `check_opaque_token` too.
//!   Named residual: an unissued `signature`/`data` carrying base64-alphabet raw content (a bare
//!   IBAN, a hex secret) still goes upstream; `check_opaque_token` explains why no detector check
//!   is applied. The client is the user's own tool; accepted.
//!
//! **Named trade-off, not fixed here: a block partway through does not undo vault interning
//! already done by earlier fields in the same request.** `system`/`messages` are masked field
//! by field, in order; if a later field triggers `BlockedContentBlock` (an `image` block in
//! `messages[3]`, say), the whole request still fails closed at the *forwarding* level — nothing
//! reaches the upstream, `Daemon::mask_request` returns `Err`, no bindings are recorded into the
//! session store — but any entity already `vault.intern()`-ed by an earlier, successfully-masked
//! field (`system`, or `messages[0..3]`) stays interned; there's no transactional rollback
//! across multiple `mask()` calls. Not a leak (the vault is local and encrypted — interning
//! something that's never forwarded is inert, not a disclosure), but a real, accepted gap in
//! audit-trail tidiness: the local audit log can carry `Scan` events for a request whose overall
//! outcome was "blocked, never sent." Fixing it means transactional multi-call semantics, a
//! larger change than this milestone's own scope.

use serde_json::Value;

use vg_core::{
    mask, ArtefactHint, Context, Input, MaskError, MaskStats, MaskedPack, Namespace,
    PlaceholderBinding, Policy,
};

use crate::codec::{IssuedBlockRef, IssuedThinking};
use crate::schema::anthropic::ContentBlockKind;

/// The result of masking one request body: the re-serialized masked bytes, plus everything the
/// caller (`Daemon::mask_request`) needs — `bindings` to record into the session-scoped binding
/// store, `stats` to summarize what happened (`server.rs` surfaces it as a response header).
/// No separate `mapping_refs` field: every `MappingRef` a binding carries is already reachable
/// via `bindings[i].mapping_ref`, so a second, always-redundant copy isn't kept here.
pub(crate) struct MaskedRequest {
    pub(crate) body: Vec<u8>,
    pub(crate) bindings: Vec<PlaceholderBinding>,
    pub(crate) stats: MaskStats,
}

#[derive(Debug, thiserror::Error)]
pub enum MaskRequestError {
    #[error("request body is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("request body is not a JSON object")]
    NotAnObject,
    #[error("system[] entry is not a recognized {{\"type\": \"text\", \"text\": ...}} block")]
    MalformedSystemEntry,
    #[error("messages[] entry is malformed: {0}")]
    MalformedMessage(&'static str),
    #[error("content block type {0:?} is blocked by policy (image/document/unrecognized)")]
    BlockedContentBlock(String),
    #[error("masking failed: {0}")]
    Mask(#[from] MaskError),
}

/// Parses `body`, masks every text-bearing field reachable from `system`/`messages[].content`,
/// and re-serializes. Fails closed (returns `Err`, masks nothing, forwards nothing) on
/// malformed JSON, a non-object body, a malformed `system`/`messages` shape, or any
/// unrecognized/blocked content-block kind.
pub(crate) fn mask_request(
    body: &[u8],
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    issued: &IssuedThinking,
) -> Result<MaskedRequest, MaskRequestError> {
    let mut value: Value = serde_json::from_slice(body)?;
    let root = value.as_object_mut().ok_or(MaskRequestError::NotAnObject)?;

    let mut acc = MaskAccumulator::default();

    // `system` is optional per the Anthropic schema; `Value::Null` is treated the same as the
    // key being absent entirely, not as a malformed shape. Doubt-driven-development finding:
    // a strict `Value::String`/`Value::Array`-only match (this function's first version) would
    // fail closed on a request that explicitly sends `"system": null` instead of omitting the
    // key — a real, legal way to represent "no system prompt" some client JSON serializers
    // produce by default for an absent optional field, not a malformed request.
    match root.get_mut("system") {
        Some(Value::Null) | None => {}
        Some(system) => mask_system(system, ctx, policy, ns, &mut acc)?,
    }

    if let Some(messages) = root.get_mut("messages") {
        let messages = messages
            .as_array_mut()
            .ok_or(MaskRequestError::MalformedMessage(
                "messages must be an array",
            ))?;
        for message in messages.iter_mut() {
            mask_message(message, ctx, policy, ns, issued, &mut acc)?;
        }
    }

    let body = serde_json::to_vec(&value).expect("re-serializing a parsed Value cannot fail");
    Ok(MaskedRequest {
        body,
        bindings: acc.bindings,
        stats: acc.stats,
    })
}

/// `system` is a bare string, or an array of `{"type": "text", "text": "...", ...}` entries
/// (`cache_control` and other fields, if present, round-trip untouched since only `text` is
/// mutated). Anything else fails closed.
fn mask_system(
    system: &mut Value,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    match system {
        Value::String(s) => mask_leaf_in_place(s, ctx, policy, ns, acc),
        Value::Array(entries) => {
            for entry in entries.iter_mut() {
                if entry.get("type").and_then(Value::as_str) != Some("text") {
                    return Err(MaskRequestError::MalformedSystemEntry);
                }
                match entry.get_mut("text") {
                    Some(Value::String(s)) => mask_leaf_in_place(s, ctx, policy, ns, acc)?,
                    _ => return Err(MaskRequestError::MalformedSystemEntry),
                }
            }
            Ok(())
        }
        _ => Err(MaskRequestError::MalformedSystemEntry),
    }
}

/// One `messages[]` entry's `content`: a bare string, or an array of content blocks.
fn mask_message(
    message: &mut Value,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    issued: &IssuedThinking,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    let from_assistant = message.get("role").and_then(Value::as_str) == Some("assistant");
    let content = message
        .get_mut("content")
        .ok_or(MaskRequestError::MalformedMessage(
            "message missing content",
        ))?;
    match content {
        Value::String(s) => mask_leaf_in_place(s, ctx, policy, ns, acc),
        Value::Array(blocks) => {
            for block in blocks.iter_mut() {
                mask_content_block(block, ctx, policy, ns, issued, from_assistant, acc)?;
            }
            Ok(())
        }
        _ => Err(MaskRequestError::MalformedMessage(
            "content must be a string or an array of content blocks",
        )),
    }
}

/// One content block, dispatched by [`ContentBlockKind`]. `text` masks its own `text` field;
/// `tool_use`/`tool_result` mask every string leaf inside `input`/`content` recursively;
/// `thinking` masks its `thinking` text only; `redacted_thinking` passes through unchanged;
/// `document`/`image`/anything unrecognized blocks the whole request.
fn mask_content_block(
    block: &mut Value,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    issued: &IssuedThinking,
    from_assistant: bool,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    match ContentBlockKind::of(block) {
        ContentBlockKind::Text => match block.get_mut("text") {
            Some(Value::String(s)) => mask_leaf_in_place(s, ctx, policy, ns, acc),
            _ => Err(MaskRequestError::MalformedMessage(
                "text content block missing its text field",
            )),
        },
        // Round-2 doubt-pass finding (Codex): `input` is *required* by the Anthropic schema —
        // an earlier version of this arm treated its absence as "nothing to mask, fine," which
        // silently forwarded a malformed block instead of failing closed on it. A present
        // `input` (including an empty `{}`) is unaffected; only genuine absence changes.
        ContentBlockKind::ToolUse => match block.get_mut("input") {
            Some(input) => mask_value_strings_recursive(input, ctx, policy, ns, acc),
            None => Err(MaskRequestError::MalformedMessage(
                "tool_use content block missing its required input field",
            )),
        },
        // `content` is optional on a tool_result block per the Anthropic schema.
        ContentBlockKind::ToolResult => match block.get_mut("content") {
            Some(content) => mask_value_strings_recursive(content, ctx, policy, ns, acc),
            None => Ok(()),
        },
        ContentBlockKind::Thinking => {
            mask_thinking_block(block, ctx, policy, ns, issued, from_assistant, acc)
        }
        ContentBlockKind::RedactedThinking => {
            check_thinking_shape(block, from_assistant, &["type", "data"])?;
            let Some(Value::String(data)) = block.get("data") else {
                return Err(MaskRequestError::MalformedMessage(
                    "redacted_thinking content block missing its data field",
                ));
            };
            if issued.contains(IssuedBlockRef::Redacted { data }) {
                return Ok(());
            }
            check_opaque_token(data)
        }
        ContentBlockKind::Document => Err(MaskRequestError::BlockedContentBlock(
            "document".to_string(),
        )),
        ContentBlockKind::Image => Err(MaskRequestError::BlockedContentBlock("image".to_string())),
        // Round-2 doubt-pass finding (Codex): echoing the raw, client-supplied `"type"` string
        // back in a client-facing error response is a real risk this crate's own contract
        // singles out — nothing stops a malformed/adversarial block from putting sensitive
        // content in `"type"` itself. A generic, fixed label is used instead; the raw value is
        // discarded, not merely hidden behind a `Debug` impl that could still leak it later.
        ContentBlockKind::Unknown(_) => Err(MaskRequestError::BlockedContentBlock(
            "unrecognized".to_string(),
        )),
    }
}

/// A `thinking` block: forwarded verbatim if the upstream issued exactly this block to this
/// session; otherwise its `signature` must be an opaque token and its `thinking` text is masked.
/// See the module doc's "Thinking blocks" section.
fn mask_thinking_block(
    block: &mut Value,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    issued: &IssuedThinking,
    from_assistant: bool,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    check_thinking_shape(block, from_assistant, &["type", "thinking", "signature"])?;
    let (Some(Value::String(signature)), Some(Value::String(thinking))) =
        (block.get("signature"), block.get("thinking"))
    else {
        return Err(MaskRequestError::MalformedMessage(
            "thinking content block needs string thinking and signature fields",
        ));
    };
    if issued.contains(IssuedBlockRef::Thinking {
        signature,
        thinking,
    }) {
        return Ok(());
    }
    check_opaque_token(signature)?;
    match block.get_mut("thinking") {
        Some(Value::String(s)) => mask_leaf_in_place(s, ctx, policy, ns, acc),
        _ => unreachable!("checked to be a string just above"),
    }
}

/// Thinking blocks are model output, so they are only valid in `assistant` messages, and they
/// may carry no field beyond `allowed`. Review finding: without both checks, a thinking-shaped
/// block in a `user` message, or an extra field on one, forwarded content unmasked that `main`
/// used to block.
fn check_thinking_shape(
    block: &Value,
    from_assistant: bool,
    allowed: &[&str],
) -> Result<(), MaskRequestError> {
    if !from_assistant {
        return Err(MaskRequestError::MalformedMessage(
            "thinking blocks are only valid in assistant messages",
        ));
    }
    let Value::Object(map) = block else {
        return Err(MaskRequestError::MalformedMessage(
            "content block is not an object",
        ));
    };
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(MaskRequestError::MalformedMessage(
            "thinking content block carries an unexpected field",
        ));
    }
    Ok(())
}

/// A `signature` or `redacted_thinking.data` value that isn't on the issued record goes upstream
/// unmasked (masking would corrupt it), so it must at least be shaped like what the API issues:
/// non-empty base64/base64url. That alone rejects anything with spaces, `@`, `.`, `:` and the
/// like (an email, prose, a URL). **Deliberately no detector check** (round-2 review finding):
/// the IBAN detector matches fragments of about 8.6% of random 200-800 char base64 strings, and
/// one false hit fails every later request in a resumed session, since history replays all
/// thinking. Named residual: a raw value that is itself base64-alphabet (a bare IBAN, a hex or
/// base64 secret) can ride in an unissued `signature`/`data`.
fn check_opaque_token(token: &str) -> Result<(), MaskRequestError> {
    let base64_shaped = !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    if base64_shaped {
        Ok(())
    } else {
        Err(MaskRequestError::MalformedMessage(
            "thinking signature/data is not an opaque base64 token",
        ))
    }
}

/// Masks every string leaf inside `value`, recursively, regardless of nesting — used for
/// `tool_use.input`/`tool_result.content`, which are arbitrary tool-defined JSON with no fixed
/// content-block structure of their own to interpret **except** for one real, structured
/// exception: a nested `{"type": "image", ...}` or `{"type": "document", ...}` object, found
/// anywhere in the tree. Round-2 doubt-pass finding (Codex): an earlier version of this walker
/// treated every object uniformly, so a `tool_result.content` array containing an Anthropic
/// `ImageBlockParam` (a real, schema-legal shape — `tool_result.content` is
/// `string | Array<TextBlockParam | ImageBlockParam>`) would have its base64 image bytes
/// recursively string-masked and forwarded instead of blocking the whole request, silently
/// bypassing this module's own top-level "image/document blocks the whole request" invariant
/// the moment it appeared one level deeper than `messages[].content` itself.
fn mask_value_strings_recursive(
    value: &mut Value,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    match value {
        Value::String(s) => mask_leaf_in_place(s, ctx, policy, ns, acc),
        Value::Array(items) => {
            for item in items.iter_mut() {
                mask_value_strings_recursive(item, ctx, policy, ns, acc)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            match map.get("type").and_then(Value::as_str) {
                Some("image") => {
                    return Err(MaskRequestError::BlockedContentBlock("image".to_string()))
                }
                Some("document") => {
                    return Err(MaskRequestError::BlockedContentBlock(
                        "document".to_string(),
                    ))
                }
                _ => {}
            }
            for v in map.values_mut() {
                mask_value_strings_recursive(v, ctx, policy, ns, acc)?;
            }
            Ok(())
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => Ok(()),
    }
}

/// The one place this module calls `vg_core::mask` — every leaf text field goes through here.
/// An empty string is left alone rather than round-tripped through `mask()`: nothing to detect,
/// and it avoids minting a `TraceId`/`AuditEvent::Scan` for a field that carries no content.
fn mask_leaf_in_place(
    s: &mut String,
    ctx: &Context,
    policy: &Policy,
    ns: &Namespace,
    acc: &mut MaskAccumulator,
) -> Result<(), MaskRequestError> {
    if s.is_empty() {
        return Ok(());
    }
    let input = Input {
        buf: s.as_bytes().to_vec(),
        hint: ArtefactHint::default(),
    };
    // The tuple's own `mapping_refs` element is discarded, not unused: it's identical content
    // to `pack.bindings[i].mapping_ref` for every `i` (a frozen-contract redundancy in `mask`'s
    // own return shape, not introduced here) — `absorb` dedups on `pack.bindings` alone.
    let (pack, _mapping_refs, _event, _trace_id) = mask(&input, ctx, policy, ns)?;
    *s = pack.text.clone();
    acc.absorb(pack);
    Ok(())
}

/// Accumulates the merged result of every per-field `mask()` call in one request: deduped
/// `bindings` (a value reused across two fields must not be double-listed) and `stats` summed
/// key-by-key.
#[derive(Default)]
struct MaskAccumulator {
    bindings: Vec<PlaceholderBinding>,
    stats: MaskStats,
}

impl MaskAccumulator {
    fn absorb(&mut self, pack: MaskedPack) {
        for b in pack.bindings {
            if !self.bindings.contains(&b) {
                self.bindings.push(b);
            }
        }
        for (ty, count) in pack.stats.counts.0 {
            *self.stats.counts.0.entry(ty).or_insert(0) += count;
        }
        self.stats.blocked_artefacts += pack.stats.blocked_artefacts;
    }
}

#[cfg(test)]
mod tests {
    //! Inline unit tests, not a separate `tests/mask_request.rs` integration file: every item
    //! under test here is `pub(crate)`, and an integration test compiles as a separate crate
    //! that can't see `pub(crate)` items — the same reason this codebase's other `pub(crate)`
    //! modules (`vg-core`'s `telemetry::aggregator`, `telemetry::block_reason`) test inline too.

    use std::path::{Path, PathBuf};

    use serde_json::{json, Value};
    use tempfile::TempDir;

    use vg_audit::JsonlAuditSink;
    use vg_core::{
        Context, Detector, Namespace, Parser, Policy, PolicyEngine, PolicyLayers, RepoId,
    };
    use vg_detectors::all_detectors;
    use vg_parsers::all_parsers;
    use vg_policy::LayeredPolicyEngine;
    use vg_vault::{Vault, VaultConfig};

    use super::{mask_request, MaskRequestError};
    use crate::codec::{IssuedBlock, IssuedThinking};

    const TEST_KEY: [u8; 32] = [7u8; 32];
    const SECRET_TOKEN: &str = "Zx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We";

    fn global_policy_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vg-policy/fixtures/global.policy.json")
    }

    fn build_policy(dir: &Path) -> Policy {
        let engine = LayeredPolicyEngine::load(PolicyLayers {
            global: global_policy_path(),
            repo: None,
            session: None,
        })
        .expect("load default policy fixture");
        let vault = Vault::open_with_key(VaultConfig::new(dir.join("vault.db")), TEST_KEY)
            .expect("open temp-keyed vault");
        let audit = JsonlAuditSink::open(dir.join("audit.jsonl")).expect("open temp audit sink");
        Policy {
            engine: Box::new(engine),
            vault: Box::new(vault),
            audit: Box::new(audit),
        }
    }

    fn ns() -> Namespace {
        Namespace::Repo(RepoId("veilgremlin-vgproxy-mask-request-tests".to_string()))
    }

    fn with_real_context<R>(body: impl FnOnce(&Context) -> R) -> R {
        let detectors = all_detectors();
        let detector_refs: Vec<&dyn Detector> = detectors.iter().map(|d| d.as_ref()).collect();
        let parsers = all_parsers();
        let parser_refs: Vec<&dyn Parser> = parsers.iter().map(|p| p.as_ref()).collect();
        let ctx = Context {
            parsers: &parser_refs,
            detectors: &detector_refs,
        };
        body(&ctx)
    }

    fn run(body: &Value, policy: &Policy) -> Result<Value, MaskRequestError> {
        let bytes = serde_json::to_vec(body).expect("fixture serializes");
        let namespace = ns();
        let masked = with_real_context(|ctx| {
            mask_request(&bytes, ctx, policy, &namespace, &IssuedThinking::default())
        })?;
        Ok(serde_json::from_slice(&masked.body).expect("masked body is valid JSON"))
    }

    /// A minimal structural comparator: same JSON "shape" at every position (same variant kind,
    /// same object key set, same array length, non-string leaves identical) — only string
    /// leaves may differ. Mirrors the discipline `vg-adapters-claude/src/hook.rs`'s own
    /// `same_shape` validator uses for the same reason (not reusable directly — private to a
    /// different crate).
    fn same_shape(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::String(_), Value::String(_)) => true,
            (Value::Array(xa), Value::Array(xb)) => {
                xa.len() == xb.len() && xa.iter().zip(xb).all(|(x, y)| same_shape(x, y))
            }
            (Value::Object(ma), Value::Object(mb)) => {
                ma.len() == mb.len()
                    && ma.keys().all(|k| mb.contains_key(k))
                    && ma
                        .iter()
                        .all(|(k, v)| mb.get(k).is_some_and(|w| same_shape(v, w)))
            }
            (Value::Number(_), Value::Number(_)) => a == b,
            (Value::Bool(_), Value::Bool(_)) => a == b,
            (Value::Null, Value::Null) => true,
            _ => false,
        }
    }

    #[test]
    fn masks_a_system_string_and_preserves_unrelated_fields() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "model": "claude-x",
            "max_tokens": 1024,
            "temperature": 0.5,
            "system": "contact jane.doe@example.com about the incident",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });

        let masked = run(&body, &policy).expect("masks successfully");

        assert!(same_shape(&body, &masked), "masked: {masked}");
        // Unrelated fields round-trip byte-for-byte (values, not just shape).
        assert_eq!(masked["model"], json!("claude-x"));
        assert_eq!(masked["max_tokens"], json!(1024));
        assert_eq!(masked["temperature"], json!(0.5));
        // The email is gone from system; a placeholder took its place.
        let system = masked["system"].as_str().expect("system stays a string");
        assert!(!system.contains("jane.doe@example.com"), "system: {system}");
        assert!(system.contains("EMAIL_001"), "system: {system}");
    }

    #[test]
    fn masks_a_system_array_without_reordering_or_merging_entries() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": [
                {"type": "text", "text": "first: jane.doe@example.com"},
                {"type": "text", "text": "second: ops@example.com"}
            ],
            "messages": []
        });

        let masked = run(&body, &policy).expect("masks successfully");
        let entries = masked["system"].as_array().expect("system stays an array");
        assert_eq!(entries.len(), 2, "entries must not be merged: {masked}");
        let first = entries[0]["text"].as_str().unwrap();
        let second = entries[1]["text"].as_str().unwrap();
        assert!(first.starts_with("first:"), "order preserved: {first}");
        assert!(second.starts_with("second:"), "order preserved: {second}");
        assert!(first.contains("EMAIL_001"), "first: {first}");
        assert!(second.contains("EMAIL_002"), "second: {second}");
    }

    #[test]
    fn tools_array_is_byte_for_byte_untouched() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let tools = json!([
            {
                "name": "send_email",
                "description": "Sends an email to jane.doe@example.com for testing purposes",
                "input_schema": {"type": "object", "properties": {"to": {"type": "string"}}}
            }
        ]);
        let body = json!({
            "system": "hello",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools,
        });

        let masked = run(&body, &policy).expect("masks successfully");
        // tools[] is never read by mask_request — must survive byte-for-byte, including the
        // email-shaped string inside its description, which would otherwise be a detector hit.
        assert_eq!(masked["tools"], tools);
    }

    #[test]
    fn recursively_masks_tool_use_input_and_tool_result_content() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "bash",
                            "input": {
                                "command": format!("echo {SECRET_TOKEN}"),
                                "nested": {"note": "cc ops@example.com"}
                            }
                        }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": "result mentions jane.doe@example.com"
                        }
                    ]
                }
            ]
        });

        let masked = run(&body, &policy).expect("masks successfully");
        let masked_str = serde_json::to_string(&masked).unwrap();
        assert!(!masked_str.contains(SECRET_TOKEN), "masked: {masked_str}");
        assert!(
            !masked_str.contains("ops@example.com"),
            "masked: {masked_str}"
        );
        assert!(
            !masked_str.contains("jane.doe@example.com"),
            "masked: {masked_str}"
        );
        // "command" and "name" keys themselves (structure) survive; only leaf values change.
        assert!(masked_str.contains("\"command\""), "masked: {masked_str}");
        assert!(
            masked_str.contains("\"name\":\"bash\""),
            "masked: {masked_str}"
        );
    }

    #[test]
    fn image_content_block_blocks_the_whole_request() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}
            ]
        });

        let err = run(&body, &policy).expect_err("image blocks the whole request");
        assert!(matches!(err, MaskRequestError::BlockedContentBlock(k) if k == "image"));
    }

    #[test]
    fn document_content_block_blocks_the_whole_request() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {"role": "user", "content": [{"type": "document", "source": {"type": "text", "data": "irrelevant"}}]}
            ]
        });

        let err = run(&body, &policy).expect_err("document blocks the whole request");
        assert!(matches!(err, MaskRequestError::BlockedContentBlock(k) if k == "document"));
    }

    /// A2 (post `amendment-2026-09-14-001.yaml`): `stream` in any shape — `true`, `false`, or
    /// absent — round-trips untouched on the request side. Streaming responses are handled on
    /// the way back out by `crate::stream_demask`, selected in `server.rs`; this module no
    /// longer blocks the request for it (an earlier version of this test asserted the opposite,
    /// before the real live-run proof found the real `claude` CLI always sends `stream: true`
    /// and blocking it made every real CLI session fail closed).
    #[test]
    fn stream_field_round_trips_untouched_regardless_of_value() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());

        let explicit_true = json!({
            "system": "hi",
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}]
        });
        run(&explicit_true, &policy).expect("stream: true is not blocked");

        let explicit_false = json!({
            "system": "hi",
            "stream": false,
            "messages": [{"role": "user", "content": "hello"}]
        });
        run(&explicit_false, &policy).expect("stream: false is not blocked");

        let absent = json!({
            "system": "hi",
            "messages": [{"role": "user", "content": "hello"}]
        });
        run(&absent, &policy).expect("absent stream key is not blocked");
    }

    /// Round-2 doubt-pass regression (Codex): a real, schema-legal shape —
    /// `tool_result.content` is `string | Array<TextBlockParam | ImageBlockParam>` — nests an
    /// image block one level inside `tool_result.content`. An earlier version of
    /// `mask_value_strings_recursive` treated every object uniformly and would have
    /// recursively string-masked the base64 image data and forwarded it, silently bypassing
    /// the "image blocks the whole request" invariant the moment it appeared inside a tool
    /// result instead of at the top level.
    #[test]
    fn an_image_block_nested_inside_tool_result_content_still_blocks_the_whole_request() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [
                            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
                        ]
                    }]
                }
            ]
        });

        let err = run(&body, &policy)
            .expect_err("a nested image block must block the whole request, not be masked");
        assert!(matches!(err, MaskRequestError::BlockedContentBlock(k) if k == "image"));
    }

    /// Round-2 doubt-pass regression (Codex): `input` is required by the Anthropic schema; an
    /// earlier version silently treated its absence as "nothing to mask," forwarding a
    /// malformed block instead of failing closed on it.
    #[test]
    fn a_tool_use_block_missing_its_required_input_field_fails_closed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "bash"}]}
            ]
        });

        let err = run(&body, &policy)
            .expect_err("a tool_use block missing input must fail closed, not pass through");
        assert!(matches!(err, MaskRequestError::MalformedMessage(_)));
    }

    /// veil-proxy#86 finding 1: the exact history shape a default Claude Code session sends
    /// after a thinking turn — an assistant `[thinking, tool_use]` turn followed by a
    /// `tool_result` user turn. It must be forwarded, not blocked, and the thinking block must
    /// reach the upstream byte-identical (its `signature` covers the text) when its text is
    /// already placeholder-bearing, which is what the client holds since responses never
    /// demask thinking.
    #[test]
    fn a_replayed_thinking_block_is_forwarded_byte_identical_with_its_signature() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        // A realistic signature is long base64 — the exact shape the entropy detector redacts
        // if anything ever masks it.
        let signature = "EqQBCkYIBxgCKkDzQ9vR2kLm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4WeZx9Kq2Lm7Pw4Rt6Yv1Bn8Fs3Hd5Jc0Ga4We";
        let thinking_block = json!({
            "type": "thinking",
            "thinking": "The user wants invoices sent to EMAIL_001. I should read billing/invoice.py first.",
            "signature": signature
        });
        let body = json!({
            "system": "hi",
            "messages": [
                {"role": "user", "content": "fix the failing test"},
                {"role": "assistant", "content": [
                    thinking_block.clone(),
                    {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"file_path": "billing/invoice.py"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "send to jane.doe@example.com"}
                ]}
            ]
        });

        let masked = run(&body, &policy).expect("a thinking turn in history must not fail closed");

        assert_eq!(masked["messages"][1]["content"][0], thinking_block);
        let masked_str = serde_json::to_string(&masked).unwrap();
        assert!(
            !masked_str.contains("jane.doe@example.com"),
            "masked: {masked_str}"
        );
    }

    /// A thinking block carrying a raw value (a client that demasked it itself) never sends the
    /// raw value upstream: the text is masked, the signature is still left alone.
    #[test]
    fn a_raw_value_inside_a_replayed_thinking_block_is_masked_not_forwarded() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "I should email jane.doe@example.com", "signature": "sig"}
                ]}
            ]
        });

        let masked = run(&body, &policy).expect("masks successfully");
        let block = &masked["messages"][0]["content"][0];
        let thinking = block["thinking"].as_str().unwrap();
        assert!(
            !thinking.contains("jane.doe@example.com"),
            "thinking: {thinking}"
        );
        assert!(thinking.contains("EMAIL_001"), "thinking: {thinking}");
        assert_eq!(block["signature"], json!("sig"));
    }

    #[test]
    fn a_redacted_thinking_block_is_forwarded_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let redacted = json!({
            "type": "redacted_thinking",
            "data": "EmwKAhgBEgy3va3pzix/LafPsn4aDFIT2Xlxh0L5L8rLVyIwxtE3rAFBa8cr3qpPkNRj2YfWXGmKDxH4mPnZ5sQ7vB8zT"
        });
        let body = json!({
            "messages": [
                {"role": "assistant", "content": [redacted.clone(), {"type": "text", "text": "done"}]}
            ]
        });

        let masked = run(&body, &policy).expect("redacted_thinking must not fail closed");
        assert_eq!(masked["messages"][0]["content"][0], redacted);
    }

    #[test]
    fn a_thinking_block_missing_its_text_or_a_redacted_block_missing_its_data_fails_closed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        for block in [
            json!({"type": "thinking", "signature": "sig"}),
            json!({"type": "redacted_thinking"}),
        ] {
            let body = json!({"messages": [{"role": "assistant", "content": [block]}]});
            let err = run(&body, &policy).expect_err("malformed thinking block must fail closed");
            assert!(
                matches!(err, MaskRequestError::MalformedMessage(_)),
                "{err}"
            );
        }
    }

    /// Review findings (fresh-context adversarial round): each of these forwarded a raw value
    /// unmasked under the first version of the thinking fix, and all were fail-closed on `main`.
    #[test]
    fn thinking_blocks_that_could_smuggle_raw_content_fail_closed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let raw = "jane.doe@example.com";
        let cases = [
            // thinking in a user message
            json!({"role": "user", "content": [{"type": "thinking", "thinking": "x", "signature": "sig"}]}),
            // raw value in the signature
            json!({"role": "assistant", "content": [{"type": "thinking", "thinking": "x", "signature": raw}]}),
            // extra field on a thinking block
            json!({"role": "assistant", "content": [{"type": "thinking", "thinking": "x", "signature": "sig", "extra": raw}]}),
            // raw values in redacted data
            json!({"role": "assistant", "content": [{"type": "redacted_thinking", "data": format!("{raw} GB33BUKB20201555555555")}]}),
            // nested extra object on redacted_thinking
            json!({"role": "assistant", "content": [{"type": "redacted_thinking", "data": "abc", "meta": {"note": raw}}]}),
            // redacted_thinking in a user message
            json!({"role": "user", "content": [{"type": "redacted_thinking", "data": "abc"}]}),
        ];
        for message in cases {
            let body = json!({"messages": [message.clone()]});
            let err = run(&body, &policy).expect_err("must fail closed");
            assert!(
                matches!(err, MaskRequestError::MalformedMessage(_)),
                "{message}: {err}"
            );
        }
    }

    /// Round-2 review finding: a detector check on unissued signatures rejected ~8.6% of random
    /// base64 signatures (IBAN false positives), permanently breaking resumed sessions. Realistic
    /// random signatures must all pass the shape check.
    #[test]
    fn random_base64_signatures_are_accepted_by_the_opaque_token_check() {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..500 {
            let signature: String = (0..400)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    B64[(x % 64) as usize] as char
                })
                .collect();
            super::check_opaque_token(&signature).expect("random base64 is accepted");
        }
    }

    /// Review finding (plausible, not reproducible without the real API): the model's own
    /// thinking can hold text a detector flags, and re-masking it would change the signed bytes
    /// on every later turn. A block the upstream issued to this session is forwarded verbatim;
    /// the same block not on the record is still masked.
    #[test]
    fn an_issued_thinking_block_is_forwarded_verbatim_and_an_unissued_one_is_masked() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let thinking = "I'll add a test fixture user, test.user@example.com, to the suite.";
        let block = json!({"type": "thinking", "thinking": thinking, "signature": "EqQBCkYIBxgC"});
        let body = json!({"messages": [{"role": "assistant", "content": [block.clone()]}]});
        let bytes = serde_json::to_vec(&body).unwrap();
        let namespace = ns();

        let mut issued = IssuedThinking::default();
        issued.insert(&IssuedBlock::Thinking {
            signature: "EqQBCkYIBxgC".to_string(),
            thinking: thinking.to_string(),
        });
        let masked =
            with_real_context(|ctx| mask_request(&bytes, ctx, &policy, &namespace, &issued))
                .expect("masks successfully");
        let masked: Value = serde_json::from_slice(&masked.body).unwrap();
        assert_eq!(
            masked["messages"][0]["content"][0], block,
            "issued: verbatim"
        );

        let masked = run(&body, &policy).expect("masks successfully");
        let text = masked["messages"][0]["content"][0]["thinking"]
            .as_str()
            .unwrap();
        assert!(
            !text.contains("test.user@example.com"),
            "unissued: masked: {text}"
        );
    }

    #[test]
    fn unrecognized_content_block_type_blocks_the_whole_request() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "hi",
            "messages": [
                {"role": "user", "content": [{"type": "video", "source": "whatever"}]}
            ]
        });

        let err = run(&body, &policy).expect_err("unrecognized type blocks the whole request");
        // The raw client-supplied type string ("video") is deliberately NOT echoed back — see
        // this arm's own doc comment for why (a round-2 doubt-pass finding: echoing untrusted
        // request content back in an error response is a real risk this crate's contract
        // singles out).
        assert!(matches!(err, MaskRequestError::BlockedContentBlock(k) if k == "unrecognized"));
    }

    #[test]
    fn count_tokens_shaped_body_masks_identically_to_a_messages_shaped_one() {
        // count_tokens omits max_tokens/stream but has the same system/messages shape.
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "model": "claude-x",
            "system": "contact jane.doe@example.com",
            "messages": [{"role": "user", "content": "hello"}]
        });

        let masked = run(&body, &policy).expect("masks successfully");
        let system = masked["system"].as_str().unwrap();
        assert!(!system.contains("jane.doe@example.com"), "system: {system}");
        assert!(system.contains("EMAIL_001"), "system: {system}");
    }

    #[test]
    fn the_same_raw_value_reused_across_two_fields_gets_the_same_placeholder() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": "contact jane.doe@example.com",
            "messages": [
                {"role": "user", "content": "cc jane.doe@example.com too"}
            ]
        });

        let masked = run(&body, &policy).expect("masks successfully");
        let system = masked["system"].as_str().unwrap();
        let message = masked["messages"][0]["content"].as_str().unwrap();
        // Vault-level dedup is namespace-scoped, not call-scoped: the same raw value across
        // two separate mask() calls (one per leaf field) still gets the same placeholder.
        assert!(system.contains("EMAIL_001"), "system: {system}");
        assert!(message.contains("EMAIL_001"), "message: {message}");
    }

    #[test]
    fn malformed_json_body_fails_closed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let result = with_real_context(|ctx| {
            mask_request(
                b"not json",
                ctx,
                &policy,
                &namespace,
                &IssuedThinking::default(),
            )
        });
        assert!(matches!(result, Err(MaskRequestError::InvalidJson(_))));
    }

    #[test]
    fn non_object_body_fails_closed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let result = with_real_context(|ctx| {
            mask_request(
                b"[1,2,3]",
                ctx,
                &policy,
                &namespace,
                &IssuedThinking::default(),
            )
        });
        assert!(matches!(result, Err(MaskRequestError::NotAnObject)));
    }

    #[test]
    fn empty_string_leaf_is_left_alone_not_round_tripped_through_mask() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({"system": "", "messages": []});

        let masked = run(&body, &policy).expect("masks successfully");
        assert_eq!(masked["system"], json!(""));
    }

    #[test]
    fn explicit_null_system_is_treated_as_absent_not_malformed() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let body = json!({
            "system": null,
            "messages": [{"role": "user", "content": "contact jane.doe@example.com"}]
        });

        let masked = run(&body, &policy).expect("null system must not fail closed");
        assert_eq!(masked["system"], json!(null));
        let message = masked["messages"][0]["content"].as_str().unwrap();
        assert!(
            !message.contains("jane.doe@example.com"),
            "message: {message}"
        );
    }
}
