//! Demasks a streaming (SSE) Anthropic Messages API response — pulled forward from M6 into A2
//! (INT-2026-09-13-001, `amendment-2026-09-14-001.yaml`): running the real live-run proof
//! against the real, unmodified `claude` CLI found that it always sends `stream: true` at the
//! API layer (no flag forces non-streaming), so `mask_request.rs`'s original "block `stream:
//! true` outright" design made the whole live-run proof unsatisfiable by any real CLI session.
//!
//! **Deliberately NOT full M6.** This module buffers the *entire* upstream SSE stream before
//! attempting any demasking (the same buffer-then-return shape `demask_response.rs`'s own
//! non-streaming path already has, and `upstream::forward` already buffers every response
//! regardless of kind) — no incremental/low-latency delivery to the wrapped client. That
//! buffering is what sidesteps, rather than solves, the "SSE chunk-boundary/partial-placeholder"
//! question `beta-implementation-plan.md`'s own A4 entry named as unanswered by M4's design: a
//! placeholder split across two small `text_delta` chunks is reconstructed into its full text
//! (across the *whole* stream, not a bounded window) before rehydration is ever attempted, so it
//! is never demasked as two separate, unresolvable fragments.
//!
//! **`text_delta` and `input_json_delta` content is demasked.** Every other event kind —
//! `message_start`, `content_block_start`, `content_block_stop`, `message_delta`,
//! `message_stop`, `ping`, `thinking_delta`/`signature_delta`, anything this parser doesn't
//! specifically recognize — round-trips unchanged. Thinking is left alone on purpose: the client
//! replays it verbatim and the API checks it against its signature (veil-proxy#86 finding 1, see
//! `mask_request.rs`'s module doc).
//!
//! **`input_json_delta` (veil-proxy#86 finding 2).** Tool-call arguments stream as `partial_json`
//! fragments. An earlier version passed them through, so the client received tool calls with
//! literal placeholders (`Edit {old_string: "… IBAN_001 …"}`) that could never match the real
//! file — while the non-streaming path already demasked `tool_use.input`. Now, per content-block
//! index, every fragment is concatenated, checked to be valid JSON, and each string *value* in
//! it is demasked in place (keys, numbers and layout are copied byte-for-byte; see
//! [`demask_input_json`]), then emitted as one `input_json_delta`. If nothing resolved, or the
//! concatenation doesn't parse, that index's original fragments pass through unchanged.
//! Demasking tool input means real values reach local tools: that is the intended trust
//! boundary, since the client side already holds them.
//!
//! **Consolidation, not true re-streaming.** For each content-block `index` that carries at
//! least one demaskable delta, this module emits exactly one `content_block_delta` event carrying
//! the *entire* demasked text (or tool-input JSON) for that index, at the position of that
//! index's first delta in the original stream, and drops every later original delta for the same
//! index — their content is already included. A client parsing this as ordinary SSE per the
//! Anthropic streaming protocol (concatenate `text_delta.text` / `input_json_delta.partial_json`
//! per index in event order) reconstructs the identical final content either way; only the
//! number/size of the delta events differs.
//!
//! **Deliberately infallible**, same posture as `demask_response.rs`: an unparseable frame, a
//! non-UTF-8 body, or any other unexpected shape passes through unchanged rather than blocking a
//! successful response — the request already reached the real upstream and got a real answer;
//! refusing to return it would be strictly worse than an unresolved placeholder.

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use vg_core::{Namespace, PlaceholderBinding, Policy};

use super::demask_response::demask_text;
use crate::codec::{DemaskedResponse, IssuedBlock};

/// Demasks every `text_delta` and `input_json_delta` fragment in `body` (an Anthropic Messages
/// API SSE stream, fully buffered) against `bindings`, and re-serializes. Always returns bytes —
/// see this module's own doc for why it cannot fail. `body` that isn't valid UTF-8 is returned
/// unchanged: real SSE is always UTF-8 text, so this is a defensive fallback, not an expected
/// path.
pub(crate) fn demask_sse_response(
    body: &[u8],
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) -> DemaskedResponse {
    let Ok(text) = std::str::from_utf8(body) else {
        return DemaskedResponse {
            body: body.to_vec(),
            issued: Vec::new(),
        };
    };

    let frames = parse_frames(text);
    let issued = issued_blocks(&frames);

    // Pass 1: accumulate every demaskable delta's content per content-block index, across the
    // WHOLE buffered stream — never demasked per-chunk, which is exactly the partial-placeholder
    // trap this module's own doc names.
    let mut raw_by_index: BTreeMap<u64, (DeltaKind, String)> = BTreeMap::new();
    for frame in &frames {
        if let Some((kind, fragment)) = demaskable_delta(frame) {
            let entry = raw_by_index
                .entry(frame_index(frame))
                .or_insert_with(|| (kind, String::new()));
            // An index mixing delta kinds isn't a shape the protocol produces; leave it alone
            // rather than guess (its fragments are then passed through, see pass 2).
            if entry.0 != kind {
                entry.0 = DeltaKind::Mixed;
            }
            entry.1.push_str(fragment);
        }
    }

    // `None` means "pass this index's original fragments through unchanged".
    let demasked_by_index: BTreeMap<u64, Option<String>> = raw_by_index
        .into_iter()
        .map(|(index, (kind, raw))| {
            let demasked = match kind {
                DeltaKind::Text => Some(demask_text(&raw, bindings, policy, ns)),
                DeltaKind::InputJson => demask_input_json(&raw, bindings, policy, ns),
                DeltaKind::Mixed => None,
            };
            (index, demasked)
        })
        .collect();

    // Pass 2: re-emit every frame verbatim, except a demaskable delta — the first one for a
    // given index carries the whole demasked content; every later one for the same index is
    // dropped.
    let mut already_emitted: HashSet<u64> = HashSet::new();
    let mut out = String::with_capacity(text.len());
    for frame in &frames {
        let Some((kind, _)) = demaskable_delta(frame) else {
            push_raw_frame(&mut out, frame.raw);
            continue;
        };
        let index = frame_index(frame);
        let Some(Some(demasked)) = demasked_by_index.get(&index) else {
            push_raw_frame(&mut out, frame.raw);
            continue;
        };
        if !already_emitted.insert(index) {
            continue; // already consolidated into this index's first delta
        }
        let Some(mut parsed) = frame.parsed.clone() else {
            push_raw_frame(&mut out, frame.raw);
            continue;
        };
        if let Some(delta) = parsed.get_mut("delta").and_then(Value::as_object_mut) {
            delta.insert(kind.field().to_string(), Value::String(demasked.clone()));
        }
        write_frame(&mut out, frame.event, &parsed);
    }
    DemaskedResponse {
        body: out.into_bytes(),
        issued,
    }
}

/// Reassembles every thinking block the stream carries, for the session's issued-thinking
/// record: `content_block_start` opens a `thinking`/`redacted_thinking` block at an index, and
/// that index's `thinking_delta`/`signature_delta` fragments append to it. Read-only: nothing
/// here changes what is emitted.
fn issued_blocks(frames: &[Frame<'_>]) -> Vec<IssuedBlock> {
    let mut by_index: BTreeMap<u64, IssuedBlock> = BTreeMap::new();
    for frame in frames {
        let Some(parsed) = frame.parsed.as_ref() else {
            continue;
        };
        let str_of =
            |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        match parsed.get("type").and_then(Value::as_str) {
            Some("content_block_start") => {
                let Some(block) = parsed.get("content_block") else {
                    continue;
                };
                let started = match block.get("type").and_then(Value::as_str) {
                    Some("thinking") => IssuedBlock::Thinking {
                        signature: str_of(block, "signature"),
                        thinking: str_of(block, "thinking"),
                    },
                    Some("redacted_thinking") => IssuedBlock::Redacted {
                        data: str_of(block, "data"),
                    },
                    _ => continue,
                };
                by_index.insert(frame_index(frame), started);
            }
            Some("content_block_delta") => {
                let Some(IssuedBlock::Thinking {
                    signature,
                    thinking,
                }) = by_index.get_mut(&frame_index(frame))
                else {
                    continue;
                };
                let Some(delta) = parsed.get("delta") else {
                    continue;
                };
                match delta.get("type").and_then(Value::as_str) {
                    Some("thinking_delta") => thinking.push_str(&str_of(delta, "thinking")),
                    Some("signature_delta") => signature.push_str(&str_of(delta, "signature")),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    by_index.into_values().collect()
}

/// Reassembled `input_json_delta` content for one `tool_use` block, demasked **losslessly**:
/// every JSON string *value* is decoded, demasked, and re-encoded only if a placeholder in it
/// resolved; object keys, numbers, whitespace and key order are copied byte-for-byte. The first
/// version parsed into a `serde_json::Value` and re-serialized it, which (review finding) sorted
/// keys, collapsed duplicate keys, and turned big integers and `1e2` into lossy floats on
/// every tool call, placeholder or not. `None` (pass the original fragments through unchanged)
/// when nothing resolved, when the concatenation isn't valid JSON, or when it's empty (a
/// no-argument tool call).
fn demask_input_json(
    raw: &str,
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) -> Option<String> {
    if raw.is_empty() || serde_json::from_str::<Value>(raw).is_err() {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut changed = false;
    let mut copied_to = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        // Scanning bytes is safe for UTF-8: no multi-byte sequence contains `"` or `\`.
        let start = i;
        i += 1;
        while i < bytes.len() && bytes[i] != b'"' {
            i += if bytes[i] == b'\\' { 2 } else { 1 };
        }
        let end = i + 1; // one past the closing quote
        i = end;
        let is_key = raw[end..].trim_start().starts_with(':');
        if is_key {
            continue;
        }
        let token = &raw[start..end];
        let Ok(decoded) = serde_json::from_str::<String>(token) else {
            continue;
        };
        let demasked = demask_text(&decoded, bindings, policy, ns);
        if demasked != decoded {
            out.push_str(&raw[copied_to..start]);
            out.push_str(&Value::String(demasked).to_string());
            copied_to = end;
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    out.push_str(&raw[copied_to..]);
    Some(out)
}

/// Which demaskable delta kind one content-block index carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaKind {
    Text,
    InputJson,
    Mixed,
}

impl DeltaKind {
    /// The `delta` field holding this kind's content.
    fn field(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::InputJson | Self::Mixed => "partial_json",
        }
    }
}

fn frame_index(frame: &Frame<'_>) -> u64 {
    frame
        .parsed
        .as_ref()
        .and_then(|v| v.get("index"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// One SSE frame: the fields this module understands (`event:`, a JSON-parsed `data:`, if any),
/// plus the original raw text — used verbatim for anything this parser doesn't specifically
/// rewrite, so a real trailing separator/blank-line quirk this module doesn't model is preserved
/// rather than risking a subtly different re-serialization.
struct Frame<'a> {
    event: Option<&'a str>,
    parsed: Option<Value>,
    raw: &'a str,
}

/// Splits `text` on the SSE frame separator (a blank line) and parses each frame's `event:`/
/// `data:` lines. A frame with no `data:` line, or a `data:` line that isn't valid JSON (a
/// malformed/unexpected frame, or the final empty chunk after a trailing separator), gets
/// `parsed: None` — [`demask_sse_response`] round-trips it verbatim via `raw`.
fn parse_frames(text: &str) -> Vec<Frame<'_>> {
    let mut frames = Vec::new();
    for raw in split_frames(text) {
        if raw.is_empty() {
            continue;
        }
        let mut event = None;
        let mut data = None;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim());
            }
        }
        let parsed = data.and_then(|d| serde_json::from_str::<Value>(d).ok());
        frames.push(Frame { event, parsed, raw });
    }
    frames
}

/// SSE frames are separated by a blank line — `\n\n` (real Anthropic SSE, and everything hyper
/// delivers over HTTP/1.1 chunked transfer, uses bare `\n` line endings). `\r\n\r\n` is not
/// specifically handled: not observed from the real API, and an unhandled `\r` just becomes part
/// of the frame's raw/data text, which still round-trips correctly via the `raw` fallback path.
fn split_frames(text: &str) -> impl Iterator<Item = &str> {
    text.split("\n\n")
}

/// Appends `raw` plus the `\n\n` frame separator [`split_frames`] stripped off during parsing —
/// a real bug this module's own live-run proof caught: an earlier version pushed `raw` alone
/// for any pass-through (unrewritten) frame, silently concatenating it directly onto the next
/// frame's `event:`/`data:` line with no separator at all, producing a stream the real `claude`
/// CLI's own SSE parser couldn't parse ("Could not parse message into JSON"). Every frame this
/// module emits — rewritten via [`write_frame`] or passed through raw — must end with the same
/// terminator real SSE requires.
fn push_raw_frame(out: &mut String, raw: &str) {
    out.push_str(raw);
    out.push_str("\n\n");
}

/// `Some((kind, fragment))` iff `frame` is a `content_block_delta` event whose `delta.type` is
/// `text_delta` or `input_json_delta` — the only shapes this module rewrites. Returns the
/// delta's own fragment (not yet accumulated).
fn demaskable_delta<'a>(frame: &'a Frame<'_>) -> Option<(DeltaKind, &'a str)> {
    let parsed = frame.parsed.as_ref()?;
    if parsed.get("type").and_then(Value::as_str) != Some("content_block_delta") {
        return None;
    }
    let delta = parsed.get("delta")?;
    let kind = match delta.get("type").and_then(Value::as_str)? {
        "text_delta" => DeltaKind::Text,
        "input_json_delta" => DeltaKind::InputJson,
        _ => return None,
    };
    let fragment = delta.get(kind.field()).and_then(Value::as_str)?;
    Some((kind, fragment))
}

fn write_frame(out: &mut String, event: Option<&str>, data: &Value) {
    if let Some(event) = event {
        out.push_str("event: ");
        out.push_str(event);
        out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(&data.to_string());
    out.push_str("\n\n");
}

#[cfg(test)]
mod tests {
    //! Inline unit tests — same reasoning as `demask_response.rs`'s own test module: every
    //! item under test here is `pub(crate)`/private, unreachable from a separate
    //! integration-test crate. `build_policy`/`ns`/`mask_and_get_bindings` deliberately mirror
    //! `demask_response.rs`'s own identically-named test helpers rather than importing them
    //! (private to that module's `#[cfg(test)]` block) — real, vault-backed bindings, not
    //! hand-constructed fixtures, same reasoning as the sibling module's own tests.

    use std::path::{Path, PathBuf};

    use tempfile::TempDir;
    use vg_audit::JsonlAuditSink;
    use vg_core::{
        mask, ArtefactHint, Context, Detector, Input, Parser, PolicyEngine, PolicyLayers, RepoId,
    };
    use vg_detectors::all_detectors;
    use vg_parsers::all_parsers;
    use vg_policy::LayeredPolicyEngine;
    use vg_vault::{Vault, VaultConfig};

    use super::*;

    const TEST_KEY: [u8; 32] = [7u8; 32];

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
        Namespace::Repo(RepoId(
            "veilgremlin-vgproxy-stream-demask-tests".to_string(),
        ))
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

    fn mask_and_get_bindings(
        raw: &str,
        ns: &Namespace,
        policy: &Policy,
    ) -> (String, Vec<PlaceholderBinding>) {
        let input = Input {
            buf: raw.as_bytes().to_vec(),
            hint: ArtefactHint::default(),
        };
        let (pack, _refs, _event, _trace_id) =
            with_real_context(|ctx| mask(&input, ctx, policy, ns)).expect("mask succeeds");
        (pack.text, pack.bindings)
    }

    fn sse_event(event: &str, data: &Value) -> String {
        format!("event: {event}\ndata: {}\n\n", data)
    }

    fn content_block_delta(index: u64, text: &str) -> String {
        sse_event(
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "text_delta", "text": text}
            }),
        )
    }

    /// The core claim this whole module exists for: a placeholder split across two separate
    /// `text_delta` chunks (exactly the "SSE chunk-boundary/partial-placeholder" case
    /// `beta-implementation-plan.md`'s own A4 entry named as unanswered by M4's design) is
    /// still correctly demasked, because both chunks are reconstructed into one full string
    /// before rehydration ever runs — never demasked as two separate, unresolvable fragments.
    #[test]
    fn placeholder_split_across_two_deltas_is_still_demasked() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (masked_text, bindings) =
            mask_and_get_bindings("contact jane.doe@example.com", &namespace, &policy);
        assert!(masked_text.contains("EMAIL_001"), "masked: {masked_text}");

        // Split the masked text's placeholder across a chunk boundary: "...EMAIL_" in one
        // delta, "001" in the next — a real, plausible SSE chunking a token-by-token model
        // response could produce.
        let split_at = masked_text.find("EMAIL_").expect("placeholder present") + "EMAIL_".len();
        let (first_half, second_half) = masked_text.split_at(split_at);

        let mut stream = String::new();
        stream.push_str(&sse_event(
            "message_start",
            &serde_json::json!({"type": "message_start", "message": {"id": "msg_1"}}),
        ));
        stream.push_str(&sse_event(
            "content_block_start",
            &serde_json::json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ));
        stream.push_str(&content_block_delta(0, first_half));
        stream.push_str(&content_block_delta(0, second_half));
        stream.push_str(&sse_event(
            "content_block_stop",
            &serde_json::json!({"type": "content_block_stop", "index": 0}),
        ));
        stream.push_str(&sse_event(
            "message_stop",
            &serde_json::json!({"type": "message_stop"}),
        ));

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        assert!(
            demasked.contains("jane.doe@example.com"),
            "demasked stream: {demasked}"
        );
        assert!(
            !demasked.contains("EMAIL_001"),
            "demasked stream: {demasked}"
        );
        // The two original deltas for index 0 consolidate into exactly one — counting the
        // `event: content_block_delta` line specifically, since the substring
        // "content_block_delta" also appears once more per event inside its own `data:`
        // JSON (`"type":"content_block_delta"`), which would double-count a naive substring
        // search.
        assert_eq!(demasked.matches("event: content_block_delta\n").count(), 1);
        // Every other event kind still present, untouched.
        assert!(demasked.contains("message_start"));
        assert!(demasked.contains("content_block_start"));
        assert!(demasked.contains("content_block_stop"));
        assert!(demasked.contains("message_stop"));
        // Every frame, rewritten or passed through raw, is properly terminated and re-parses
        // as well-formed SSE — the exact regression the real live-run proof caught (an earlier
        // version silently dropped the `\n\n` separator on pass-through frames, producing a
        // stream the real `claude` CLI's own SSE parser choked on with "Could not parse
        // message into JSON").
        assert!(
            demasked.ends_with("\n\n"),
            "every frame, including the last, must be `\\n\\n`-terminated: {demasked:?}"
        );
        for frame in demasked.split("\n\n") {
            if frame.is_empty() {
                continue;
            }
            let data_line = frame
                .lines()
                .find_map(|l| l.strip_prefix("data:"))
                .unwrap_or_else(|| panic!("frame has no data: line: {frame:?}"));
            serde_json::from_str::<Value>(data_line.trim()).unwrap_or_else(|e| {
                panic!("frame's data: line is not valid JSON ({e}): {frame:?}")
            });
        }
    }

    /// Events with nothing to demask — a `ping`, and a tool-use `input_json_delta` holding no
    /// placeholder — come back with the same content (the single-fragment tool input is
    /// re-serialized, which for this compact input is byte-identical).
    #[test]
    fn non_text_delta_events_round_trip_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (_masked, bindings) =
            mask_and_get_bindings("contact jane.doe@example.com", &namespace, &policy);

        let ping = sse_event("ping", &serde_json::json!({"type": "ping"}));
        let tool_delta = sse_event(
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": "{\"a\":1}"}
            }),
        );
        let mut stream = String::new();
        stream.push_str(&ping);
        stream.push_str(&tool_delta);

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        assert!(demasked.contains("\"partial_json\":\"{\\\"a\\\":1}\""));
        assert!(demasked.contains("\"type\":\"ping\""));
    }

    fn input_json_delta(index: u64, partial_json: &str) -> String {
        sse_event(
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": partial_json}
            }),
        )
    }

    /// Streams a `tool_use` block named `name` whose input JSON is `input_json`, split into
    /// fragments at `split_points` (byte offsets into `input_json`).
    fn tool_use_stream(name: &str, input_json: &str, split_points: &[usize]) -> String {
        let mut stream = String::new();
        stream.push_str(&sse_event(
            "content_block_start",
            &serde_json::json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_1", "name": name, "input": {}}}),
        ));
        let mut last = 0;
        for &at in split_points
            .iter()
            .chain(std::iter::once(&input_json.len()))
        {
            stream.push_str(&input_json_delta(1, &input_json[last..at]));
            last = at;
        }
        stream.push_str(&sse_event(
            "content_block_stop",
            &serde_json::json!({"type": "content_block_stop", "index": 1}),
        ));
        stream
    }

    /// Reassembles a demasked stream's `tool_use` input the way the client does: concatenate
    /// every `input_json_delta.partial_json` for index 1 in order, then parse.
    fn reassembled_tool_input(demasked: &str) -> Value {
        let mut json = String::new();
        let mut delta_frames = 0;
        for frame in demasked.split("\n\n") {
            let Some(data) = frame.lines().find_map(|l| l.strip_prefix("data:")) else {
                continue;
            };
            let v: Value = serde_json::from_str(data.trim()).expect("frame data is JSON");
            if v["delta"]["type"] == "input_json_delta" && v["index"] == 1 {
                json.push_str(v["delta"]["partial_json"].as_str().unwrap());
                delta_frames += 1;
            }
        }
        assert_eq!(
            delta_frames, 1,
            "fragments consolidate into one delta: {demasked}"
        );
        serde_json::from_str(&json).expect("reassembled input parses")
    }

    /// veil-proxy#86 finding 2: the exact failure the spike hit. The model saw a masked value,
    /// emitted an `Edit` whose `old_string` held the placeholder, and — with `input_json_delta`
    /// passed through — the client got the literal placeholder, so the edit could never match
    /// the real file. The placeholder is split mid-token across two fragments here.
    #[test]
    fn a_placeholder_split_across_input_json_fragments_is_demasked() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (masked_text, bindings) = mask_and_get_bindings(
            "send to jane.doe@example.com within 30 days",
            &namespace,
            &policy,
        );
        assert!(masked_text.contains("EMAIL_001"), "masked: {masked_text}");

        let input_json = serde_json::json!({
            "file_path": "billing/invoice.py",
            "old_string": masked_text,
            "new_string": "fixed"
        })
        .to_string();
        let split = input_json.find("EMAIL_").unwrap() + "EMA".len();
        let stream = tool_use_stream("Edit", &input_json, &[10, split]);

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        let input = reassembled_tool_input(&demasked);
        assert_eq!(
            input["old_string"],
            "send to jane.doe@example.com within 30 days"
        );
        assert_eq!(input["file_path"], "billing/invoice.py");
        assert!(!demasked.contains("EMAIL_001"), "demasked: {demasked}");
        // The block's own id/name (in content_block_start) are untouched.
        assert!(
            demasked.contains("\"name\":\"Edit\""),
            "demasked: {demasked}"
        );
        assert!(
            demasked.contains("\"id\":\"toolu_1\""),
            "demasked: {demasked}"
        );
    }

    /// A tool literally named like a placeholder keeps its name — the stream-side counterpart
    /// of `demask_response.rs`'s `BLOCK_METADATA_KEYS` regression. The name lives in
    /// `content_block_start`, which this module never rewrites.
    #[test]
    fn a_tool_named_like_a_placeholder_keeps_its_name() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);
        assert_eq!(masked_text, "EMAIL_001");

        let stream = tool_use_stream("EMAIL_001", "{\"q\":\"EMAIL_001\"}", &[]);
        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        assert!(
            demasked.contains("\"name\":\"EMAIL_001\""),
            "demasked: {demasked}"
        );
        assert_eq!(
            reassembled_tool_input(&demasked)["q"],
            "jane.doe@example.com"
        );
    }

    /// Fragments that don't reassemble into valid JSON pass through byte-for-byte, fragment by
    /// fragment — the module's infallible posture.
    #[test]
    fn malformed_input_json_passes_through_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (_masked, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        let stream = tool_use_stream("Edit", "{\"old_string\": \"EMAIL_001", &[5]);
        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        assert_eq!(String::from_utf8(demasked).unwrap(), stream);
    }

    /// Review finding (fresh-context adversarial round): the first version parsed the tool input
    /// into a `Value` and re-serialized it on every tool call, sorting keys and corrupting big
    /// integers and exponent literals. Only string values that actually resolve may change.
    #[test]
    fn tool_input_is_demasked_losslessly_and_untouched_when_nothing_resolves() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        let tail =
            r#""n":12345678901234567890123,"f":1e2,"big":18446744073709551616,"u":"\u00e9 é"}"#;
        let without = format!(r#"{{"z":1,"k":"k","k":"dup",{tail}"#);
        let stream = tool_use_stream("Bash", &without, &[9]);
        let out = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        assert_eq!(
            String::from_utf8(out).unwrap(),
            stream,
            "no placeholder: fragments pass through byte-for-byte"
        );

        let with = format!(r#"{{"z":1,"to":"{masked_text}",{tail}"#);
        let stream = tool_use_stream("Bash", &with, &[9]);
        let out = String::from_utf8(
            demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body,
        )
        .unwrap();
        let expected = with.replace(&masked_text, "jane.doe@example.com");
        let reassembled: String = out
            .split("\n\n")
            .filter_map(|f| f.lines().find_map(|l| l.strip_prefix("data:")))
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .filter(|v| v["delta"]["type"] == "input_json_delta")
            .map(|v| v["delta"]["partial_json"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            reassembled, expected,
            "only the placeholder's string value changes"
        );
    }

    /// The same logical response demasks `tool_use.input` identically whether it arrives as
    /// one JSON body (`demask_response.rs`) or as SSE (this module).
    #[test]
    fn streaming_and_non_streaming_demask_tool_input_identically() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (masked_text, bindings) = mask_and_get_bindings(
            "cc jane.doe@example.com and ops@example.com",
            &namespace,
            &policy,
        );

        let input = serde_json::json!({"command": "notify", "args": {"to": [masked_text], "n": 2}});
        let json_body = serde_json::json!({
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": input}]
        });
        let non_streamed = super::super::demask_response::demask_response(
            &serde_json::to_vec(&json_body).unwrap(),
            &bindings,
            &policy,
            &namespace,
        )
        .body;
        let non_streamed: Value = serde_json::from_slice(&non_streamed).unwrap();

        let input_json = input.to_string();
        let stream = tool_use_stream("Bash", &input_json, &[7, 19, 30]);
        let streamed = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let streamed = reassembled_tool_input(&String::from_utf8(streamed).unwrap());

        assert_eq!(streamed, non_streamed["content"][0]["input"]);
        assert!(
            streamed.to_string().contains("ops@example.com"),
            "{streamed}"
        );
    }

    /// Thinking deltas (and their signature) stay exactly as issued — veil-proxy#86 finding 1.
    #[test]
    fn thinking_and_signature_deltas_round_trip_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (_masked, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        let mut stream = String::new();
        stream.push_str(&sse_event(
            "content_block_delta",
            &serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "contact EMAIL_001"}}),
        ));
        stream.push_str(&sse_event(
            "content_block_delta",
            &serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "EqQBCkYIBxgC"}}),
        ));

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        assert_eq!(String::from_utf8(demasked).unwrap(), stream);
    }

    /// A malformed/unparseable frame among otherwise-valid ones doesn't panic and doesn't
    /// corrupt neighboring frames — this module's own "deliberately infallible" posture.
    #[test]
    fn a_malformed_frame_does_not_panic_or_drop_other_frames() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (_masked, bindings) =
            mask_and_get_bindings("contact jane.doe@example.com", &namespace, &policy);

        let mut stream = String::new();
        stream.push_str("event: content_block_delta\ndata: not valid json at all\n\n");
        stream.push_str(&sse_event(
            "message_stop",
            &serde_json::json!({"type": "message_stop"}),
        ));

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace).body;
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        assert!(demasked.contains("not valid json at all"));
        assert!(demasked.contains("message_stop"));
    }

    /// Non-UTF-8 input is returned unchanged rather than panicking — the top-level defensive
    /// fallback this module's own doc names.
    #[test]
    fn non_utf8_body_is_returned_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (_masked, bindings) =
            mask_and_get_bindings("contact jane.doe@example.com", &namespace, &policy);

        let invalid = vec![0xff, 0xfe, 0xfd];
        let out = demask_sse_response(&invalid, &bindings, &policy, &namespace).body;
        assert_eq!(out, invalid);
    }
}
