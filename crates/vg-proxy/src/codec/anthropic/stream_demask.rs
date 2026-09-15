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
//! **Only `text_delta` content is demasked.** Every other event kind — `message_start`,
//! `content_block_start`, `content_block_stop`, `message_delta`, `message_stop`, `ping`, tool-use
//! `input_json_delta` fragments, thinking-block deltas, anything this parser doesn't specifically
//! recognize — round-trips unchanged, matching `demask_response.rs`'s own "text-bearing fields
//! only" scope precedent (`BLOCK_METADATA_KEYS`) rather than a new policy decision. Extending
//! demasking to tool-use/thinking content is out of scope here, same as it is for
//! `demask_response.rs`'s non-streaming path.
//!
//! **Consolidation, not true re-streaming.** For each content-block `index` that carries at
//! least one `text_delta`, this module emits exactly one `content_block_delta` event carrying
//! the *entire* demasked text for that index (at the position of that index's first delta in the
//! original stream) and drops every subsequent original delta for the same index — their content
//! is already included. A client parsing this as ordinary SSE per the Anthropic streaming
//! protocol (concatenate `text_delta.text` per index in event order) reconstructs the identical
//! final text either way; only the number/size of the delta events differs.
//!
//! **Deliberately infallible**, same posture as `demask_response.rs`: an unparseable frame, a
//! non-UTF-8 body, or any other unexpected shape passes through unchanged rather than blocking a
//! successful response — the request already reached the real upstream and got a real answer;
//! refusing to return it would be strictly worse than an unresolved placeholder.

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use vg_core::{Namespace, PlaceholderBinding, Policy};

use super::demask_response::demask_text;

/// Demasks every `text_delta` fragment in `body` (an Anthropic Messages API SSE stream, fully
/// buffered) against `bindings`, and re-serializes. Always returns bytes — see this module's own
/// doc for why it cannot fail. `body` that isn't valid UTF-8 is returned unchanged: real SSE is
/// always UTF-8 text, so this is a defensive fallback, not an expected path.
pub(crate) fn demask_sse_response(
    body: &[u8],
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec();
    };

    let frames = parse_frames(text);

    // Pass 1: accumulate every `text_delta`'s text per content-block index, across the WHOLE
    // buffered stream — never demasked per-chunk, which is exactly the partial-placeholder trap
    // this module's own doc names.
    let mut text_by_index: BTreeMap<u64, String> = BTreeMap::new();
    for frame in &frames {
        if let Some(delta_text) = text_delta_text(frame) {
            let index = frame
                .parsed
                .as_ref()
                .and_then(|v| v.get("index"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            text_by_index.entry(index).or_default().push_str(delta_text);
        }
    }

    let demasked_by_index: BTreeMap<u64, String> = text_by_index
        .into_iter()
        .map(|(index, raw)| (index, demask_text(&raw, bindings, policy, ns)))
        .collect();

    // Pass 2: re-emit every frame verbatim, except a `content_block_delta` text_delta event —
    // the first one for a given index carries the whole demasked text; every later one for the
    // same index is dropped.
    let mut already_emitted: HashSet<u64> = HashSet::new();
    let mut out = String::with_capacity(text.len());
    for frame in &frames {
        match text_delta_text(frame) {
            Some(_) => {
                let index = frame
                    .parsed
                    .as_ref()
                    .and_then(|v| v.get("index"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if !already_emitted.insert(index) {
                    continue; // already consolidated into this index's first delta
                }
                let Some(mut parsed) = frame.parsed.clone() else {
                    push_raw_frame(&mut out, frame.raw);
                    continue;
                };
                if let Some(delta) = parsed.get_mut("delta").and_then(Value::as_object_mut) {
                    if let Some(demasked) = demasked_by_index.get(&index) {
                        delta.insert("text".to_string(), Value::String(demasked.clone()));
                    }
                }
                write_frame(&mut out, frame.event, &parsed);
            }
            None => push_raw_frame(&mut out, frame.raw),
        }
    }
    out.into_bytes()
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

/// `Some(text)` iff `frame` is a `content_block_delta` event whose `delta.type` is `text_delta`
/// — the only shape this module rewrites. Returns the delta's own text (not yet accumulated).
fn text_delta_text<'a>(frame: &'a Frame<'_>) -> Option<&'a str> {
    let parsed = frame.parsed.as_ref()?;
    if parsed.get("type").and_then(Value::as_str) != Some("content_block_delta") {
        return None;
    }
    let delta = parsed.get("delta")?;
    if delta.get("type").and_then(Value::as_str) != Some("text_delta") {
        return None;
    }
    delta.get("text").and_then(Value::as_str)
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

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace);
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

    /// Non-`text_delta` events — including a `ping` and a tool-use `input_json_delta` — round-
    /// trip completely unchanged, proving this module doesn't touch content it doesn't
    /// specifically understand (matching `demask_response.rs`'s own `BLOCK_METADATA_KEYS`
    /// precedent: no classifier, but a real scope boundary).
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

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace);
        let demasked = String::from_utf8(demasked).expect("valid utf-8");

        assert!(demasked.contains("\"partial_json\":\"{\\\"a\\\":1}\""));
        assert!(demasked.contains("\"type\":\"ping\""));
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

        let demasked = demask_sse_response(stream.as_bytes(), &bindings, &policy, &namespace);
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
        let out = demask_sse_response(&invalid, &bindings, &policy, &namespace);
        assert_eq!(out, invalid);
    }
}
