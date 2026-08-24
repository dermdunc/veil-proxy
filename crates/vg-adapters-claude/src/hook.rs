//! The Claude Code hook adapter (`interface-contracts.md` §8, **v1.3**).
//!
//! Claude Code invokes a hook by running a command with a JSON event on stdin. This module
//! maps each hook event to a `vg_core::mask` call and reduces the result to Claude Code's
//! **actual** hook protocol (the frozen §8 contract's `0/2/1` scheme was built on an
//! inverted model of the platform — under real semantics exit 1 is a *non-blocking*
//! warning and exit 2 discards stdout, so every "fail closed" path failed open and every
//! transform over-blocked; caught by the T09 doubt-pass, verified against the hooks docs):
//!
//! - exit **0**, empty stdout = pass-through (nothing sensitive; proceed unchanged)
//! - exit **0**, stdout = JSON = the transform, per event:
//!   - `PreToolUse` → `hookSpecificOutput.updatedInput` carries the **masked** tool input
//!     (real substitution; the raw input never runs)
//!   - `PostToolUse` → `hookSpecificOutput.updatedToolOutput` carries the **masked** tool
//!     result (real substitution; the raw result never reaches the model)
//!   - `UserPromptSubmit` → the platform cannot rewrite a prompt, so a sensitive prompt is
//!     **blocked** (`{"decision":"block"}`) with the masked version in the reason for the
//!     user to resubmit — fail-closed by construction, at the cost of one resubmit
//! - exit **2**, reason on stderr = block (policy Block, unparseable payload, schema
//!   drift, masking error). Exit 2 is the platform's only *blocking* code.
//!
//! The adapter **never** calls `vault.resolve` — demask is the separate, user-invoked
//! `vg demask` flow.

use serde_json::Value;

use vg_core::ArtefactHint;

use crate::runtime::Engine;

/// The three hook events this adapter handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
}

impl HookEvent {
    /// Parses an event from a CLI token (`user-prompt-submit`) or Claude Code's own
    /// `hook_event_name` spelling (`UserPromptSubmit`), case- and separator-insensitively.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace(['_', '-'], "").as_str() {
            "userpromptsubmit" => Some(HookEvent::UserPromptSubmit),
            "pretooluse" => Some(HookEvent::PreToolUse),
            "posttooluse" => Some(HookEvent::PostToolUse),
            _ => None,
        }
    }

    /// Claude Code's `hook_event_name` spelling, used in the generated hook settings.
    pub fn event_name(&self) -> &'static str {
        match self {
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
        }
    }

    /// The `vg hook <name>` CLI token.
    pub fn cli_name(&self) -> &'static str {
        match self {
            HookEvent::UserPromptSubmit => "user-prompt-submit",
            HookEvent::PreToolUse => "pre-tool-use",
            HookEvent::PostToolUse => "post-tool-use",
        }
    }

    /// All three, for generating the hook settings.
    pub fn all() -> [HookEvent; 3] {
        [
            HookEvent::UserPromptSubmit,
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
        ]
    }
}

/// What the CLI should do after running a hook: an exit code and optional stdout/stderr.
/// Returned (rather than exiting directly) so it is unit-testable and the CLI owns the one
/// `process::exit`.
#[derive(Debug, Default)]
pub struct HookResult {
    pub exit_code: i32,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

impl HookResult {
    fn pass_through() -> Self {
        HookResult {
            exit_code: 0,
            stdout: None,
            stderr: None,
        }
    }
    /// A transform: exit 0 with the event-appropriate JSON on stdout (the only channel the
    /// platform parses for structured output). `note` goes to stderr, which on exit 0 lands
    /// in the debug log only.
    fn transformed(json: Value, note: Option<String>) -> Self {
        HookResult {
            exit_code: 0,
            stdout: Some(json.to_string()),
            stderr: note,
        }
    }
    /// A block: exit 2 — the platform's only *blocking* exit code (any other non-zero is a
    /// non-blocking warning that lets the raw content continue). stderr carries the reason.
    fn block(reason: String) -> Self {
        HookResult {
            exit_code: 2,
            stdout: None,
            stderr: Some(reason),
        }
    }
}

/// Runs one hook invocation: parse the stdin JSON, mask the event's subject text, and
/// reduce to the v1.3 protocol (exit 0 + JSON transform / exit 2 block — see the module
/// docs). `engine` is the already-opened engine over the session's state dir.
pub fn run_hook(event: HookEvent, stdin_json: &str, engine: &Engine) -> HookResult {
    let value: Value = match serde_json::from_str(stdin_json) {
        Ok(v) => v,
        Err(e) => {
            // Fail closed: an unreadable payload means we cannot prove it is masked.
            return HookResult::block(format!(
                "veilgremlin: could not parse {} hook input as JSON ({e}); blocking to avoid \
                 sending unmasked content",
                event.event_name()
            ));
        }
    };

    let (subject, hint) = match extract_subject(event, &value) {
        // Well-formed payload with genuinely nothing to guard (e.g. an empty prompt) —
        // proceed unchanged.
        Ok(None) => return HookResult::pass_through(),
        Ok(Some(pair)) => pair,
        // Schema drift: the payload parsed as JSON but the field this adapter guards is
        // missing or the wrong type. Silently passing through here would disable the
        // shield forever after a Claude Code payload rename (doubt-pass High) — block.
        Err(drift) => {
            return HookResult::block(format!(
                "veilgremlin: unrecognised {} hook payload shape ({drift}); blocking to \
                 avoid sending unmasked content",
                event.event_name()
            ));
        }
    };

    let (pack, _refs, _event, _trace_id) = match engine.mask_text(&subject, hint) {
        Ok(out) => out,
        Err(e) => {
            return HookResult::block(format!(
                "veilgremlin: masking failed for a {} hook ({e}); blocking to avoid sending \
                 unmasked content",
                event.event_name()
            ));
        }
    };

    if pack.stats.blocked_artefacts > 0 {
        return HookResult::block(format!(
            "veilgremlin: artefact blocked by policy on a {} hook — not sent (policy {})",
            event.event_name(),
            pack.policy_version
        ));
    }

    if pack.text == subject {
        // No byte changed: nothing sensitive was found. Pass through.
        return HookResult::pass_through();
    }

    // Transformed. Persist the pack so a later `vg demask` can reverse it — but only when it
    // has reversible bindings (a purely-redacted artefact has nothing to demask).
    let note = if pack.bindings.is_empty() {
        None
    } else {
        match engine.save_pack(&pack) {
            Ok(path) => Some(format!(
                "veilgremlin: masked pack saved to {}",
                path.display()
            )),
            Err(e) => Some(format!(
                "veilgremlin: WARNING masked pack could not be persisted ({e}); demask will be \
                 unavailable for this artefact"
            )),
        }
    };
    match transform_output(event, &value, &pack.text) {
        Ok(json) => HookResult::transformed(json, note),
        // Fail closed: if the masked content cannot be rendered back into the structured
        // shape the platform substitutes (e.g. masking broke the JSON of a tool payload),
        // blocking beats letting the raw content continue.
        Err(why) => HookResult::block(format!(
            "veilgremlin: masked {} content could not be rendered into the hook's \
             structured output ({why}); blocking to avoid sending unmasked content",
            event.event_name()
        )),
    }
}

/// Builds the exit-0 JSON that makes the platform *substitute* the masked content — the
/// only mechanism that actually replaces anything (stdout on exit 2 is discarded).
fn transform_output(event: HookEvent, value: &Value, masked: &str) -> Result<Value, String> {
    match event {
        // The platform cannot rewrite a prompt in flight (no `updatedPrompt` exists), so
        // the fail-closed rendering of "transformed" is: block the raw prompt and hand the
        // user the masked version to resubmit. The friction is deliberate; the alternative
        // (warn-and-send) ships the raw prompt and defeats the shield.
        HookEvent::UserPromptSubmit => Ok(serde_json::json!({
            "decision": "block",
            "reason": format!(
                "VeilGremlin: this prompt contained sensitive values, and a prompt cannot \
                 be rewritten in flight — the raw prompt was NOT sent. Resubmit the masked \
                 version if intended:\n\n{masked}"
            ),
        })),
        HookEvent::PreToolUse => {
            let original = value.get("tool_input").ok_or("tool_input disappeared")?;
            let updated = masked_payload(original, masked)?;
            Ok(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": updated,
                }
            }))
        }
        HookEvent::PostToolUse => {
            let original = value
                .get("tool_response")
                .ok_or("tool_response disappeared")?;
            let updated = masked_payload(original, masked)?;
            Ok(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": updated,
                }
            }))
        }
    }
}

/// Renders masked text back into the same JSON shape the original payload had: a bare
/// string stays a string; anything else must re-parse as JSON **and** be shape-identical
/// to the original — same nesting, same object keys, same array lengths, identical
/// non-string scalars, only string *values* free to differ. Masking substitutes inside
/// string values, so this normally holds; a finding that spanned structure (or rewrote an
/// object *key*) breaks it, and the caller fails closed rather than hand the platform a
/// payload with a different schema (Codex round-2 finding).
fn masked_payload(original: &Value, masked: &str) -> Result<Value, String> {
    if original.is_string() {
        return Ok(Value::String(masked.to_string()));
    }
    let parsed: Value = serde_json::from_str(masked)
        .map_err(|e| format!("masked payload no longer parses as JSON: {e}"))?;
    same_shape(original, &parsed)?;
    Ok(parsed)
}

/// Verifies `masked` differs from `original` only in string values.
fn same_shape(original: &Value, masked: &Value) -> Result<(), String> {
    match (original, masked) {
        (Value::String(_), Value::String(_)) => Ok(()),
        (Value::Null, Value::Null) => Ok(()),
        (Value::Bool(a), Value::Bool(b)) if a == b => Ok(()),
        (Value::Number(a), Value::Number(b)) if a == b => Ok(()),
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => a
            .iter()
            .zip(b.iter())
            .try_for_each(|(x, y)| same_shape(x, y)),
        (Value::Object(a), Value::Object(b)) if a.len() == b.len() => {
            for (key, x) in a {
                let y = b
                    .get(key)
                    .ok_or_else(|| "masked payload changed an object key".to_string())?;
                same_shape(x, y)?;
            }
            Ok(())
        }
        _ => Err("masked payload changed the JSON structure".to_string()),
    }
}

/// Extracts the subject text to mask and an artefact hint for one event.
///
/// - `Ok(Some(..))` — the subject to mask.
/// - `Ok(None)` — a well-formed payload with genuinely nothing to guard (empty prompt,
///   empty tool payload).
/// - `Err(..)` — **schema drift**: the field this adapter relies on is missing or the wrong
///   type. Claude Code always sends `prompt` on `UserPromptSubmit` and `tool_input` on the
///   tool events; their absence means the payload shape changed under us, and the caller
///   must fail closed rather than silently stop masking (doubt-pass finding).
///
/// - `UserPromptSubmit` masks the `prompt` string.
/// - `PreToolUse` masks the `tool_input`; `PostToolUse` masks the `tool_response` if present,
///   else the `tool_input`. The value is serialised to compact JSON as the subject text.
///   A `file_path` string inside the tool payload becomes the hint path, so an artefact-level
///   block (e.g. writing a `.env`) fires through the same policy the CLI uses.
pub fn extract_subject(
    event: HookEvent,
    value: &Value,
) -> Result<Option<(String, ArtefactHint)>, String> {
    match event {
        HookEvent::UserPromptSubmit => {
            let prompt = value
                .get("prompt")
                .ok_or("no `prompt` field")?
                .as_str()
                .ok_or("`prompt` is not a string")?;
            if prompt.is_empty() {
                return Ok(None);
            }
            Ok(Some((prompt.to_string(), ArtefactHint::default())))
        }
        HookEvent::PreToolUse | HookEvent::PostToolUse => {
            // PreToolUse guards the input; PostToolUse guards the *response* only — the
            // input was already guarded (or blocked) by the PreToolUse hook, and v1.3's
            // transform substitutes into `updatedToolOutput`, where rewritten input would
            // be incoherent.
            let payload = if matches!(event, HookEvent::PostToolUse) {
                value
                    .get("tool_response")
                    .ok_or("no `tool_response` field")?
            } else {
                value.get("tool_input").ok_or("no `tool_input` field")?
            };
            let text = value_to_subject(payload);
            if text.is_empty() {
                return Ok(None);
            }
            // The artefact hint (file_path) lives in `tool_input` for both events — a
            // PostToolUse response to reading `.env` must fire the same artefact policy.
            let hint = value
                .get("tool_input")
                .map(hint_from_payload)
                .unwrap_or_default();
            Ok(Some((text, hint)))
        }
    }
}

/// Renders a tool payload to the string that gets masked. A bare JSON string is masked as
/// itself (not JSON-quoted); anything else is compact-serialised.
fn value_to_subject(payload: &Value) -> String {
    match payload {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Derives an artefact hint from a tool payload's `file_path`, if any.
fn hint_from_payload(payload: &Value) -> ArtefactHint {
    let mut hint = ArtefactHint::default();
    if let Some(path) = payload.get("file_path").and_then(Value::as_str) {
        hint.path = Some(std::path::PathBuf::from(path));
    }
    hint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_parse_accepts_both_spellings() {
        assert_eq!(
            HookEvent::parse("user-prompt-submit"),
            Some(HookEvent::UserPromptSubmit)
        );
        assert_eq!(
            HookEvent::parse("UserPromptSubmit"),
            Some(HookEvent::UserPromptSubmit)
        );
        assert_eq!(HookEvent::parse("PreToolUse"), Some(HookEvent::PreToolUse));
        assert_eq!(HookEvent::parse("nonsense"), None);
    }

    #[test]
    fn extract_user_prompt() {
        let v: Value =
            serde_json::json!({"hook_event_name":"UserPromptSubmit","prompt":"hi there"});
        let (text, _hint) = extract_subject(HookEvent::UserPromptSubmit, &v)
            .expect("well-formed")
            .expect("subject");
        assert_eq!(text, "hi there");
    }

    #[test]
    fn extract_tool_input_with_file_path_hint() {
        let v: Value = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/.env", "content": "API_TOKEN=abc"}
        });
        let (text, hint) = extract_subject(HookEvent::PreToolUse, &v)
            .expect("well-formed")
            .expect("subject");
        assert!(text.contains("API_TOKEN"));
        assert_eq!(
            hint.path.as_deref(),
            Some(std::path::Path::new("/tmp/.env"))
        );
    }

    #[test]
    fn transform_output_shapes_match_the_platform_protocol() {
        // PreToolUse: masked object goes back as hookSpecificOutput.updatedInput.
        let v: Value = serde_json::json!({
            "tool_input": {"file_path": "/tmp/n.txt", "content": "mail a@b.com"}
        });
        let masked = r#"{"file_path":"/tmp/n.txt","content":"mail EMAIL_001"}"#;
        let out = transform_output(HookEvent::PreToolUse, &v, masked).expect("transform");
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            out["hookSpecificOutput"]["updatedInput"]["content"],
            "mail EMAIL_001"
        );

        // PostToolUse: a bare-string response stays a string in updatedToolOutput.
        let v: Value = serde_json::json!({"tool_response": "raw a@b.com"});
        let out = transform_output(HookEvent::PostToolUse, &v, "raw EMAIL_001").expect("transform");
        assert_eq!(
            out["hookSpecificOutput"]["updatedToolOutput"],
            "raw EMAIL_001"
        );

        // UserPromptSubmit: the platform cannot rewrite a prompt → decision:block with the
        // masked text in the reason.
        let v: Value = serde_json::json!({"prompt": "mail a@b.com"});
        let out = transform_output(HookEvent::UserPromptSubmit, &v, "mail EMAIL_001").expect("ok");
        assert_eq!(out["decision"], "block");
        assert!(out["reason"].as_str().unwrap().contains("mail EMAIL_001"));

        // A masked object payload that no longer parses as JSON fails (caller blocks).
        let v: Value = serde_json::json!({"tool_input": {"content": "x"}});
        assert!(transform_output(HookEvent::PreToolUse, &v, "not json {").is_err());
    }

    #[test]
    fn missing_prompt_is_schema_drift_not_pass_through() {
        // Claude Code always sends `prompt` on UserPromptSubmit; its absence means the
        // payload shape changed and the adapter must fail closed, not silently stop masking.
        let v: Value = serde_json::json!({"hook_event_name":"UserPromptSubmit"});
        assert!(extract_subject(HookEvent::UserPromptSubmit, &v).is_err());
        let v: Value = serde_json::json!({"hook_event_name":"UserPromptSubmit","prompt":42});
        assert!(extract_subject(HookEvent::UserPromptSubmit, &v).is_err());
        // An empty prompt is well-formed nothing-to-mask, not drift.
        let v: Value = serde_json::json!({"hook_event_name":"UserPromptSubmit","prompt":""});
        assert!(extract_subject(HookEvent::UserPromptSubmit, &v)
            .expect("well-formed")
            .is_none());
    }
}
