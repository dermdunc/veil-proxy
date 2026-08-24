//! Anthropic Messages API content-block classification (plan §10.2 `schema/anthropic.rs`).
//!
//! **Deliberately not a full-body typed schema.** A real request body carries many fields this
//! milestone (M3) doesn't need to understand — `max_tokens`, `temperature`, `top_p`,
//! `stop_sequences`, `tool_choice`, `metadata`, `stream`, `thinking`, and more. Deserializing
//! into a narrow `#[derive(Deserialize)]` struct naming only the fields this crate cares about,
//! then re-serializing that struct, would silently **drop** every field it doesn't name — a
//! real corruption bug once a real Claude Code session (M5) sends a real request. Instead,
//! [`crate::mask_request`] parses the body as a generic `serde_json::Value` and mutates only
//! `system`/`messages[].content` text leaves in place; this module's only job is classifying a
//! content block's `"type"` discriminant during that walk, so every unmodified field round-trips
//! byte-for-byte-equivalent through the untouched parts of the tree.

use serde_json::Value;

/// One content block's `"type"` discriminant, matched during [`crate::mask_request`]'s walk
/// over `messages[].content`. Every content-block kind the plan names, plus `Unknown` for
/// anything else — fail-closed (plan §10.2: "fail-closed on anything unrecognized"), never a
/// silent pass-through for a block type this crate doesn't recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContentBlockKind {
    /// `{"type": "text", "text": "..."}` — the `text` field is masked directly.
    Text,
    /// `{"type": "tool_use", "input": {...}, ...}` — every string leaf inside `input` is
    /// masked recursively (session decision: matches what the existing hook-based mechanism
    /// already does for `tool_input`, done here as a real tree-walk instead of a stringify
    /// hack). Distinct from `tools[]` (the top-level tool *definitions*), which this crate
    /// never reads or touches.
    ToolUse,
    /// `{"type": "tool_result", "content": ..., ...}` — every string leaf inside `content` is
    /// masked recursively, whether `content` is a bare string or a nested array of blocks.
    ToolResult,
    /// `{"type": "document", ...}` — blocks the whole request (session decision: real
    /// text/base64/url-sourced handling is a named, deferred gap, not built here).
    Document,
    /// `{"type": "image", ...}` — blocks the whole request (plan §10.2, unchanged).
    Image,
    /// Anything else, including a missing or non-string `"type"` field. Blocks the whole
    /// request — the fail-closed default for a shape this crate doesn't recognize.
    Unknown(String),
}

impl ContentBlockKind {
    /// Classifies `block`'s `"type"` field. Never panics: a block with no `"type"` field, or
    /// one whose value isn't a JSON string, classifies as `Unknown(String::new())` — fails
    /// closed like any other unrecognized shape, not treated as a parse error distinct from
    /// "unrecognized."
    pub(crate) fn of(block: &Value) -> Self {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => Self::Text,
            Some("tool_use") => Self::ToolUse,
            Some("tool_result") => Self::ToolResult,
            Some("document") => Self::Document,
            Some("image") => Self::Image,
            Some(other) => Self::Unknown(other.to_string()),
            None => Self::Unknown(String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::ContentBlockKind;

    #[test]
    fn classifies_every_named_kind() {
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "text", "text": "hi"})),
            ContentBlockKind::Text
        );
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "tool_use", "input": {}})),
            ContentBlockKind::ToolUse
        );
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "tool_result", "content": "x"})),
            ContentBlockKind::ToolResult
        );
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "document"})),
            ContentBlockKind::Document
        );
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "image"})),
            ContentBlockKind::Image
        );
    }

    #[test]
    fn unrecognized_type_string_is_unknown() {
        assert_eq!(
            ContentBlockKind::of(&json!({"type": "video"})),
            ContentBlockKind::Unknown("video".to_string())
        );
    }

    #[test]
    fn missing_type_field_is_unknown_not_a_panic() {
        assert_eq!(
            ContentBlockKind::of(&json!({"text": "no type field"})),
            ContentBlockKind::Unknown(String::new())
        );
    }

    #[test]
    fn non_string_type_field_is_unknown_not_a_panic() {
        assert_eq!(
            ContentBlockKind::of(&json!({"type": 42})),
            ContentBlockKind::Unknown(String::new())
        );
    }

    #[test]
    fn non_object_block_is_unknown_not_a_panic() {
        assert_eq!(
            ContentBlockKind::of(&json!("just a string, not a block")),
            ContentBlockKind::Unknown(String::new())
        );
        assert_eq!(
            ContentBlockKind::of(&json!(null)),
            ContentBlockKind::Unknown(String::new())
        );
    }
}
