//! Demasks a model response body before it reaches the wrapped client (plan §10.2/§10.3
//! milestone M4) — the piece that closes the "mask outbound, demask inbound" loop `vg-proxy`
//! exists for. Response *masking* (`mask_request.rs`) is fail-closed by design: any ambiguity
//! blocks the whole request, because the risk is PII leaving the machine. Response *demasking*
//! is the opposite risk shape — the request has already been sent and answered, so refusing to
//! return a successful response over a demask ambiguity would be strictly worse than leaving a
//! placeholder unresolved. **This module is deliberately infallible**: a malformed/unexpected
//! response shape returns the body unchanged; a denied or unresolvable binding for one leaf
//! leaves that leaf's text unchanged and moves on — never blocks the response, never panics.
//!
//! **Session-store-backed, not pack-backed.** A response can echo a placeholder minted by an
//! *earlier* request in the same conversation (the H1 case), not only the request that produced
//! this particular response — so this module takes the caller's already-resolved
//! `&[PlaceholderBinding]` (the session's full accumulated store, via
//! `Daemon::demask_response`/`SessionShim::bindings_for`), not a single request's own bindings.
//!
//! **Reuses `vg_core::rehydrate` as a black box**, one call per leaf text field, mirroring
//! `mask_request.rs`'s "one `vg_core::mask()` call per leaf" shape: `rehydrate` only ever reads
//! `pack.text`/`pack.bindings` (confirmed by reading its implementation before writing this
//! module), so a synthetic, single-use [`MaskedPack`] built from `(leaf, bindings)` is a
//! faithful, zero-`vg_core`-changes way to reuse its substitution algorithm (longest-display-
//! first, token-boundary-respecting, never re-scans restored output) for this direction too.
//!
//! **Every content block is demasked payload-field-by-field, regardless of kind — no
//! classifier, but a structural-key skip-list.** An earlier version of this module reused
//! [`crate::schema::anthropic::ContentBlockKind`] and only special-cased `text`/`tool_use`
//! blocks, on the (wrong) assumption that a non-streaming response's `content[]` only ever
//! contains those two kinds. Round 1 of doubt-driven-development caught this: real responses
//! can also carry `thinking`/`redacted_thinking` (extended thinking) and server-side tool
//! blocks (`server_tool_use`, `web_search_tool_result`, `mcp_tool_use`, `mcp_tool_result`, ...)
//! — none of which `ContentBlockKind` names, so they classified as `Unknown` and were silently
//! left untouched. The first fix went too far the other way: it recursed into *every* field of
//! every block unconditionally, including structural metadata (`"type"`, `"id"`, `"name"`,
//! `"signature"`) — round 2 (Codex) caught that a minted placeholder's low-entropy, predictable
//! shape (`EMAIL_001`, `PERSON_002`, ...) can plausibly collide with a real tool name or block
//! id over a long session, silently corrupting it (a `tool_use` block literally named
//! `"EMAIL_001"` would have its `name` rewritten to a raw email, breaking the wrapped client's
//! ability to dispatch that tool call). [`BLOCK_METADATA_KEYS`] is the fix: still no per-kind
//! classifier (forward-compatible with any future block kind's own payload fields), but a
//! block's own known structural keys are never substituted, only recursed past.

use serde_json::Value;

use vg_core::{
    rehydrate, Actor, ActorId, Destination, MappingRef, MaskStats, MaskedPack, Namespace,
    PlaceholderBinding, Policy,
};

/// The fixed identity `vg-proxy` uses for its own response-demask calls — not a per-user
/// identity (there's no CLI `--actor` assertion in this path), matching the same "local trust
/// boundary, not per-actor authentication" model the H2 session token and the CLI's own
/// self-asserted `--actor`/`--role` (F4) already establish elsewhere in this codebase.
/// `demask_roles` is left unset in the policy fixture for `proxy-response`, so this identity's
/// `roles` never need to match anything.
fn proxy_actor() -> Actor {
    Actor {
        id: ActorId("vg-proxy".to_string()),
        roles: vec!["proxy".to_string()],
    }
}

/// Demasks every text-bearing field reachable from a response body's `content[]` array against
/// `bindings`. Always returns bytes — see this module's own doc for why it cannot fail.
pub(crate) fn demask_response(
    body: &[u8],
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    let Some(root) = value.as_object_mut() else {
        return body.to_vec();
    };
    let Some(content) = root.get_mut("content").and_then(Value::as_array_mut) else {
        return body.to_vec();
    };

    for block in content.iter_mut() {
        demask_content_block(block, bindings, policy, ns);
    }

    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

/// Structural/metadata field names on a content block that must never be substituted — round-2
/// doubt-pass finding (Codex): the first version of the "demask every block unconditionally"
/// fix (see the module doc above) recursed into these too, and a minted placeholder's low-
/// entropy, predictable shape (`EMAIL_001`, `PERSON_002`, ...) can plausibly collide with a
/// real tool name, block id, or thinking signature over a long session — not the
/// "astronomically unlikely" case the module doc originally, wrongly, argued. Concretely: a
/// `tool_use` block literally named `"EMAIL_001"` would have its `name` silently rewritten to
/// the raw email, breaking the wrapped client's ability to dispatch that tool call correctly.
/// These keys are skipped at the content-block's own top level only — a field with the same
/// name *inside* a tool's own `input` object (freeform, tool-defined) is not structural and is
/// still demasked normally.
const BLOCK_METADATA_KEYS: &[&str] = &["type", "id", "name", "signature", "tool_use_id"];

/// Demasks one content block: every field except [`BLOCK_METADATA_KEYS`] is recursively
/// demasked, regardless of the block's `"type"` — still classifier-free (forward-compatible
/// with any future block kind's own payload fields), just no longer blind to which top-level
/// keys are structural.
fn demask_content_block(
    block: &mut Value,
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) {
    let Value::Object(map) = block else {
        return;
    };
    for (key, v) in map.iter_mut() {
        if BLOCK_METADATA_KEYS.contains(&key.as_str()) {
            continue;
        }
        demask_value_strings_recursive(v, bindings, policy, ns);
    }
}

/// Demasks every string leaf inside `value`, recursively — the substitution-direction
/// counterpart of `mask_request.rs::mask_value_strings_recursive`. No fail-closed short-circuit
/// on a nested `image`/`document`-shaped object: there is nothing to block in this direction,
/// only text to leave alone if it isn't a plain string leaf. No structural-key skip here either
/// — this only ever runs on payload subtrees (`text`, `input`, ...) once
/// [`demask_content_block`] has already excluded the block's own metadata keys.
fn demask_value_strings_recursive(
    value: &mut Value,
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) {
    match value {
        Value::String(s) => demask_leaf_in_place(s, bindings, policy, ns),
        Value::Array(items) => {
            for item in items.iter_mut() {
                demask_value_strings_recursive(item, bindings, policy, ns);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                demask_value_strings_recursive(v, bindings, policy, ns);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

/// The one place this module calls `vg_core::rehydrate`. A denied or unresolvable demask leaves
/// `s` unchanged — the placeholder stays visible rather than the response failing.
fn demask_leaf_in_place(
    s: &mut String,
    bindings: &[PlaceholderBinding],
    policy: &Policy,
    ns: &Namespace,
) {
    if s.is_empty() || bindings.is_empty() {
        return;
    }
    let pack = MaskedPack {
        text: s.clone(),
        mapping_refs: bindings
            .iter()
            .map(|b| b.mapping_ref)
            .collect::<Vec<MappingRef>>(),
        bindings: bindings.to_vec(),
        stats: MaskStats::default(),
        policy_version: policy.engine.version().to_string(),
    };
    if let Ok(restored) = rehydrate(
        &pack,
        policy,
        ns,
        Destination::ProxyResponse,
        &proxy_actor(),
    ) {
        *s = restored;
    }
}

#[cfg(test)]
mod tests {
    //! Inline unit tests — same reasoning as `mask_request.rs`'s own test module: every item
    //! under test here is `pub(crate)`, unreachable from a separate integration-test crate.

    use std::path::{Path, PathBuf};

    use serde_json::{json, Value};
    use tempfile::TempDir;

    use vg_audit::JsonlAuditSink;
    use vg_core::{
        mask, ArtefactHint, Context, Detector, Input, Namespace, Parser, Policy, PolicyEngine,
        PolicyLayers, RepoId,
    };
    use vg_detectors::all_detectors;
    use vg_parsers::all_parsers;
    use vg_policy::LayeredPolicyEngine;
    use vg_vault::{Vault, VaultConfig};

    use super::demask_response;

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

    /// A policy fixture where `proxy-response` is explicitly demask-denied, to exercise the
    /// graceful-degrade path (a denied leaf keeps its placeholder, not an error).
    fn build_denying_policy(dir: &Path) -> Policy {
        let fixture_path = dir.join("denying.policy.json");
        let mut fixture: Value =
            serde_json::from_str(&std::fs::read_to_string(global_policy_path()).unwrap()).unwrap();
        fixture["destinations"]["proxy-response"]["demask_allowed"] = json!(false);
        std::fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        let engine = LayeredPolicyEngine::load(PolicyLayers {
            global: fixture_path,
            repo: None,
            session: None,
        })
        .expect("load denying policy fixture");
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
            "veilgremlin-vgproxy-demask-response-tests".to_string(),
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

    /// Masks `raw` through the real pipeline and returns its bindings — the same mechanism
    /// `mask_request.rs` uses in production, reused here to get real, vault-backed bindings to
    /// demask against, not hand-constructed fixtures.
    fn mask_and_get_bindings(
        raw: &str,
        ns: &Namespace,
        policy: &Policy,
    ) -> (String, Vec<vg_core::PlaceholderBinding>) {
        let input = Input {
            buf: raw.as_bytes().to_vec(),
            hint: ArtefactHint::default(),
        };
        let (pack, _refs, _event, _trace_id) =
            with_real_context(|ctx| mask(&input, ctx, policy, ns)).expect("mask succeeds");
        (pack.text, pack.bindings)
    }

    #[test]
    fn round_trip_restores_the_raw_value_in_a_text_block() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (masked_text, bindings) =
            mask_and_get_bindings("contact jane.doe@example.com", &namespace, &policy);
        assert!(masked_text.contains("EMAIL_001"));

        let response = json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": format!("Sure, I'll {masked_text}")}]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        let text = demasked["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("jane.doe@example.com"), "text: {text}");
        assert!(!text.contains("EMAIL_001"), "text: {text}");
    }

    #[test]
    fn bindings_from_two_separate_mask_calls_both_resolve_in_one_response() {
        // The H1 scenario at this layer: this function takes whatever bindings the caller
        // hands it (the session's full accumulated store in production, per `Daemon::demask_response`),
        // not bindings tied to a single originating mask() call — proven here by merging
        // bindings from two independent mask() calls and demasking a response that echoes both.
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (masked_a, bindings_a) =
            mask_and_get_bindings("first: jane.doe@example.com", &namespace, &policy);
        let (masked_b, bindings_b) =
            mask_and_get_bindings("second: ops@example.com", &namespace, &policy);
        let mut bindings = bindings_a;
        bindings.extend(bindings_b);

        let response = json!({
            "content": [{"type": "text", "text": format!("{masked_a} / {masked_b}")}]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        let text = demasked["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("jane.doe@example.com"), "text: {text}");
        assert!(text.contains("ops@example.com"), "text: {text}");
    }

    #[test]
    fn malformed_response_body_passes_through_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let body = b"not json at all";
        let demasked = demask_response(body, &[], &policy, &namespace);
        assert_eq!(demasked, body);
    }

    #[test]
    fn a_response_with_no_content_array_passes_through_unchanged() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let body = serde_json::to_vec(&json!({"id": "msg_1", "type": "message"})).unwrap();
        let demasked = demask_response(&body, &[], &policy, &namespace);
        assert_eq!(demasked, body);
    }

    #[test]
    fn recursively_demasks_a_tool_use_input_placeholder() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        let response = json!({
            "content": [{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "send_email",
                "input": {"to": masked_text, "nested": {"note": "fyi"}}
            }]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        let to = demasked["content"][0]["input"]["to"].as_str().unwrap();
        assert_eq!(to, "jane.doe@example.com");
        // Structure survives: the nested field untouched by any placeholder is still there.
        assert_eq!(
            demasked["content"][0]["input"]["nested"]["note"],
            json!("fyi")
        );
    }

    /// Round-2 doubt-pass regression (Codex-class finding, single-model round): an earlier
    /// version classified content blocks via `ContentBlockKind` and only special-cased `text`/
    /// `tool_use`, silently leaving any other real Anthropic block kind (`thinking`,
    /// `server_tool_use`, ...) untouched — a placeholder echoed inside one would never resolve.
    /// `thinking` is real, not hypothetical: extended-thinking responses carry it today.
    #[test]
    fn a_placeholder_echoed_inside_a_thinking_block_still_resolves() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        let response = json!({
            "content": [
                {"type": "thinking", "thinking": format!("I should contact {masked_text}"), "signature": "sig"},
                {"type": "text", "text": "Done."}
            ]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        let thinking = demasked["content"][0]["thinking"].as_str().unwrap();
        assert!(
            thinking.contains("jane.doe@example.com"),
            "thinking: {thinking}"
        );
        assert!(!thinking.contains("EMAIL_001"), "thinking: {thinking}");
        // The block's own structural fields survive untouched.
        assert_eq!(demasked["content"][0]["type"], json!("thinking"));
        assert_eq!(demasked["content"][0]["signature"], json!("sig"));
    }

    /// Round-2 doubt-pass regression (Codex): the fix for the *previous* finding (demask every
    /// content block, not just text/tool_use) initially recursed into every field
    /// unconditionally, including a block's own structural metadata. A minted placeholder's
    /// low-entropy, predictable shape can coincidentally equal a real tool name/id/signature —
    /// this proves that coincidence no longer corrupts the block: a `tool_use` block literally
    /// named `"EMAIL_001"` (matching a real binding's display) must keep that exact name, not
    /// have it rewritten to the raw email.
    #[test]
    fn a_structural_field_that_coincidentally_matches_a_placeholder_display_is_not_substituted() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let (_masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);
        // Sanity: the vault really did mint EMAIL_001 for this fixture, matching the collision
        // this test constructs deliberately, not by luck.
        assert_eq!(bindings[0].display, "EMAIL_001");

        let response = json!({
            "content": [{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "EMAIL_001",
                "input": {}
            }]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        assert_eq!(
            demasked["content"][0]["name"],
            json!("EMAIL_001"),
            "a structural field must never be substituted, even on a coincidental display match"
        );
    }

    #[test]
    fn unrelated_response_fields_round_trip_untouched() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let response = json!({
            "id": "msg_1",
            "model": "claude-x",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "content": [{"type": "text", "text": "hello"}]
        });
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &[], &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        assert_eq!(demasked["id"], json!("msg_1"));
        assert_eq!(demasked["model"], json!("claude-x"));
        assert_eq!(demasked["stop_reason"], json!("end_turn"));
        assert_eq!(demasked["usage"]["input_tokens"], json!(10));
    }

    #[test]
    fn a_denied_destination_leaves_the_placeholder_in_place_instead_of_erroring() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();
        let (masked_text, bindings) =
            mask_and_get_bindings("jane.doe@example.com", &namespace, &policy);

        // A *separate* policy (proxy-response demask-denied) applied at demask time — the
        // vault/namespace are unrelated to the denial, so this isolates the "denied" path.
        let denying_policy = build_denying_policy(dir.path());

        let response = json!({"content": [{"type": "text", "text": masked_text.clone()}]});
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &bindings, &denying_policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        let text = demasked["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            text, masked_text,
            "a denied demask must leave the placeholder in place"
        );
    }

    #[test]
    fn empty_bindings_leaves_a_placeholder_shaped_string_untouched() {
        let dir = TempDir::new().expect("temp dir");
        let policy = build_policy(dir.path());
        let namespace = ns();

        let response = json!({"content": [{"type": "text", "text": "EMAIL_001 is here"}]});
        let body = serde_json::to_vec(&response).unwrap();

        let demasked = demask_response(&body, &[], &policy, &namespace);
        let demasked: Value = serde_json::from_slice(&demasked).unwrap();
        assert_eq!(demasked["content"][0]["text"], json!("EMAIL_001 is here"));
    }
}
