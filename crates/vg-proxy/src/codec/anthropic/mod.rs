//! The Anthropic Messages API codec (Track H, milestone H2b). Everything items 3-6 of
//! the plan's §1.2 table named as provider-shaped now lives here: the route table
//! (direct Anthropic + Bedrock InvokeModel), the request-mask walk
//! ([`mask_request`]), response/SSE demasking ([`demask_response`], [`stream_demask`]),
//! and the header-forwarding policy below (fork F4).
//!
//! **Fork F4 (header-forwarding policy), decided 2026-09-14** — adopting the plan's
//! own §7 recommendation rather than the prior fixed-enum default: a small named-
//! singleton list (headers this codec always forwards because a human explicitly
//! reviewed and approved each one), a prefix allowlist (`anthropic-*`,
//! `x-claude-code-*`), and a credential-shaped denylist that wins over any prefix
//! match — so a hypothetical future header like `anthropic-session-token` is never
//! auto-forwarded just because it starts with an approved prefix. No behavior change
//! from the prior fixed list: `content-type`, `x-api-key`, `authorization`,
//! `anthropic-version`, and `anthropic-beta` all still forward exactly as before —
//! this only makes the *policy* structural so H3's OpenAI codec can express its own
//! lists against the same shape once H1's real captured traffic names them.

pub(crate) mod demask_response;
pub(crate) mod mask_request;
pub(crate) mod stream_demask;

use hyper::header::HeaderName;
use hyper::{HeaderMap, Method};
use vg_core::{Context, Namespace, PlaceholderBinding, Policy};

use crate::route::RouteVerdict;

use super::{Codec, SelectedHeaders};
use mask_request::{MaskRequestError, MaskedRequest};

pub(crate) struct AnthropicCodec;

impl Codec for AnthropicCodec {
    fn classify_route(&self, method: &Method, request_target: &str) -> RouteVerdict {
        classify_route(method, request_target)
    }

    fn select_headers(&self, inbound: &HeaderMap) -> SelectedHeaders {
        select_headers(inbound)
    }

    fn mask_request(
        &self,
        body: &[u8],
        ctx: &Context,
        policy: &Policy,
        namespace: &Namespace,
    ) -> Result<MaskedRequest, MaskRequestError> {
        mask_request::mask_request(body, ctx, policy, namespace)
    }

    fn demask_response(
        &self,
        body: &[u8],
        bindings: &[PlaceholderBinding],
        policy: &Policy,
        namespace: &Namespace,
    ) -> Vec<u8> {
        demask_response::demask_response(body, bindings, policy, namespace)
    }

    fn demask_streaming_response(
        &self,
        body: &[u8],
        bindings: &[PlaceholderBinding],
        policy: &Policy,
        namespace: &Namespace,
    ) -> Vec<u8> {
        stream_demask::demask_sse_response(body, bindings, policy, namespace)
    }
}

// --- Route classification (moved from route.rs — H2b's own Anthropic/Bedrock match
// arms; `RouteVerdict` itself stays in `route.rs` as a shared, provider-agnostic type)
// ---

/// Deny-by-default route classifier for the Anthropic codec (plan §5 step 2 / §10.2
/// `route.rs`, moved here by H2b).
///
/// Matches on PATH only, ignoring any query string — Claude Code posts inference
/// requests as `/v1/messages?beta=true`, so a literal full-target match would wrongly
/// block every real inference request. `request_target` may be a bare path or a
/// path+query request-target; the query portion, if present, is discarded before
/// matching.
fn classify_route(method: &Method, request_target: &str) -> RouteVerdict {
    let path = match request_target.split_once('?') {
        Some((path, _)) => path,
        None => request_target,
    };

    match (method, path) {
        // Anthropic direct — context-carrying, MASK.
        (&Method::POST, "/v1/messages") => RouteVerdict::Mask,
        (&Method::POST, "/v1/messages/count_tokens") => RouteVerdict::Mask,
        // Recognized, non-context-carrying probes/metadata — PASS. Deliberately query-agnostic
        // (doubt-pass finding, independently raised by two reviewers): the plan's "match on
        // path only, ignoring query string" rule (§5 step 2) is stated once, governing the
        // whole classify step, not scoped to the Mask examples alone — and both these routes
        // are non-context-carrying by design (Claude Code's own probes, not user content), so
        // a query variant carries no additional masking risk. Not an oversight.
        (&Method::HEAD, "/") => RouteVerdict::Pass,
        (&Method::HEAD, "/api/hello") => RouteVerdict::Pass,
        (&Method::GET, "/inference-profiles") => RouteVerdict::Pass,
        (&Method::GET, "/v1/models") => RouteVerdict::Pass,
        // Bedrock InvokeModel — context-carrying, MASK. Not a literal-string match: `{model}`
        // is an opaque, non-empty path segment (a model ID), so it isn't enumerable up front.
        (&Method::POST, p) if is_bedrock_invoke(p) => RouteVerdict::Mask,
        // Everything else, including "The Batch API" (v3.1: removed from the route table —
        // it never appears in Claude Code's own gateway protocol docs) and Bedrock Converse
        // (Claude Code never calls it): fail closed.
        _ => RouteVerdict::Block,
    }
}

/// `/model/{model}/invoke` and `/model/{model}/invoke-with-response-stream` — the Bedrock
/// InvokeModel routes (streaming and non-streaming). `{model}` must be a single non-empty path
/// segment; anything else (an empty segment, extra trailing segments, `/converse`) is not a
/// match and falls through to `Block`.
///
/// **Invariant (doubt-pass finding): matching happens on the raw, undecoded path bytes.**
/// `{model}` is accepted as an opaque segment exactly as the plan describes it — no
/// percent-decoding or normalization happens here, so `%2F`/`%2e%2e`/etc. inside a model ID are
/// just bytes that happen to not equal the literal `/` this function splits on, not a decoded
/// path-traversal shape. This is the safe order (match-then-never-decode, not decode-then-match)
/// and must stay that way: any future milestone that decodes the model ID must do so strictly
/// *after* this match, never before it, or the classifier and whatever decodes downstream could
/// disagree about where the segment boundary is.
fn is_bedrock_invoke(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/model/") else {
        return false;
    };
    match rest.rsplit_once('/') {
        Some((model_id, "invoke")) => !model_id.is_empty() && !model_id.contains('/'),
        Some((model_id, "invoke-with-response-stream")) => {
            !model_id.is_empty() && !model_id.contains('/')
        }
        _ => false,
    }
}

// --- Header-forwarding policy (fork F4) ---

/// Headers this codec always forwards verbatim — a small, explicitly reviewed set
/// (unchanged from the pre-H2b fixed list), never subject to prefix or denylist logic.
/// `content-length`/`host` are deliberately excluded: `upstream.rs` recomputes both
/// fresh for the new body/upstream on every request, so a stale copied value could
/// never silently disagree with the real one sent.
///
/// `anthropic-version` and `anthropic-beta` are named here, not left to match
/// [`ALLOWED_PREFIXES`], even though both happen to start with `anthropic-`: they were
/// part of the original pre-H2b `FORWARDED_HEADERS` five-entry list (already reviewed,
/// sent on essentially every real Claude Code request), so treating them as "unnamed
/// prefix matches" would flag them as review candidates on every single request —
/// exactly the log-spam the named/unnamed split exists to avoid — instead of reserving
/// [`SelectedHeaders::unnamed_prefix_matches`] for genuinely new, previously-unreviewed
/// `anthropic-*`/`x-claude-code-*` headers.
const NAMED_SINGLETONS: &[&str] = &[
    "content-type",
    "x-api-key",
    "authorization",
    "anthropic-version",
    "anthropic-beta",
];

/// Header-name prefixes this codec forwards, EXCEPT any name also matching
/// [`CREDENTIAL_DENYLIST_SUBSTRINGS`] (denylist wins — see [`select_headers`]).
const ALLOWED_PREFIXES: &[&str] = &["anthropic-", "x-claude-code-"];

/// Substrings that mark a header name as credential-shaped, checked against the
/// lowercased name. Wins over [`ALLOWED_PREFIXES`]: a prefix match alone is not
/// sufficient authorization to forward something that looks like it carries a secret
/// — only [`NAMED_SINGLETONS`] (`authorization`, `x-api-key`) are deliberately
/// approved credential headers, and both are matched before this denylist ever runs.
///
/// `key` and `auth` are included precisely *because* `x-api-key`/`authorization` are
/// the two credential-shaped named singletons: their own names prove this codec
/// already treats "key" and "auth" as credential-shaped categories, so a hypothetical
/// future prefix-matching header like `anthropic-encryption-key` or
/// `anthropic-service-auth` must be caught by the same reasoning, not silently
/// auto-forwarded just because the denylist never generalized the pattern its own
/// named singletons demonstrate. `NAMED_SINGLETONS` is checked (and short-circuits)
/// before this denylist ever runs, so `x-api-key`/`authorization` themselves are
/// unaffected by adding their own shape to the denylist.
const CREDENTIAL_DENYLIST_SUBSTRINGS: &[&str] = &[
    "token", "secret", "cookie", "session", "password", "key", "auth",
];

fn is_credential_shaped(name: &str) -> bool {
    CREDENTIAL_DENYLIST_SUBSTRINGS
        .iter()
        .any(|pattern| name.contains(pattern))
}

/// Applies fork F4's policy: named singletons first (always forwarded if present),
/// then every other inbound header whose name matches an allowed prefix and is NOT
/// credential-shaped.
fn select_headers(inbound: &HeaderMap) -> SelectedHeaders {
    let mut forward = Vec::new();
    let mut unnamed_prefix_matches = Vec::new();
    let mut denied_by_credential_pattern = Vec::new();

    for name in NAMED_SINGLETONS {
        if let Some(value) = inbound.get(*name) {
            forward.push((HeaderName::from_static(name), value.clone()));
        }
    }

    for (name, value) in inbound.iter() {
        let name_str = name.as_str();
        if NAMED_SINGLETONS.contains(&name_str) {
            continue; // already handled above
        }
        if !ALLOWED_PREFIXES
            .iter()
            .any(|prefix| name_str.starts_with(prefix))
        {
            continue; // not a candidate at all -- no prefix match, nothing to record
        }
        // Codex cross-model critique (H2b): the denylist's substring match is
        // deliberately broad (a false positive silently drops a benign header rather
        // than risk forwarding a credential -- the safe direction of error for a
        // masking proxy), but a silent drop with zero signal defeats F4's own
        // "per-release review of what actually appeared" goal. Named here, not
        // forwarded, distinct from `unnamed_prefix_matches` (which DID forward).
        if is_credential_shaped(name_str) {
            denied_by_credential_pattern.push(name.clone());
            continue; // denylist wins over any prefix match
        }
        forward.push((name.clone(), value.clone()));
        unnamed_prefix_matches.push(name.clone());
    }

    SelectedHeaders {
        forward,
        unnamed_prefix_matches,
        denied_by_credential_pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn named_singletons_forward_unconditionally() {
        let inbound = header_map(&[
            ("content-type", "application/json"),
            ("x-api-key", "sk-test"),
            ("authorization", "Bearer test"),
            ("anthropic-version", "2026-01-01"),
            ("anthropic-beta", "some-beta-flag"),
        ]);
        let selected = select_headers(&inbound);
        // Codex cross-model critique (H2b): assert identity/value, not just count —
        // a wrong name or value with the right length would previously have passed.
        let mut forwarded: Vec<(String, String)> = selected
            .forward
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        forwarded.sort();
        let mut expected = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-api-key".to_string(), "sk-test".to_string()),
            ("authorization".to_string(), "Bearer test".to_string()),
            ("anthropic-version".to_string(), "2026-01-01".to_string()),
            ("anthropic-beta".to_string(), "some-beta-flag".to_string()),
        ];
        expected.sort();
        assert_eq!(forwarded, expected);
        // All five are reviewed named singletons (including the two that happen to
        // start with the `anthropic-` prefix) — none should be flagged as an "unnamed"
        // review candidate. This is the regression guard for a real H2b bug: before
        // this fix, `anthropic-version`/`anthropic-beta` fell through to the prefix
        // loop and were flagged as unnamed prefix matches on *every* real request
        // (both headers are sent on essentially every Claude Code call), which meant
        // `Daemon::select_headers`'s F4 review-candidate log fired on every single
        // request instead of only for genuinely new, previously-unreviewed headers.
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn unreviewed_anthropic_prefixed_headers_forward_and_are_named_as_review_candidates() {
        // A hypothetical future Anthropic-side header that is not yet on the reviewed
        // named-singleton list — this is what `unnamed_prefix_matches` exists to catch,
        // as distinct from the already-reviewed `anthropic-version`/`anthropic-beta`
        // (see `named_singletons_forward_unconditionally`).
        let inbound = header_map(&[("anthropic-organization-id", "org-123")]);
        let selected = select_headers(&inbound);
        assert_eq!(selected.forward.len(), 1);
        // Codex cross-model critique (H2b): assert the actual identity/value, not
        // just a matching count.
        assert_eq!(selected.forward[0].0.as_str(), "anthropic-organization-id");
        assert_eq!(selected.forward[0].1.to_str().unwrap(), "org-123");
        assert_eq!(
            selected.unnamed_prefix_matches[0].as_str(),
            "anthropic-organization-id"
        );
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn x_claude_code_prefixed_headers_forward() {
        let inbound = header_map(&[("x-claude-code-attribution", "some-value")]);
        let selected = select_headers(&inbound);
        assert_eq!(selected.forward.len(), 1);
        assert_eq!(selected.unnamed_prefix_matches.len(), 1);
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn credential_shaped_prefix_match_is_denied_despite_matching_prefix() {
        // A hypothetical future header that matches the anthropic- prefix but looks
        // credential-shaped — the whole point of F4's denylist-wins-over-prefix rule.
        let inbound = header_map(&[("anthropic-session-token", "should-never-forward")]);
        let selected = select_headers(&inbound);
        assert!(selected.forward.is_empty());
        assert!(selected.unnamed_prefix_matches.is_empty());
        // Denied, but NAMED so a per-release review can still see it happened
        // (Codex cross-model critique, H2b) — a silent drop with zero signal would
        // defeat F4's own "per-release review of what actually appeared" goal.
        assert_eq!(
            selected.denied_by_credential_pattern[0].as_str(),
            "anthropic-session-token"
        );
    }

    #[test]
    fn key_and_auth_shaped_prefix_matches_are_denied_despite_matching_prefix() {
        // Regression guard: the denylist substrings originally omitted "key"/"auth"
        // even though the two credential-shaped NAMED_SINGLETONS (`x-api-key`,
        // `authorization`) are exactly that shape — so a hypothetical future
        // `anthropic-*`/`x-claude-code-*` header carrying a secondary key or auth
        // token would have been silently auto-forwarded via the prefix allowlist.
        let inbound = header_map(&[
            ("anthropic-encryption-key", "should-never-forward"),
            ("anthropic-service-auth", "should-never-forward"),
            ("x-claude-code-auth-token", "should-never-forward"),
        ]);
        let selected = select_headers(&inbound);
        assert!(selected.forward.is_empty());
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert_eq!(selected.denied_by_credential_pattern.len(), 3);
    }

    #[test]
    fn named_singletons_are_unaffected_by_their_own_shape_being_in_the_denylist() {
        // `x-api-key` and `authorization` are both credential-shaped (they match
        // "key"/"auth" in CREDENTIAL_DENYLIST_SUBSTRINGS) but must still forward,
        // exactly once each, because NAMED_SINGLETONS is checked — and short-circuits
        // via the `continue` in the prefix loop — before the denylist ever runs.
        let inbound = header_map(&[("x-api-key", "sk-test"), ("authorization", "Bearer test")]);
        let selected = select_headers(&inbound);
        assert_eq!(selected.forward.len(), 2);
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn credential_shaped_headers_without_an_allowed_prefix_are_ignored_not_denied() {
        // A denylist-matching header name that ISN'T even a prefix candidate (e.g. a
        // generic `cookie` header) should be silently dropped like any other
        // unrelated header — not double-counted into `denied_by_credential_pattern`,
        // which is scoped to headers that matched an allowed prefix specifically.
        let inbound = header_map(&[("cookie", "session=abc"), ("x-auth-generic", "token")]);
        let selected = select_headers(&inbound);
        assert!(selected.forward.is_empty());
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn unrelated_headers_never_forward() {
        let inbound = header_map(&[
            ("host", "evil.example"),
            ("content-length", "9999"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        let selected = select_headers(&inbound);
        assert!(selected.forward.is_empty());
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn existing_five_header_default_is_unregressed() {
        // The exact pre-H2b FORWARDED_HEADERS list — proving no behavior change for
        // the traffic this proxy already handles.
        let inbound = header_map(&[
            ("content-type", "application/json"),
            ("x-api-key", "sk-test"),
            ("authorization", "Bearer test"),
            ("anthropic-version", "2026-01-01"),
            ("anthropic-beta", "some-beta-flag"),
        ]);
        let selected = select_headers(&inbound);
        assert_eq!(selected.forward.len(), 5);
        // None of the pre-H2b default traffic should be flagged as an unnamed review
        // candidate — it is all on the reviewed named-singleton list.
        assert!(selected.unnamed_prefix_matches.is_empty());
        assert!(selected.denied_by_credential_pattern.is_empty());
    }

    #[test]
    fn classify_route_matches_pre_h2b_behavior_for_anthropic_direct() {
        assert_eq!(
            classify_route(&Method::POST, "/v1/messages"),
            RouteVerdict::Mask
        );
        assert_eq!(
            classify_route(&Method::POST, "/v1/messages?beta=true"),
            RouteVerdict::Mask
        );
    }

    #[test]
    fn classify_route_matches_pre_h2b_behavior_for_bedrock_invoke() {
        assert_eq!(
            classify_route(&Method::POST, "/model/claude-3/invoke"),
            RouteVerdict::Mask
        );
        assert_eq!(
            classify_route(&Method::POST, "/model/claude-3/invoke-with-response-stream"),
            RouteVerdict::Mask
        );
    }

    #[test]
    fn classify_route_blocks_unrecognized_paths() {
        assert_eq!(
            classify_route(&Method::POST, "/v1/completions"),
            RouteVerdict::Block
        );
    }
}
