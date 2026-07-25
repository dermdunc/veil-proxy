use hyper::Method;

/// M1 scope note (plan §10.3, milestone 1): `Mask` and `Pass` are both "matched" outcomes at
/// this milestone — neither forwards anywhere real yet, since M1 has no upstream client at
/// all. The three-way split exists now because M3 (request masking) and later milestones need
/// it, not because M1's own HTTP behavior distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteVerdict {
    /// Recognized, context-carrying route — text fields must be masked before forwarding.
    Mask,
    /// Recognized, non-context-carrying route (probe / metadata) — safe to pass through
    /// unmasked.
    Pass,
    /// Not on the enumerated route table. Fail closed: never passed through.
    Block,
}

/// Deny-by-default route classifier (plan §5 step 2 / §10.2 `route.rs`).
///
/// Matches on PATH only, ignoring any query string — Claude Code posts inference requests as
/// `/v1/messages?beta=true`, so a literal full-target match would wrongly block every real
/// inference request. `request_target` may be a bare path or a path+query request-target; the
/// query portion, if present, is discarded before matching.
pub fn classify(method: &Method, request_target: &str) -> RouteVerdict {
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
