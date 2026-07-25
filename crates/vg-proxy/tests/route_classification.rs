use hyper::Method;
use vg_proxy::route::{classify, RouteVerdict};

/// Table-driven per plan §10.2 (`tests/route_classification.rs`): every enumerated route masks
/// or passes correctly, path-only matching with the query string ignored (§5 step 2); everything
/// else blocks.
#[test]
fn enumerated_routes_classify_correctly() {
    let cases: &[(Method, &str, RouteVerdict)] = &[
        // --- Anthropic direct — context-carrying, MASK ---
        (Method::POST, "/v1/messages", RouteVerdict::Mask),
        // query string must be ignored — Claude Code posts `?beta=true`
        (Method::POST, "/v1/messages?beta=true", RouteVerdict::Mask),
        (
            Method::POST,
            "/v1/messages/count_tokens",
            RouteVerdict::Mask,
        ),
        // --- Bedrock InvokeModel — context-carrying, MASK ---
        (
            Method::POST,
            "/model/anthropic.claude-3-opus/invoke",
            RouteVerdict::Mask,
        ),
        (
            Method::POST,
            "/model/anthropic.claude-3-opus/invoke-with-response-stream",
            RouteVerdict::Mask,
        ),
        // opaque/encoded model IDs are still a single path segment
        (
            Method::POST,
            "/model/anthropic.claude-3-opus%3A0/invoke",
            RouteVerdict::Mask,
        ),
        // --- Recognized, non-context-carrying probes/metadata — PASS ---
        (Method::HEAD, "/", RouteVerdict::Pass),
        (Method::HEAD, "/api/hello", RouteVerdict::Pass),
        (
            Method::GET,
            "/inference-profiles?type=SYSTEM_DEFINED",
            RouteVerdict::Pass,
        ),
        (Method::GET, "/v1/models?limit=1000", RouteVerdict::Pass),
        (Method::GET, "/v1/models", RouteVerdict::Pass),
        // --- Everything else — fail closed ---
        // "The Batch API" — v3.1 correction: removed, never appears in Claude Code's own
        // gateway protocol docs.
        (Method::POST, "/v1/messages/batches", RouteVerdict::Block),
        // Bedrock Converse — Claude Code never calls it.
        (
            Method::POST,
            "/model/anthropic.claude-3-opus/converse",
            RouteVerdict::Block,
        ),
        // malformed Bedrock invoke shapes
        (Method::POST, "/model//invoke", RouteVerdict::Block),
        (
            Method::POST,
            "/model/anthropic.claude-3-opus/invoke/extra",
            RouteVerdict::Block,
        ),
        (
            Method::POST,
            "/model/anthropic.claude-3-opus",
            RouteVerdict::Block,
        ),
        // right path, wrong method
        (Method::GET, "/v1/messages", RouteVerdict::Block),
        (Method::POST, "/v1/models", RouteVerdict::Block),
        // unenumerated routes
        (Method::POST, "/", RouteVerdict::Block),
        (Method::GET, "/unknown", RouteVerdict::Block),
    ];

    for (method, target, expected) in cases {
        let actual = classify(method, target);
        assert_eq!(
            actual, *expected,
            "{method} {target} classified as {actual:?}, expected {expected:?}"
        );
    }
}
