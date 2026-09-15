//! Deny-by-default route classifier's crate-level entry point.
//!
//! **Track H, H2b:** the Anthropic/Bedrock match arms that used to live directly in
//! this file now live in [`crate::codec::anthropic`], the codec that owns that shape —
//! this file keeps only a thin, codec-agnostic dispatch so external callers
//! (`tests/route_classification.rs`) keep a stable path. [`RouteVerdict`] itself is
//! genuinely provider-agnostic (every codec classifies into the same three-way
//! mask/pass/block outcome), so it stays defined here rather than moving into the
//! codec module.

use hyper::Method;

use crate::codec::anthropic::AnthropicCodec;
use crate::codec::Codec;

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
/// Delegates to the currently-active codec. Today that's always [`AnthropicCodec`] —
/// H2a (canonical `Origin` + per-origin routing, plan §4) will pick the right codec
/// per request once a second one exists; until then, a fixed codec here is not a
/// shortcut, it's an accurate description of what this build actually supports.
pub fn classify(method: &Method, request_target: &str) -> RouteVerdict {
    AnthropicCodec.classify_route(method, request_target)
}
