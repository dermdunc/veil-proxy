//! Per-provider protocol codec seam (Track H, milestone H2b —
//! `docs/architecture/multi-harness-proxy-plan.md` §2/§4). A [`Codec`] owns everything
//! that is shaped by a specific model-API provider: route classification, the
//! request-mask walk, response/SSE demasking, and header-forwarding policy (fork F4).
//! Everything below this seam — the mask/vault/policy/demask engine in `vg-core` and
//! `Daemon`, and the verified-TLS upstream client in `upstream.rs` — is reused
//! unchanged by every codec (plan §1.1: "nothing in `vg-core`'s `mask()`/vault/policy
//! path knows what transport or provider called it").
//!
//! **D-H-1 (plan §2):** "the codec sees a request body + headers for provider P, never
//! a CONNECT target; the transport sees an origin and bytes, never a `messages`
//! array." This module is the codec half of that boundary — `upstream.rs`/`server.rs`/
//! `route.rs` (transport/routing) hold no provider-shaped types or logic after this
//! milestone; see each module's own doc for what moved out.
//!
//! Today there is exactly one codec ([`anthropic::AnthropicCodec`]) — H3 adds a second
//! (OpenAI Responses) once H1's spike has picked a Codex interception mechanism. This
//! trait's shape is therefore proven against one real implementation, not yet against
//! two: [`MaskedRequest`]/[`MaskRequestError`] (defined under
//! [`anthropic::mask_request`]) are reused here as-is rather than pre-generalized for a
//! codec that doesn't exist yet. Whether H3's OpenAI codec shares these types or gets
//! its own is a real, undecided question for that milestone, not resolved here.

pub mod anthropic;

use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};

use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, Method};
use vg_core::{Context, Namespace, PlaceholderBinding, Policy};

use crate::route::RouteVerdict;

// `MaskRequestError` must stay `pub` (not `pub(crate)`): `ProxyError::MaskRequest`
// (a `pub` enum variant, `error.rs`) carries it, and Rust forbids a private type in a
// public interface. `MaskedRequest` has no such external reachability requirement —
// it's destructured only inside `Daemon::mask_request` (same crate) — so it stays
// `pub(crate)`, matching its pre-H2b visibility exactly.
pub use anthropic::mask_request::MaskRequestError;
pub(crate) use anthropic::mask_request::MaskedRequest;

/// One extended-thinking block exactly as the upstream issued it in a response (veil-proxy#86
/// finding 1). Recorded per session so a later request replaying it can be forwarded verbatim:
/// the upstream wrote those bytes, so sending them back discloses nothing new, and keeping them
/// byte-identical keeps their signature valid even when the model's own thinking holds text a
/// detector would flag (which re-masking would change).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IssuedBlock {
    Thinking { signature: String, thinking: String },
    Redacted { data: String },
}

/// A session's record of every [`IssuedBlock`] seen so far, as keyed 64-bit fingerprints (the
/// block text itself is never retained). `RandomState` is seeded per process, so a client can't
/// precompute a collision to get an unissued block forwarded unmasked.
#[derive(Debug, Clone, Default)]
pub(crate) struct IssuedThinking {
    hasher: RandomState,
    seen: HashSet<u64>,
}

impl IssuedThinking {
    fn fingerprint(&self, block: IssuedBlockRef<'_>) -> u64 {
        match block {
            IssuedBlockRef::Thinking {
                signature,
                thinking,
            } => self.hasher.hash_one(("thinking", signature, thinking)),
            IssuedBlockRef::Redacted { data } => self.hasher.hash_one(("redacted", data)),
        }
    }

    pub(crate) fn insert(&mut self, block: &IssuedBlock) {
        let fingerprint = self.fingerprint(block.as_ref());
        self.seen.insert(fingerprint);
    }

    pub(crate) fn contains(&self, block: IssuedBlockRef<'_>) -> bool {
        self.seen.contains(&self.fingerprint(block))
    }
}

/// Borrowed form of [`IssuedBlock`], for lookups straight from a request body.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IssuedBlockRef<'a> {
    Thinking {
        signature: &'a str,
        thinking: &'a str,
    },
    Redacted {
        data: &'a str,
    },
}

impl IssuedBlock {
    fn as_ref(&self) -> IssuedBlockRef<'_> {
        match self {
            Self::Thinking {
                signature,
                thinking,
            } => IssuedBlockRef::Thinking {
                signature,
                thinking,
            },
            Self::Redacted { data } => IssuedBlockRef::Redacted { data },
        }
    }
}

/// A demasked response body plus every thinking block the upstream issued in it.
pub(crate) struct DemaskedResponse {
    pub(crate) body: Vec<u8>,
    pub(crate) issued: Vec<IssuedBlock>,
}

/// The result of applying a codec's header-forwarding policy (Track H fork F4,
/// decided 2026-09-14: prefix allowlist + named singletons + a credential-shaped
/// denylist that wins over any prefix match) to one inbound request's headers.
pub(crate) struct SelectedHeaders {
    /// Headers to copy verbatim to the upstream request, in the order they were
    /// selected (named singletons first, then prefix matches).
    pub forward: Vec<(HeaderName, HeaderValue)>,
    /// Header names that matched an allowed prefix without being on the reviewed
    /// named-singleton list — named, not merely counted, so a per-release review has
    /// something concrete to look at (plan §7 F4: "counted (never logged by value)").
    /// Values are never included here, and callers must never log them either.
    pub unnamed_prefix_matches: Vec<HeaderName>,
    /// Header names that matched an allowed prefix but were DENIED anyway because
    /// they also matched the credential-shaped denylist — never forwarded, but named
    /// here (Codex cross-model critique, H2b) so a genuine false positive (the
    /// denylist's substring match is deliberately broad, e.g. `anthropic-keyword`
    /// would be denied) is visible to a per-release review instead of silently
    /// vanishing with no signal at all. Values are never included here either.
    pub denied_by_credential_pattern: Vec<HeaderName>,
}

/// Everything shaped by a specific model-API provider. A harness binds one codec
/// (D-H-1); `Daemon` holds a `Box<dyn Codec>` and dispatches every provider-shaped
/// decision through it instead of hardcoding one provider's shape into the transport
/// layer.
pub(crate) trait Codec: Send + Sync {
    /// Classifies one inbound request into mask/pass/block — the match arms that used
    /// to live directly in `route.rs` before this milestone.
    fn classify_route(&self, method: &Method, request_target: &str) -> RouteVerdict;

    /// Selects which inbound headers this codec forwards to its upstream, per its own
    /// header-forwarding policy (fork F4).
    fn select_headers(&self, inbound: &HeaderMap) -> SelectedHeaders;

    /// Masks a request body through the shared `vg_core::mask` pipeline, using this
    /// codec's own request-tree walk shape. `issued` is the session's record of thinking
    /// blocks the upstream issued, which may be forwarded verbatim.
    fn mask_request(
        &self,
        body: &[u8],
        ctx: &Context,
        policy: &Policy,
        namespace: &Namespace,
        issued: &IssuedThinking,
    ) -> Result<MaskedRequest, MaskRequestError>;

    /// Demasks a complete, non-streaming response body. Infallible by design — see
    /// [`anthropic::demask_response`]'s own doc for why.
    fn demask_response(
        &self,
        body: &[u8],
        bindings: &[PlaceholderBinding],
        policy: &Policy,
        namespace: &Namespace,
    ) -> DemaskedResponse;

    /// Demasks a complete, fully-buffered SSE response body (A2's buffer-first
    /// design). See [`anthropic::stream_demask`]'s own doc for its scope.
    fn demask_streaming_response(
        &self,
        body: &[u8],
        bindings: &[PlaceholderBinding],
        policy: &Policy,
        namespace: &Namespace,
    ) -> DemaskedResponse;
}
