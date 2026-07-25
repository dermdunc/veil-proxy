//! `vg-proxy`: the local masking-proxy front door — a long-lived daemon Claude Code is pointed
//! at via `ANTHROPIC_BASE_URL`/`ANTHROPIC_BEDROCK_BASE_URL`, intended to mask the whole
//! assembled request/response instead of a per-invocation hook.
//! See `docs/plans/veilgremlin-masking-proxy-plan-v1.md`.
//!
//! **Current scope: M1 only (plan §10.3, milestone 1) — transport + routing skeleton.** Plain
//! HTTP on loopback, the deny-by-default route classifier, and nothing else: no TLS, no
//! upstream client, no masking, no credentials. Zero egress risk by construction — later
//! milestones (M2 daemon core, M3 request masking, ...) build on this.

pub mod error;
pub mod route;
pub mod server;

pub use error::ProxyError;
pub use route::RouteVerdict;
