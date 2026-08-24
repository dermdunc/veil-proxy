//! `vg-proxy`: the local masking-proxy front door — a long-lived daemon Claude Code is pointed
//! at via `ANTHROPIC_BASE_URL`/`ANTHROPIC_BEDROCK_BASE_URL`, intended to mask the whole
//! assembled request/response instead of a per-invocation hook.
//! See `docs/plans/veilgremlin-masking-proxy-plan-v1.md`.
//!
//! **Current scope: M1 + M2 (plan §10.3, milestones 1-2).** M1: plain HTTP on loopback, the
//! deny-by-default route classifier — no TLS, no upstream client, no masking, no credentials.
//! M2: the daemon core (`vg-vault` opened once) and the H2 session-namespace shim, tested in
//! isolation via direct calls — not yet wired into the HTTP server's request path, since
//! nothing schema-aware exists yet to route toward (M3+). Zero egress risk by construction
//! throughout: there is still no upstream client anywhere in this crate.

pub mod daemon;
pub mod error;
pub mod mask_request;
pub mod route;
mod schema;
pub mod server;
pub mod session;
pub mod upstream;

pub use daemon::Daemon;
pub use error::ProxyError;
pub use route::RouteVerdict;
pub use session::{SessionConflict, SessionError, SessionShim, NAMESPACE_HEADER};
