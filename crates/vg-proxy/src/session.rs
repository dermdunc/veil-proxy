use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};

use thiserror::Error;
use uuid::Uuid;
use vg_core::{Namespace, PlaceholderBinding, SessionId};

/// The header `vg run` injects to carry a session's namespace token (plan §5 H2). Header-name
/// lookups against `hyper::HeaderMap` are already case-insensitive, so the exact casing here
/// only matters for what gets written on the injection side.
pub const NAMESPACE_HEADER: &str = "x-vg-namespace";

/// Doubt-pass finding: an unbounded, unvalidated header value in an error `Display` is an
/// echo-reflection habit worth capping on principle (same reasoning as M1's
/// `MAX_ECHOED_TARGET_LEN`), even though the token itself isn't secret (a UUID, "a tenancy
/// selector, not an authenticator" per plan §5 H2).
const MAX_ECHOED_HEADER_LEN: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("X-VG-Namespace header value {0:?} is not a valid session token (expected a UUID)")]
    InvalidNamespaceHeader(String),
    #[error("no X-VG-Namespace header and {0} has no registered session — fail closed")]
    UnregisteredAddr(SocketAddr),
    #[error(
        "refusing to register non-loopback address {0} for the H2 port-fallback path — \
         the daemon binds localhost-only (plan §5 H2)"
    )]
    NotLoopback(SocketAddr),
}

/// H2 shim (plan §5 H2 / §10.2 `session.rs`): resolves each request's [`Namespace`] from
/// either the `X-VG-Namespace` header (the primary path) or a registered per-session loopback
/// address (the fallback for callers that can't thread a custom header through), and holds the
/// session-scoped accumulated binding store (H1's fix, §8.5) — per-`Namespace`
/// [`PlaceholderBinding`]s that response demask will resolve against once a later milestone
/// wires up real content. M2 builds the data structures and resolution logic only; nothing
/// populates real bindings yet.
///
/// **Port-fallback is registration, not derivation (M2 design note, not spelled out verbatim
/// in the plan).** Resolving an address to a `Namespace` requires *someone* to have registered
/// that mapping first — deriving a `Namespace` deterministically from the address alone would
/// be actively wrong, not just simplified: once the OS reassigns a port to an unrelated later
/// session, a stateless derivation would silently resolve it to the same `Namespace` as
/// whatever session used that port before, breaking the isolation the whole shim exists to
/// provide. [`SessionShim::register_port`] is that registration step.
///
/// **Doubt-pass finding, not fully closeable at this milestone: a port-reuse handoff race.**
/// Nothing in this crate synchronously ties "session B starts listening on port P" to
/// "`register_port(P, B)` has been called" — the real caller that would provide that atomicity
/// doesn't exist yet (no milestone wires up per-session listeners). Until it does, a request
/// arriving on a reused port in the gap between the OS freeing it and the new session's
/// `register_port` call would resolve to the *previous* session's `Namespace`, silently. Three
/// primitives are provided so that real caller can close the gap when it's built —
/// [`SessionShim::unregister_port`] (compare-and-remove: only releases a mapping if the caller
/// names the `Namespace` it expects to be there, round-2 doubt-pass fix — a plain
/// remove-by-address let a stale session's delayed cleanup delete a *different*, newer
/// session's live mapping), [`SessionShim::register_port_if_absent`] for a caller that wants to
/// fail rather than silently clobber an existing registration, and
/// [`SessionShim::register_port`]'s `Option<Namespace>` return for a caller that wants to
/// overwrite but observe what it replaced — but the atomicity itself is deferred to that
/// milestone, not solved here.
///
/// **Doubt-pass finding, explicitly an open plan-level question, not resolved here: binding
/// store lifetime/eviction.** `docs/next-actions.md`'s own open-questions list already carries
/// this forward unresolved from v2 ("session-store lifetime/eviction... still undecided") —
/// this shim intentionally does not invent an eviction policy, since a namespace token being
/// reused (deliberately or via a bug) would otherwise transparently hand back a prior session's
/// accumulated bindings once demask is wired to this store (M4+). Left as the plan's own open
/// question, not silently assumed away.
///
/// **Round-2 doubt-pass (cross-model) findings, deliberately NOT changed — already the plan's
/// own locked design, not a gap in this shim:**
/// - **The header always wins over a registered address, with no daemon-side validation that
///   the token corresponds to a session the daemon actually knows about.** Plan §5 H2 states
///   the token explicitly: "a tenancy selector, not an authenticator." Any local process can
///   already reach this loopback-only daemon and claim any namespace via the header — that is
///   the accepted trust boundary (the local-machine boundary, not per-process authentication),
///   and the plan assigns spoofing/collision mitigation to the *injection* side
///   (`vg-adapters-claude`'s `wrapper.rs`, §5 H2 point 3: "`vg run`'s injection must detect this
///   and fail loudly"), not to this shim's resolution side. Building a live-session registry
///   here would be a materially bigger feature than M2 scopes, and would contradict the
///   documented trust model, not fix a bug in it.
/// - **Integration-time trap for whichever milestone wires a real `hyper::HeaderMap` into
///   `resolve`'s `namespace_header: Option<&str>` parameter:** `HeaderValue::to_str()` returns
///   `Result`, and a naive `.ok()` mapping a malformed (non-UTF-8) header value to `None` would
///   silently fall back to the port-fallback path instead of failing closed on a garbled
///   header. Nothing to fix here yet — no header-extraction code exists in this crate — but
///   whichever milestone adds it must map a present-but-invalid header to
///   `SessionError::InvalidNamespaceHeader`, never to `None`.
pub struct SessionShim {
    addr_registrations: Mutex<HashMap<SocketAddr, Namespace>>,
    binding_store: Mutex<HashMap<Namespace, Vec<PlaceholderBinding>>>,
}

impl SessionShim {
    pub fn new() -> Self {
        Self {
            addr_registrations: Mutex::new(HashMap::new()),
            binding_store: Mutex::new(HashMap::new()),
        }
    }

    /// Registers `addr` (the full socket address, not just the port — doubt-pass finding: a
    /// port-only key would collide across a dual-stack daemon binding both `127.0.0.1` and
    /// `::1` on the same numeric port) as belonging to `namespace` for the loopback-address
    /// fallback path. Refuses non-loopback addresses (round-2 doubt-pass finding — the same
    /// class of gap M1 already closed for the listener bind itself, recurring here at the
    /// session-registration boundary). Returns the previously-registered `Namespace` for
    /// `addr`, if any, so a future caller with session-liveness information can distinguish an
    /// expected same-session re-registration from a suspicious cross-namespace overwrite.
    pub fn register_port(
        &self,
        addr: SocketAddr,
        namespace: Namespace,
    ) -> Result<Option<Namespace>, SessionError> {
        if !addr.ip().is_loopback() {
            return Err(SessionError::NotLoopback(addr));
        }
        Ok(lock(&self.addr_registrations).insert(addr, namespace))
    }

    /// Like [`SessionShim::register_port`], but fails instead of overwriting if `addr` is
    /// already registered to a different namespace (round-2 doubt-pass finding) — for a caller
    /// that wants "clobbering an existing mapping is always suspicious," not "clobbering is
    /// fine, just tell me what I overwrote." Re-registering the *same* namespace for `addr`
    /// (idempotent renewal) still succeeds.
    pub fn register_port_if_absent(
        &self,
        addr: SocketAddr,
        namespace: Namespace,
    ) -> Result<(), SessionConflict> {
        if !addr.ip().is_loopback() {
            return Err(SessionConflict::NotLoopback(addr));
        }
        let mut registrations = lock(&self.addr_registrations);
        match registrations.get(&addr) {
            Some(existing) if *existing != namespace => {
                Err(SessionConflict::AlreadyRegistered(existing.clone()))
            }
            _ => {
                registrations.insert(addr, namespace);
                Ok(())
            }
        }
    }

    /// Releases `addr`'s registration — but only if it currently maps to `expected`
    /// (compare-and-remove, round-2 doubt-pass fix). A plain remove-by-address let session A's
    /// delayed/stale cleanup delete session B's live mapping after B had already taken over
    /// `addr`; requiring the caller to name the `Namespace` it believes it owns makes that
    /// cross-session deletion impossible — a cleanup call that no longer matches what's
    /// registered is a no-op, not a deletion. Returns whether a removal actually happened.
    pub fn unregister_port(&self, addr: SocketAddr, expected: &Namespace) -> bool {
        let mut registrations = lock(&self.addr_registrations);
        if registrations.get(&addr) == Some(expected) {
            registrations.remove(&addr);
            true
        } else {
            false
        }
    }

    /// Resolves a request's [`Namespace`]: the header wins if present, and must parse as a
    /// valid session token; otherwise falls back to whatever `Namespace` was registered for
    /// `local_addr`. Fails closed — never guesses — if the header is present but invalid, or
    /// if there's no header and the address was never registered.
    pub fn resolve(
        &self,
        namespace_header: Option<&str>,
        local_addr: SocketAddr,
    ) -> Result<Namespace, SessionError> {
        if let Some(token) = namespace_header {
            return parse_namespace_header(token);
        }
        lock(&self.addr_registrations)
            .get(&local_addr)
            .cloned()
            .ok_or(SessionError::UnregisteredAddr(local_addr))
    }

    /// Merges `bindings` into `namespace`'s accumulated store (H1's fix). Not yet called by
    /// any real request path in M2 — that starts once request masking exists — but the data
    /// structure and its per-namespace isolation are testable now.
    ///
    /// **Round-2 doubt-pass fix: materializes `bindings` before acquiring the lock.** The
    /// `lock()` helper's own doc comment claims every critical section here is a single,
    /// panic-free `HashMap` op — that was false for this method specifically, since the old
    /// code ran `.extend(bindings)` on a caller-supplied iterator *inside* the lock. A caller's
    /// iterator that panics partway through (not implausible — an iterator that maps over
    /// something fallible, say) would have left a torn, partially-applied batch under a
    /// poisoned-then-silently-recovered lock. Collecting first means the only thing that
    /// happens under the lock is an infallible `Vec::extend` from an already-complete `Vec`.
    pub fn record_bindings(
        &self,
        namespace: &Namespace,
        bindings: impl IntoIterator<Item = PlaceholderBinding>,
    ) {
        let bindings: Vec<PlaceholderBinding> = bindings.into_iter().collect();
        lock(&self.binding_store)
            .entry(namespace.clone())
            .or_default()
            .extend(bindings);
    }

    /// Returns `namespace`'s accumulated bindings so far — empty if nothing has been recorded
    /// for it, which is the expected state for every namespace in M2.
    pub fn bindings_for(&self, namespace: &Namespace) -> Vec<PlaceholderBinding> {
        lock(&self.binding_store)
            .get(namespace)
            .cloned()
            .unwrap_or_default()
    }
}

impl Default for SessionShim {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned by [`SessionShim::register_port_if_absent`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionConflict {
    #[error("refusing to register non-loopback address {0} for the H2 port-fallback path")]
    NotLoopback(SocketAddr),
    #[error("address already registered to a different namespace: {0:?}")]
    AlreadyRegistered(Namespace),
}

/// Doubt-pass finding: `.lock().expect(...)` would permanently poison-panic every subsequent
/// call from every session for the rest of the process's life if any future change ever panics
/// while holding either lock — an all-sessions blast radius from what should be a per-call
/// failure. Every critical section here is now genuinely a single, infallible `HashMap` op
/// (round-2 fix: `record_bindings` no longer runs caller-supplied iterator code under the
/// lock), so recovering a poisoned guard is safe: the data is exactly as consistent as it was
/// before whatever panicked.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Doubt-pass finding: the nil UUID (`00000000-...-000000000000`) is a common
/// uninitialized/default sentinel — accepting it as a legitimate, distinct namespace would
/// turn any code path that accidentally defaults to `Uuid::default()`/`Uuid::nil()` instead of
/// generating a real token into a silent shared-namespace bug. Rejected the same way a
/// malformed token is: fail closed, not "somehow valid."
fn parse_namespace_header(token: &str) -> Result<Namespace, SessionError> {
    let uuid = Uuid::parse_str(token)
        .ok()
        .filter(|uuid| !uuid.is_nil())
        .ok_or_else(|| {
            let truncated: String = token.chars().take(MAX_ECHOED_HEADER_LEN).collect();
            SessionError::InvalidNamespaceHeader(truncated)
        })?;
    Ok(Namespace::Session(SessionId(uuid)))
}
