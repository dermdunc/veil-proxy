use std::net::SocketAddr;
use std::sync::Arc;

use vg_core::{Namespace, PlaceholderBinding, VaultStore};
use vg_vault::{Vault, VaultConfig};

use crate::error::ProxyError;
use crate::session::{SessionConflict, SessionShim};

/// The long-lived daemon core (plan §10.3 milestone 2): opens `vg-vault` exactly once and
/// holds it for the process's lifetime, so every request is served against the same open
/// vault instead of re-opening — and re-hitting the OS keychain — per request, the exact
/// friction T11's NO-GO named as the hook adapter's second failure mode. Also owns the H2
/// session-namespace shim and the session-scoped accumulated binding store (H1's fix, §8.5).
///
/// **M2 scope, not yet wired into the HTTP server.** `handle_fake_request` simulates what a
/// real request handler will do once request masking exists (M3+): resolve the namespace,
/// touch the shared vault. `server::handle` (M1) still returns its fixed test-double response
/// and does not consult a `Daemon` at all — connecting the two is scoped to the milestone that
/// actually has something schema-aware to do with the result, not built prematurely here.
pub struct Daemon {
    vault: Arc<Vault>,
    session_shim: SessionShim,
}

impl Daemon {
    /// Opens the vault via the OS keychain ([`Vault::open`]) — the production path.
    pub fn open(vault_config: VaultConfig) -> Result<Self, ProxyError> {
        let vault = Vault::open(vault_config)?;
        Ok(Self::from_vault(vault))
    }

    /// Opens the vault with a caller-supplied key ([`Vault::open_with_key`]), bypassing the OS
    /// keychain — the seam tests use, mirroring `Vault`'s own two-constructor pattern.
    pub fn open_with_key(vault_config: VaultConfig, key: [u8; 32]) -> Result<Self, ProxyError> {
        let vault = Vault::open_with_key(vault_config, key)?;
        Ok(Self::from_vault(vault))
    }

    fn from_vault(vault: Vault) -> Self {
        Self {
            vault: Arc::new(vault),
            session_shim: SessionShim::new(),
        }
    }

    /// Registers a loopback address as belonging to `namespace` — the H2 port-fallback path's
    /// registration step (plan §5 H2). See [`SessionShim`]'s doc comment for why this is a
    /// registration, not a stateless derivation, and for the port-reuse handoff race that
    /// remains open until a real per-session-listener caller exists. Fails if `addr` isn't
    /// loopback (round-2 doubt-pass finding). Returns the previously-registered `Namespace` for
    /// `addr`, if any.
    pub fn register_port(
        &self,
        addr: SocketAddr,
        namespace: Namespace,
    ) -> Result<Option<Namespace>, ProxyError> {
        Ok(self.session_shim.register_port(addr, namespace)?)
    }

    /// Like [`Daemon::register_port`], but fails instead of silently overwriting a mapping
    /// already registered to a *different* namespace — see
    /// [`SessionShim::register_port_if_absent`].
    pub fn register_port_if_absent(
        &self,
        addr: SocketAddr,
        namespace: Namespace,
    ) -> Result<(), SessionConflict> {
        self.session_shim.register_port_if_absent(addr, namespace)
    }

    /// Releases `addr`'s registration — only if it currently maps to `expected`
    /// (compare-and-remove) — see [`SessionShim::unregister_port`]. Returns whether a removal
    /// actually happened.
    pub fn unregister_port(&self, addr: SocketAddr, expected: &Namespace) -> bool {
        self.session_shim.unregister_port(addr, expected)
    }

    /// M2's stand-in for real request handling (§10.3 milestone 2: "serves many sequential
    /// fake requests"): resolves the request's [`Namespace`] via the H2 shim, then touches the
    /// shared vault with a real, safe, idempotent [`VaultStore`] operation (`purge_expired`)
    /// to prove the vault survives being reused across many sequential calls rather than
    /// reopened per request — no real masked content flows through it yet. Returns the
    /// resolved namespace and the purge count for test assertions.
    pub fn handle_fake_request(
        &self,
        namespace_header: Option<&str>,
        local_addr: SocketAddr,
    ) -> Result<(Namespace, usize), ProxyError> {
        let namespace = self.session_shim.resolve(namespace_header, local_addr)?;
        let purged = self.vault.purge_expired()?;
        Ok((namespace, purged))
    }

    /// Returns the accumulated bindings recorded for `namespace` so far (H1's fix, §8.5) —
    /// empty in M2 since nothing populates real content yet; the data structure and its
    /// per-namespace isolation are what this milestone proves.
    pub fn bindings_for(&self, namespace: &Namespace) -> Vec<PlaceholderBinding> {
        self.session_shim.bindings_for(namespace)
    }

    /// Records `bindings` into `namespace`'s accumulated store (H1's fix) — exposed for tests;
    /// no real request path calls this until masking exists (M3+).
    pub fn record_bindings(
        &self,
        namespace: &Namespace,
        bindings: impl IntoIterator<Item = PlaceholderBinding>,
    ) {
        self.session_shim.record_bindings(namespace, bindings);
    }
}
