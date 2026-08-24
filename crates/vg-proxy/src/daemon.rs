use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use vg_audit::JsonlAuditSink;
use vg_core::{
    Context, Detector, EntityType, MaskStats, Namespace, Parser, Placeholder, PlaceholderBinding,
    Policy, PolicyEngine, PolicyLayers, Secret, VaultError, VaultStore,
};
use vg_detectors::all_detectors;
use vg_parsers::all_parsers;
use vg_policy::LayeredPolicyEngine;
use vg_vault::{Vault, VaultConfig};

use crate::demask_response;
use crate::error::ProxyError;
use crate::mask_request::{mask_request, MaskedRequest};
use crate::session::{SessionConflict, SessionShim};

/// A `VaultStore` wrapper around a shared `Arc<Vault>` (M3). `Daemon` needs the same open vault
/// reachable two ways: as a concrete `Vault` for its own `handle_fake_request`/liveness checks
/// (M2, unchanged), and boxed as `Policy.vault: Box<dyn VaultStore>` for `mask_request`'s real
/// masking calls (M3, new). `Arc<Vault>` can't be boxed as `Box<dyn VaultStore>` directly —
/// `VaultStore` is implemented for `Vault`, not `Arc<Vault>`, and there's no blanket impl (adding
/// one here would be an orphan-rule violation from this crate anyway). Mirrors
/// `vg_audit::SharedTelemetrySink`'s own precedent for the identical shared-handle problem.
struct SharedVault(Arc<Vault>);

impl VaultStore for SharedVault {
    fn intern(
        &self,
        value: &Secret,
        ty: EntityType,
        ns: &Namespace,
    ) -> Result<Placeholder, VaultError> {
        self.0.intern(value, ty, ns)
    }

    fn resolve(&self, p: &Placeholder, ns: &Namespace) -> Result<Secret, VaultError> {
        self.0.resolve(p, ns)
    }

    fn purge_expired(&self) -> Result<usize, VaultError> {
        self.0.purge_expired()
    }
}

/// The long-lived daemon core (plan §10.3 milestones 2-3): opens `vg-vault` exactly once and
/// holds it for the process's lifetime — the exact friction T11's NO-GO named as the hook
/// adapter's second failure mode. Also owns the H2 session-namespace shim, the session-scoped
/// accumulated binding store (H1's fix, §8.5), and — as of M3 — a full `Policy` + detector/
/// parser registry, the same shape `vg-adapters-claude::Engine` assembles, so
/// [`Daemon::mask_request`] can call the real `vg_core::mask` pipeline.
///
/// **Not production state-dir/keychain discovery.** Unlike `Engine::open` (which discovers a
/// `.veilgremlin/` state dir, bootstraps a default policy file, and opens the vault through the
/// OS keychain), `Daemon::open`/`open_with_key` take already-resolved `PolicyLayers` paths and
/// an audit log path directly — matching what this milestone's own tests need. A real `vg-proxy`
/// daemon *binary* with state-dir/keychain discovery is separate, unscoped, later work (named
/// explicitly in `docs/next-actions.md`, not silently assumed solved by this milestone).
pub struct Daemon {
    vault: Arc<Vault>,
    policy: Policy,
    detectors: Vec<Box<dyn Detector>>,
    parsers: Vec<Box<dyn Parser>>,
    session_shim: SessionShim,
}

impl Daemon {
    /// Opens the vault via the OS keychain ([`Vault::open`]) — the production path — and
    /// assembles the full policy/detector/parser/audit stack from `policy_layers`/
    /// `audit_log_path`.
    pub fn open(
        vault_config: VaultConfig,
        policy_layers: PolicyLayers,
        audit_log_path: impl AsRef<Path>,
    ) -> Result<Self, ProxyError> {
        let vault = Vault::open(vault_config)?;
        Self::from_vault(vault, policy_layers, audit_log_path)
    }

    /// Opens the vault with a caller-supplied key ([`Vault::open_with_key`]), bypassing the OS
    /// keychain — the seam tests use, mirroring `Vault`'s own two-constructor pattern.
    pub fn open_with_key(
        vault_config: VaultConfig,
        key: [u8; 32],
        policy_layers: PolicyLayers,
        audit_log_path: impl AsRef<Path>,
    ) -> Result<Self, ProxyError> {
        let vault = Vault::open_with_key(vault_config, key)?;
        Self::from_vault(vault, policy_layers, audit_log_path)
    }

    fn from_vault(
        vault: Vault,
        policy_layers: PolicyLayers,
        audit_log_path: impl AsRef<Path>,
    ) -> Result<Self, ProxyError> {
        let vault = Arc::new(vault);
        let engine = LayeredPolicyEngine::load(policy_layers)?;
        let audit = JsonlAuditSink::open(audit_log_path)?;
        let policy = Policy {
            engine: Box::new(engine),
            vault: Box::new(SharedVault(Arc::clone(&vault))),
            audit: Box::new(audit),
        };
        Ok(Self {
            vault,
            policy,
            detectors: all_detectors(),
            parsers: all_parsers(),
            session_shim: SessionShim::new(),
        })
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

    /// M2's stand-in for real request handling, kept: resolves the request's [`Namespace`] via
    /// the H2 shim, then touches the shared vault with a real, safe, idempotent
    /// [`VaultStore`] operation (`purge_expired`) to prove the vault survives being reused
    /// across many sequential calls rather than reopened per request. Namespace/liveness
    /// testing only — [`Daemon::mask_request`] is the real M3 request path.
    pub fn handle_fake_request(
        &self,
        namespace_header: Option<&str>,
        local_addr: SocketAddr,
    ) -> Result<(Namespace, usize), ProxyError> {
        let namespace = self.session_shim.resolve(namespace_header, local_addr)?;
        let purged = self.vault.purge_expired()?;
        Ok((namespace, purged))
    }

    /// The real M3 request path: resolves `namespace_header`/`local_addr` to a [`Namespace`]
    /// via the same H2 shim `handle_fake_request` uses, masks `body` through the real
    /// `vg_core::mask` pipeline (see [`crate::mask_request::mask_request`] for how), records
    /// the resulting bindings into that namespace's accumulated session store (H1's fix), and
    /// returns the masked bytes ready to forward alongside summary stats (`server.rs` surfaces
    /// these as a response header) and the resolved [`Namespace`] itself — M4's
    /// [`Daemon::demask_response`] needs the same namespace for the matching response, without
    /// re-parsing the header a second time.
    pub fn mask_request(
        &self,
        body: &[u8],
        namespace_header: Option<&str>,
        local_addr: SocketAddr,
    ) -> Result<(Vec<u8>, MaskStats, Namespace), ProxyError> {
        let namespace = self.session_shim.resolve(namespace_header, local_addr)?;
        let MaskedRequest {
            body,
            bindings,
            stats,
        } = self.with_context(|ctx| mask_request(body, ctx, &self.policy, &namespace))?;
        self.session_shim.record_bindings(&namespace, bindings);
        Ok((body, stats, namespace))
    }

    /// The real M4 response path: demasks `body` (a model response) against `namespace`'s full
    /// accumulated binding store — not just the bindings from the request that produced this
    /// response, since a response can echo a placeholder minted by an *earlier* request in the
    /// same conversation (the H1 case). Infallible, matching
    /// [`crate::demask_response::demask_response`]'s own design: a malformed response or an
    /// unresolvable/denied binding never blocks the response from reaching the client.
    ///
    /// **Named, not fixed here (round-2 doubt-pass finding):** [`SessionShim::record_bindings`]
    /// appends to a namespace's binding `Vec` with no dedup beyond what the vault already gives
    /// a repeated raw value (the same *display* string, but still a new `Vec` entry each
    /// request), and this call clones the whole accumulated `Vec` via `bindings_for`, then
    /// [`crate::demask_response::demask_response`] clones it again per leaf field. For a long
    /// conversation that repeatedly references the same entities, this is real, unbounded
    /// clone-and-growth cost this milestone is the first caller to actually trigger — not fixed
    /// here because a proper fix (dedup at record time, or avoid the per-leaf clone) touches
    /// `SessionShim`'s already-merged, already-doubt-reviewed M2 code, a larger change than
    /// this milestone's own scope.
    pub fn demask_response(&self, body: &[u8], namespace: &Namespace) -> Vec<u8> {
        let bindings = self.session_shim.bindings_for(namespace);
        demask_response::demask_response(body, &bindings, &self.policy, namespace)
    }

    /// Runs `f` with a fresh [`Context`] over the owned detector/parser registries. Same shape
    /// as `vg-adapters-claude::Engine::with_context` — the trait-object slices borrow local
    /// `Vec`s, so they can't outlive a helper that returns them, hence a closure.
    fn with_context<R>(&self, f: impl FnOnce(&Context) -> R) -> R {
        let dets: Vec<&dyn Detector> = self.detectors.iter().map(|d| d.as_ref()).collect();
        let pars: Vec<&dyn Parser> = self.parsers.iter().map(|p| p.as_ref()).collect();
        let ctx = Context {
            parsers: &pars,
            detectors: &dets,
        };
        f(&ctx)
    }

    /// Returns the accumulated bindings recorded for `namespace` so far (H1's fix, §8.5).
    pub fn bindings_for(&self, namespace: &Namespace) -> Vec<PlaceholderBinding> {
        self.session_shim.bindings_for(namespace)
    }

    /// Records `bindings` into `namespace`'s accumulated store (H1's fix) — exposed for tests;
    /// [`Daemon::mask_request`] is the real caller in production.
    pub fn record_bindings(
        &self,
        namespace: &Namespace,
        bindings: impl IntoIterator<Item = PlaceholderBinding>,
    ) {
        self.session_shim.record_bindings(namespace, bindings);
    }
}
