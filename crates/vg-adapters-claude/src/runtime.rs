//! The shared `Engine`: opens (or creates) everything under a [`StatePaths`] and composes
//! the real pipeline once, so the hooks and every `vg` subcommand mask/scan/demask through
//! the same wiring.
//!
//! Ownership note: the `Engine` owns a `vg_core::Policy` (the vault/policy/audit trait
//! objects) plus the detector/parser registries, and lends a fresh `vg_core::Context` for
//! each operation (the context borrows short-lived reference slices into the owned `Box`
//! registries — the same lifetime shape `vg-core`'s own pipeline tests use).

use std::io;

use vg_core::telemetry::TraceId;
use vg_core::{
    mask as core_mask, rehydrate as core_rehydrate, scan as core_scan, Actor, ArtefactHint,
    AuditEvent, Context, Destination, Detector, EntityType, Finding, HandlingClass, Input,
    MappingRef, MaskError, MaskedPack, Namespace, Parser, Policy, PolicyEngine, PolicyError,
    PolicyLayers, RehydrateDenied, RepoId, VaultError,
};

use vg_audit::{
    JsonlAuditSink, SharedTelemetrySink, TelemetryConversionCounts, TelemetryCountingAuditSink,
};
use vg_detectors::all_detectors;
use vg_parsers::all_parsers;
use vg_policy::LayeredPolicyEngine;
use vg_vault::{Vault, VaultConfig};

use crate::pack::{PackError, StoredPack};
use crate::state::StatePaths;

/// Environment variable holding a 64-hex-char (32-byte) vault DB key. **A test/CI seam
/// only:** when set, the vault is opened with this key via [`Vault::open_with_key`],
/// bypassing the OS keychain so a suite never reads or mutates the real keychain. Unset (the
/// production path) opens the keychain-wrapped vault via [`Vault::open`]. Setting it in
/// production forfeits the "DB key never persisted plaintext" guarantee — same caveat as
/// `Vault::open_with_key` itself.
pub const VAULT_KEY_ENV: &str = "VG_VAULT_KEY_HEX";

/// The default global policy written to `policy/global.policy.json` on first use if the
/// operator has not supplied one. Mirrors `vg-policy`'s reference fixture: entities masked
/// by default, secrets/keys irreversibly redacted, `.env`/`.pem` artefacts blocked, and the
/// two hard-deny destinations pinned masked-only. Operators edit this file (or add
/// `repo.policy.json`/`session.policy.json` overlays) to tune policy.
///
/// Public so the `vg-bench` eval harness can score the corpus against the *exact* default
/// policy the product ships, from a single source of truth (no duplicated JSON to drift).
pub const DEFAULT_GLOBAL_POLICY: &str = r#"{
  "version": "veilgremlin-default-global-v1",
  "signature": "phase1-unverified-placeholder",
  "entities": {
    "default": "mask",
    "overrides": {
      "email": "mask",
      "person": "mask",
      "hostname": "pass",
      "password": "irreversible-redact",
      "secret": "irreversible-redact",
      "private-key": "irreversible-redact",
      "api-key": "irreversible-redact",
      "access-token": "irreversible-redact"
    }
  },
  "artefacts": {
    "default": "pass",
    "by_extension": {
      "env": "block",
      "pem": "block"
    },
    "by_mime": {}
  },
  "destinations": {
    "remote-model-prompt": { "masked_only": true, "demask_allowed": false },
    "observability-sink": { "masked_only": true, "demask_allowed": false },
    "local-patch": { "masked_only": false, "demask_allowed": true },
    "local-test-fixture": { "masked_only": false, "demask_allowed": true },
    "local-explanation-buffer": { "masked_only": false, "demask_allowed": false }
  }
}
"#;

/// Errors opening the engine.
#[derive(Debug)]
pub enum EngineError {
    Io(io::Error),
    Policy(PolicyError),
    Vault(VaultError),
    Audit(String),
    BadVaultKey(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Io(e) => write!(f, "state io error: {e}"),
            EngineError::Policy(e) => write!(f, "policy error: {e}"),
            EngineError::Vault(e) => write!(f, "vault error: {e}"),
            EngineError::Audit(e) => write!(f, "audit error: {e}"),
            EngineError::BadVaultKey(e) => write!(f, "invalid {VAULT_KEY_ENV}: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<io::Error> for EngineError {
    fn from(e: io::Error) -> Self {
        EngineError::Io(e)
    }
}
impl From<PolicyError> for EngineError {
    fn from(e: PolicyError) -> Self {
        EngineError::Policy(e)
    }
}
impl From<VaultError> for EngineError {
    fn from(e: VaultError) -> Self {
        EngineError::Vault(e)
    }
}

/// The composed VeilGremlin engine over one state directory.
pub struct Engine {
    paths: StatePaths,
    policy: Policy,
    detectors: Vec<Box<dyn Detector>>,
    parsers: Vec<Box<dyn Parser>>,
    namespace: Namespace,
    /// `Some` only when the resolved policy has `telemetry_enabled: true` (ADR-015:
    /// opt-in, never opt-out — absent/false is the default and leaves this `None`,
    /// with zero behaviour change from before this field existed: no keychain access,
    /// no wrapping sink, `telemetry_counts()` reports nothing). Held alongside
    /// `policy.audit` (which owns a `Box<dyn AuditSink>` built from a clone of the same
    /// handle) purely so callers can inspect counts without downcasting a trait object —
    /// see `vg_audit::SharedTelemetrySink`'s own doc for why it exists.
    telemetry_sink: Option<SharedTelemetrySink>,
}

impl Engine {
    /// Opens (creating on first use) the engine over `paths`: ensures the state dirs,
    /// bootstraps a default `global.policy.json` if absent, loads the layered policy, opens
    /// the vault (keychain or test-key seam) and the audit log, and builds the detector/
    /// parser registries.
    ///
    /// If the resolved policy enables telemetry, also loads (or first-generates) this
    /// device's actor-pseudonymization key from the OS keychain
    /// (`vg_vault::load_or_create_actor_pseudonym_key`) and wraps the audit sink in a
    /// [`TelemetryCountingAuditSink`] — see that type's own doc for what it does and, as
    /// importantly, does not do (it counts `EdgeEvent::try_from_audit_event` outcomes; it
    /// does not persist or transmit anything).
    pub fn open(paths: StatePaths) -> Result<Self, EngineError> {
        paths.ensure()?;
        bootstrap_default_policy(&paths)?;

        let engine = LayeredPolicyEngine::load(policy_layers(&paths))?;
        let vault = open_vault(&paths)?;
        let plain_audit = JsonlAuditSink::open(paths.audit_log())
            .map_err(|e| EngineError::Audit(e.to_string()))?;

        // A doubt-driven-development finding, not a hypothetical: `telemetry_enabled()`
        // reflects the *resolved policy*, which can come from a state dir F3 already
        // documents as an untrusted-input surface (`crate::state::Provenance::Discovered`
        // — a `.veilgremlin/` adopted wholesale from a cloned repo's ancestor directory).
        // In that scenario every layer inside it, including what looks like the "global"
        // layer, is part of the untrusted input, so a repo/session-only restriction would
        // not have closed this. Unlike other F3-weakened settings (which only degrade
        // masking within the current process and only get a warning), an enabled-here
        // `telemetry_enabled` triggers a *new*, consequential, irreversible side effect —
        // generating a persistent per-device OS-keychain secret — the first time it fires,
        // with no operator-facing surface anywhere that shows telemetry is active. That
        // combination is treated as a hard-deny in code, the same posture this codebase
        // already takes for the `RemoteModelPrompt`/`ObservabilitySink` hard-deny
        // destinations, not merely another warned-about F3 consequence.
        let telemetry_enabled = engine.telemetry_enabled()
            && !matches!(paths.provenance(), crate::state::Provenance::Discovered);
        if engine.telemetry_enabled() && !telemetry_enabled {
            eprintln!(
                "veilgremlin: WARNING telemetry_enabled=true in a discovered (not pinned or \
                 created-here) state dir — refusing to enable telemetry. A state dir adopted \
                 from an ancestor directory is untrusted input (F3); it must not be able to \
                 trigger OS-keychain secret generation. Pin the state dir with \
                 --state-dir/VG_STATE_DIR if this policy is actually yours."
            );
        }

        let (audit, telemetry_sink): (Box<dyn vg_core::AuditSink>, Option<SharedTelemetrySink>) =
            if telemetry_enabled {
                let actor_key = vg_vault::load_or_create_actor_pseudonym_key()?;
                let sink = SharedTelemetrySink::new(TelemetryCountingAuditSink::new(
                    Box::new(plain_audit),
                    actor_key,
                ));
                (Box::new(sink.clone()), Some(sink))
            } else {
                (Box::new(plain_audit), None)
            };

        let policy = Policy {
            engine: Box::new(engine),
            vault: Box::new(vault),
            audit,
        };
        let namespace = repo_namespace(&paths);

        Ok(Self {
            paths,
            policy,
            detectors: all_detectors(),
            parsers: all_parsers(),
            namespace,
            telemetry_sink,
        })
    }

    /// A snapshot of telemetry-conversion outcome counts, or `None` if telemetry is not
    /// enabled for the resolved policy. See [`TelemetryCountingAuditSink`]'s doc for what
    /// this does and does not represent — outcome counts, not stored/transmittable
    /// payloads.
    pub fn telemetry_counts(&self) -> Option<TelemetryConversionCounts> {
        self.telemetry_sink.as_ref().map(|s| s.counts())
    }

    pub fn paths(&self) -> &StatePaths {
        &self.paths
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub fn policy_version(&self) -> String {
        self.policy.engine.version().to_string()
    }

    /// The policy engine's class for one entity type.
    pub fn classify_entity(&self, ty: EntityType) -> HandlingClass {
        self.policy.engine.classify_entity(ty)
    }

    /// The policy engine's class for one artefact hint.
    pub fn classify_artefact(&self, hint: &ArtefactHint) -> HandlingClass {
        self.policy.engine.classify_artefact(hint)
    }

    /// Whether demask is permitted for `dest`/`actor` (mirrors the engine gate; `rehydrate`
    /// still enforces the hard-deny gate independently).
    pub fn demask_allowed(&self, dest: Destination, actor: &Actor) -> bool {
        self.policy.engine.demask_allowed(dest, actor)
    }

    /// Runs `f` with a fresh `Context` over the owned detector/parser registries.
    fn with_context<R>(&self, f: impl FnOnce(&Context) -> R) -> R {
        let dets: Vec<&dyn Detector> = self.detectors.iter().map(|d| d.as_ref()).collect();
        let pars: Vec<&dyn Parser> = self.parsers.iter().map(|p| p.as_ref()).collect();
        let ctx = Context {
            parsers: &pars,
            detectors: &dets,
        };
        f(&ctx)
    }

    /// Scans `text` (with `hint`) for entities, changing nothing.
    pub fn scan_text(&self, text: &str, hint: ArtefactHint) -> Vec<Finding> {
        let input = Input {
            buf: text.as_bytes().to_vec(),
            hint,
        };
        self.with_context(|ctx| core_scan(&input, ctx))
    }

    /// Masks `text` (with `hint`) through the full pipeline, interning reversible values.
    pub fn mask_text(
        &self,
        text: &str,
        hint: ArtefactHint,
    ) -> Result<(MaskedPack, Vec<MappingRef>, AuditEvent, TraceId), MaskError> {
        let input = Input {
            buf: text.as_bytes().to_vec(),
            hint,
        };
        self.with_context(|ctx| core_mask(&input, ctx, &self.policy, &self.namespace))
    }

    /// Reverses `pack` under `ns` for `dest`/`actor`, enforcing the demask gate.
    pub fn rehydrate(
        &self,
        pack: &MaskedPack,
        ns: &Namespace,
        dest: Destination,
        actor: &Actor,
    ) -> Result<String, RehydrateDenied> {
        core_rehydrate(pack, &self.policy, ns, dest, actor)
    }

    /// Persists a masked pack under `packs/` for a later `vg demask`, returning its path.
    pub fn save_pack(&self, pack: &MaskedPack) -> Result<std::path::PathBuf, PackError> {
        StoredPack::from_pack(pack, &self.namespace).save_in(&self.paths.packs_dir())
    }
}

/// The layered policy paths: the required global layer plus any repo/session overlays that
/// exist on disk.
fn policy_layers(paths: &StatePaths) -> PolicyLayers {
    let opt = |p: std::path::PathBuf| p.is_file().then_some(p);
    PolicyLayers {
        global: paths.global_policy(),
        repo: opt(paths.repo_policy()),
        session: opt(paths.session_policy()),
    }
}

/// Writes [`DEFAULT_GLOBAL_POLICY`] to the well-known global path if the operator has not
/// provided one, so `vg` is usable out of the box.
fn bootstrap_default_policy(paths: &StatePaths) -> io::Result<()> {
    let global = paths.global_policy();
    if !global.exists() {
        std::fs::write(&global, DEFAULT_GLOBAL_POLICY)?;
    }
    Ok(())
}

/// The repo-scoped namespace keying placeholder stability to the working tree (the state
/// dir's parent), so the same value masks to the same placeholder across invocations. A
/// persisted pack records this namespace verbatim, so a later demask resolves under the same
/// scope regardless of the directory it runs from.
fn repo_namespace(paths: &StatePaths) -> Namespace {
    Namespace::Repo(RepoId(paths.repo_root().to_string_lossy().into_owned()))
}

/// Opens the vault at the state dir's `vault.db`, honouring the [`VAULT_KEY_ENV`] test seam.
pub fn open_vault(paths: &StatePaths) -> Result<Vault, EngineError> {
    let config = VaultConfig::new(paths.vault_db());
    match std::env::var(VAULT_KEY_ENV) {
        Ok(hex) => {
            // The env-key seam exists for tests/CI (no OS keychain). Honouring it
            // silently in a real session would mean an env-visible vault key with no
            // trace (doubt-pass finding) — warn loudly instead of guessing intent.
            eprintln!(
                "veilgremlin: WARNING {VAULT_KEY_ENV} is set — vault key taken from the \
                 environment, NOT the OS keychain. This is a test seam; unset it for real \
                 sessions."
            );
            let key = parse_key_hex(&hex)?;
            Ok(Vault::open_with_key(config, key)?)
        }
        Err(_) => Ok(Vault::open(config)?),
    }
}

/// Parses a 64-hex-char string into a 32-byte key.
fn parse_key_hex(hex: &str) -> Result<[u8; 32], EngineError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(EngineError::BadVaultKey(format!(
            "expected 64 hex chars (32 bytes), got {}",
            hex.len()
        )));
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s =
            std::str::from_utf8(chunk).map_err(|_| EngineError::BadVaultKey("non-utf8".into()))?;
        key[i] = u8::from_str_radix(s, 16)
            .map_err(|_| EngineError::BadVaultKey(format!("non-hex byte {s:?}")))?;
    }
    Ok(key)
}

#[cfg(test)]
mod telemetry_wiring_tests {
    use super::*;
    use crate::state::StatePaths;

    /// A 64-hex-char (32-byte) key, distinct from any real secret, for the env-var test
    /// seams below.
    const TEST_KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const ACTOR_PSEUDONYM_KEY_ENV: &str = "VG_ACTOR_PSEUDONYM_KEY_HEX";

    fn open_engine_in_temp_dir(policy_json: Option<&str>) -> (tempfile::TempDir, Engine) {
        open_engine_with_provenance(policy_json, crate::state::Provenance::Pinned)
    }

    fn open_engine_with_provenance(
        policy_json: Option<&str>,
        provenance: crate::state::Provenance,
    ) -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::rooted_at(dir.path().to_path_buf()).with_provenance(provenance);
        paths.ensure().expect("ensure state dirs");
        if let Some(json) = policy_json {
            // Written before `Engine::open` -- `bootstrap_default_policy` only writes
            // the default policy "if absent", so this pre-empts it.
            std::fs::create_dir_all(paths.policy_dir()).expect("policy dir");
            std::fs::write(paths.global_policy(), json).expect("write policy fixture");
        }
        let engine = Engine::open(paths).expect("Engine::open");
        (dir, engine)
    }

    #[test]
    fn telemetry_disabled_by_default_leaves_engine_open_behaviour_unchanged() {
        // No policy fixture -> bootstrap_default_policy's own default, which does not
        // mention telemetry_enabled at all. No env vars touched: this must not attempt
        // any keychain access.
        let (_dir, engine) = open_engine_in_temp_dir(None);
        assert!(engine.telemetry_counts().is_none());
    }

    #[test]
    fn telemetry_explicitly_false_also_leaves_counts_none() {
        let (_dir, engine) = open_engine_in_temp_dir(Some(r#"{"telemetry_enabled": false}"#));
        assert!(engine.telemetry_counts().is_none());
    }

    /// Regression for a doubt-driven-development finding: `telemetry_enabled: true`
    /// resolved from a *discovered* (not pinned or created-here) state dir must be
    /// refused, not honoured -- F3 already documents a discovered `.veilgremlin/` as
    /// untrusted input, and this is the one setting in it that triggers a new,
    /// irreversible side effect (OS-keychain secret generation) rather than just
    /// weakening in-process masking. No env vars touched: this must fail closed before
    /// ever reaching `load_or_create_actor_pseudonym_key`.
    #[test]
    fn telemetry_enabled_is_refused_when_the_state_dir_was_discovered_not_pinned() {
        let (_dir, engine) = open_engine_with_provenance(
            Some(r#"{"telemetry_enabled": true}"#),
            crate::state::Provenance::Discovered,
        );
        assert!(
            engine.telemetry_counts().is_none(),
            "a discovered state dir must never enable telemetry, regardless of what its \
             policy says"
        );
    }

    /// Unsets `VAULT_KEY_ENV`/`ACTOR_PSEUDONYM_KEY_ENV` on drop, unconditionally —
    /// a Codex cross-model finding in this same round: the original inline
    /// `set_var`/... /`remove_var` sequence only cleaned up on the success path, so a
    /// panic partway through (e.g. `Engine::open(...).expect(...)` failing) would have
    /// left these process-global vars set for the rest of the test binary. `Drop` runs
    /// during unwinding too, so this cleans up regardless of how the test exits.
    struct EnvVarGuard;

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(VAULT_KEY_ENV);
                std::env::remove_var(ACTOR_PSEUDONYM_KEY_ENV);
            }
        }
    }

    /// The one test in this crate's suite that touches `VAULT_KEY_ENV`/
    /// `VG_ACTOR_PSEUDONYM_KEY_HEX` — sound for the same reason `vg-vault`'s own
    /// `keychain.rs` tests give: these names are unique to this test, and no other test
    /// in this binary reads or writes them, so there is no cross-test race despite
    /// `cargo test`'s default parallelism.
    #[test]
    fn telemetry_enabled_wires_the_counting_sink_and_counts_a_real_write() {
        unsafe {
            std::env::set_var(VAULT_KEY_ENV, TEST_KEY_HEX);
            std::env::set_var(ACTOR_PSEUDONYM_KEY_ENV, TEST_KEY_HEX);
        }
        let _cleanup = EnvVarGuard;
        let (_dir, engine) = open_engine_in_temp_dir(Some(r#"{"telemetry_enabled": true}"#));

        let counts = engine
            .telemetry_counts()
            .expect("telemetry must be enabled");
        assert_eq!(counts.get("DemaskDecision"), Default::default());

        // Hard-deny denial path: `rehydrate` writes AuditEvent::DemaskDecision {
        // allowed: false, .. } before returning Err, regardless of pack/vault content
        // (interface-contracts.md's hard-deny gate fires before any vault resolve).
        let pack = MaskedPack {
            text: String::new(),
            mapping_refs: Vec::new(),
            bindings: Vec::new(),
            stats: vg_core::MaskStats {
                counts: vg_core::EntityCounts::default(),
                blocked_artefacts: 0,
            },
            policy_version: engine.policy_version(),
        };
        let actor = Actor {
            id: vg_core::ActorId("test-actor".to_string()),
            roles: Vec::new(),
        };
        let result = engine.rehydrate(
            &pack,
            engine.namespace(),
            Destination::RemoteModelPrompt,
            &actor,
        );
        assert!(result.is_err(), "hard-deny destination must deny");

        let counts = engine.telemetry_counts().expect("still enabled");
        assert_eq!(
            counts.get("DemaskDecision").ok,
            1,
            "the denial's DemaskDecision must have converted Ok via the actor-key entry point"
        );
    }
}
