//! The repo-local `.veilgremlin/` state directory: the one consistent place the hooks and
//! the `vg` CLI keep the vault DB, audit log, layered policy packs, and persisted masked
//! packs (a demask needs the pack a prior mask produced).
//!
//! Layout under the state root (`.veilgremlin/` by default, git-ignored):
//!
//! ```text
//! .veilgremlin/
//!   vault.db                     SQLCipher mapping store (vg-vault)
//!   audit.jsonl                  append-only audit log (vg-audit)
//!   claude-hooks.json            hook config `vg run` writes for Claude Code
//!   policy/
//!     global.policy.json         required layer (written from a default on first use)
//!     repo.policy.json           optional overlay
//!     session.policy.json        optional overlay
//!   packs/
//!     <uuid>.json                one persisted MaskedPack per masked artefact
//! ```
//!
//! Resolution precedence for the state root: an explicit path (the CLI's `--state-dir`),
//! then the `VG_STATE_DIR` environment variable, then the nearest existing `.veilgremlin`
//! walking up from the current directory, else `<cwd>/.veilgremlin`.

use std::env;
use std::io;
use std::path::{Path, PathBuf};

/// Environment variable that pins the state directory (an absolute or cwd-relative path to
/// the `.veilgremlin` dir itself), overriding upward discovery. The CLI's `--state-dir`
/// flag takes precedence over it.
pub const STATE_DIR_ENV: &str = "VG_STATE_DIR";

/// The conventional directory name for the repo-local state dir.
pub const STATE_DIR_NAME: &str = ".veilgremlin";

/// Resolved paths under one state directory.
#[derive(Debug, Clone)]
pub struct StatePaths {
    /// The `.veilgremlin` directory itself.
    root: PathBuf,
    /// The directory the state dir lives in — used to key the repo `Namespace` so
    /// placeholders are stable across invocations in the same working tree.
    repo_root: PathBuf,
    /// How this state dir was chosen — carried on the struct (not just returned
    /// alongside it from [`StatePaths::resolve`]) so it survives being passed into
    /// `Engine::open` and beyond. Added for a real, demonstrated reason (a
    /// doubt-driven-development finding during the telemetry-emitter work, not
    /// speculative): `Engine::open` needs to know whether the *entire* resolved policy
    /// — including what looks like the "global" layer — might itself be attacker-
    /// controlled (F3: a `.veilgremlin/` adopted wholesale from a cloned repo's
    /// ancestor directory makes every layer inside it, global included, part of the
    /// untrusted input). Previously this information was computed once in the CLI's
    /// `dispatch` and discarded after printing a warning — too late for anything
    /// downstream to act on it.
    provenance: Provenance,
}

/// How [`StatePaths::resolve`] chose the state dir — the trust-provenance of the resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Explicit `--state-dir` or `VG_STATE_DIR` — the operator named it.
    Pinned,
    /// Adopted from an ancestor directory by upward discovery. **Untrusted-input surface
    /// (F3):** a `.veilgremlin/` committed into a cloned repo, or a stray `~/.veilgremlin`,
    /// is adopted here — its policy could weaken the shield. Callers should warn.
    Discovered,
    /// No dir found; a fresh one will be created in the cwd. Trusted (the operator's cwd).
    CreatedInCwd,
}

impl Provenance {
    /// A one-line stderr warning when the state dir was *discovered* rather than pinned or
    /// created, so an adopted-from-an-ancestor policy is never silently trusted. `None` for
    /// the trusted provenances.
    pub fn discovered_warning(&self, root: &Path) -> Option<String> {
        match self {
            Provenance::Discovered => Some(format!(
                "veilgremlin: NOTE using a discovered state dir at {} (adopted from an \
                 ancestor, not pinned). Its policy governs masking — pin it with \
                 --state-dir/VG_STATE_DIR if you did not create it.",
                root.display()
            )),
            _ => None,
        }
    }
}

impl StatePaths {
    /// Resolves the state paths, applying the precedence documented on the module. Does not
    /// create anything on disk — call [`StatePaths::ensure`] for that. The [`Provenance`]
    /// records HOW the dir was chosen, so callers can warn when it was *discovered* from an
    /// ancestor (an untrusted-input surface — F3) rather than pinned or created here.
    pub fn resolve(explicit: Option<PathBuf>) -> io::Result<(Self, Provenance)> {
        if let Some(dir) = explicit {
            return Ok((
                Self::rooted_at(dir).with_provenance(Provenance::Pinned),
                Provenance::Pinned,
            ));
        }
        if let Some(dir) = env::var_os(STATE_DIR_ENV) {
            return Ok((
                Self::rooted_at(PathBuf::from(dir)).with_provenance(Provenance::Pinned),
                Provenance::Pinned,
            ));
        }
        let cwd = env::current_dir()?;
        if let Some(found) = discover_upward(&cwd) {
            return Ok((
                Self::rooted_at(found).with_provenance(Provenance::Discovered),
                Provenance::Discovered,
            ));
        }
        Ok((
            Self::rooted_at(cwd.join(STATE_DIR_NAME)).with_provenance(Provenance::CreatedInCwd),
            Provenance::CreatedInCwd,
        ))
    }

    /// Builds paths rooted at a specific `.veilgremlin` directory (its parent becomes the
    /// repo root). Absolutised best-effort so a persisted pack's repo namespace does not
    /// depend on the cwd a later `vg demask` runs from.
    ///
    /// Defaults to [`Provenance::Pinned`] — the trusted case, matching how every existing
    /// caller uses this constructor (an explicit path, or a test fixture standing in for
    /// the operator's own directory). [`StatePaths::resolve`] overrides this via
    /// [`Self::with_provenance`] when it actually discovers rather than pins.
    pub fn rooted_at(root: PathBuf) -> Self {
        let root = absolutise(root);
        let repo_root = root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.clone());
        Self {
            root,
            repo_root,
            provenance: Provenance::Pinned,
        }
    }

    /// `pub(crate)`, not private: also used by `runtime.rs`'s own tests to construct a
    /// `Provenance::Discovered` fixture without going through real upward filesystem
    /// discovery (regression coverage for the telemetry hard-deny gate in
    /// `Engine::open`).
    pub(crate) fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// How this state dir was chosen — see [`Provenance`].
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// Creates the state directory and its `policy/` and `packs/` subdirectories if absent.
    pub fn ensure(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.policy_dir())?;
        std::fs::create_dir_all(self.packs_dir())?;
        // Self-gitignore the whole state dir (doubt-pass mitigation): packs hold the full
        // masked text of prompts/tool IO in plaintext, and an accidentally committed
        // `.veilgremlin/` would publish packs + audit log + vault file. A `*` ignore
        // inside the dir needs no repo `.gitignore` edit. Written only if absent, so a
        // deliberate operator override survives.
        let gitignore = self.root.join(".gitignore");
        if !gitignore.exists() {
            std::fs::write(&gitignore, "*\n")?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn vault_db(&self) -> PathBuf {
        self.root.join("vault.db")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    pub fn hook_config(&self) -> PathBuf {
        self.root.join("claude-hooks.json")
    }

    pub fn policy_dir(&self) -> PathBuf {
        self.root.join("policy")
    }

    pub fn global_policy(&self) -> PathBuf {
        self.policy_dir().join("global.policy.json")
    }

    pub fn repo_policy(&self) -> PathBuf {
        self.policy_dir().join("repo.policy.json")
    }

    pub fn session_policy(&self) -> PathBuf {
        self.policy_dir().join("session.policy.json")
    }

    pub fn packs_dir(&self) -> PathBuf {
        self.root.join("packs")
    }
}

/// Walks up from `start` looking for an existing `.veilgremlin` directory, returning it if
/// found (so a hook fired deep in a subdirectory shares the repo-root state).
fn discover_upward(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(STATE_DIR_NAME);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// Makes `path` absolute against the cwd when it is relative, without touching the
/// filesystem (`std::fs::canonicalize` would require the path to exist and resolve
/// symlinks; we only want a stable, cwd-independent key). Falls back to the input on any
/// error.
fn absolutise(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    match env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}
