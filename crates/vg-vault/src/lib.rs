//! `vg-vault` — encrypted placeholder store implementing [`vg_core::VaultStore`].
//!
//! AES-256 at rest (SQLCipher); the DB key is wrapped by the OS keychain and never
//! persisted plaintext; [`vg_core::Secret`] zeroizes on drop; stable placeholders come from
//! the salted HMAC in [`vg_core::keying`] over `(canonical(value), ty, ns)`
//! (`docs/architecture/interface-contracts.md` §5). `IrreversibleRedact` values are never
//! passed to `intern` — that gate is the caller's (the `mask` pipeline's) responsibility,
//! per the contract; this crate stores whatever it is handed.
//!
//! ## Where the keying lives
//!
//! This crate does **not** reimplement canonicalisation or the HMAC — [`intern`](Vault::intern)
//! calls [`vg_core::placeholder_key`] for the stable lookup key and
//! [`vg_core::Keyer::key_for`] for the ordinal/display of a genuinely new value. The one
//! subtlety the T04 review flagged as a hard requirement: a `Keyer` is in-memory and would
//! restart its ordinal counters at `001` after a process restart, so at construction the
//! vault reseeds the `Keyer` from its own persisted `mapping` rows
//! ([`Keyer::seed_ordinal`](vg_core::Keyer::seed_ordinal)) — otherwise a fresh process could
//! mint a second `EMAIL_001` for a different address than the one already recorded. See
//! [`Vault::open_with_key`] and `reseed_ordinals`.
//!
//! ## Concurrency
//!
//! `VaultStore` is `Send + Sync`; a `rusqlite::Connection` is `Send` but not `Sync`, so it
//! is guarded by a `Mutex`. Every method locks it, which also makes `intern`'s
//! check-then-insert atomic within a process. Multiple *processes* sharing one DB file is
//! out of scope for Phase 1 (the reseed happens once, at open); the `UNIQUE` index on the
//! ordinal columns is the backstop if that assumption is ever violated.

mod codec;
mod error;
mod keychain;
mod random;
mod schema;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use vg_core::{
    placeholder_key, EntityType, Keyer, MappingRef, Namespace, Placeholder, Secret, VaultError,
    VaultStore,
};

use crate::codec::{
    entity_columns, entity_from_columns, namespace_columns, namespace_from_columns,
};
use crate::error::{crypto_err, sql_err};
use crate::keychain::load_or_create_db_key;
use crate::random::fill_random;

pub use crate::keychain::load_or_create_actor_pseudonym_key;

/// The default OS-keychain service name under which the DB key is stored.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "com.veilgremlin.vault";

/// How to open a [`Vault`].
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Filesystem path to the SQLCipher database file (created if absent).
    pub db_path: PathBuf,
    /// Keychain service name the DB key is stored under.
    pub keychain_service: String,
    /// Keychain account the DB key is stored under. `None` derives it from `db_path`, so
    /// distinct vault files get distinct keychain entries.
    pub keychain_account: Option<String>,
    /// Time-to-live applied to newly interned mappings. `None` means no expiry (the mapping
    /// lives until explicitly purged). `purge_expired` removes rows past `created_at + ttl`.
    pub default_ttl: Option<Duration>,
}

impl VaultConfig {
    /// A config for `db_path` with the default keychain service, a path-derived account, and
    /// no TTL.
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
            keychain_service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
            keychain_account: None,
            default_ttl: None,
        }
    }

    /// Sets a default TTL for newly interned mappings.
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    fn account(&self) -> String {
        self.keychain_account
            .clone()
            .unwrap_or_else(|| self.db_path.to_string_lossy().into_owned())
    }
}

/// SQLCipher-backed [`VaultStore`]. Construct with [`Vault::open`] (production, keychain-wrapped
/// key) or [`Vault::open_with_key`] (a caller-supplied key, for tests or an alternative key
/// custodian).
pub struct Vault {
    conn: Mutex<Connection>,
    keyer: Keyer,
    salt: Vec<u8>,
    default_ttl: Option<Duration>,
}

impl std::fmt::Debug for Vault {
    /// Deliberately redacting: `Vault` holds the HMAC `salt` (and a `Keyer` that also holds
    /// it), so a derived `Debug` would print secret key material. Only non-sensitive shape is
    /// shown. Added during PR review to satisfy a test's `{:?}` on `Result<Vault, _>` without
    /// a salt-leaking derive.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("default_ttl", &self.default_ttl)
            .field("salt", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens (or creates) the vault at `config.db_path`, fetching the DB encryption key from
    /// the OS keychain — generating and storing a fresh one on first use.
    pub fn open(config: VaultConfig) -> Result<Self, VaultError> {
        let key = load_or_create_db_key(&config.keychain_service, &config.account())?;
        Self::init(config, key)
    }

    /// Opens (or creates) the vault using a caller-supplied 32-byte encryption key, bypassing
    /// the OS keychain entirely.
    ///
    /// This is the seam tests use (with a temp-file DB and a fixed key) so the suite never
    /// depends on — or mutates — the real macOS keychain. It is also the hook for a future
    /// alternative key custodian (an HSM, an env-injected key) without changing the storage
    /// layer. The caller is then responsible for the key's secrecy; the "never persisted
    /// plaintext" guarantee only holds for the [`Vault::open`] keychain path.
    pub fn open_with_key(config: VaultConfig, key: [u8; 32]) -> Result<Self, VaultError> {
        Self::init(config, key)
    }

    fn init(config: VaultConfig, key: [u8; 32]) -> Result<Self, VaultError> {
        if let Some(parent) = config.db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| error::io_err(format!("create {parent:?} failed: {e}")))?;
            }
        }
        let conn = Connection::open(&config.db_path)
            .map_err(|e| error::io_err(format!("open {:?} failed: {e}", config.db_path)))?;
        // T09 made one-process-per-hook the normal operating mode, and Claude Code issues
        // parallel tool calls — so concurrent short-lived processes on this DB file are
        // now expected, not out of scope. A busy timeout turns a write collision into a
        // brief wait instead of an immediate SQLITE_BUSY -> blocked hook (doubt-pass
        // finding). Cross-process ordinal reseed races remain a documented Phase-1 limit.
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql_err)?;
        apply_key(&conn, &key)?;
        conn.execute_batch(schema::SCHEMA).map_err(sql_err)?;

        let salt = load_or_create_salt(&conn)?;
        let keyer = Keyer::new(salt.clone());
        reseed_ordinals(&conn, &keyer)?;

        Ok(Self {
            conn: Mutex::new(conn),
            keyer,
            salt,
            default_ttl: config.default_ttl,
        })
    }
}

/// Applies the raw 32-byte key via SQLCipher's `PRAGMA key` (the `x'...'` raw-key form, which
/// skips SQLCipher's passphrase KDF since we supply real key bytes), then forces a read so a
/// wrong key surfaces immediately as a `Crypto` error rather than later mid-operation.
fn apply_key(conn: &Connection, key: &[u8; 32]) -> Result<(), VaultError> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .map_err(|e| crypto_err(format!("PRAGMA key failed: {e}")))?;
    // Touching the schema decrypts the first page; a bad key fails here.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|e| crypto_err(format!("database key verification failed: {e}")))?;
    Ok(())
}

/// Fetches the per-install keying salt from `meta`, generating and storing a fresh random
/// 32-byte salt the first time. The salt lives inside the SQLCipher-encrypted DB, so it is
/// protected by the keychain-wrapped DB key; a compiled-in constant would make "salted" a
/// no-op across installs (see `vg_core::keying::placeholder_key`'s own note).
fn load_or_create_salt(conn: &Connection) -> Result<Vec<u8>, VaultError> {
    let existing: Option<Vec<u8>> = conn
        .query_row("SELECT v FROM meta WHERE k = 'salt'", [], |r| r.get(0))
        .optional()
        .map_err(sql_err)?;
    if let Some(salt) = existing {
        return Ok(salt);
    }
    let mut salt = [0u8; 32];
    fill_random(&mut salt)?;
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('salt', ?1)",
        params![&salt[..]],
    )
    .map_err(sql_err)?;
    Ok(salt.to_vec())
}

/// Reseeds `keyer`'s ordinal counters from the persisted `mapping` rows so a fresh process
/// continues each `(namespace, entity type)` sequence where the durable store left off
/// (T05's hard requirement — see the crate-level doc). A corrupt row (unparseable namespace)
/// is skipped rather than failing the open.
fn reseed_ordinals(conn: &Connection, keyer: &Keyer) -> Result<(), VaultError> {
    let mut stmt = conn
        .prepare(
            "SELECT ns_kind, ns_id, entity_kind, entity_custom, MAX(ordinal) \
             FROM mapping GROUP BY ns_kind, ns_id, entity_kind, entity_custom",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(sql_err)?;
    for row in rows {
        let (ns_kind, ns_id, entity_kind, entity_custom, max_ord) = row.map_err(sql_err)?;
        let Some(ns) = namespace_from_columns(&ns_kind, &ns_id) else {
            continue;
        };
        let ty = entity_from_columns(&entity_kind, entity_custom.as_deref());
        keyer.seed_ordinal(&ns, &ty, max_ord.max(0) as u64);
    }
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl VaultStore for Vault {
    fn intern(
        &self,
        value: &Secret,
        ty: EntityType,
        ns: &Namespace,
    ) -> Result<Placeholder, VaultError> {
        // Non-mutating lookup key: placeholder_key does not touch the Keyer's ordinal
        // counter, so an already-interned value is found and returned without minting (and
        // wasting) a new ordinal.
        let key = placeholder_key(&self.salt, value.expose_secret(), &ty, ns);
        let key_hex = key.to_hex();

        let conn = self.conn.lock().expect("vault mutex poisoned");

        if let Some((existing, expires_at)) = lookup_by_key(&conn, &key_hex)? {
            // Codex doubt-pass (2026-07-17): a matching row might be expired-but-not-yet-purged.
            // `resolve` filters on expiry (returns NotFound for an expired mapping) but this
            // lookup did not, so returning the row as-is could hand back a placeholder that
            // `resolve` immediately rejects. The value is being actively interned again, so
            // renew its TTL (re-minting `expires_at` exactly as a fresh intern would — `NULL`
            // when no TTL is configured) and return the SAME, stable placeholder. `key_hex` is
            // the PRIMARY KEY, so minting a divergent new row for the same value is impossible
            // anyway — renewal is the only correct move.
            if expires_at.is_some_and(|e| e <= unix_now()) {
                let renewed = self
                    .default_ttl
                    .map(|ttl| unix_now().saturating_add(ttl.as_secs() as i64));
                conn.prepare_cached("UPDATE mapping SET expires_at = ?1 WHERE key_hex = ?2")
                    .map_err(sql_err)?
                    .execute(params![renewed, key_hex])
                    .map_err(sql_err)?;
            }
            return Ok(existing);
        }

        // Genuinely new value: now let the Keyer assign the next ordinal/display for
        // (ns, ty). Its counter was reseeded from persisted rows at open, so this continues
        // the durable sequence rather than restarting it.
        let keyed = self.keyer.key_for(value.expose_secret(), ty.clone(), ns);
        debug_assert_eq!(
            keyed.key.to_hex(),
            key_hex,
            "keyer and placeholder_key must agree"
        );

        let mapping_ref = Uuid::new_v4();
        let (ns_kind, ns_id) = namespace_columns(ns);
        let (entity_kind, entity_custom) = entity_columns(&ty);
        let created_at = unix_now();
        let expires_at = self
            .default_ttl
            .map(|ttl| created_at.saturating_add(ttl.as_secs() as i64));

        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO mapping \
                 (key_hex, mapping_ref, display, ordinal, ns_kind, ns_id, entity_kind, \
                  entity_custom, value, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .map_err(sql_err)?;
        stmt.execute(params![
            key_hex,
            mapping_ref.to_string(),
            keyed.display,
            keyed.ordinal as i64,
            ns_kind,
            ns_id,
            entity_kind,
            entity_custom,
            value.expose_secret(),
            created_at,
            expires_at,
        ])
        .map_err(sql_err)?;

        Ok(Placeholder {
            display: keyed.display,
            mapping_ref: MappingRef(mapping_ref),
        })
    }

    fn resolve(&self, p: &Placeholder, ns: &Namespace) -> Result<Secret, VaultError> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let ref_str = p.mapping_ref.0.to_string();
        let (want_kind, want_id) = namespace_columns(ns);

        let row: Option<(String, String, String, Option<i64>)> = conn
            .prepare_cached(
                "SELECT value, ns_kind, ns_id, expires_at FROM mapping WHERE mapping_ref = ?1",
            )
            .map_err(sql_err)?
            .query_row(params![ref_str], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()
            .map_err(sql_err)?;

        // Namespace mismatch and expiry are both reported as NotFound — never distinguish
        // "exists in another namespace" from "doesn't exist" (interface-contracts.md §5).
        let resolved = row.and_then(|(value, ns_kind, ns_id, expires_at)| {
            let ns_matches = ns_kind == want_kind && ns_id == want_id;
            let expired = expires_at.is_some_and(|e| e <= unix_now());
            (ns_matches && !expired).then_some(value)
        });

        record_demask_event(&conn, &ref_str, want_kind, &want_id, resolved.is_some())?;

        match resolved {
            Some(value) => Ok(Secret::new(value)),
            None => Err(VaultError::NotFound),
        }
    }

    fn purge_expired(&self) -> Result<usize, VaultError> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let now = unix_now();
        let removed = conn
            .prepare_cached("DELETE FROM mapping WHERE expires_at IS NOT NULL AND expires_at <= ?1")
            .map_err(sql_err)?
            .execute(params![now])
            .map_err(sql_err)?;
        Ok(removed)
    }
}

/// Looks up an existing mapping by its HMAC key, returning the persisted placeholder and its
/// `expires_at` (if any). `intern` needs the expiry too, to distinguish a live row from an
/// expired-but-not-yet-purged one (Codex doubt-pass, 2026-07-17).
fn lookup_by_key(
    conn: &Connection,
    key_hex: &str,
) -> Result<Option<(Placeholder, Option<i64>)>, VaultError> {
    let row: Option<(String, String, Option<i64>)> = conn
        .prepare_cached("SELECT display, mapping_ref, expires_at FROM mapping WHERE key_hex = ?1")
        .map_err(sql_err)?
        .query_row(params![key_hex], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()
        .map_err(sql_err)?;

    match row {
        Some((display, ref_str, expires_at)) => {
            let uuid = Uuid::parse_str(&ref_str)
                .map_err(|e| crypto_err(format!("corrupt mapping_ref {ref_str:?}: {e}")))?;
            Ok(Some((
                Placeholder {
                    display,
                    mapping_ref: MappingRef(uuid),
                },
                expires_at,
            )))
        }
        None => Ok(None),
    }
}

/// Appends one row to the demask log for a `resolve` attempt (success or not). Holds only the
/// opaque mapping_ref and namespace — never the value.
fn record_demask_event(
    conn: &Connection,
    mapping_ref: &str,
    ns_kind: &str,
    ns_id: &str,
    success: bool,
) -> Result<(), VaultError> {
    conn.prepare_cached(
        "INSERT INTO demask_event (id, mapping_ref, ns_kind, ns_id, requested_at, success) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .map_err(sql_err)?
    .execute(params![
        Uuid::new_v4().to_string(),
        mapping_ref,
        ns_kind,
        ns_id,
        unix_now(),
        i64::from(success),
    ])
    .map_err(sql_err)?;
    Ok(())
}

/// Count of demask-log rows — exposed for callers/tests that want to assert the demask audit
/// trail without a second SQL layer. Not part of the `VaultStore` trait.
impl Vault {
    /// Number of rows in the append-only demask log.
    pub fn demask_event_count(&self) -> Result<usize, VaultError> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let n: i64 = conn
            .query_row("SELECT count(*) FROM demask_event", [], |r| r.get(0))
            .map_err(sql_err)?;
        Ok(n as usize)
    }

    /// Number of live (non-purged) mapping rows.
    pub fn mapping_count(&self) -> Result<usize, VaultError> {
        let conn = self.conn.lock().expect("vault mutex poisoned");
        let n: i64 = conn
            .query_row("SELECT count(*) FROM mapping", [], |r| r.get(0))
            .map_err(sql_err)?;
        Ok(n as usize)
    }
}

/// Compile-time assertion that the concrete `Vault` satisfies the trait's `Send + Sync`
/// bound (a `rusqlite::Connection` is `!Sync`, so this fails to compile if the `Mutex`
/// wrapper is ever removed).
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Vault>();
};
