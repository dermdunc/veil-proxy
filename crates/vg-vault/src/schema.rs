//! SQLCipher schema for the vault.
//!
//! The whole database file is AES-256 encrypted by SQLCipher (`PRAGMA key`, set in
//! `lib.rs` before any of this runs), so a value stored in a column is encrypted at rest by
//! that whole-DB encryption — this crate does not add a second, app-level cipher on top of
//! it. `interface-contracts.md` §5's "AES-256 at rest (SQLCipher)" is satisfied by the
//! SQLCipher layer itself.

/// Idempotent DDL run on every open. `IF NOT EXISTS` throughout so re-opening an existing
/// vault is a no-op; there is only one schema version in Phase 1.
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

-- One row per interned (value, entity type, namespace). `key_hex` is the salted HMAC
-- placeholder key (vg_core::keying::placeholder_key, hex-encoded) and is the stable lookup
-- key for `intern`'s "already interned?" check. `value` is the raw secret, protected by the
-- surrounding SQLCipher encryption. `ordinal`/`display` are the human-readable placeholder
-- (EMAIL_001) minted by the Keyer.
CREATE TABLE IF NOT EXISTS mapping (
    key_hex       TEXT PRIMARY KEY,
    mapping_ref   TEXT NOT NULL UNIQUE,
    display       TEXT NOT NULL,
    ordinal       INTEGER NOT NULL,
    ns_kind       TEXT NOT NULL,
    ns_id         TEXT NOT NULL,
    entity_kind   TEXT NOT NULL,
    entity_custom TEXT,
    value         TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER
);

-- Defends the per-(namespace, rendered display tag) ordinal sequence: two different values
-- must never land on the same display ordinal within one namespace/tag, even if a second
-- writer raced the in-memory counter.
--
-- `COALESCE(entity_custom, '')`, not the bare column, is deliberate (Codex critique,
-- 2026-07-17): SQLite treats NULL as DISTINCT in a UNIQUE index, and every fixed entity type
-- (Email, Iban, ...) stores entity_custom = NULL. With the bare column the guard therefore
-- did NOT fire for any fixed type — two racing writers could both insert EMAIL_001 for
-- different secrets in the same namespace, exactly the collision this index exists to stop.
-- COALESCEing NULL to '' makes all fixed-type rows share one key value, so the UNIQUE
-- constraint applies uniformly.
--
-- The `CASE` collapses `entity_custom` to '' for every `entity_kind = 'custom'` row too
-- (fixed 2026-08-01, closing the custom-entity-label leak alongside the vg-core display/
-- redaction-marker fixes): `Custom(name)` values used to keep their own per-name
-- discriminator here, so two *different* custom classes could each independently mint
-- ordinal 1 in the same namespace. Since vg-core's display tag for Custom now collapses
-- to a fixed "CUSTOM" prefix regardless of `name` (the class name must never reach
-- rendered text), those two rows would then both display as the literally identical
-- "CUSTOM_001" -- this index must enforce uniqueness across custom classes, not just
-- within one, to match. Fixed-type rows are unaffected: the CASE is a no-op for them
-- since their entity_custom is always NULL already.
--
-- No migration: `docs/decisions.md` (2026-08-01) verified no `.veilgremlin` state dir or
-- `vault.db` exists on this machine, so no persisted vault holds pre-fix `entity_kind =
-- 'custom'` rows. `CREATE INDEX IF NOT EXISTS` is a no-op against an already-created index
-- of the same name — any vault created before this fix ships would need its index dropped
-- and recreated, not just a reopen, to pick up the new definition.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mapping_ordinal
    ON mapping (
        ns_kind, ns_id, entity_kind,
        CASE WHEN entity_kind = 'custom' THEN '' ELSE COALESCE(entity_custom, '') END,
        ordinal
    );

-- `resolve`/`purge_expired` lookups.
CREATE INDEX IF NOT EXISTS idx_mapping_ref ON mapping (mapping_ref);
CREATE INDEX IF NOT EXISTS idx_mapping_expiry ON mapping (expires_at);

-- Append-only demask log: one row per `resolve` attempt (success or not), so a reversal is
-- always attributable. Holds only the opaque mapping_ref and namespace — never the value.
CREATE TABLE IF NOT EXISTS demask_event (
    id           TEXT PRIMARY KEY,
    mapping_ref  TEXT NOT NULL,
    ns_kind      TEXT NOT NULL,
    ns_id        TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    success      INTEGER NOT NULL
);
"#;
