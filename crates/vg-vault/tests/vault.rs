//! Integration tests for the SQLCipher-backed `Vault`.
//!
//! All tests use `Vault::open_with_key` with a temp-file DB and a fixed key, so the suite
//! never touches (or mutates) the real OS keychain — see `Vault::open_with_key`'s doc.

use std::time::Duration;

use tempfile::TempDir;
use uuid::Uuid;

use vg_core::{
    EntityType, Namespace, Placeholder, RepoId, Secret, SessionId, VaultError, VaultStore,
};
use vg_vault::{Vault, VaultConfig};

const TEST_KEY: [u8; 32] = [7u8; 32];

fn open(dir: &TempDir) -> Vault {
    Vault::open_with_key(VaultConfig::new(dir.path().join("vault.db")), TEST_KEY)
        .expect("vault opens")
}

fn open_with_ttl(dir: &TempDir, ttl: Duration) -> Vault {
    Vault::open_with_key(
        VaultConfig::new(dir.path().join("vault.db")).with_default_ttl(ttl),
        TEST_KEY,
    )
    .expect("vault opens")
}

fn repo(id: &str) -> Namespace {
    Namespace::Repo(RepoId(id.to_string()))
}

#[test]
fn satisfies_the_vault_roundtrip_contract() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    // assert_vault_roundtrip checks: stable placeholder on re-intern, correct resolve, and
    // namespace isolation (resolve under a different namespace must fail).
    vg_core::conformance::assert_vault_roundtrip(
        &vault,
        "jane.doe@example.com",
        EntityType::Email,
        &repo("acme/widgets"),
        &repo("acme/other"),
    );
}

#[test]
fn stable_placeholder_display_for_the_same_value() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let ns = repo("acme/widgets");
    let a = vault
        .intern(
            &Secret::new("jane@example.com".into()),
            EntityType::Email,
            &ns,
        )
        .unwrap();
    let b = vault
        .intern(
            &Secret::new("Jane@Example.com".into()),
            EntityType::Email,
            &ns,
        ) // case-fold
        .unwrap();
    assert_eq!(a.display, b.display, "canonicalised value must be stable");
    assert_eq!(a.mapping_ref, b.mapping_ref);
    assert_eq!(a.display, "EMAIL_001");
}

#[test]
fn distinct_values_get_sequential_ordinals() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let ns = repo("acme/widgets");
    let first = vault
        .intern(&Secret::new("a@example.com".into()), EntityType::Email, &ns)
        .unwrap();
    let second = vault
        .intern(&Secret::new("b@example.com".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(first.display, "EMAIL_001");
    assert_eq!(second.display, "EMAIL_002");
}

#[test]
fn ordinals_continue_after_reopen_not_restart_at_001() {
    // The T05 hard requirement: a fresh Keyer after a process restart must not hand out a
    // second EMAIL_001 for a different address than the one already persisted.
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");
    let first_ref;
    {
        let vault = open(&dir);
        let a = vault
            .intern(&Secret::new("a@example.com".into()), EntityType::Email, &ns)
            .unwrap();
        let b = vault
            .intern(&Secret::new("b@example.com".into()), EntityType::Email, &ns)
            .unwrap();
        assert_eq!(a.display, "EMAIL_001");
        assert_eq!(b.display, "EMAIL_002");
        first_ref = a.mapping_ref;
    } // vault dropped -> simulates process exit; Keyer state gone, DB persists

    let reopened = open(&dir); // fresh in-memory Keyer, reseeded from the DB
    let c = reopened
        .intern(&Secret::new("c@example.com".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(
        c.display, "EMAIL_003",
        "a new value after reopen must continue the sequence, not collide at 001"
    );

    // And an already-persisted value still resolves to its original placeholder + ordinal.
    let a_again = reopened
        .intern(&Secret::new("a@example.com".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(a_again.display, "EMAIL_001");
    assert_eq!(a_again.mapping_ref, first_ref);
}

#[test]
fn value_persists_and_resolves_across_reopen() {
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");
    let placeholder;
    {
        let vault = open(&dir);
        placeholder = vault
            .intern(
                &Secret::new("secret-value".into()),
                EntityType::AccountId,
                &ns,
            )
            .unwrap();
    }
    let reopened = open(&dir);
    let resolved = reopened.resolve(&placeholder, &ns).unwrap();
    assert_eq!(resolved.expose_secret(), "secret-value");
}

#[test]
fn resolve_under_wrong_namespace_is_not_found() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let placeholder = vault
        .intern(
            &Secret::new("s".into()),
            EntityType::Secret,
            &repo("repo-a"),
        )
        .unwrap();
    let err = vault
        .resolve(&placeholder, &repo("repo-b"))
        .expect_err("cross-namespace resolve must fail");
    assert!(matches!(err, VaultError::NotFound));
}

#[test]
fn resolve_unknown_placeholder_is_not_found() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let bogus = Placeholder {
        display: "EMAIL_999".to_string(),
        mapping_ref: vg_core::MappingRef(Uuid::new_v4()),
    };
    assert!(matches!(
        vault.resolve(&bogus, &repo("acme/widgets")),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn every_resolve_attempt_is_logged_to_the_demask_table() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let ns = repo("acme/widgets");
    let placeholder = vault
        .intern(&Secret::new("v".into()), EntityType::Secret, &ns)
        .unwrap();

    let _ = vault.resolve(&placeholder, &ns); // success
    let _ = vault.resolve(&placeholder, &repo("other")); // denied (ns mismatch)
    assert_eq!(
        vault.demask_event_count().unwrap(),
        2,
        "both the successful and the denied resolve must be logged"
    );
}

#[test]
fn purge_expired_removes_only_expired_rows() {
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");

    // TTL of zero: expires_at == created_at, which is <= now at purge time.
    let expiring = open_with_ttl(&dir, Duration::from_secs(0));
    expiring
        .intern(&Secret::new("ephemeral".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(expiring.mapping_count().unwrap(), 1);

    let removed = expiring.purge_expired().unwrap();
    assert_eq!(removed, 1);
    assert_eq!(expiring.mapping_count().unwrap(), 0);
}

#[test]
fn re_interning_an_expired_but_unpurged_value_renews_it_and_stays_resolvable() {
    // Codex doubt-pass (2026-07-17): intern's lookup did not filter expiry, so it could
    // return an expired-but-unpurged row's placeholder — one `resolve` then rejected as
    // expired, i.e. intern handing back an immediately-unresolvable placeholder. The fix
    // renews the TTL on re-intern and returns the same stable placeholder.
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");

    // 1. Intern with a zero TTL so the row is immediately expired but not purged.
    let first = {
        let vault = open_with_ttl(&dir, Duration::from_secs(0));
        vault
            .intern(&Secret::new("recurring".into()), EntityType::Email, &ns)
            .unwrap()
    };

    // 2. Reopen with a real TTL and re-intern the same value.
    let vault = open_with_ttl(&dir, Duration::from_secs(3600));
    let again = vault
        .intern(&Secret::new("recurring".into()), EntityType::Email, &ns)
        .unwrap();

    // Same value -> same stable placeholder (not a divergent new mint).
    assert_eq!(again.display, first.display);
    assert_eq!(again.mapping_ref, first.mapping_ref);

    // And — the actual bug — it now resolves, because re-intern renewed the expiry.
    assert_eq!(
        vault.resolve(&again, &ns).unwrap().expose_secret(),
        "recurring",
        "a re-interned value must be resolvable, not stuck expired"
    );
    // Still exactly one row (renewed in place, not duplicated).
    assert_eq!(vault.mapping_count().unwrap(), 1);
}

#[test]
fn purge_leaves_non_expiring_rows() {
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");
    let vault = open(&dir); // no TTL -> expires_at is NULL
    vault
        .intern(&Secret::new("kept".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(vault.purge_expired().unwrap(), 0);
    assert_eq!(vault.mapping_count().unwrap(), 1);
}

#[test]
fn ordinals_are_scoped_per_namespace() {
    let dir = TempDir::new().unwrap();
    let vault = open(&dir);
    let a = vault
        .intern(
            &Secret::new("x@example.com".into()),
            EntityType::Email,
            &repo("a"),
        )
        .unwrap();
    let b = vault
        .intern(
            &Secret::new("y@example.com".into()),
            EntityType::Email,
            &repo("b"),
        )
        .unwrap();
    assert_eq!(a.display, "EMAIL_001");
    assert_eq!(
        b.display, "EMAIL_001",
        "each namespace has its own sequence"
    );
    assert_ne!(a.mapping_ref, b.mapping_ref);
}

#[test]
fn the_ordinal_unique_guard_fires_for_a_fixed_entity_type_null_entity_custom() {
    // Codex critique (2026-07-17): the UNIQUE ordinal index keyed on the bare
    // `entity_custom` column did NOT protect fixed entity types (Email, Iban, ...), because
    // those store entity_custom = NULL and SQLite treats NULL as distinct in a UNIQUE index
    // — so two writers racing the in-memory counter could both persist EMAIL_001 for
    // different secrets in the same namespace. With `COALESCE(entity_custom, '')` the guard
    // now fires. Simulate the race with two Vault instances that both reseed from the empty
    // DB and each independently mint EMAIL_001.
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");
    let v1 = open(&dir);
    let v2 = open(&dir); // both reseeded from the (empty) DB: both counters start at 0

    let first = v1
        .intern(&Secret::new("a@example.com".into()), EntityType::Email, &ns)
        .unwrap();
    assert_eq!(first.display, "EMAIL_001");

    // v2's independent Keyer also mints EMAIL_001 (ordinal 1) for a *different* value; the
    // INSERT must now be rejected by the UNIQUE ordinal guard instead of silently creating a
    // second EMAIL_001 row.
    let second = v2.intern(&Secret::new("b@example.com".into()), EntityType::Email, &ns);
    assert!(
        second.is_err(),
        "a duplicate EMAIL_001 for a fixed entity type must be rejected, got {second:?}"
    );
}

#[test]
fn the_ordinal_unique_guard_fires_across_different_custom_classes() {
    // Regression for the custom-entity-label leak fix (docs/decisions.md, 2026-08-01):
    // the display tag for every `Custom(name)` value now collapses to a shared "CUSTOM"
    // prefix regardless of `name` (vg-core::keying), so two *different* custom classes in
    // the same namespace must share one ordinal domain, not one each -- otherwise two
    // unrelated values could both mint the literally identical display string
    // "CUSTOM_001". This is the same race-safety pattern as
    // `the_ordinal_unique_guard_fires_for_a_fixed_entity_type_null_entity_custom` above,
    // but across `entity_custom` values instead of within one.
    let dir = TempDir::new().unwrap();
    let ns = repo("acme/widgets");
    let v1 = open(&dir);
    let v2 = open(&dir); // both reseeded from the (empty) DB: both counters start at 0

    let first = v1
        .intern(
            &Secret::new("Project Nightingale".into()),
            EntityType::Custom("internal-project-codename".to_string()),
            &ns,
        )
        .unwrap();
    assert_eq!(first.display, "CUSTOM_001");

    // v2's independent Keyer also mints CUSTOM_001 (ordinal 1) for a *different* custom
    // class in the same namespace; the INSERT must be rejected by the UNIQUE ordinal
    // guard rather than silently creating a second CUSTOM_001 row that collides in
    // rendered display text with the first, unrelated value.
    let second = v2.intern(
        &Secret::new("Q4 financial forecast".into()),
        EntityType::Custom("board-material".to_string()),
        &ns,
    );
    assert!(
        second.is_err(),
        "a duplicate CUSTOM_001 across two different custom classes must be rejected, got {second:?}"
    );
}

#[test]
fn wrong_key_fails_to_open() {
    let dir = TempDir::new().unwrap();
    {
        let vault = open(&dir);
        vault
            .intern(&Secret::new("v".into()), EntityType::Email, &repo("r"))
            .unwrap();
    }
    let wrong = Vault::open_with_key(VaultConfig::new(dir.path().join("vault.db")), [9u8; 32]);
    assert!(
        matches!(wrong, Err(VaultError::Crypto(_))),
        "opening with the wrong key must be a Crypto error, got {wrong:?}"
    );
}

#[test]
fn session_namespace_round_trips_across_reopen() {
    // Exercises the session (UUID-backed) namespace codec path, not just repo.
    let dir = TempDir::new().unwrap();
    let ns = Namespace::Session(SessionId(Uuid::from_u128(1234)));
    let placeholder;
    {
        let vault = open(&dir);
        placeholder = vault
            .intern(&Secret::new("tok".into()), EntityType::TraceId, &ns)
            .unwrap();
    }
    let reopened = open(&dir);
    // A new value in the same session must continue the ordinal sequence after reseed.
    let second = reopened
        .intern(&Secret::new("tok2".into()), EntityType::TraceId, &ns)
        .unwrap();
    assert_eq!(second.display, "TRACE_ID_002");
    assert_eq!(
        reopened.resolve(&placeholder, &ns).unwrap().expose_secret(),
        "tok"
    );
}
