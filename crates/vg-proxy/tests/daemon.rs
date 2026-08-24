//! Plan §10.3 milestone 2 tests: "single-open-across-N-requests assertion; correct namespace
//! routing per session token." Follows `vg-vault`'s own established test convention
//! (`Vault::open_with_key` with a temp-file DB and a fixed key, never touching the real OS
//! keychain).

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use tempfile::TempDir;
use uuid::Uuid;
use vg_core::{MappingRef, Namespace, PlaceholderBinding, PolicyLayers, SessionId};
use vg_proxy::{Daemon, ProxyError, SessionConflict, SessionError};
use vg_vault::VaultConfig;

const TEST_KEY: [u8; 32] = [7u8; 32];

fn global_policy_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vg-policy/fixtures/global.policy.json")
}

fn open_daemon(dir: &TempDir) -> Daemon {
    Daemon::open_with_key(
        VaultConfig::new(dir.path().join("vault.db")),
        TEST_KEY,
        PolicyLayers {
            global: global_policy_path(),
            repo: None,
            session: None,
        },
        dir.path().join("audit.jsonl"),
    )
    .expect("daemon opens")
}

/// The milestone's own test description, directly: one `Daemon` opened once (the only
/// `Daemon::open_with_key` call in this test) reused for many sequential fake requests across
/// two distinct session tokens, proving both properties at once — the same daemon serves many
/// requests, and each session's header resolves to its own distinct, stable `Namespace`.
#[test]
fn single_open_serves_many_fake_requests_with_correct_namespace_routing() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);

    let session_a = Uuid::new_v4().to_string();
    let session_b = Uuid::new_v4().to_string();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    for i in 0..20 {
        let header = if i % 2 == 0 { &session_a } else { &session_b };
        let (namespace, _purged) = daemon
            .handle_fake_request(Some(header), addr)
            .unwrap_or_else(|err| panic!("fake request {i} should succeed: {err}"));

        let expected = Namespace::Session(SessionId(Uuid::parse_str(header).unwrap()));
        assert_eq!(
            namespace, expected,
            "request {i} routed to the wrong namespace"
        );
    }
}

#[test]
fn missing_header_and_unregistered_addr_fails_closed() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

    let err = daemon
        .handle_fake_request(None, addr)
        .expect_err("an unregistered address with no header must fail closed");
    assert!(matches!(
        err,
        ProxyError::Session(SessionError::UnregisteredAddr(a)) if a == addr
    ));
}

#[test]
fn registered_addr_resolves_when_header_is_absent() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54322".parse().unwrap();
    let namespace = Namespace::Session(SessionId(Uuid::new_v4()));
    assert_eq!(daemon.register_port(addr, namespace.clone()).unwrap(), None);

    let (resolved, _) = daemon
        .handle_fake_request(None, addr)
        .expect("registered address should resolve");
    assert_eq!(resolved, namespace);
}

#[test]
fn header_takes_priority_over_a_registered_addr() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54323".parse().unwrap();
    let addr_namespace = Namespace::Session(SessionId(Uuid::new_v4()));
    daemon.register_port(addr, addr_namespace.clone()).unwrap();

    let header_session = Uuid::new_v4().to_string();
    let (resolved, _) = daemon
        .handle_fake_request(Some(&header_session), addr)
        .expect("header path should resolve");
    assert_ne!(resolved, addr_namespace);
    assert_eq!(
        resolved,
        Namespace::Session(SessionId(Uuid::parse_str(&header_session).unwrap()))
    );
}

#[test]
fn invalid_header_fails_closed_even_if_the_addr_is_registered() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54324".parse().unwrap();
    daemon
        .register_port(addr, Namespace::Session(SessionId(Uuid::new_v4())))
        .unwrap();

    let err = daemon
        .handle_fake_request(Some("not-a-uuid"), addr)
        .expect_err("an invalid header must fail closed, not silently fall back to the port");
    assert!(matches!(
        err,
        ProxyError::Session(SessionError::InvalidNamespaceHeader(_))
    ));
}

/// Doubt-pass finding (cross-model): the nil UUID is a common uninitialized/default sentinel
/// and must not be accepted as a legitimate, distinct namespace.
#[test]
fn nil_uuid_header_fails_closed() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54330".parse().unwrap();

    let err = daemon
        .handle_fake_request(Some("00000000-0000-0000-0000-000000000000"), addr)
        .expect_err("the nil UUID must not resolve to a valid namespace");
    assert!(matches!(
        err,
        ProxyError::Session(SessionError::InvalidNamespaceHeader(_))
    ));
}

/// Doubt-pass finding: a port-only key would collide across a dual-stack daemon binding both
/// `127.0.0.1` and `::1` on the same numeric port. Registering the same port number on two
/// different loopback IPs must resolve to two independent namespaces, not collide.
#[test]
fn same_port_different_loopback_ip_resolves_independently() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let v4_addr: SocketAddr = "127.0.0.1:54325".parse().unwrap();
    let v6_addr: SocketAddr = "[::1]:54325".parse().unwrap();
    let v4_namespace = Namespace::Session(SessionId(Uuid::new_v4()));
    let v6_namespace = Namespace::Session(SessionId(Uuid::new_v4()));

    daemon.register_port(v4_addr, v4_namespace.clone()).unwrap();
    daemon.register_port(v6_addr, v6_namespace.clone()).unwrap();

    let (resolved_v4, _) = daemon.handle_fake_request(None, v4_addr).unwrap();
    let (resolved_v6, _) = daemon.handle_fake_request(None, v6_addr).unwrap();
    assert_eq!(resolved_v4, v4_namespace);
    assert_eq!(resolved_v6, v6_namespace);
    assert_ne!(resolved_v4, resolved_v6);
}

/// Doubt-pass finding (round 2, cross-model): registration must be refused for a non-loopback
/// address, the same fail-closed property M1 already enforces at the listener-bind boundary.
#[test]
fn register_port_refuses_non_loopback_address() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "0.0.0.0:54331".parse().unwrap();
    let namespace = Namespace::Session(SessionId(Uuid::new_v4()));

    let err = daemon
        .register_port(addr, namespace)
        .expect_err("registering a non-loopback address must fail");
    assert!(matches!(
        err,
        ProxyError::Session(SessionError::NotLoopback(a)) if a == addr
    ));
}

/// Doubt-pass finding: `register_port`'s silent overwrite needs a stricter alternative for a
/// caller that wants "clobbering an existing mapping is always suspicious."
#[test]
fn register_port_if_absent_rejects_a_conflicting_overwrite_but_allows_renewal() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54332".parse().unwrap();
    let first = Namespace::Session(SessionId(Uuid::new_v4()));
    let second = Namespace::Session(SessionId(Uuid::new_v4()));

    daemon
        .register_port_if_absent(addr, first.clone())
        .expect("first registration into an empty slot should succeed");

    // Idempotent renewal of the SAME namespace still succeeds.
    daemon
        .register_port_if_absent(addr, first.clone())
        .expect("re-registering the same namespace should succeed");

    // A different namespace trying to claim the same address is rejected, not silently applied.
    let conflict = daemon
        .register_port_if_absent(addr, second)
        .expect_err("a conflicting namespace must be rejected");
    assert!(matches!(conflict, SessionConflict::AlreadyRegistered(ns) if ns == first));

    let (resolved, _) = daemon.handle_fake_request(None, addr).unwrap();
    assert_eq!(
        resolved, first,
        "the rejected conflict must not have taken effect"
    );
}

/// Doubt-pass finding: `register_port`'s previously-registered-namespace return, used to
/// observe (not prevent) an overwrite.
#[test]
fn register_port_returns_the_previous_namespace_on_overwrite() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
    let first = Namespace::Session(SessionId(Uuid::new_v4()));
    let second = Namespace::Session(SessionId(Uuid::new_v4()));

    assert_eq!(daemon.register_port(addr, first.clone()).unwrap(), None);
    assert_eq!(
        daemon.register_port(addr, second.clone()).unwrap(),
        Some(first)
    );

    let (resolved, _) = daemon.handle_fake_request(None, addr).unwrap();
    assert_eq!(resolved, second);
}

/// Doubt-pass finding (round 2, cross-model): `unregister_port` must be compare-and-remove, or
/// a stale session's delayed cleanup can delete a *different*, newer session's live mapping
/// after a handoff. Session A's cleanup naming its own (stale) namespace must be a no-op once
/// B has taken over the address; only a cleanup naming the *currently* registered namespace
/// actually removes it.
#[test]
fn unregister_port_is_compare_and_remove_not_remove_by_address_alone() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let addr: SocketAddr = "127.0.0.1:54327".parse().unwrap();
    let session_a = Namespace::Session(SessionId(Uuid::new_v4()));
    let session_b = Namespace::Session(SessionId(Uuid::new_v4()));

    daemon.register_port(addr, session_a.clone()).unwrap();
    // B takes over the address (e.g. after the OS reused the port for a new session).
    daemon.register_port(addr, session_b.clone()).unwrap();

    // A's stale cleanup, naming A, must NOT remove B's live mapping.
    assert!(!daemon.unregister_port(addr, &session_a));
    let (resolved, _) = daemon.handle_fake_request(None, addr).unwrap();
    assert_eq!(resolved, session_b, "A's stale cleanup must not evict B");

    // B's own cleanup, naming B, does remove it.
    assert!(daemon.unregister_port(addr, &session_b));
    let err = daemon
        .handle_fake_request(None, addr)
        .expect_err("address should fail closed once its registration is released");
    assert!(matches!(
        err,
        ProxyError::Session(SessionError::UnregisteredAddr(a)) if a == addr
    ));
}

/// H1's fix (§8.5): the accumulated binding store isolates per `Namespace`, and starts empty
/// for anything nobody has recorded into yet — the expected M2 state for every namespace,
/// since nothing populates real content until request masking exists.
#[test]
fn binding_store_is_empty_by_default_and_isolated_per_namespace() {
    let dir = TempDir::new().unwrap();
    let daemon = open_daemon(&dir);
    let ns_a = Namespace::Session(SessionId(Uuid::new_v4()));
    let ns_b = Namespace::Session(SessionId(Uuid::new_v4()));

    assert!(daemon.bindings_for(&ns_a).is_empty());

    daemon.record_bindings(
        &ns_a,
        vec![PlaceholderBinding {
            display: "EMAIL_001".to_string(),
            mapping_ref: MappingRef(Uuid::new_v4()),
        }],
    );

    assert_eq!(daemon.bindings_for(&ns_a).len(), 1);
    assert!(
        daemon.bindings_for(&ns_b).is_empty(),
        "recording into ns_a must not leak into ns_b"
    );
}

/// Doubt-pass finding: no concurrency coverage existed despite two `Mutex`es guarding shared
/// state. Many threads hammer `register_port`/`resolve`/`record_bindings`/`bindings_for`
/// concurrently across distinct addresses/namespaces; nothing should panic (in particular,
/// mutex poisoning from one thread must not cascade — the fix under test), and each thread's
/// own writes must be visible under its own key afterward.
#[test]
fn concurrent_access_across_many_threads_does_not_panic_or_corrupt_state() {
    let dir = TempDir::new().unwrap();
    let daemon = Arc::new(open_daemon(&dir));

    let handles: Vec<_> = (0u16..50)
        .map(|i| {
            let daemon = Arc::clone(&daemon);
            thread::spawn(move || {
                let addr: SocketAddr = format!("127.0.0.1:{}", 60000 + i).parse().unwrap();
                let namespace = Namespace::Session(SessionId(Uuid::new_v4()));
                daemon.register_port(addr, namespace.clone()).unwrap();
                daemon.record_bindings(
                    &namespace,
                    vec![PlaceholderBinding {
                        display: format!("EMAIL_{i:03}"),
                        mapping_ref: MappingRef(Uuid::new_v4()),
                    }],
                );
                let (resolved, _) = daemon.handle_fake_request(None, addr).unwrap();
                assert_eq!(resolved, namespace);
                assert_eq!(daemon.bindings_for(&namespace).len(), 1);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("worker thread should not panic");
    }
}
