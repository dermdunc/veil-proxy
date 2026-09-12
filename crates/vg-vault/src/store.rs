//! A trait seam over the OS keychain, so the `enrol` state machine's write-ordering and
//! crash-recovery logic (ADR-017, XREPO-009) can be unit-tested without ever touching a real
//! keychain. `pub(crate)`, not a public API: unlike the `VG_DEVICE_SIGNING_*` env-var seams,
//! this creates no new production escape hatch -- the fake implementations below are
//! `#[cfg(test)]`, so they cannot be reached from a production build, only from this crate's
//! own test suite (downstream integration tests still link the real `OsKeychain`, the same
//! structural limit `keychain.rs`'s own env-seam doc comments already name).

use keyring::{Entry, Error as KeyringError};

use crate::error::{crypto_err, VaultError};

/// Get/set/delete over an OS-keychain-shaped `(service, account)` secret store.
pub(crate) trait SecretStore {
    /// `Ok(None)` for "no such entry" -- never an error, matching `keyring`'s own
    /// `NoEntry` case, which every caller in this crate already treats as a normal,
    /// expected outcome rather than a failure.
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, VaultError>;
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), VaultError>;
    /// Deleting an already-absent entry is not an error -- every caller in `enrol.rs` deletes
    /// as a best-effort cleanup step (a pending entry after install, a stale marker on
    /// rollback), and a "you already did that" error there would only ever be handled by
    /// ignoring it, so this trait ignores it at the source instead.
    fn delete(&self, service: &str, account: &str) -> Result<(), VaultError>;
}

/// Lets a `&S` stand in for `S` wherever a `SecretStore` is needed -- e.g.
/// `FailAfterNWrites::new(&inner, n)` wrapping a borrowed store in tests, without requiring
/// every fake to also implement the trait a second time by reference.
impl<T: SecretStore + ?Sized> SecretStore for &T {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, VaultError> {
        (**self).get(service, account)
    }
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), VaultError> {
        (**self).set(service, account, value)
    }
    fn delete(&self, service: &str, account: &str) -> Result<(), VaultError> {
        (**self).delete(service, account)
    }
}

/// The real backend: the same `keyring::Entry` every other loader/writer in this crate uses.
pub(crate) struct OsKeychain;

impl SecretStore for OsKeychain {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, VaultError> {
        let entry = Entry::new(service, account)
            .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(crypto_err(format!("keychain read failed: {e}"))),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), VaultError> {
        let entry = Entry::new(service, account)
            .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;
        entry
            .set_password(value)
            .map_err(|e| crypto_err(format!("keychain store failed: {e}")))
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), VaultError> {
        let entry = Entry::new(service, account)
            .map_err(|e| crypto_err(format!("keychain entry init failed: {e}")))?;
        match entry.delete_password() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(crypto_err(format!("keychain delete failed: {e}"))),
        }
    }
}

#[cfg(test)]
pub(crate) mod fakes {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{crypto_err, SecretStore, VaultError};

    /// An in-process, never-touches-the-real-keychain `SecretStore`, for the `enrol` state
    /// machine's unit tests (ADR-017 §15).
    #[derive(Default)]
    pub(crate) struct InMemoryStore {
        entries: Mutex<HashMap<(String, String), String>>,
    }

    impl SecretStore for InMemoryStore {
        fn get(&self, service: &str, account: &str) -> Result<Option<String>, VaultError> {
            let key = (service.to_string(), account.to_string());
            Ok(self
                .entries
                .lock()
                .expect("lock poisoned")
                .get(&key)
                .cloned())
        }

        fn set(&self, service: &str, account: &str, value: &str) -> Result<(), VaultError> {
            let key = (service.to_string(), account.to_string());
            self.entries
                .lock()
                .expect("lock poisoned")
                .insert(key, value.to_string());
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), VaultError> {
            let key = (service.to_string(), account.to_string());
            self.entries.lock().expect("lock poisoned").remove(&key);
            Ok(())
        }
    }

    /// Wraps another `SecretStore` and simulates a crash after a fixed number of writes
    /// (`set`/`delete` calls combined, 0-indexed budget): the first `allowed_writes` calls
    /// succeed and take effect: every call after that errors *without* taking effect, as if
    /// the process had died immediately after the last allowed write's effect took hold.
    /// `get` always passes through -- a crashed process's own re-run still needs to read
    /// the state its last write left behind.
    pub(crate) struct FailAfterNWrites<S> {
        inner: S,
        remaining: Mutex<usize>,
    }

    impl<S> FailAfterNWrites<S> {
        pub(crate) fn new(inner: S, allowed_writes: usize) -> Self {
            Self {
                inner,
                remaining: Mutex::new(allowed_writes),
            }
        }
    }

    impl<S: SecretStore> SecretStore for FailAfterNWrites<S> {
        fn get(&self, service: &str, account: &str) -> Result<Option<String>, VaultError> {
            self.inner.get(service, account)
        }

        fn set(&self, service: &str, account: &str, value: &str) -> Result<(), VaultError> {
            let mut remaining = self.remaining.lock().expect("lock poisoned");
            if *remaining == 0 {
                return Err(crypto_err("simulated crash: write never took effect"));
            }
            *remaining -= 1;
            drop(remaining);
            self.inner.set(service, account, value)
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), VaultError> {
            let mut remaining = self.remaining.lock().expect("lock poisoned");
            if *remaining == 0 {
                return Err(crypto_err("simulated crash: delete never took effect"));
            }
            *remaining -= 1;
            drop(remaining);
            self.inner.delete(service, account)
        }
    }
}
