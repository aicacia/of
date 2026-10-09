use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use std::{collections::HashMap, sync::Mutex};

use key::{DerivationPath, DerivedKey};
use keyring_core::Entry;

use crate::repo::{PrivateKeyRepo, RepoError, RepoResult};

static SET_CREDENTIAL_STORE: Mutex<bool> = Mutex::new(false);

pub struct PrivateKeyKeyringRepo {
    service_name: String,
}

impl PrivateKeyKeyringRepo {
    pub fn new(service_name: impl Into<String>) -> RepoResult<Self> {
        init_credential_store()?;
        Ok(Self {
            service_name: service_name.into(),
        })
    }

    pub fn new_with_store(
        service_name: impl Into<String>,
        store: Arc<keyring_core::CredentialStore>,
    ) -> Self {
        let mut initialized = SET_CREDENTIAL_STORE
            .lock()
            .expect("credential-store initialization lock is not poisoned");
        keyring_core::set_default_store(store);
        *initialized = true;
        Self {
            service_name: service_name.into(),
        }
    }
}

impl PrivateKeyRepo for PrivateKeyKeyringRepo {
    fn load(
        &self,
        namespace: &str,
        derivation_path: &DerivationPath,
    ) -> RepoResult<Option<DerivedKey>> {
        let entry_name = derived_key_entry_name(namespace, &derivation_path.to_string());
        let entry = create_key_entry(&self.service_name, &entry_name)?;

        match entry.get_secret() {
            Ok(secret_bytes) => {
                let xprv = String::from_utf8(secret_bytes)
                    .map_err(|error| RepoError::InvalidInput(error.to_string()))?;
                Ok(Some(DerivedKey::from_xprv(xprv, derivation_path.clone())?))
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn store(&self, namespace: &str, derived_key: &DerivedKey) -> RepoResult<()> {
        let entry_name =
            derived_key_entry_name(namespace, &derived_key.derivation_path().to_string());
        let entry = create_key_entry(&self.service_name, &entry_name)?;
        entry.set_secret(derived_key.to_xprv_string().as_bytes())?;
        Ok(())
    }

    fn delete(&self, namespace: &str, derivation_path: &DerivationPath) -> RepoResult<()> {
        let entry_name = derived_key_entry_name(namespace, &derivation_path.to_string());
        let entry = create_key_entry(&self.service_name, &entry_name)?;
        entry.delete_credential()?;
        Ok(())
    }
}

pub(crate) fn create_key_entry(service: &str, user: &str) -> keyring_core::Result<Entry> {
    let mut modifiers = HashMap::new();
    modifiers.insert("target", "IdP");
    let entry = Entry::new_with_modifiers(service, user, &modifiers)?;
    Ok(entry)
}

fn derived_key_entry_name(namespace: &str, derivation_path: &str) -> String {
    format!("{namespace}:{derivation_path}")
}

pub(crate) fn init_credential_store() -> keyring_core::Result<()> {
    initialize_store(&SET_CREDENTIAL_STORE, set_credential_store)
}

fn initialize_store(
    state: &Mutex<bool>,
    initialize: impl FnOnce() -> keyring_core::Result<()>,
) -> keyring_core::Result<()> {
    let mut initialized = state
        .lock()
        .expect("credential-store initialization lock is not poisoned");
    if !*initialized {
        initialize()?;
        *initialized = true;
    }
    Ok(())
}

fn set_credential_store() -> keyring_core::Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()?;
    #[cfg(all(target_os = "linux", feature = "headless"))]
    let store = linux_keyutils_keyring_store::Store::new()?;
    #[cfg(all(target_os = "linux", not(feature = "headless")))]
    let store = dbus_secret_service_keyring_store::Store::new()?;
    #[cfg(target_os = "android")]
    let store = android_native_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(test)]
mod initialization_tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::initialize_store;

    #[test]
    fn failed_provider_initialization_retries_before_publishing_ready() {
        let initialized = Mutex::new(false);
        assert!(initialize_store(&initialized, || Err(keyring_core::Error::NoEntry)).is_err());
        assert!(
            !*initialized.lock().expect("initialization state"),
            "failed initialization must not poison readiness"
        );
        let calls = AtomicUsize::new(0);
        initialize_store(&initialized, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .expect("retry provider setup");
        initialize_store(&initialized, || {
            panic!("successful initialization must be reused")
        })
        .expect("reuse provider");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_callers_wait_until_provider_initialization_finishes() {
        let initialized = Arc::new(Mutex::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let first = std::thread::spawn({
            let initialized = initialized.clone();
            let calls = calls.clone();
            move || {
                initialize_store(&initialized, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).expect("initializer entered");
                    resume_rx.recv().expect("resume initialization");
                    Ok(())
                })
                .expect("first initialization")
            }
        });
        entered_rx.recv().expect("wait for initialization start");
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn({
            let initialized = initialized.clone();
            let calls = calls.clone();
            move || {
                initialize_store(&initialized, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .expect("second caller");
                finished_tx.send(()).expect("second caller finished");
            }
        });
        assert!(
            finished_rx.try_recv().is_err(),
            "no early initialized result"
        );
        resume_tx.send(()).expect("release initializer");
        first.join().expect("initializer thread");
        second.join().expect("waiting thread");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
