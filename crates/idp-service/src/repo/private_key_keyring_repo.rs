use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

use key::{DerivationPath, DerivedKey};
use keyring_core::Entry;

use crate::repo::{PrivateKeyRepo, RepoError, RepoResult};

static SET_CREDENTIAL_STORE: AtomicBool = AtomicBool::new(false);

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
        keyring_core::set_default_store(store);
        SET_CREDENTIAL_STORE.store(true, Ordering::Release);
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
    if SET_CREDENTIAL_STORE.compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
        == Ok(false)
    {
        set_credential_store()?;
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
