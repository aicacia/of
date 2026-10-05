use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

use super::{
    RepoResult,
    private_key_keyring_repo::{create_key_entry, init_credential_store},
};

pub struct RawKeyringRepo {
    service_name: String,
}

impl RawKeyringRepo {
    pub fn new(service_name: impl Into<String>) -> RepoResult<Self> {
        init_credential_store()?;
        Ok(Self {
            service_name: service_name.into(),
        })
    }

    pub fn load(
        &self,
        user_sub: &str,
        client_id: &str,
        key_name: &str,
    ) -> RepoResult<Option<Vec<u8>>> {
        let entry = create_key_entry(
            &self.service_name,
            &entry_name(user_sub, client_id, key_name),
        )?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn store(
        &self,
        user_sub: &str,
        client_id: &str,
        key_name: &str,
        bytes: &[u8],
    ) -> RepoResult<()> {
        let entry = create_key_entry(
            &self.service_name,
            &entry_name(user_sub, client_id, key_name),
        )?;
        entry.set_secret(bytes)?;
        Ok(())
    }

    pub fn delete(&self, user_sub: &str, client_id: &str, key_name: &str) -> RepoResult<()> {
        let entry = create_key_entry(
            &self.service_name,
            &entry_name(user_sub, client_id, key_name),
        )?;
        entry.delete_credential()?;
        Ok(())
    }
}

fn entry_name(user_sub: &str, client_id: &str, key_name: &str) -> String {
    if user_sub.is_empty() && client_id.is_empty() {
        key_name.to_owned()
    } else {
        format!("{key_name}:{user_sub}:{client_id}")
    }
}
