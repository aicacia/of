use std::io;

use idp_model::model::Id;
use idp_service::repo::RawKeyringRepo;

const KEYRING_SERVICE: &str = "local.unified-service-credentials";

#[derive(Clone, Copy)]
pub enum ServiceRelationship {
    ManagementToIdp,
    StorageToIdp,
    StorageToManagement,
    IdpToManagement,
}

impl ServiceRelationship {
    pub(crate) const fn key_name(self) -> &'static str {
        match self {
            Self::ManagementToIdp => "management-to-idp",
            Self::StorageToIdp => "storage-to-idp",
            Self::StorageToManagement => "storage-to-management",
            Self::IdpToManagement => "idp-to-management",
        }
    }
}

/// Creation requires verified never-produced history consumed durably before this call.
pub fn ensure_secret(
    installation_id: Id,
    relationship: ServiceRelationship,
    client_id: Id,
    never_produced: bool,
) -> io::Result<String> {
    let keyring = RawKeyringRepo::new(KEYRING_SERVICE).map_err(io::Error::other)?;
    let user = installation_id.to_string();
    let client = client_id.to_string();
    let key_name = relationship.key_name();

    ensure_secret_with(
        never_produced,
        || {
            keyring
                .load(&user, &client, key_name)
                .map_err(io::Error::other)
        },
        |secret| {
            keyring
                .store(&user, &client, key_name, secret)
                .map_err(io::Error::other)
        },
    )
}

pub fn load_secret(
    installation_id: Id,
    relationship: ServiceRelationship,
    client_id: Id,
) -> io::Result<String> {
    let keyring = RawKeyringRepo::new(KEYRING_SERVICE).map_err(io::Error::other)?;
    let secret = keyring
        .load(
            &installation_id.to_string(),
            &client_id.to_string(),
            relationship.key_name(),
        )
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "service credential is missing"))?;
    decode_secret(secret)
}

pub fn delete_secret(
    installation_id: Id,
    relationship: ServiceRelationship,
    client_id: Id,
) -> io::Result<()> {
    let keyring = RawKeyringRepo::new(KEYRING_SERVICE).map_err(io::Error::other)?;
    let user = installation_id.to_string();
    let client = client_id.to_string();
    let key_name = relationship.key_name();
    if keyring
        .load(&user, &client, key_name)
        .map_err(io::Error::other)?
        .is_some()
    {
        keyring
            .delete(&user, &client, key_name)
            .map_err(io::Error::other)?;
        if keyring
            .load(&user, &client, key_name)
            .map_err(io::Error::other)?
            .is_some()
        {
            return Err(io::Error::other(
                "secure-store deletion was not durable; retry reset",
            ));
        }
    }
    Ok(())
}

fn ensure_secret_with(
    never_produced: bool,
    mut load: impl FnMut() -> io::Result<Option<Vec<u8>>>,
    store: impl FnOnce(&[u8]) -> io::Result<()>,
) -> io::Result<String> {
    if let Some(secret) = load()? {
        return decode_secret(secret);
    }

    if !never_produced {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "retained service credential is missing; replacement is not authorized",
        ));
    }

    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let secret = encode_hex(&bytes);
    store(secret.as_bytes())?;
    if load()?.as_deref() != Some(secret.as_bytes()) {
        return Err(io::Error::other(
            "secure-store credential readback did not match; setup remains incomplete",
        ));
    }
    Ok(secret)
}

fn decode_secret(bytes: Vec<u8>) -> io::Result<String> {
    let secret = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if secret.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service client secret is empty in secure storage",
        ));
    }
    Ok(secret)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::{ServiceRelationship, encode_hex, ensure_secret_with};

    #[test]
    fn secret_key_names_are_relationship_specific() {
        assert_ne!(
            ServiceRelationship::ManagementToIdp.key_name(),
            ServiceRelationship::StorageToIdp.key_name()
        );
        assert_ne!(
            ServiceRelationship::StorageToManagement.key_name(),
            ServiceRelationship::IdpToManagement.key_name()
        );
    }

    #[test]
    fn service_secret_is_persisted_before_return_and_reused() {
        let stored = RefCell::new(None);
        let secret = ensure_secret_with(
            true,
            || Ok(stored.borrow().clone()),
            |secret| {
                *stored.borrow_mut() = Some(secret.to_vec());
                Ok(())
            },
        )
        .expect("persist a new service secret");
        assert_eq!(secret.len(), 64);
        assert_eq!(stored.borrow().as_deref(), Some(secret.as_bytes()));

        let reused = ensure_secret_with(
            false,
            || Ok(stored.borrow().clone()),
            |_| panic!("must not replace a persisted service secret"),
        )
        .expect("reuse persisted service secret");
        assert_eq!(reused, secret);
    }

    #[test]
    fn missing_attempted_secret_is_refused_before_the_store_is_called() {
        let error = ensure_secret_with(
            false,
            || Ok(None),
            |_| panic!("historical retry must not write to the provider"),
        )
        .expect_err("missing retained credential requires recovery");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn keyring_write_failure_does_not_return_a_secret() {
        let error = ensure_secret_with(
            true,
            || Ok(None),
            |_| Err(std::io::Error::other("keyring unavailable")),
        )
        .expect_err("failed secure storage must fail provisioning");
        assert!(error.to_string().contains("keyring unavailable"));
    }

    #[test]
    fn successful_write_without_durable_readback_fails_closed() {
        assert!(ensure_secret_with(true, || Ok(None), |_| Ok(())).is_err());
    }

    #[test]
    fn ambiguous_write_failure_reuses_the_retained_secret_on_retry() {
        let stored = RefCell::new(None);
        assert!(
            ensure_secret_with(
                true,
                || Ok(stored.borrow().clone()),
                |secret| {
                    *stored.borrow_mut() = Some(secret.to_vec());
                    Err(std::io::Error::other("reply lost after secure-store write"))
                },
            )
            .is_err()
        );
        let retained = stored
            .borrow()
            .clone()
            .expect("write persisted before error");
        let reused = ensure_secret_with(
            false,
            || Ok(stored.borrow().clone()),
            |_| panic!("retry must not replace retained credentials"),
        )
        .expect("retry after ambiguous write");
        assert_eq!(reused.as_bytes(), retained);
    }

    #[test]
    #[ignore = "writes isolated credentials to the real OS secure store"]
    fn real_os_secure_store_retains_and_deletes_relationship_credentials() {
        let installation = idp_model::model::Id::now_v7();
        for relationship in [
            ServiceRelationship::ManagementToIdp,
            ServiceRelationship::StorageToIdp,
            ServiceRelationship::StorageToManagement,
            ServiceRelationship::IdpToManagement,
        ] {
            let client = idp_model::model::Id::now_v7();
            let secret = super::ensure_secret(installation, relationship, client, true)
                .expect("real OS write and exact readback");
            assert_eq!(
                super::load_secret(installation, relationship, client)
                    .expect("real OS retained credential"),
                secret
            );
            assert_eq!(
                super::ensure_secret(installation, relationship, client, false)
                    .expect("real OS exact retry"),
                secret
            );
            super::delete_secret(installation, relationship, client)
                .expect("real OS verified deletion");
            super::delete_secret(installation, relationship, client)
                .expect("real OS idempotent deletion retry");
            assert!(super::load_secret(installation, relationship, client).is_err());
        }
    }

    #[test]
    #[ignore = "writes isolated credentials to the real OS secure store"]
    fn missing_existing_relationship_retry_never_writes_a_replacement() {
        let installation = idp_model::model::Id::now_v7();
        let client = idp_model::model::Id::now_v7();
        let relationship = ServiceRelationship::ManagementToIdp;
        super::ensure_secret(installation, relationship, client, true)
            .expect("positively fresh relationship credential");
        super::delete_secret(installation, relationship, client).expect("simulate credential loss");
        let retry = super::ensure_secret(installation, relationship, client, false);
        let replacement = super::load_secret(installation, relationship, client);
        super::delete_secret(installation, relationship, client).expect("isolated fixture cleanup");
        assert!(
            retry.is_err(),
            "historical missing credential must deny retry"
        );
        assert!(
            replacement.is_err(),
            "denial must precede every replacement write"
        );
    }

    #[test]
    fn hexadecimal_secret_encoding_is_fixed_width() {
        assert_eq!(encode_hex(&[0x00, 0x1a, 0xff]), "001aff");
    }
}
