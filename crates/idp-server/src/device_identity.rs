use std::io;

use idp_service::repo::RawKeyringRepo;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use iroh_chain::{EndpointIdStore, Server};

use crate::DeviceIdentity;

const KEYRING_SERVICE: &str = "local.device-identity";
const KEYRING_ENTRY: &str = "device";

pub async fn open() -> io::Result<DeviceIdentity> {
    let secret_key = load_or_create_secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .bind()
        .await
        .map_err(io::Error::other)?;
    Ok(DeviceIdentity::new(endpoint, secret_key))
}

pub async fn open_with_allowlist(allowed: EndpointIdStore) -> io::Result<(DeviceIdentity, Server)> {
    let secret_key = load_or_create_secret_key()?;
    let server = Server::bind_with_secret_key(presets::N0, secret_key.clone(), allowed)
        .await
        .map_err(io::Error::other)?;
    let identity = identity_from_server(&server, secret_key)?;
    Ok((identity, server))
}

pub fn identity_from_server(server: &Server, secret_key: SecretKey) -> io::Result<DeviceIdentity> {
    if server.endpoint().id() != secret_key.public() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Iroh server endpoint does not match its secret key",
        ));
    }
    Ok(DeviceIdentity::new(server.endpoint().clone(), secret_key))
}

fn load_or_create_secret_key() -> io::Result<SecretKey> {
    let keyring = RawKeyringRepo::new(KEYRING_SERVICE).map_err(io::Error::other)?;
    match keyring
        .load("", "", KEYRING_ENTRY)
        .map_err(io::Error::other)?
    {
        Some(bytes) => Ok(SecretKey::from_bytes(&bytes.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid Iroh key")
        })?)),
        None => {
            let secret_key = SecretKey::generate();
            keyring
                .store("", "", KEYRING_ENTRY, &secret_key.to_bytes())
                .map_err(io::Error::other)?;
            Ok(secret_key)
        }
    }
}

pub fn delete() -> io::Result<()> {
    RawKeyringRepo::new(KEYRING_SERVICE)
        .map_err(io::Error::other)?
        .delete("", "", KEYRING_ENTRY)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use iroh::{SecretKey, endpoint::presets};
    use iroh_chain::{EndpointIdStore, Server};

    use super::identity_from_server;

    #[tokio::test]
    async fn rejects_a_key_that_does_not_match_the_shared_endpoint() {
        let server_key = SecretKey::generate();
        let server =
            Server::bind_with_secret_key(presets::N0, server_key, EndpointIdStore::default())
                .await
                .expect("bind test Iroh server");

        assert!(identity_from_server(&server, SecretKey::generate()).is_err());
        server.endpoint().close().await;
    }

    #[test]
    fn restores_device_key_bytes() {
        let key = SecretKey::generate();
        assert_eq!(
            SecretKey::from_bytes(&key.to_bytes()).public(),
            key.public()
        );
    }
}
