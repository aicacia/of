use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use idp_server::{DeviceIdentity, IdpRuntime, device_identity_from_server};
use iroh::{EndpointId, SecretKey, endpoint::presets};
use iroh_chain::{EndpointIdStore, Server};

const ENDPOINT_KEY_FILE: &str = "endpoint.key";

pub struct UnifiedEndpoint {
    server: Server,
    allowed_peers: EndpointIdStore,
    secret_key: SecretKey,
    key_path: PathBuf,
}

impl UnifiedEndpoint {
    pub async fn open(data_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(data_dir)?;
        let key_path = data_dir.join(ENDPOINT_KEY_FILE);
        let secret_key = load_or_create_secret_key(&key_path)?;
        let allowed_peers = EndpointIdStore::default();
        allowed_peers.replace([secret_key.public()]);
        let server =
            Server::bind_with_secret_key(presets::N0, secret_key.clone(), allowed_peers.clone())
                .await
                .map_err(io::Error::other)?;

        Ok(Self {
            server,
            allowed_peers,
            secret_key,
            key_path,
        })
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    pub fn identity(&self) -> io::Result<DeviceIdentity> {
        device_identity_from_server(&self.server, self.secret_key.clone())
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.server.endpoint().id()
    }

    pub fn refresh_admission(&self, approved_peers: impl IntoIterator<Item = EndpointId>) {
        let mut peers = approved_peers.into_iter().collect::<Vec<_>>();
        peers.push(self.endpoint_id());
        self.allowed_peers.replace(peers);
    }

    pub async fn refresh_approved_peers(&self, idp: &IdpRuntime) -> io::Result<()> {
        let peers = idp.approved_peer_ids().await?;
        self.refresh_admission(peers);
        Ok(())
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub async fn close(&self) {
        self.server.endpoint().close().await;
    }
}

fn load_or_create_secret_key(path: &Path) -> io::Result<SecretKey> {
    match fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid unified endpoint key")
            })?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let secret_key = SecretKey::generate();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            file.write_all(&secret_key.to_bytes())?;
            file.sync_all()?;
            Ok(secret_key)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use iroh::{
        Endpoint, SecretKey,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler},
    };
    use iroh_chain::DATA_ALPN;

    use super::{UnifiedEndpoint, load_or_create_secret_key};

    #[derive(Debug)]
    struct TestProtocol(tokio::sync::mpsc::UnboundedSender<()>);

    impl ProtocolHandler for TestProtocol {
        async fn accept(&self, _connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            self.0.send(()).expect("test receiver remains open");
            Ok(())
        }
    }

    fn test_dir() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("unified-endpoint-{}-{unique}", std::process::id()))
    }

    #[tokio::test]
    async fn owns_one_persisted_endpoint_and_matches_idp_identity() {
        let data_dir = test_dir();
        let endpoint = UnifiedEndpoint::open(&data_dir)
            .await
            .expect("open unified endpoint");
        let endpoint_id = endpoint.endpoint_id();
        let peer_id = SecretKey::generate().public();
        let revoked_peer_id = SecretKey::generate().public();
        endpoint.refresh_admission([peer_id, revoked_peer_id]);
        assert!(endpoint.server().peers().contains(peer_id));
        assert!(endpoint.server().peers().contains(revoked_peer_id));
        assert!(endpoint.server().peers().contains(endpoint_id));

        endpoint.refresh_admission([peer_id]);
        assert!(endpoint.server().peers().contains(peer_id));
        assert!(!endpoint.server().peers().contains(revoked_peer_id));
        assert!(endpoint.server().peers().contains(endpoint_id));
        assert_eq!(
            endpoint
                .identity()
                .expect("build IdP identity")
                .endpoint_id(),
            endpoint_id
        );
        assert_eq!(endpoint.key_path(), data_dir.join("endpoint.key"));
        endpoint.close().await;

        let restored = UnifiedEndpoint::open(&data_dir)
            .await
            .expect("reopen unified endpoint");
        assert_eq!(restored.endpoint_id(), endpoint_id);
        restored.close().await;
        fs::remove_dir_all(data_dir).expect("remove endpoint test directory");
    }

    #[tokio::test]
    async fn iroh_rejects_connections_after_peer_revocation() {
        let data_dir = test_dir();
        let unified = UnifiedEndpoint::open(&data_dir)
            .await
            .expect("open unified endpoint");
        let peer = Endpoint::builder(presets::Minimal)
            .bind()
            .await
            .expect("bind test peer endpoint");
        let peer_id = peer.id();
        unified.refresh_admission([peer_id]);
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let _router = unified.server().router(TestProtocol(accepted_tx));
        let address = unified.server().endpoint().addr();

        let connection = peer
            .connect(address.clone(), DATA_ALPN)
            .await
            .expect("approved peer connects");
        tokio::time::timeout(std::time::Duration::from_secs(5), accepted_rx.recv())
            .await
            .expect("approved peer reaches protocol handler")
            .expect("protocol acceptance event arrives");
        connection.close(0u32.into(), b"done");
        connection.closed().await;
        unified.refresh_admission([]);
        let _connection = peer
            .connect(address, DATA_ALPN)
            .await
            .expect("Iroh handshake can complete before remote admission rejection");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), accepted_rx.recv())
                .await
                .is_err(),
            "revoked peer must not reach the protocol handler"
        );

        peer.close().await;
        unified.close().await;
        fs::remove_dir_all(data_dir).expect("remove endpoint test directory");
    }

    #[test]
    fn rejects_invalid_existing_key_file() {
        let data_dir = test_dir();
        fs::create_dir_all(&data_dir).expect("create endpoint test directory");
        let path = data_dir.join("endpoint.key");
        fs::write(&path, SecretKey::generate().to_bytes()[..16].to_vec())
            .expect("write invalid endpoint key");
        assert_eq!(
            load_or_create_secret_key(&path)
                .expect_err("reject malformed endpoint key")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(data_dir).expect("remove endpoint test directory");
    }
}
