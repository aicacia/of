use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
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
    /// Reopens only the canonical identity; missing identity requires exact recovery.
    /// Requires stable, owner-controlled directory ancestry, with no symlinks or `..` components.
    /// On Unix, the key must not grant group or other access. These pathname checks
    /// are not protection against hostile concurrent ancestor mutation.
    pub async fn open(data_dir: &Path, idp_config: &idp_server::AppConfig) -> io::Result<Self> {
        let data_dir = managed_directory(data_dir)?;
        let key_path = data_dir.join(ENDPOINT_KEY_FILE);
        let (secret_key, file) = load_secret_key(&key_path)?;
        file.sync_all()?;
        sync_directory_ancestry(&data_dir)?;
        let allowed_peers = EndpointIdStore::default();
        allowed_peers.replace([secret_key.public()]);
        let server = idp_server::bind_node_join_endpoint(
            idp_config,
            presets::N0,
            secret_key.clone(),
            allowed_peers.clone(),
        )
        .await?;

        Ok(Self {
            server,
            allowed_peers,
            secret_key,
            key_path,
        })
    }

    /// Creates an identity only for a positively fresh Node in a new endpoint directory.
    /// Once attempted, callers must use `open`, including after a bind failure.
    /// The managed-path preconditions of `open` also apply here.
    pub async fn open_fresh(
        data_dir: &Path,
        idp_config: &idp_server::AppConfig,
    ) -> io::Result<Self> {
        reject_symlink_ancestry(data_dir)?;
        let parent = data_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.recursive(true).create(parent)?;
        builder.recursive(false).create(data_dir)?;
        #[cfg(test)]
        publication_checkpoint("directory-created");
        let data_dir = managed_directory(data_dir)?;
        sync_directory_ancestry(&data_dir)?;
        #[cfg(test)]
        publication_checkpoint("ancestry-synced");
        publish_secret_key(&data_dir)?;
        Self::open(&data_dir, idp_config).await
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

    /// Reads canonical identity under the managed-path and key policy of `open`.
    pub fn persisted_endpoint_id(data_dir: &Path) -> io::Result<EndpointId> {
        let data_dir = managed_directory(data_dir)?;
        Ok(load_secret_key(&data_dir.join(ENDPOINT_KEY_FILE))?
            .0
            .public())
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub async fn close(&self) {
        self.server.endpoint().close().await;
    }
}

fn load_secret_key(path: &Path) -> io::Result<(SecretKey, fs::File)> {
    let entry = fs::symlink_metadata(path)?;
    if !entry.is_file() || entry.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unified endpoint key must be a regular file",
        ));
    }
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let current_entry = fs::symlink_metadata(path)?;
    if !metadata.is_file() || !current_entry.is_file() || current_entry.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unified endpoint key must remain a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if (entry.dev(), entry.ino()) != (metadata.dev(), metadata.ino())
            || (current_entry.dev(), current_entry.ino()) != (metadata.dev(), metadata.ino())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unified endpoint key changed while opening",
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unified endpoint key must not grant group or other access",
            ));
        }
    }
    let mut bytes = Vec::new();
    (&mut file).take(33).read_to_end(&mut bytes)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid unified endpoint key"))?;
    Ok((SecretKey::from_bytes(&bytes), file))
}

fn publish_secret_key(directory: &Path) -> io::Result<()> {
    let temporary = directory.join("endpoint.key.pending");
    let canonical = directory.join(ENDPOINT_KEY_FILE);
    let secret_key = SecretKey::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(test)]
    publication_checkpoint("temporary-created");
    let bytes = secret_key.to_bytes();
    file.write_all(&bytes[..16])?;
    #[cfg(test)]
    publication_checkpoint("partial-written");
    file.write_all(&bytes[16..])?;
    #[cfg(test)]
    publication_checkpoint("key-written");
    file.sync_all()?;
    #[cfg(test)]
    publication_checkpoint("key-synced");
    fs::hard_link(&temporary, &canonical)?;
    #[cfg(test)]
    publication_checkpoint("key-published");
    fs::File::open(directory)?.sync_all()?;
    #[cfg(test)]
    publication_checkpoint("publication-synced");
    fs::remove_file(&temporary)?;
    #[cfg(test)]
    publication_checkpoint("temporary-removed");
    fs::File::open(directory)?.sync_all()?;
    #[cfg(test)]
    publication_checkpoint("cleanup-synced");
    Ok(())
}

#[cfg(test)]
fn publication_checkpoint(checkpoint: &str) {
    if std::env::var("OF_ENDPOINT_TEST_CHECKPOINT").as_deref() == Ok(checkpoint) {
        std::process::exit(86);
    }
}

fn reject_symlink_ancestry(directory: &Path) -> io::Result<()> {
    let absolute = std::env::current_dir()?.join(directory);
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        if component == Component::ParentDir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unified endpoint path must not contain parent traversal",
            ));
        }
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unified endpoint ancestry must contain only nonsymlink directories",
                ));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn managed_directory(directory: &Path) -> io::Result<PathBuf> {
    reject_symlink_ancestry(directory)?;
    fs::canonicalize(directory)
}

fn sync_directory_ancestry(directory: &Path) -> io::Result<()> {
    let physical = managed_directory(directory)?;
    for ancestor in physical.ancestors() {
        fs::File::open(ancestor)?.sync_all()?;
    }
    Ok(())
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

    use super::UnifiedEndpoint;

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
    async fn existing_open_refuses_missing_identity_without_creating_state() {
        let root = test_dir();
        let data_dir = root.join("endpoint");
        fs::create_dir_all(&data_dir).expect("historical endpoint directory");
        fs::write(root.join("idp.redb"), b"surviving owner metadata")
            .expect("historical owner fixture");
        let result = UnifiedEndpoint::open(&data_dir, &idp_server::AppConfig::default()).await;
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        assert!(UnifiedEndpoint::persisted_endpoint_id(&data_dir).is_err());
        assert_eq!(
            fs::read_dir(&data_dir)
                .expect("unchanged directory")
                .count(),
            0
        );
        fs::remove_dir_all(root).expect("remove historical fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_insecure_existing_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = test_dir();
        let config = idp_server::AppConfig::default();
        let endpoint = UnifiedEndpoint::open_fresh(&data_dir, &config)
            .await
            .expect("fresh secure identity");
        let identity = endpoint.endpoint_id();
        endpoint.close().await;
        let key_path = data_dir.join("endpoint.key");
        for mode in [0o644, 0o620, 0o606, 0o666] {
            fs::set_permissions(&key_path, fs::Permissions::from_mode(mode))
                .expect("insecure historical key fixture");
            assert!(
                matches!(UnifiedEndpoint::open(&data_dir, &config).await, Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
            );
            assert_eq!(
                UnifiedEndpoint::persisted_endpoint_id(&data_dir)
                    .expect_err("insecure identity lookup")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                fs::metadata(&key_path)
                    .expect("unchanged permissions")
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("restore secure fixture permissions");
        let endpoint = UnifiedEndpoint::open(&data_dir, &config)
            .await
            .expect("secure exact reopen");
        assert_eq!(endpoint.endpoint_id(), identity);
        endpoint.close().await;
        fs::remove_dir_all(data_dir).expect("remove permissions fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_directory_ancestry_before_read_or_creation() {
        use std::os::unix::fs::symlink;

        let root = test_dir();
        let physical = root.join("physical");
        let directory = physical.join("endpoint");
        let config = idp_server::AppConfig::default();
        let endpoint = UnifiedEndpoint::open_fresh(&directory, &config)
            .await
            .expect("physical endpoint");
        endpoint.close().await;
        let alias = root.join("alias");
        symlink(&physical, &alias).expect("symlink parent fixture");
        let leaf_alias = root.join("endpoint-alias");
        symlink(&directory, &leaf_alias).expect("symlink endpoint directory fixture");
        for path in [
            alias.join("endpoint"),
            leaf_alias,
            alias.join("../physical/endpoint"),
        ] {
            assert!(
                matches!(UnifiedEndpoint::open(&path, &config).await, Err(error) if error.kind() == std::io::ErrorKind::InvalidData)
            );
            assert_eq!(
                UnifiedEndpoint::persisted_endpoint_id(&path)
                    .expect_err("symlink identity lookup")
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        for path in [
            alias.join("new/endpoint"),
            root.join("missing/../alias/new/endpoint"),
        ] {
            assert!(
                matches!(UnifiedEndpoint::open_fresh(&path, &config).await, Err(error) if error.kind() == std::io::ErrorKind::InvalidData)
            );
        }
        assert!(
            !physical.join("new").exists(),
            "refuse before creating through a symlink"
        );
        fs::remove_dir_all(root).expect("remove ancestry fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_existing_symlink_key_without_changing_its_target() {
        use std::os::unix::fs::symlink;

        let directory = test_dir();
        let config = idp_server::AppConfig::default();
        let endpoint = UnifiedEndpoint::open_fresh(&directory, &config)
            .await
            .expect("secure key fixture");
        let identity = endpoint.endpoint_id();
        endpoint.close().await;
        let key = directory.join("endpoint.key");
        let target = directory.join("retained.key");
        fs::rename(&key, &target).expect("retain original inode");
        symlink(&target, &key).expect("symlink key fixture");
        assert!(
            matches!(UnifiedEndpoint::open(&directory, &config).await, Err(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
        assert_eq!(
            UnifiedEndpoint::persisted_endpoint_id(&directory)
                .expect_err("symlink key lookup")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(
            fs::symlink_metadata(&key)
                .expect("unchanged symlink")
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&key).expect("remove symlink fixture");
        fs::rename(&target, &key).expect("restore canonical fixture");
        assert_eq!(
            UnifiedEndpoint::persisted_endpoint_id(&directory).expect("target remains exact"),
            identity
        );
        fs::remove_dir_all(directory).expect("remove symlink key fixture");
    }

    #[tokio::test]
    async fn fresh_creation_publishes_identity_and_retry_is_exact() {
        let root = test_dir();
        let data_dir = root.join("new-parent/endpoint");
        let config = idp_server::AppConfig::default();
        let endpoint = UnifiedEndpoint::open_fresh(&data_dir, &config)
            .await
            .expect("positively fresh creation");
        let identity = endpoint.endpoint_id();
        assert_eq!(
            UnifiedEndpoint::persisted_endpoint_id(&data_dir).expect("published identity"),
            identity
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for directory in [&data_dir, &root.join("new-parent"), &root] {
                assert_eq!(
                    fs::metadata(directory)
                        .expect("managed directory metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
            assert_eq!(
                fs::metadata(endpoint.key_path())
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        endpoint.close().await;
        assert!(
            matches!(UnifiedEndpoint::open_fresh(&data_dir, &config).await, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        let reopened = UnifiedEndpoint::open(&data_dir, &config)
            .await
            .expect("exact retry");
        assert_eq!(reopened.endpoint_id(), identity);
        reopened.close().await;
        fs::remove_file(data_dir.join("endpoint.key")).expect("simulate canonical key loss");
        assert!(UnifiedEndpoint::open(&data_dir, &config).await.is_err());
        assert!(
            UnifiedEndpoint::open_fresh(&data_dir, &config)
                .await
                .is_err()
        );
        assert!(UnifiedEndpoint::persisted_endpoint_id(&data_dir).is_err());
        fs::remove_dir_all(root).expect("remove fresh fixture");
    }

    #[tokio::test]
    async fn endpoint_publication_child() {
        let Some(directory) = std::env::var_os("OF_ENDPOINT_TEST_DIRECTORY") else {
            return;
        };
        UnifiedEndpoint::open_fresh(
            std::path::Path::new(&directory),
            &idp_server::AppConfig::default(),
        )
        .await
        .expect("child fresh publication")
        .close()
        .await;
    }

    #[tokio::test]
    async fn interrupted_publication_reopens_exactly_or_refuses_missing_canonical_identity() {
        for (checkpoint, published) in [
            ("directory-created", false),
            ("ancestry-synced", false),
            ("temporary-created", false),
            ("partial-written", false),
            ("key-written", false),
            ("key-synced", false),
            ("key-published", true),
            ("publication-synced", true),
            ("temporary-removed", true),
            ("cleanup-synced", true),
        ] {
            let root = test_dir();
            let directory = root.join("parent/endpoint");
            let status =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "endpoint::tests::endpoint_publication_child",
                        "--nocapture",
                    ])
                    .env("OF_ENDPOINT_TEST_DIRECTORY", &directory)
                    .env("OF_ENDPOINT_TEST_CHECKPOINT", checkpoint)
                    .status()
                    .expect("run interrupted endpoint child");
            assert_eq!(
                status.code(),
                Some(86),
                "checkpoint {checkpoint} must execute"
            );
            let config = idp_server::AppConfig::default();
            assert!(
                matches!(UnifiedEndpoint::open_fresh(&directory, &config).await, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists)
            );
            if published {
                let identity = UnifiedEndpoint::persisted_endpoint_id(&directory)
                    .expect("complete canonical publication");
                let endpoint = UnifiedEndpoint::open(&directory, &config)
                    .await
                    .expect("exact interrupted retry");
                assert_eq!(endpoint.endpoint_id(), identity);
                endpoint.close().await;
                let endpoint = UnifiedEndpoint::open(&directory, &config)
                    .await
                    .expect("second exact retry");
                assert_eq!(endpoint.endpoint_id(), identity);
                endpoint.close().await;
            } else {
                assert!(
                    matches!(UnifiedEndpoint::open(&directory, &config).await, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                );
                assert!(UnifiedEndpoint::persisted_endpoint_id(&directory).is_err());
            }
            fs::remove_dir_all(root).expect("remove interrupted fixture");
        }
    }

    #[tokio::test]
    async fn owns_one_persisted_endpoint_and_matches_idp_identity() {
        let data_dir = test_dir();
        let endpoint = UnifiedEndpoint::open_fresh(&data_dir, &idp_server::AppConfig::default())
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

        let restored = UnifiedEndpoint::open(&data_dir, &idp_server::AppConfig::default())
            .await
            .expect("reopen unified endpoint");
        assert_eq!(restored.endpoint_id(), endpoint_id);
        restored.close().await;
        fs::remove_dir_all(data_dir).expect("remove endpoint test directory");
    }

    #[tokio::test]
    async fn iroh_rejects_connections_after_peer_revocation() {
        let data_dir = test_dir();
        let unified = UnifiedEndpoint::open_fresh(&data_dir, &idp_server::AppConfig::default())
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

    #[tokio::test]
    async fn rejects_invalid_existing_key_file() {
        let data_dir = test_dir();
        fs::create_dir_all(&data_dir).expect("create endpoint test directory");
        let path = data_dir.join("endpoint.key");
        fs::write(&path, SecretKey::generate().to_bytes()[..16].to_vec())
            .expect("write invalid endpoint key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure malformed key fixture");
        }
        assert_eq!(
            match UnifiedEndpoint::open(&data_dir, &idp_server::AppConfig::default()).await {
                Err(error) => error.kind(),
                Ok(_) => panic!("malformed endpoint key must be rejected"),
            },
            std::io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(data_dir).expect("remove endpoint test directory");
    }
}
