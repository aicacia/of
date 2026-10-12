use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use axum::Router;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    time::{Duration, sleep},
};
use tokio_rustls::TlsAcceptor;

use crate::localhost_trust::install_ca_to_user_trust_store;

pub fn localhost_ca_cert_path(data_dir: &Path) -> PathBuf {
    data_dir.join("localhost-ca.pem")
}

fn localhost_ca_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("localhost-ca.key")
}

fn localhost_ca_der_path(data_dir: &Path) -> PathBuf {
    data_dir.join("localhost-ca.der")
}

fn localhost_ca_trust_path(data_dir: &Path) -> PathBuf {
    data_dir.join("localhost-ca.trusted")
}

fn localhost_server_cert_paths(data_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        data_dir.join("localhost-server.der"),
        data_dir.join("localhost-server.key"),
        data_dir.join("localhost-server.pem"),
    )
}

fn validate_localhost_paths(data_dir: &Path) -> io::Result<()> {
    let absolute = std::env::current_dir()?.join(data_dir);
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        if component == Component::ParentDir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "localhost TLS path must not contain parent traversal",
            ));
        }
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "localhost TLS ancestry is not a nonsymlink directory: {}",
                        prefix.display()
                    ),
                ));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    for name in [
        "localhost-ca.key",
        "localhost-ca.pem",
        "localhost-ca.der",
        "localhost-ca.trusted",
        "localhost-server.key",
        "localhost-server.pem",
        "localhost-server.der",
        "https-port",
    ] {
        regular_file_exists(&data_dir.join(name))?;
    }
    Ok(())
}

fn regular_file_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "localhost state path is not a regular file: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn generate_ca_certificate(ca_key: &KeyPair) -> io::Result<rcgen::Certificate> {
    let mut ca_params = CertificateParams::new(vec![]).map_err(io::Error::other)?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Localhost CA");

    ca_params.self_signed(ca_key).map_err(io::Error::other)
}

async fn load_or_create_ca(data_dir: &Path) -> io::Result<(KeyPair, bool)> {
    let key_path = localhost_ca_key_path(data_dir);

    if regular_file_exists(&key_path)? {
        protect_private_key_file(&key_path)?;
        let key = fs::read_to_string(&key_path)?;
        return Ok((KeyPair::from_pem(&key).map_err(io::Error::other)?, false));
    }

    let key = KeyPair::generate().map_err(io::Error::other)?;
    write_private_key_file(&key_path, key.serialize_pem().as_bytes())?;

    Ok((key, true))
}

async fn ensure_ca_certificate_pem(
    data_dir: &Path,
    ca_key: &KeyPair,
) -> io::Result<(String, bool)> {
    let ca_pem_path = localhost_ca_cert_path(data_dir);
    let ca_der_path = localhost_ca_der_path(data_dir);

    if regular_file_exists(&ca_pem_path)? && regular_file_exists(&ca_der_path)? {
        return Ok((fs::read_to_string(&ca_pem_path)?, false));
    }

    let ca_cert = generate_ca_certificate(ca_key)?;
    let ca_pem = ca_cert.pem();
    let ca_der = ca_cert.der().to_vec();
    fs::write(&ca_pem_path, ca_pem.as_bytes())?;
    fs::write(&ca_der_path, &ca_der)?;
    Ok((ca_pem, true))
}

async fn load_or_create_server_cert(data_dir: &Path, ca_key: &KeyPair) -> io::Result<()> {
    let (cert_path, key_path, cert_pem_path) = localhost_server_cert_paths(data_dir);

    if regular_file_exists(&cert_path)?
        && regular_file_exists(&key_path)?
        && regular_file_exists(&cert_pem_path)?
    {
        protect_private_key_file(&key_path)?;
        return Ok(());
    }

    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.is_ca = IsCa::NoCa;

    let key = KeyPair::generate().map_err(io::Error::other)?;

    let ca_params = {
        let mut params = CertificateParams::new(vec![]).map_err(io::Error::other)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Localhost CA");
        params
    };

    let ca_issuer = Issuer::new(ca_params, ca_key);
    let cert = params
        .signed_by(&key, &ca_issuer)
        .map_err(io::Error::other)?;

    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    let cert_pem = cert.pem();

    fs::write(&cert_path, &cert_der)?;
    write_private_key_file(&key_path, &key_der)?;
    fs::write(cert_pem_path, cert_pem.as_bytes())?;

    Ok(())
}

fn write_private_key_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn protect_private_key_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("private key path is not a regular file: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub async fn ensure_localhost_certificate(data_dir: &Path) -> io::Result<PathBuf> {
    validate_localhost_paths(data_dir)?;
    fs::create_dir_all(data_dir)?;

    let cert_path = localhost_ca_cert_path(data_dir);
    let trust_path = localhost_ca_trust_path(data_dir);
    let (ca, is_new_ca) = load_or_create_ca(data_dir).await?;
    let (_, is_new_pem) = ensure_ca_certificate_pem(data_dir, &ca).await?;
    load_or_create_server_cert(data_dir, &ca).await?;

    if is_new_ca || is_new_pem || !regular_file_exists(&trust_path)? {
        install_ca_to_user_trust_store(&cert_path)?;
        fs::write(trust_path, [])?;
    }

    Ok(cert_path)
}

pub fn invalidate_localhost_certificate_trust(data_dir: &Path) -> io::Result<()> {
    validate_localhost_paths(data_dir)?;
    if let Err(err) = fs::remove_file(localhost_ca_trust_path(data_dir)) {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err);
        }
    }
    Ok(())
}

pub async fn verify_localhost_server(base_url: &str) -> io::Result<()> {
    let client = reqwest::Client::new();
    let setup_status_url = format!("{base_url}/lidp/setup/status");

    for _ in 0..50 {
        let result = async {
            let status = client
                .get(&setup_status_url)
                .send()
                .await
                .map_err(io::Error::other)?
                .error_for_status()
                .map_err(io::Error::other)?
                .json::<serde_json::Value>()
                .await
                .map_err(io::Error::other)?;
            if status.get("stage").and_then(serde_json::Value::as_str) != Some("installation") {
                return Err(io::Error::other("unexpected localhost setup state"));
            }
            Ok(())
        }
        .await;

        if result.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    Err(io::Error::other(
        "localhost server failed trust verification",
    ))
}

pub async fn verify_unified_localhost_server(base_url: &str) -> io::Result<()> {
    let client = reqwest::Client::new();
    let health_url = format!("{base_url}/idp/health");
    for _ in 0..50 {
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(io::Error::other(
        "unified localhost server failed TLS and health verification",
    ))
}

fn build_server_config(data_dir: &Path) -> Result<Arc<rustls::ServerConfig>, String> {
    validate_localhost_paths(data_dir).map_err(|error| error.to_string())?;
    let (cert_path, key_path, _) = localhost_server_cert_paths(data_dir);
    let cert_der = fs::read(&cert_path).map_err(|err| err.to_string())?;
    let key_der = fs::read(&key_path).map_err(|err| err.to_string())?;
    let ca_der = fs::read(localhost_ca_der_path(data_dir)).map_err(|err| err.to_string())?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der), CertificateDer::from(ca_der)],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
        )
        .map_err(|err| err.to_string())?;

    Ok(Arc::new(server_config))
}

struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => match self.acceptor.clone().accept(stream).await {
                    Ok(tls_stream) => return (tls_stream, addr),
                    Err(err) => {
                        log::warn!("localhost TLS accept failed: {err}");
                        continue;
                    }
                },
                Err(err) => {
                    log::warn!("localhost TCP accept failed: {err}");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub fn localhost_server_base_url(port: u16) -> String {
    format!("https://localhost:{port}")
}

pub async fn reserve_localhost_listener(data_dir: &Path) -> Result<(TcpListener, u16), String> {
    validate_localhost_paths(data_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
    let port_path = data_dir.join("https-port");
    if regular_file_exists(&port_path).map_err(|error| error.to_string())? {
        return bind_saved_localhost_port(&port_path).await;
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let mut port_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&port_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            drop(listener);
            return bind_saved_localhost_port(&port_path).await;
        }
        Err(error) => return Err(error.to_string()),
    };
    if let Err(error) = writeln!(port_file, "{port}").and_then(|()| port_file.sync_all()) {
        let _ = fs::remove_file(&port_path);
        return Err(error.to_string());
    }

    Ok((listener, port))
}

async fn bind_saved_localhost_port(port_path: &Path) -> Result<(TcpListener, u16), String> {
    regular_file_exists(port_path).map_err(|error| error.to_string())?;
    let port_text = fs::read_to_string(port_path).map_err(|error| error.to_string())?;
    let port = port_text.trim().parse::<u16>().map_err(|error| {
        format!(
            "saved HTTPS port in {} is invalid: {error}",
            port_path.display()
        )
    })?;
    if port == 0 {
        return Err(format!(
            "saved HTTPS port in {} must not be zero",
            port_path.display()
        ));
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|error| format!("cannot bind saved HTTPS port {port}: {error}"))?;
    Ok((listener, port))
}

#[allow(
    dead_code,
    reason = "app::close owns this state after startup retains the server handle"
)]
#[derive(Debug)]
pub struct LocalhostServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tauri::async_runtime::JoinHandle<()>>,
}

#[allow(
    dead_code,
    reason = "app::close shuts down the retained localhost server owner"
)]
impl LocalhostServer {
    pub async fn close(self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task {
            task.await.map_err(io::Error::other)?;
        }
        Ok(())
    }
}

pub fn start_unified_localhost_server(
    router: Router,
    listener: TcpListener,
    data_dir: &Path,
) -> Result<LocalhostServer, String> {
    let tls_listener = TlsListener {
        inner: listener,
        acceptor: TlsAcceptor::from(build_server_config(data_dir)?),
    };

    let (shutdown, shutdown_signal) = oneshot::channel();
    let task = tauri::async_runtime::spawn(async move {
        let shutdown = async move {
            if shutdown_signal.await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        if let Err(err) = axum::serve(tls_listener, router)
            .with_graceful_shutdown(shutdown)
            .await
        {
            log::error!("unified localhost server failed: {err}");
        }
    });

    Ok(LocalhostServer {
        shutdown: Some(shutdown),
        task: Some(task),
    })
}

#[cfg(test)]
pub(crate) async fn prepare_test_tls(data_dir: &Path) -> reqwest::Certificate {
    validate_localhost_paths(data_dir).expect("safe isolated TLS paths");
    fs::create_dir_all(data_dir).expect("isolated TLS directory");
    let (ca, _) = load_or_create_ca(data_dir).await.expect("fixture CA key");
    let (pem, _) = ensure_ca_certificate_pem(data_dir, &ca)
        .await
        .expect("fixture CA certificate");
    load_or_create_server_cert(data_dir, &ca)
        .await
        .expect("fixture server certificate");
    reqwest::Certificate::from_pem(pem.as_bytes()).expect("explicit fixture trust")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[cfg(unix)]
    fn tls_path_snapshot(directory: &Path) -> Vec<(String, Vec<u8>, u32, u64)> {
        use std::os::unix::fs::MetadataExt;

        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("read isolated TLS state")
            .map(|entry| {
                let entry = entry.expect("TLS fixture entry");
                let metadata = fs::symlink_metadata(entry.path()).expect("TLS fixture metadata");
                let bytes = if metadata.file_type().is_symlink() {
                    fs::read_link(entry.path())
                        .expect("fixture symlink target")
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec()
                } else if metadata.is_file() {
                    fs::read(entry.path()).expect("TLS fixture bytes")
                } else {
                    Vec::new()
                };
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    bytes,
                    metadata.mode(),
                    metadata.ino(),
                )
            })
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    #[cfg(unix)]
    async fn tls_path_fixture() -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("tls-path-{}", uuid::Uuid::new_v4()));
        let directory = root.join("retained/tls");
        let _certificate = prepare_test_tls(&directory).await;
        fs::write(directory.join("localhost-ca.trusted"), []).expect("fixture trust marker");
        for name in ["setup-ids.json", "endpoint.key", "node-signer.key"] {
            fs::write(directory.join(name), format!("retained-{name}"))
                .expect("retained identity sentinel");
        }
        let (listener, _) = reserve_localhost_listener(&directory)
            .await
            .expect("fixture persisted HTTPS port");
        drop(listener);
        for name in ["localhost-ca.key", "localhost-server.key"] {
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o640))
                .expect("fixture key modes expose premature chmod");
        }
        root
    }

    #[cfg(unix)]
    async fn assert_tls_path_refused(directory: &Path) {
        let error = ensure_localhost_certificate(directory)
            .await
            .expect_err("unsafe TLS state must stop certificate preparation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(reserve_localhost_listener(directory).await.is_err());
        assert!(invalidate_localhost_certificate_trust(directory).is_err());
        if let Ok(port) = fs::read_to_string(directory.join("https-port")) {
            let port = port
                .trim()
                .parse::<u16>()
                .expect("fixture saved HTTPS port");
            let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("refused reservation must not retain saved port");
            drop(rebound);
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("isolated startup listener");
        let address = listener.local_addr().expect("startup listener address");
        assert!(start_unified_localhost_server(Router::new(), listener, directory).is_err());
        let rebound = TcpListener::bind(address)
            .await
            .expect("refused TLS startup must release transferred listener");
        drop(rebound);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_paths_reject_symlink_directory_and_ancestor_without_mutation() {
        use std::os::unix::fs::symlink;

        for ancestor in [false, true] {
            let root = tls_path_fixture().await;
            let retained = root.join("retained/tls");
            let before = tls_path_snapshot(&retained);
            let link = root.join("redirected");
            let target = if ancestor {
                root.join("retained")
            } else {
                retained.clone()
            };
            symlink(&target, &link).expect("redirect TLS directory");
            let redirected = if ancestor {
                link.join("tls")
            } else {
                link.clone()
            };
            assert_tls_path_refused(&redirected).await;
            assert_eq!(fs::read_link(&link).expect("unchanged redirect"), target);
            assert!(
                tls_path_snapshot(&retained) == before,
                "retained TLS state changed"
            );
            fs::remove_dir_all(root).expect("remove isolated TLS path fixture");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_paths_reject_symlink_entries_without_mutation() {
        use std::os::unix::fs::symlink;

        for name in [
            "localhost-ca.key",
            "localhost-ca.pem",
            "localhost-ca.der",
            "localhost-ca.trusted",
            "localhost-server.key",
            "localhost-server.pem",
            "localhost-server.der",
            "https-port",
        ] {
            for dangling in [false, true] {
                let root = tls_path_fixture().await;
                let directory = root.join("retained/tls");
                let targets = root.join("targets");
                fs::create_dir(&targets).expect("isolated redirect targets");
                let target = targets.join(name);
                fs::rename(directory.join(name), &target).expect("retain redirect target");
                let destination = if dangling {
                    targets.join("absent")
                } else {
                    target.clone()
                };
                symlink(&destination, directory.join(name)).expect("redirect TLS entry");
                let before = tls_path_snapshot(&directory);
                let targets_before = tls_path_snapshot(&targets);
                assert_tls_path_refused(&directory).await;
                assert!(
                    tls_path_snapshot(&directory) == before,
                    "retained TLS state changed"
                );
                assert!(
                    tls_path_snapshot(&targets) == targets_before,
                    "redirect targets changed"
                );
                fs::remove_dir_all(root).expect("remove isolated TLS path fixture");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_paths_reject_nonregular_entries_without_mutation() {
        use std::os::unix::net::UnixListener;

        for name in [
            "localhost-ca.key",
            "localhost-ca.pem",
            "localhost-ca.der",
            "localhost-ca.trusted",
            "localhost-server.key",
            "localhost-server.pem",
            "localhost-server.der",
            "https-port",
        ] {
            for socket in [false, true] {
                let root = tls_path_fixture().await;
                let directory = root.join("retained/tls");
                let targets = root.join("targets");
                fs::create_dir(&targets).expect("isolated retained originals");
                let path = directory.join(name);
                fs::rename(&path, targets.join(name)).expect("retain original TLS entry");
                let socket_owner = if socket {
                    Some(UnixListener::bind(&path).expect("nonregular socket entry"))
                } else {
                    fs::create_dir(&path).expect("nonregular directory entry");
                    None
                };
                let before = tls_path_snapshot(&directory);
                let targets_before = tls_path_snapshot(&targets);
                assert_tls_path_refused(&directory).await;
                assert!(
                    tls_path_snapshot(&directory) == before,
                    "retained TLS state changed"
                );
                assert!(
                    tls_path_snapshot(&targets) == targets_before,
                    "retained originals changed"
                );
                drop(socket_owner);
                fs::remove_dir_all(root).expect("remove isolated TLS path fixture");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_paths_reject_missing_descendants_and_parent_traversal() {
        use std::os::unix::fs::symlink;

        let root = tls_path_fixture().await;
        let retained = root.join("retained/tls");
        let before = tls_path_snapshot(&retained);
        let link = root.join("redirected");
        symlink(root.join("retained"), &link).expect("redirect ancestor of absent TLS root");
        assert_tls_path_refused(&link.join("absent/tls")).await;
        assert!(!root.join("retained/absent").exists());
        assert_tls_path_refused(&root.join("retained/../retained/tls")).await;
        let file = root.join("not-a-directory");
        fs::write(&file, "retained-ancestor").expect("non-directory ancestor");
        assert_tls_path_refused(&file.join("tls")).await;
        assert_eq!(
            fs::read(&file).expect("unchanged ancestor"),
            b"retained-ancestor"
        );
        assert!(
            tls_path_snapshot(&retained) == before,
            "retained TLS state changed"
        );
        fs::remove_dir_all(root).expect("remove isolated TLS path fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_paths_regular_state_reopens_without_identity_replacement() {
        let root = tls_path_fixture().await;
        let directory = root.join("retained/tls");
        ensure_localhost_certificate(&directory)
            .await
            .expect("reuse explicit fixture trust");
        let before = tls_path_snapshot(&directory);
        ensure_localhost_certificate(&directory)
            .await
            .expect("reopen retained TLS state");
        let (listener, port) = reserve_localhost_listener(&directory)
            .await
            .expect("reuse safe persisted port");
        let server = start_unified_localhost_server(Router::new(), listener, &directory)
            .expect("start safe retained TLS server");
        server.close().await.expect("close retained TLS server");
        let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("closed safe listener releases saved port");
        drop(rebound);
        assert!(
            tls_path_snapshot(&directory) == before,
            "retained TLS state changed"
        );
        fs::remove_dir_all(root).expect("remove isolated TLS path fixture");
    }

    #[tokio::test]
    async fn localhost_certificate_is_reusable() {
        let data_dir = std::env::temp_dir().join(format!("idp-{}", uuid::Uuid::new_v4()));

        let certificate = ensure_localhost_certificate(&data_dir).await.unwrap();
        assert!(certificate.exists());
        assert!(data_dir.join("localhost-ca.trusted").exists());
        assert!(data_dir.join("localhost-server.der").exists());
        ensure_localhost_certificate(&data_dir).await.unwrap();

        fs::remove_dir_all(data_dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = std::env::temp_dir().join(format!("private-key-{}", uuid::Uuid::new_v4()));
        ensure_localhost_certificate(&data_dir)
            .await
            .expect("create localhost keys");
        for path in [
            localhost_ca_key_path(&data_dir),
            localhost_server_cert_paths(&data_dir).1,
        ] {
            assert_eq!(
                fs::metadata(path)
                    .expect("read private key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(data_dir).expect("remove private key fixture");
    }

    #[tokio::test]
    async fn reserves_localhost_listener_and_reuses_its_port() {
        let data_dir = std::env::temp_dir().join(format!("https-port-{}", uuid::Uuid::new_v4()));
        let (listener, port) = reserve_localhost_listener(&data_dir)
            .await
            .expect("reserve localhost listener");
        assert_eq!(
            listener.local_addr().expect("read listener address").port(),
            port
        );
        drop(listener);

        let (restarted_listener, restarted_port) = reserve_localhost_listener(&data_dir)
            .await
            .expect("reuse persisted localhost port");
        assert_eq!(restarted_port, port);
        drop(restarted_listener);
        fs::remove_dir_all(data_dir).expect("remove temporary listener state");
    }

    #[tokio::test]
    async fn fails_if_saved_localhost_port_is_occupied() {
        let data_dir = std::env::temp_dir().join(format!("https-port-{}", uuid::Uuid::new_v4()));
        let (listener, port) = reserve_localhost_listener(&data_dir)
            .await
            .expect("reserve localhost listener");
        let error = reserve_localhost_listener(&data_dir)
            .await
            .expect_err("an occupied persisted port must fail");
        assert!(error.contains(&port.to_string()));
        drop(listener);
        fs::remove_dir_all(data_dir).expect("remove temporary listener state");
    }

    #[tokio::test]
    async fn rejects_invalid_saved_localhost_ports() {
        let data_dir = std::env::temp_dir().join(format!("https-port-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data_dir).expect("create temporary listener state");
        let port_path = data_dir.join("https-port");
        for value in ["invalid", "0"] {
            fs::write(&port_path, value).expect("write invalid persisted port");
            assert!(reserve_localhost_listener(&data_dir).await.is_err());
        }
        fs::remove_dir_all(data_dir).expect("remove temporary listener state");
    }

    #[tokio::test]
    async fn localhost_server_rejects_missing_tls_configuration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let data_dir = std::env::temp_dir().join(format!("missing-tls-{}", uuid::Uuid::new_v4()));
        assert!(start_unified_localhost_server(Router::new(), listener, &data_dir).is_err());
    }

    #[tokio::test]
    async fn localhost_server_closes_gracefully() {
        let data_dir = std::env::temp_dir().join(format!("idp-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data_dir).unwrap();
        let (ca, _) = load_or_create_ca(&data_dir).await.unwrap();
        ensure_ca_certificate_pem(&data_dir, &ca).await.unwrap();
        load_or_create_server_cert(&data_dir, &ca).await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        start_unified_localhost_server(Router::new(), listener, &data_dir)
            .expect("start localhost HTTPS listener")
            .close()
            .await
            .unwrap();
        TcpListener::bind(addr).await.unwrap();

        fs::remove_dir_all(data_dir).unwrap();
    }
}
