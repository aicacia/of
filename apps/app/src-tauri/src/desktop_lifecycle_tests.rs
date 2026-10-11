use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::Arc,
};

use idp_model::model::Id;
use idp_service::repo::PrivateKeyKeyringRepo;
use tokio::net::TcpListener;
use unified_server::{LocalProvisioner, ServiceClientCredentials, UnifiedConfig};

use crate::localhost_server::{prepare_test_tls, start_unified_localhost_server};

use super::finish_runtime_startup;

struct TestStore(Arc<keyring_core::mock::Store>);

impl keyring_core::api::CredentialStoreApi for TestStore {
    fn vendor(&self) -> String {
        self.0.vendor()
    }
    fn id(&self) -> String {
        self.0.id()
    }
    fn build(
        &self,
        service: &str,
        user: &str,
        _: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        keyring_core::api::CredentialStoreApi::build(&*self.0, service, user, None)
    }
    fn search(&self, spec: &HashMap<&str, &str>) -> keyring_core::Result<Vec<keyring_core::Entry>> {
        self.0.search(spec)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct Fixture {
    root: PathBuf,
    config: UnifiedConfig,
}

impl Fixture {
    async fn provision() -> Self {
        let root = std::env::temp_dir().join(format!("desktop-lifecycle-{}", Id::now_v7()));
        fs::create_dir(&root).expect("isolated desktop host");
        let password = root.join("password");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&password)
            .expect("protected fixture password")
            .write_all(b"desktop-lifecycle-fixture-password\n")
            .expect("write fixture password");
        let mut idp = idp_server::AppConfig::default();
        idp.data_dir = root.join("idp").to_string_lossy().into_owned();
        idp.oauth2.issuer = format!("https://desktop-{}.test/idp", Id::now_v7());
        idp.api_public_uri = "https://identity.test".into();
        idp.service_audience = Some("https://identity.test/service".into());
        idp.password.memory_mib = 1;
        idp.password.iterations = 1;
        let credentials = |secret: &str, audience: &str| ServiceClientCredentials {
            client_id: Id::now_v7().to_string(),
            client_secret: secret.into(),
            audience: audience.into(),
        };
        let config = UnifiedConfig {
            listen_addr: "127.0.0.1:0".parse().expect("isolated listener"),
            endpoint_data_dir: root.join("endpoint"),
            idp,
            management: management_server::AppConfig {
                data_dir: root.join("management").to_string_lossy().into_owned(),
                api_public_uri: "https://management.test".into(),
                storage_audience: "https://storage.test".into(),
                ..Default::default()
            },
            storage: storage_server::AppConfig {
                data_dir: root.join("storage").to_string_lossy().into_owned(),
                api_public_uri: "https://storage.test".into(),
                ..Default::default()
            },
            management_idp_client: credentials(
                "fixture-management-idp",
                "https://identity.test/service",
            ),
            storage_idp_client: credentials("fixture-storage-idp", "https://identity.test/service"),
            storage_management_client: credentials(
                "fixture-storage-management",
                "https://storage.test",
            ),
            idp_management_client: Some(credentials("fixture-idp-management", "idp-management")),
        };
        let store: Arc<keyring_core::CredentialStore> = Arc::new(TestStore(
            keyring_core::mock::Store::new().expect("isolated credential provider"),
        ));
        let _ = PrivateKeyKeyringRepo::new_with_store(&config.idp.oauth2.issuer, store);
        let mut provisioner =
            LocalProvisioner::create(config.clone(), "operator", "Desktop fixture", &password)
                .expect("explicit fresh fixture intent");
        provisioner
            .provision(&password)
            .await
            .expect("provision real owner state");
        drop(provisioner);
        Self { root, config }
    }
}

#[tokio::test]
async fn desktop_startup_failure_closes_runtime_after_listener_cleanup_error() {
    let fixture = Fixture::provision().await;
    let (mut runtime, guard) = LocalProvisioner::open_runtime(fixture.config.clone())
        .await
        .expect("real completed runtime");
    let endpoint = runtime.endpoint_id();
    let cancellation = runtime.cancellation_token();
    let tls = fixture.root.join("tls");
    let _ca = prepare_test_tls(&tls).await;
    let listener = runtime.take_listener().expect("desktop listener transfer");
    let address = listener.local_addr().expect("desktop port");
    let server = start_unified_localhost_server(runtime.router(), listener, &tls)
        .expect("real desktop TLS server");
    runtime
        .start_background_tasks()
        .await
        .expect("start owned background work");
    let result = finish_runtime_startup(
        runtime,
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected startup failure",
        )),
        async move {
            server.close().await?;
            Err(io::Error::other("injected listener cleanup failure"))
        },
    )
    .await;
    let error = match result {
        Ok(_) => panic!("startup failure must not publish a runtime"),
        Err(error) => error,
    };
    assert!(
        cancellation.is_cancelled(),
        "listener cleanup error must not bypass runtime shutdown"
    );
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "injected startup failure");
    let listener = TcpListener::bind(address)
        .await
        .expect("same desktop port released");
    drop(listener);
    drop(guard);
    let (runtime, guard) = LocalProvisioner::open_runtime(fixture.config.clone())
        .await
        .expect("owner state can reopen after failed desktop startup");
    assert_eq!(
        runtime.endpoint_id(),
        endpoint,
        "startup failure must retain endpoint identity"
    );
    let cancellation = runtime.cancellation_token();
    let runtime = finish_runtime_startup(runtime, Ok(()), async {
        panic!("successful ownership handoff must not poll cleanup");
    })
    .await
    .expect("successful startup returns its runtime owner");
    assert!(!cancellation.is_cancelled());
    runtime.shutdown().await.expect("reopened runtime shutdown");
    drop(guard);
    fs::remove_dir_all(fixture.root).expect("remove only isolated desktop fixture");
}

#[tokio::test]
async fn desktop_tls_startup_failure_releases_runtime_and_reserved_port() {
    let fixture = Fixture::provision().await;
    let (mut runtime, guard) = LocalProvisioner::open_runtime(fixture.config.clone())
        .await
        .expect("real completed runtime");
    let cancellation = runtime.cancellation_token();
    let listener = runtime.take_listener().expect("desktop listener transfer");
    let address = listener.local_addr().expect("reserved desktop port");
    let missing_tls = fixture.root.join("missing-tls");
    let tls_error = start_unified_localhost_server(runtime.router(), listener, &missing_tls)
        .expect_err("missing TLS configuration must refuse startup");
    let result =
        finish_runtime_startup(runtime, Err(io::Error::other(tls_error)), async { Ok(()) }).await;
    assert!(result.is_err(), "TLS failure must not publish a runtime");
    assert!(
        cancellation.is_cancelled(),
        "pre-server failure must shut down the runtime"
    );
    assert!(
        !missing_tls.exists(),
        "cleanup must not create replacement TLS state"
    );
    let listener = TcpListener::bind(address)
        .await
        .expect("reserved port released after TLS failure");
    drop(listener);
    drop(guard);
    fs::remove_dir_all(fixture.root).expect("remove only isolated desktop fixture");
}
