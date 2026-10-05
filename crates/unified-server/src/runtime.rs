use std::{fs, io, path::Path, sync::Arc, time::Duration};

use api::serve_listener;
use axum::Router;
use db::{NativeEngine, open_native_engine};
use idp_server::{IdpRuntime, build_runtime as build_idp_runtime};
use iroh::protocol::Router as IrohRouter;
use management_service::{HostedControlPlane, PermissionClient};
use storage_server::{
    IdpClient, ManagementClient, RouterState as StorageRouterState, StorageRuntime,
    build_runtime as build_storage_runtime,
};
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use tokio_util::sync::CancellationToken;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::{
    UnifiedEndpoint, compose_protocol_router, compose_router,
    config::{ServiceClientCredentials, UnifiedConfig},
};

const IDP_PREFIX: &str = "/idp";
const MANAGEMENT_PREFIX: &str = "/management";
const STORAGE_PREFIX: &str = "/storage";
const PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

pub struct UnifiedRuntime {
    listener: Option<TcpListener>,
    listener_addr: std::net::SocketAddr,
    router: Router,
    endpoint: Arc<UnifiedEndpoint>,
    idp_runtime: Arc<IdpRuntime>,
    api_base: String,
    protocol_router: Option<IrohRouter>,
    storage_runtime: Option<StorageRuntime>,
    cancellation_token: CancellationToken,
    peer_refresh: Option<JoinHandle<()>>,
}

impl UnifiedRuntime {
    pub async fn build(config: UnifiedConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let listener_addr = listener.local_addr()?;
        Self::build_on_listener(config, listener, loopback_base(listener_addr)).await
    }

    pub async fn build_on_listener(
        config: UnifiedConfig,
        listener: TcpListener,
        api_base: String,
    ) -> io::Result<Self> {
        validate_config(&config)?;
        validate_data_dirs(&config)?;
        let listener_addr = listener.local_addr()?;
        if !listener_addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unified listener must bind to loopback; use a TLS-terminating reverse proxy for external access",
            ));
        }
        validate_api_base(&api_base, listener_addr)?;
        let cancellation_token = CancellationToken::new();
        let endpoint = Arc::new(UnifiedEndpoint::open(&config.endpoint_data_dir).await?);
        let server = endpoint.server().clone();

        let idp_api_base = format!("{api_base}{IDP_PREFIX}/");
        let management_api_base = format!("{api_base}{MANAGEMENT_PREFIX}/");
        let permission_client = config
            .idp_management_client
            .as_ref()
            .map(|credentials| {
                if credentials.audience != management_service::MANAGEMENT_APPLICATION_URI {
                    return Err("IdP permission audience must be idp-management".to_owned());
                }
                PermissionClient::new(
                    &management_api_base,
                    &idp_api_base,
                    &config.idp.oauth2.issuer,
                    &credentials.client_id,
                    &credentials.client_secret,
                )
            })
            .transpose()
            .map_err(invalid_config)?;
        let idp_engine = open_service_engine(&config.idp.data_dir, "idp.redb")?;
        let mut idp_config = config.idp;
        idp_config.server.prefix = Some(IDP_PREFIX.to_owned());
        idp_config.control_plane_uri = None;
        let idp_runtime = Arc::new(
            build_idp_runtime(
                &idp_config,
                idp_engine,
                Arc::new(endpoint.identity()?),
                server.clone(),
                permission_client,
            )
            .await?,
        );

        let idp_api_base = format!("{api_base}{IDP_PREFIX}/");
        let management_api_base = format!("{api_base}{MANAGEMENT_PREFIX}/");
        let storage_api_base = format!("{api_base}{STORAGE_PREFIX}/");
        let management_control_plane = build_control_plane(
            &config.management_idp_client,
            &idp_api_base,
            &storage_api_base,
            &idp_config.oauth2.issuer,
        )?;
        let management_control_plane = Arc::new(match config.idp_management_client.as_ref() {
            Some(credentials) => management_control_plane
                .with_permission_evaluator(&credentials.client_id)
                .map_err(invalid_config)?,
            None => management_control_plane,
        });

        let management_engine =
            open_service_engine(&config.management.data_dir, "management.redb")?;
        let mut management_config = config.management;
        management_config.server.prefix = Some(MANAGEMENT_PREFIX.to_owned());
        let management_router = management_server::build_router(
            management_engine,
            &management_config.api_public_uri,
            MANAGEMENT_PREFIX,
            &management_config.storage_audience,
            management_control_plane,
        )
        .await
        .map_err(io::Error::other)?;

        let mut storage_config = config.storage;
        storage_config.server.prefix = Some(STORAGE_PREFIX.to_owned());
        storage_config.idp_api_base_uri = idp_api_base.clone();
        storage_config.idp_issuer_uri = idp_config.oauth2.issuer.clone();
        storage_config.idp_oauth_client_id = Some(config.storage_idp_client.client_id.clone());
        storage_config.idp_oauth_client_secret =
            Some(config.storage_idp_client.client_secret.clone());
        storage_config.idp_service_audience = Some(config.storage_idp_client.audience.clone());
        storage_config.management_api_base_uri = management_api_base;
        storage_config.management_oauth_client_id =
            Some(config.storage_management_client.client_id.clone());
        storage_config.management_oauth_client_secret =
            Some(config.storage_management_client.client_secret.clone());
        storage_config.management_service_audience =
            Some(config.storage_management_client.audience.clone());

        let idp_client = IdpClient::new(
            &storage_config.idp_api_base_uri,
            storage_config
                .idp_oauth_client_id
                .as_deref()
                .expect("unified Storage IdP client ID was set"),
            storage_config
                .idp_oauth_client_secret
                .as_deref()
                .expect("unified Storage IdP client secret was set"),
            &storage_config.idp_issuer_uri,
            storage_config
                .idp_service_audience
                .as_deref()
                .expect("unified Storage IdP audience was set"),
        )
        .map_err(invalid_config)?;
        let management_client = ManagementClient::new(
            &storage_config.management_api_base_uri,
            &storage_config.idp_api_base_uri,
            storage_config
                .management_oauth_client_id
                .as_deref()
                .expect("unified Storage Management client ID was set"),
            storage_config
                .management_oauth_client_secret
                .as_deref()
                .expect("unified Storage Management client secret was set"),
            &storage_config.idp_issuer_uri,
            storage_config
                .management_service_audience
                .as_deref()
                .expect("unified Storage Management audience was set"),
        )
        .map_err(invalid_config)?;
        let storage_state = StorageRouterState::new(&storage_config.api_public_uri)
            .with_idp_client(idp_client)
            .with_management_client(management_client);
        let storage_runtime = build_storage_runtime(
            storage_state,
            Path::new(&storage_config.data_dir),
            STORAGE_PREFIX,
            "",
            Some(server.clone()),
            cancellation_token.clone(),
        )?;

        let protocol_router = compose_protocol_router(&server, &idp_runtime, &storage_runtime)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Storage replication handler is unavailable in unified mode",
                )
            })?;
        let router = compose_router(
            idp_runtime.router(),
            management_router,
            storage_runtime.router(),
        )
        .layer(CorsLayer::very_permissive().allow_private_network(true))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new().gzip(idp_config.server.gzip));
        Ok(Self {
            listener: Some(listener),
            listener_addr,
            router,
            endpoint,
            idp_runtime,
            api_base,
            protocol_router: Some(protocol_router),
            storage_runtime: Some(storage_runtime),
            cancellation_token,
            peer_refresh: None,
        })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener_addr
    }

    pub fn take_listener(&mut self) -> io::Result<TcpListener> {
        self.listener.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Unified runtime listener was already taken",
            )
        })
    }

    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.endpoint.endpoint_id()
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub async fn start_background_tasks(&mut self) -> io::Result<()> {
        if self.peer_refresh.is_some() {
            return Ok(());
        }
        if let Err(error) = self
            .endpoint
            .refresh_approved_peers(&self.idp_runtime)
            .await
        {
            log::warn!("initial unified Iroh peer refresh failed: {error}");
            self.endpoint.refresh_admission([]);
        }
        if let Some(storage_runtime) = self.storage_runtime.as_mut() {
            storage_runtime.start_background_tasks();
        }
        self.peer_refresh = Some(spawn_peer_refresh(
            Arc::clone(&self.endpoint),
            Arc::clone(&self.idp_runtime),
            self.cancellation_token.clone(),
        ));
        Ok(())
    }

    pub async fn serve(mut self) -> io::Result<()> {
        let listener = self.take_listener()?;
        let serve_task = tokio::spawn(serve_listener(
            self.router.clone(),
            listener,
            self.cancellation_token.clone(),
        ));
        if let Err(error) = wait_until_ready(&self.api_base, &self.cancellation_token).await {
            self.cancellation_token.cancel();
            let _ = serve_task.await;
            let _ = self.shutdown().await;
            return Err(error);
        }
        self.start_background_tasks().await?;

        let serve_result = match serve_task.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error)),
        };
        let shutdown_result = self.shutdown().await;
        serve_result.and(shutdown_result)
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.cancellation_token.cancel();
        let mut shutdown_error = None;
        if let Some(peer_refresh) = self.peer_refresh.take()
            && let Err(error) = peer_refresh.await
        {
            shutdown_error = Some(io::Error::other(error));
        }
        if let Some(storage_runtime) = self.storage_runtime.take()
            && let Err(error) = storage_runtime.shutdown().await
        {
            shutdown_error.get_or_insert(error);
        }
        self.protocol_router.take();
        self.endpoint.close().await;
        match shutdown_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn validate_config(config: &UnifiedConfig) -> io::Result<()> {
    let idp_service_audience = config
        .idp
        .service_audience
        .as_deref()
        .unwrap_or(&config.idp.api_public_uri);
    for (name, credentials) in [
        ("Management→IdP", &config.management_idp_client),
        ("Storage→IdP", &config.storage_idp_client),
        ("Storage→Management", &config.storage_management_client),
    ] {
        if credentials.client_id.trim().is_empty()
            || credentials.client_secret.is_empty()
            || credentials.audience.trim().is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} OAuth client credentials are required"),
            ));
        }
    }
    if config.management_idp_client.audience != idp_service_audience
        || config.storage_idp_client.audience != idp_service_audience
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Management and Storage IdP client audiences must match IdP's configured service audience",
        ));
    }
    if config.storage_management_client.audience != config.management.storage_audience {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Storage Management audience must match Management's configured Storage audience",
        ));
    }
    let client_ids = [
        config.management_idp_client.client_id.as_str(),
        config.storage_idp_client.client_id.as_str(),
        config.storage_management_client.client_id.as_str(),
    ];
    if client_ids[0] == client_ids[1]
        || client_ids[0] == client_ids[2]
        || client_ids[1] == client_ids[2]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Management→IdP, Storage→IdP, and Storage→Management must use distinct OAuth clients",
        ));
    }
    if let Some(evaluator) = &config.idp_management_client {
        if evaluator.client_id.trim().is_empty()
            || evaluator.client_secret.is_empty()
            || evaluator.audience != management_service::MANAGEMENT_APPLICATION_URI
            || client_ids.contains(&evaluator.client_id.as_str())
            || [
                &config.management_idp_client,
                &config.storage_idp_client,
                &config.storage_management_client,
            ]
            .iter()
            .any(|client| client.client_secret == evaluator.client_secret)
        {
            return Err(invalid_config(
                "IdP→Management requires a distinct client and secret with idp-management audience"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_data_dirs(config: &UnifiedConfig) -> io::Result<()> {
    let directories = [
        Path::new(&config.idp.data_dir),
        Path::new(&config.management.data_dir),
        Path::new(&config.storage.data_dir),
        config.endpoint_data_dir.as_path(),
    ];
    let mut canonical = Vec::with_capacity(directories.len());
    for directory in directories {
        fs::create_dir_all(directory)?;
        let path = fs::canonicalize(directory)?;
        if canonical.iter().any(|existing: &std::path::PathBuf| {
            existing.starts_with(&path) || path.starts_with(existing)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IdP, Management, Storage and unified endpoint data directories must not overlap",
            ));
        }
        canonical.push(path);
    }
    Ok(())
}

fn open_service_engine(data_dir: &str, file_name: &str) -> io::Result<Arc<NativeEngine>> {
    fs::create_dir_all(data_dir)?;
    let engine =
        open_native_engine(Path::new(data_dir).join(file_name)).map_err(io::Error::other)?;
    Ok(Arc::new(engine))
}

fn build_control_plane(
    credentials: &ServiceClientCredentials,
    idp_api_base: &str,
    storage_api_base: &str,
    issuer: &str,
) -> io::Result<HostedControlPlane> {
    HostedControlPlane::new_with_services(idp_api_base, storage_api_base, issuer)
        .and_then(|control_plane| {
            control_plane.with_idp_service_client(
                credentials.client_id.clone(),
                credentials.client_secret.clone(),
                credentials.audience.clone(),
            )
        })
        .map_err(invalid_config)
}

fn validate_api_base(api_base: &str, listener_addr: std::net::SocketAddr) -> io::Result<()> {
    let url = reqwest::Url::parse(api_base).map_err(|error| invalid_config(error.to_string()))?;
    let loopback_host = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if !matches!(url.scheme(), "http" | "https")
        || !loopback_host
        || url.port() != Some(listener_addr.port())
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid_config(
            "unified API base must use HTTP(S) on the supplied loopback listener without a path, credentials, query, or fragment".to_owned(),
        ));
    }
    Ok(())
}

fn loopback_base(address: std::net::SocketAddr) -> String {
    let loopback = match address.ip() {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    };
    format!(
        "http://{}",
        std::net::SocketAddr::new(loopback, address.port())
    )
}

async fn wait_until_ready(
    api_base: &str,
    cancellation_token: &CancellationToken,
) -> io::Result<()> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(io::Error::other)?;
    let health_url = format!("{api_base}{IDP_PREFIX}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
            () = cancellation_token.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "unified startup was cancelled"));
            }
            response = client.get(&health_url).send() => {
                if response.is_ok_and(|response| response.status().is_success()) {
                    return Ok(());
                }
            }
            () = sleep(Duration::from_millis(50)) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unified HTTP listener did not become ready",
            ));
        }
    }
}

fn invalid_config(error: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn spawn_peer_refresh(
    endpoint: Arc<UnifiedEndpoint>,
    idp_runtime: Arc<IdpRuntime>,
    cancellation_token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => return,
                () = sleep(PEER_REFRESH_INTERVAL) => {
                    if let Err(error) = endpoint.refresh_approved_peers(&idp_runtime).await {
                        log::warn!("failed to refresh unified Iroh peer admission: {error}");
                        endpoint.refresh_admission([]);
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::permission_http_tests::{run_permission_http_checks, seed_idp, seed_permissions};
    use axum::{body::Body, http::Request};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use crate::{ServiceClientCredentials, UnifiedConfig};

    use super::{UnifiedRuntime, loopback_base, validate_api_base, validate_config};

    #[test]
    fn host_api_base_must_match_the_loopback_listener() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4321);
        assert!(validate_api_base("https://localhost:4321", address).is_ok());
        assert!(validate_api_base("http://127.0.0.1:4321", address).is_ok());
        assert!(validate_api_base("https://example.com:4321", address).is_err());
        assert!(validate_api_base("https://localhost:4322", address).is_err());
        assert!(validate_api_base("https://localhost:4321/idp", address).is_err());
    }

    #[test]
    fn builds_three_prefixed_services_with_one_endpoint() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(16 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .expect("build test runtime")
                    .block_on(run_unified_listener_acceptance());
            })
            .expect("spawn large-stack unified acceptance test")
            .join()
            .expect("unified acceptance test thread did not panic");
    }

    async fn run_unified_listener_acceptance() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("unified-runtime-{}-{unique}", std::process::id()));
        let mut idp = idp_server::AppConfig::default();
        idp.data_dir = root.join("idp").to_string_lossy().into_owned();
        idp.api_public_uri = "https://idp.example".to_owned();
        idp.oauth2.issuer = format!("https://idp-{unique}.example/idp");
        idp.service_audience = Some("idp-services".to_owned());
        let mut management = management_server::AppConfig::default();
        management.data_dir = root.join("management").to_string_lossy().into_owned();
        management.api_public_uri = "https://management.example".to_owned();
        management.storage_audience = "storage-service".to_owned();
        let mut storage = storage_server::AppConfig::default();
        storage.data_dir = root.join("storage").to_string_lossy().into_owned();
        storage.api_public_uri = "https://storage.example".to_owned();
        let mut config = UnifiedConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            endpoint_data_dir: root.join("endpoint"),
            idp,
            management,
            storage,
            management_idp_client: credentials("management-idp", "idp-services"),
            storage_idp_client: credentials("storage-idp", "idp-services"),
            storage_management_client: credentials("storage-management", "storage-service"),
            idp_management_client: Some(ServiceClientCredentials {
                client_id: "idp-evaluator".into(),
                client_secret: "idp-evaluator-secret".into(),
                audience: management_service::MANAGEMENT_APPLICATION_URI.into(),
            }),
        };
        config.storage_idp_client.client_id = config.management_idp_client.client_id.clone();
        assert!(validate_config(&config).is_err());
        config.storage_idp_client.client_id = "storage-idp".to_owned();
        config.management_idp_client.client_secret = "management-idp-secret".to_owned();
        config.storage_idp_client.client_secret = "storage-idp-secret".to_owned();
        config.storage_management_client.client_secret = "storage-management-secret".to_owned();
        let endpoint = crate::UnifiedEndpoint::open(&config.endpoint_data_dir)
            .await
            .expect("open endpoint for initial test provisioning");
        let endpoint_id = endpoint.endpoint_id();
        let approved_peer_id = iroh::SecretKey::generate().public();
        let issuer = config.idp.oauth2.issuer.clone();
        let mut fixture = seed_idp(
            &root,
            &issuer,
            &endpoint_id.to_string(),
            &approved_peer_id.to_string(),
        )
        .await;
        seed_permissions(&root, &mut fixture).await;
        endpoint.close().await;

        let listener = TcpListener::bind(config.listen_addr)
            .await
            .expect("bind host-owned unified listener");
        let api_base = loopback_base(listener.local_addr().expect("read host listener address"));
        let runtime = UnifiedRuntime::build_on_listener(config, listener, api_base)
            .await
            .expect("build unified runtime on host-owned listener");
        assert_eq!(runtime.endpoint_id(), endpoint_id);
        runtime
            .endpoint
            .refresh_approved_peers(&runtime.idp_runtime)
            .await
            .expect("refresh approved peers from IdP state");
        assert!(runtime.endpoint.server().peers().contains(approved_peer_id));
        assert!(runtime.endpoint.server().peers().contains(endpoint_id));

        let address = runtime.local_addr();
        assert_ne!(address.port(), 0);
        assert!(fs::metadata(root.join("endpoint/endpoint.key")).is_ok());

        for path in ["/idp/health", "/management/health", "/storage/health"] {
            let response = runtime
                .router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("build health request"),
                )
                .await
                .expect("call unified service router");
            assert_eq!(response.status(), http::StatusCode::OK, "{path}");
        }
        for path in [
            "/idp/internal/token/validate",
            "/management/internal/replication/admission",
        ] {
            let response = runtime
                .router()
                .oneshot(
                    Request::builder()
                        .method(http::Method::POST)
                        .uri(path)
                        .header("x-internal-service", "untrusted")
                        .body(Body::empty())
                        .expect("build removed internal-route request"),
                )
                .await
                .expect("call removed internal route");
            assert_eq!(response.status(), http::StatusCode::NOT_FOUND, "{path}");
        }
        let response = runtime
            .router()
            .oneshot(
                Request::builder()
                    .uri("/management/replication/devices/untrusted/selections")
                    .header("x-internal-service", "untrusted")
                    .body(Body::empty())
                    .expect("build normal route request"),
            )
            .await
            .expect("call normal Management route");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);

        let cancellation_token = runtime.cancellation_token();
        let server_address = runtime.local_addr();
        let serve_task = tokio::spawn(runtime.serve());
        let client = reqwest::Client::new();
        for path in ["/idp/health", "/management/health", "/storage/health"] {
            let response = client
                .get(format!("http://{server_address}{path}"))
                .send()
                .await
                .expect("request live unified service");
            assert_eq!(response.status(), http::StatusCode::OK, "{path}");
        }
        let response = client
            .get(format!(
                "http://{server_address}/management/replication/devices/untrusted/selections"
            ))
            .header("x-internal-service", "untrusted")
            .send()
            .await
            .expect("request live Management route with legacy header only");
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);

        let management_idp_token = issue_client_token(
            &client,
            &server_address,
            "management-idp",
            "management-idp-secret",
            "idp-services",
            "idp.token.validate idp.device.lookup",
        )
        .await;
        let response = client
            .get(format!(
                "http://{server_address}/idp/devices/endpoints/{endpoint_id}"
            ))
            .bearer_auth(&management_idp_token)
            .send()
            .await
            .expect("call authenticated IdP device API through unified listener");
        assert_eq!(response.status(), http::StatusCode::OK);
        let identity: idp_model::contract::DeviceEndpointIdentity = response
            .json()
            .await
            .expect("parse approved endpoint identity");
        assert_eq!(identity.endpoint_id, endpoint_id.to_string());

        let storage_token = issue_client_token(
            &client,
            &server_address,
            "storage-management",
            "storage-management-secret",
            "storage-service",
            "management.replication.read",
        )
        .await;

        let response = client
            .get(format!(
                "http://{server_address}/management/replication/devices/{endpoint_id}/selections"
            ))
            .bearer_auth(&storage_token)
            .send()
            .await
            .expect("call authenticated Management API through unified listener");
        let selection_status = response.status();
        let selection_body = response.text().await.expect("read selection response");
        assert_eq!(selection_status, http::StatusCode::OK, "{selection_body}");
        let selected: serde_json::Value =
            serde_json::from_str(&selection_body).expect("parse selection response");
        assert_eq!(selected["resources"], serde_json::json!([]));

        run_permission_http_checks(
            &client,
            &format!("http://{server_address}"),
            &format!("http://{server_address}"),
            &fixture,
        )
        .await;

        let idp_metadata = get_json(
            &client,
            format!("http://{server_address}/idp/.well-known/openid-configuration"),
        )
        .await;
        assert_eq!(idp_metadata["issuer"], issuer);
        assert_eq!(
            idp_metadata["token_endpoint"],
            format!("{issuer}/oauth2/token")
        );
        for (path, expected_server) in [
            ("/idp/openapi.json", "https://idp.example/idp"),
            (
                "/management/openapi.json",
                "https://management.example/management",
            ),
            ("/storage/openapi.json", "https://storage.example/storage"),
        ] {
            let openapi = get_json(&client, format!("http://{server_address}{path}")).await;
            assert_eq!(openapi["servers"][0]["url"], expected_server, "{path}");
            if path.starts_with("/storage/") {
                assert!(openapi["paths"].get("/databases").is_some());
                assert!(openapi["paths"].get("/storage/databases").is_none());
            }
        }

        cancellation_token.cancel();
        serve_task
            .await
            .expect("join unified server")
            .expect("serve and stop unified runtime");
        let restored_endpoint = crate::UnifiedEndpoint::open(&root.join("endpoint"))
            .await
            .expect("reopen unified endpoint after shutdown");
        assert_eq!(restored_endpoint.endpoint_id(), endpoint_id);
        restored_endpoint.close().await;
        fs::remove_dir_all(root).expect("remove unified runtime data");
    }

    async fn issue_client_token(
        client: &reqwest::Client,
        address: &std::net::SocketAddr,
        client_id: &str,
        client_secret: &str,
        audience: &str,
        scope: &str,
    ) -> String {
        let response = client
            .post(format!("http://{address}/idp/oauth2/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&audience={audience}&scope={scope}"
            ))
            .send()
            .await
            .expect("request client-credentials token");
        assert_eq!(response.status(), http::StatusCode::OK);
        response
            .json::<serde_json::Value>()
            .await
            .expect("parse client-credentials response")["access_token"]
            .as_str()
            .expect("access token is present")
            .to_owned()
    }

    async fn get_json(client: &reqwest::Client, url: String) -> serde_json::Value {
        let response = client.get(url).send().await.expect("request JSON route");
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.bytes().await.expect("read JSON response");
        serde_json::from_slice(&body).expect("parse JSON response")
    }

    fn credentials(client_id: &str, audience: &str) -> ServiceClientCredentials {
        ServiceClientCredentials {
            client_id: client_id.to_owned(),
            client_secret: "test-secret".to_owned(),
            audience: audience.to_owned(),
        }
    }
}
