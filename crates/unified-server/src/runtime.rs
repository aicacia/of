use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

use api::serve_listener;
use axum::Router;
use db::Database;
use idp_model::model::Id;
use idp_server::{
    IdpRuntime, NodeJoinApproval, NodeJoinRequest, OwnerProvisioner,
    build_runtime as build_idp_runtime,
};
use iroh::protocol::Router as IrohRouter;
use iroh_chain::PairingOffer;
use management_service::{HostedControlPlane, LocalPermissions};
use storage_server::{
    DeviceReplicationPolicy, IdpClient, LocalReplicationAuthorizer, ManagementClient,
    RouterState as StorageRouterState, StorageRuntime, build_runtime as build_storage_runtime,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, broadcast},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::{
    SecurityContext, SecurityProtocol, UnifiedEndpoint, compose_protocol_router, compose_router,
    config::{ServiceClientCredentials, UnifiedConfig},
};

const IDP_PREFIX: &str = "/idp";
const MANAGEMENT_PREFIX: &str = "/management";
const STORAGE_PREFIX: &str = "/storage";
const PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn owner_replication_authorizer(
    idp: Arc<IdpRuntime>,
    management: Arc<Database>,
    local_endpoint: iroh::EndpointId,
    copies: Arc<OnceLock<storage_server::StorageCopyRetirement>>,
) -> LocalReplicationAuthorizer {
    let cleanup = Arc::new(Mutex::new(()));
    let copies = Arc::downgrade(&copies);
    LocalReplicationAuthorizer::new(move |endpoint| {
        let idp = Arc::clone(&idp);
        let management = Arc::clone(&management);
        let copies = copies.clone();
        let cleanup = Arc::clone(&cleanup);
        async move {
            let _cleanup = if endpoint == local_endpoint {
                Some(cleanup.lock().await)
            } else {
                None
            };
            let device = idp
                .approved_device_owner(endpoint)
                .await
                .map_err(|error| error.to_string())?;
            if endpoint == local_endpoint {
                let policies = management_service::replica::DbSelectionPolicyRepo::new(Arc::clone(
                    &management,
                ));
                if !policies
                    .reconcile_owner_prevalidated(device.device_id, &device.owner_subject)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    let old_owner = policies
                        .pending_cleanup_owner(device.device_id)
                        .await
                        .map_err(|error| error.to_string())?
                        .ok_or("missing local transfer cleanup intent")?;
                    copies
                        .upgrade()
                        .ok_or("Storage runtime was released")?
                        .get()
                        .ok_or("Storage cleanup is not ready")?
                        .remove_owner_copies(&old_owner)
                        .await
                        .map_err(|error| error.to_string())?;
                    let current = idp
                        .approved_device_owner(endpoint)
                        .await
                        .map_err(|error| error.to_string())?;
                    if current != device
                        || !policies
                            .complete_owner_cleanup_prevalidated(
                                device.device_id,
                                &old_owner,
                                &device.owner_subject,
                            )
                            .await
                            .map_err(|error| error.to_string())?
                    {
                        return Err("Device owner changed during local cleanup".into());
                    }
                }
            }
            let (admin_allowed, resources) =
                management_server::replication_policy(management, &device).await?;
            if endpoint == local_endpoint {
                copies
                    .upgrade()
                    .ok_or("Storage runtime was released")?
                    .get()
                    .ok_or("Storage cleanup is not ready")?
                    .activate_owner(&device.owner_subject)
                    .map_err(|error| error.to_string())?;
            }
            Ok(DeviceReplicationPolicy {
                device_id: device.device_id,
                endpoint_id: endpoint,
                owner_subject: device.owner_subject,
                state: idp_model::contract::DeviceState::Approved,
                owner_active: true,
                admin_allowed,
                resources,
            })
        }
    })
}

struct PendingNodeJoins {
    receiver: broadcast::Receiver<PairingOffer>,
    offers: BTreeMap<Id, PairingOffer>,
    answered: Vec<PairingOffer>,
}

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
    security_protocol: SecurityProtocol,
    owner: OwnerProvisioner,
    pending_joins: Mutex<PendingNodeJoins>,
    installation: String,
    _managed_copies: Arc<OnceLock<storage_server::StorageCopyRetirement>>,
    #[cfg(test)]
    management_fixture: Arc<Database>,
}

impl UnifiedRuntime {
    pub async fn build(config: UnifiedConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        let listener_addr = listener.local_addr()?;
        Self::build_on_listener(config, listener, loopback_base(listener_addr)).await
    }

    /// Opens an already provisioned host; this is not a fresh setup boundary.
    /// The host must durably authorize fresh intent, retain its exact endpoint/User/Client
    /// identities, call `UnifiedEndpoint::open_fresh` once, and complete the owner's exact
    /// secret inventory before initial private production. Retries use existing opening;
    /// missing endpoint keys or preparation evidence require recovery, not fresh fallback.
    /// The unified CLI/config currently provides no such fresh provisioning operation.
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
        let endpoint =
            Arc::new(UnifiedEndpoint::open(&config.endpoint_data_dir, &config.idp).await?);
        let server = endpoint.server().clone();
        let pending_joins = Mutex::new(PendingNodeJoins {
            receiver: server.subscribe_pairing_offers(),
            offers: BTreeMap::new(),
            answered: Vec::new(),
        });

        let management_engine =
            open_service_engine(&config.management.data_dir, "management.redb")?;
        management_service::replica::up(&management_engine)
            .await
            .map_err(io::Error::other)?;
        let local_permissions = LocalPermissions::new(Arc::clone(&management_engine));
        let idp_engine = open_service_engine(&config.idp.data_dir, "idp.redb")?;
        let mut idp_config = config.idp;
        idp_config.server.prefix = Some(IDP_PREFIX.to_owned());
        idp_config.control_plane_uri = None;
        let idp_runtime = Arc::new(
            build_idp_runtime(
                &idp_config,
                Arc::clone(&idp_engine),
                Arc::new(endpoint.identity()?),
                server.clone(),
                Some(local_permissions),
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

        let mut management_config = config.management;
        management_config.server.prefix = Some(MANAGEMENT_PREFIX.to_owned());
        let management_router = management_server::build_router(
            Arc::clone(&management_engine),
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
        let copies = Arc::new(OnceLock::new());
        let authorizer = owner_replication_authorizer(
            Arc::clone(&idp_runtime),
            Arc::clone(&management_engine),
            server.endpoint().id(),
            Arc::clone(&copies),
        );
        let management_client = management_client.with_local_replication_authorizer(authorizer);
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

        copies
            .set(
                storage_runtime
                    .copy_retirement()
                    .ok_or_else(|| io::Error::other("local Storage retirement is unavailable"))?,
            )
            .map_err(|_| io::Error::other("Storage retirement was already initialized"))?;

        let owner = OwnerProvisioner::from_database(&idp_config, Arc::clone(&idp_engine))?;
        let security_protocol = SecurityProtocol::new(
            server.clone(),
            idp_engine,
            Arc::clone(&management_engine),
            idp_config.oauth2.issuer.clone(),
            idp_config.oauth2.local_signer.clone(),
            Path::new(&config.endpoint_data_dir).join("security-sync-staging"),
            cancellation_token.clone(),
        );
        endpoint.refresh_approved_peers(&idp_runtime).await?;
        let protocol_router =
            compose_protocol_router(&server, &storage_runtime, &security_protocol).ok_or_else(
                || {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Storage replication handler is unavailable in unified mode",
                    )
                },
            )?;
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
            security_protocol,
            owner,
            pending_joins,
            installation: idp_config.oauth2.issuer.clone(),
            _managed_copies: copies,
            #[cfg(test)]
            management_fixture: management_engine,
        })
    }

    pub async fn node_public_ready(&self) -> io::Result<bool> {
        self.security_protocol
            .local_node_public_ready(&self.owner)
            .await
    }

    pub async fn node_join_public_ready(&self) -> io::Result<bool> {
        self.security_protocol
            .node_join_public_ready(&self.owner)
            .await
    }

    pub async fn node_join_accepting(
        &self,
        bearer: &str,
        accepting: Option<bool>,
    ) -> io::Result<bool> {
        if self.cancellation_token.is_cancelled() {
            return Err(io::Error::other("runtime is shutting down"));
        }
        let mut pending = self.pending_joins.lock().await;
        let accepting = self
            .idp_runtime
            .node_join_accepting(bearer, accepting)
            .await?;
        if !accepting {
            pending.offers.clear();
            while let Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) =
                pending.receiver.try_recv()
            {}
        }
        Ok(accepting)
    }

    fn display_node_join(&self, offer: &PairingOffer) -> io::Result<NodeJoinRequest> {
        let request: NodeJoinRequest = serde_json::from_slice(&offer.payload)?;
        request.validate()?;
        if request.installation != self.installation
            || request.approving_peer != self.endpoint_id().to_string()
            || request.endpoint_id != offer.remote_id.to_string()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "join Installation or authenticated endpoint mismatch",
            ));
        }
        Ok(request)
    }

    pub async fn pending_node_joins(&self, bearer: &str) -> io::Result<serde_json::Value> {
        self.idp_runtime
            .authorize_node_join_approver(bearer)
            .await?;
        let mut pending = self.pending_joins.lock().await;
        loop {
            match pending.receiver.try_recv() {
                Ok(offer) => {
                    if self.display_node_join(&offer).is_ok()
                        && self.endpoint.server().pairing_enabled()
                    {
                        pending.offers.insert(Id::now_v7(), offer);
                    }
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        if !self.endpoint.server().pairing_enabled() || self.cancellation_token.is_cancelled() {
            pending.offers.clear();
        }
        let mut display = Vec::new();
        for (id, offer) in &pending.offers {
            display.push(serde_json::json!({"offer_id": id, "authenticated_endpoint": offer.remote_id.to_string(), "request": self.display_node_join(offer)?}));
        }
        Ok(serde_json::json!(display))
    }

    pub async fn approve_pending_node_join(
        &self,
        bearer: &str,
        id: Id,
    ) -> io::Result<NodeJoinApproval> {
        let mut pending = self.pending_joins.lock().await;
        if self.cancellation_token.is_cancelled() || !self.endpoint.server().pairing_enabled() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pairing acceptance has ended",
            ));
        }
        let offer = pending.offers.get(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "pending authenticated offer is unavailable",
            )
        })?;
        self.display_node_join(offer)?;
        let approval = self.idp_runtime.approve_node_join(offer, bearer).await?;
        // reply finishes the stream but does not await delivery; retain its connection until shutdown.
        let answered = pending
            .offers
            .remove(&id)
            .expect("approved offer remains under the pending lock");
        pending.answered.push(answered);
        self.endpoint
            .refresh_approved_peers(&self.idp_runtime)
            .await?;
        Ok(approval)
    }

    pub async fn reject_pending_node_join(&self, bearer: &str, id: Id) -> io::Result<()> {
        self.idp_runtime
            .authorize_node_join_approver(bearer)
            .await?;
        let mut pending = self.pending_joins.lock().await;
        let offer = pending.offers.remove(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "pending authenticated offer is unavailable",
            )
        })?;
        let result = offer.reply(b"").await;
        pending.answered.push(offer);
        result
    }

    pub async fn synchronize_security(
        &self,
        connection: &iroh::endpoint::Connection,
        context: SecurityContext,
    ) -> io::Result<ofdb_sql::SyncResult> {
        self.security_protocol
            .synchronize(connection, context)
            .await
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
        self.endpoint.server().set_pairing_enabled(false);
        self.pending_joins.get_mut().offers.clear();
        self.pending_joins.get_mut().answered.clear();
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

fn open_service_engine(data_dir: &str, file_name: &str) -> io::Result<Arc<Database>> {
    fs::create_dir_all(data_dir)?;
    let engine = Database::open(Path::new(data_dir).join(file_name)).map_err(io::Error::other)?;
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
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(64 * 1024 * 1024)
                    .enable_all()
                    .build()
                    .expect("build test runtime")
                    .block_on(run_unified_listener_acceptance());
            })
            .expect("spawn large-stack unified acceptance test")
            .join()
            .expect("unified acceptance test thread did not panic");
    }

    async fn approve_test_peer(
        root: &std::path::Path,
        config: &idp_server::AppConfig,
        approved_peer_id: iroh::EndpointId,
        device_only_peer: iroh::EndpointId,
    ) -> idp_service::oauth2::NodeSignerBinding {
        use management_service::DeviceRepo;
        let issuer = &config.oauth2.issuer;
        let engine = super::open_service_engine(&config.data_dir, "idp.redb")
            .expect("open native trust fixture");
        let devices =
            management_service::replica::DbDeviceRepo::new(std::sync::Arc::clone(&engine));
        let approved = devices
            .find_approved_by_public_key(&approved_peer_id.to_string())
            .await
            .expect("lookup approved peer")
            .expect("approved peer Device");
        devices
            .create(
                "unified-test-owner".into(),
                "device-without-signer".into(),
                device_only_peer.to_string(),
                "".into(),
                vec![],
                0,
            )
            .await
            .expect("Device-only approval is not Node trust");
        let binding = idp_service::oauth2::NodeSignerBinding {
            member_id: approved.id,
            key_id: idp_model::model::Id::now_v7(),
            endpoint_id: approved_peer_id.to_string(),
        };
        let mut peer_config = config.clone();
        peer_config.data_dir = root
            .join("independent-peer-idp")
            .to_string_lossy()
            .into_owned();
        let peer = idp_server::OwnerProvisioner::open(&peer_config)
            .await
            .expect("independent peer signer owner with fixture secret store");
        peer.prepare_fresh_setup_secret_inventory(idp_model::model::Id::now_v7(), &[])
            .await
            .expect("fresh independent signer inventory");
        peer.prepare_setup_client_slots(&[])
            .await
            .expect("complete peer inventory before private signing");
        let public = peer
            .prepare_node_signer(&binding)
            .expect("independent peer private preparation");
        idp_service::replica::DbReplicaSignerRepo::new(engine)
            .enroll(
                &idp_model::contract::ReplicaMembership {
                    installation_id: issuer.clone(),
                    issuer: issuer.clone(),
                    member_id: binding.member_id,
                    endpoint_id: binding.endpoint_id.clone(),
                    approved_at: 1,
                    revoked_at: None,
                },
                &idp_model::contract::IdpSignerRecord {
                    member_id: binding.member_id,
                    key_id: binding.key_id,
                    issuer: issuer.clone(),
                    public_jwk: public,
                    approved_at: Some(1),
                    revoked_at: None,
                    expires_at: None,
                },
            )
            .await
            .expect("trusted fixture approval binds peer Device and independent signer");
        binding
    }

    #[tokio::test]
    async fn native_membership_restores_offline_and_learned_revocation_removes_admission() {
        let root = std::env::temp_dir().join(format!(
            "native-admission-{}",
            idp_model::model::Id::now_v7()
        ));
        let mut config = idp_server::AppConfig {
            data_dir: root.join("idp").to_string_lossy().into_owned(),
            ..idp_server::AppConfig::default()
        };
        config.oauth2.issuer = format!("https://{}.test/idp", idp_model::model::Id::now_v7());
        let endpoint_dir = root.join("endpoint");
        let initial = crate::UnifiedEndpoint::open_fresh(&endpoint_dir, &config)
            .await
            .expect("persist Node endpoint");
        let local = initial.endpoint_id();
        let peer = iroh::SecretKey::generate().public();
        let device_only = iroh::SecretKey::generate().public();
        let fixture = seed_idp(
            &root,
            &config.oauth2.issuer,
            &local.to_string(),
            &peer.to_string(),
        )
        .await;
        config.oauth2.local_signer = Some(fixture.local_signer);
        let binding = approve_test_peer(&root, &config, peer, device_only).await;
        initial.close().await;
        drop(initial);
        for revoked in [false, true] {
            let endpoint = crate::UnifiedEndpoint::open(&endpoint_dir, &config)
                .await
                .expect("offline endpoint reopen");
            assert_eq!(endpoint.endpoint_id(), local);
            let engine = super::open_service_engine(&config.data_dir, "idp.redb")
                .expect("native trust reopen");
            let idp = idp_server::build_runtime(
                &config,
                std::sync::Arc::clone(&engine),
                std::sync::Arc::new(endpoint.identity().expect("restored identity")),
                endpoint.server().clone(),
                None,
            )
            .await
            .expect("offline signer and trust runtime");
            let idp = std::sync::Arc::new(idp);
            endpoint
                .refresh_approved_peers(&idp)
                .await
                .expect("restore trusted signer admission");
            assert!(
                idp.approved_device_owner(local).await.is_err(),
                "synthetic fixture owner is not an active User; Node admission alone cannot authorize resources"
            );
            assert_eq!(endpoint.server().peers().contains(peer), !revoked);
            assert!(endpoint.server().peers().contains(local));
            assert!(!endpoint.server().peers().contains(device_only));
            if !revoked {
                use idp_service::repo::UserRepo;
                let users = idp_service::replica::DbUserRepo::new(
                    std::sync::Arc::clone(&engine),
                    config.password.clone(),
                );
                let owner = users
                    .find_user_by_username_or_email("administrator")
                    .await
                    .expect("local owner lookup")
                    .expect("fixture active owner");
                let member = config
                    .oauth2
                    .local_signer
                    .as_ref()
                    .expect("local binding")
                    .member_id;
                engine
                    .client()
                    .translate_and_execute(
                        &format!(
                            "UPDATE devices SET owner_subject = '{}' WHERE id = CAST('{}' AS UUID)",
                            owner.id, member
                        ),
                        &db::SqlTranslator,
                    )
                    .await
                    .expect("bind trusted fixture Device to real local owner");
                assert_eq!(
                    idp.approved_device_owner(local)
                        .await
                        .expect("current conflict-clear approved Device and active owner")
                        .owner_subject,
                    owner.id.to_string()
                );
                let management = super::open_service_engine(
                    &root.join("management").to_string_lossy(),
                    "management.redb",
                )
                .expect("native Management owner");
                management_service::replica::up(&management)
                    .await
                    .expect("local policy schema");
                let policies = management_service::replica::DbSelectionPolicyRepo::new(
                    std::sync::Arc::clone(&management),
                );
                let copies = std::sync::Arc::new(std::sync::OnceLock::new());
                assert!(
                    copies
                        .set(storage_server::StorageCopyRetirement::new(
                            std::sync::Arc::new(
                                storage_service::DatabaseRuntime::new(root.join("databases"))
                                    .expect("native database runtime")
                            ),
                            std::sync::Arc::new(
                                storage_service::ScopedFileSystemRuntime::new(
                                    root.join("files"),
                                    local
                                )
                                .expect("native filesystem runtime")
                            ),
                        ))
                        .is_ok()
                );
                let authorizer = super::owner_replication_authorizer(
                    std::sync::Arc::clone(&idp),
                    management,
                    local,
                    std::sync::Arc::clone(&copies),
                );
                assert!(
                    authorizer.selected_resources(local).await.is_err(),
                    "missing local policy fails closed"
                );
                policies
                    .set_prevalidated(management_service::replica::SelectionPolicy {
                        device_id: member,
                        owner_subject: owner.id.to_string(),
                        application_id: None,
                        selected_kind: None,
                        selected_id: None,
                        admin_allowed: true,
                    })
                    .await
                    .expect("persist real empty policy");
                assert!(
                    authorizer
                        .selected_resources(local)
                        .await
                        .expect("production owner-service callback works offline")
                        .is_empty()
                );
                assert!(
                    authorizer.selected_resources(device_only).await.is_err(),
                    "Device-only pairing cannot supply policy evidence"
                );
                policies
                    .set_admin_allowed_prevalidated(member, &owner.id.to_string(), false)
                    .await
                    .expect("learn restriction");
                assert!(
                    authorizer.selected_resources(local).await.is_err(),
                    "production callback reads newly learned restrictions"
                );
                users
                    .delete_user_by_id(owner.id)
                    .await
                    .expect("learn owner deletion");
                assert!(
                    idp.approved_device_owner(local).await.is_err(),
                    "next owner-service call denies deleted User without peer contact"
                );
                idp_service::replica::DbReplicaSignerRepo::new(std::sync::Arc::clone(&engine))
                    .revoke(binding.member_id, &config.oauth2.issuer, 2)
                    .await
                    .expect("learn revocation");
                endpoint
                    .refresh_approved_peers(&idp)
                    .await
                    .expect("update admission from current local trust");
                assert!(!endpoint.server().peers().contains(peer));
            }
            endpoint.close().await;
        }
        fs::remove_dir_all(root).expect("remove isolated native Node stores");
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
        let endpoint = crate::UnifiedEndpoint::open_fresh(&config.endpoint_data_dir, &config.idp)
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
        config.idp.oauth2.local_signer = Some(fixture.local_signer.clone());
        seed_permissions(&root, &mut fixture).await;
        let device_only_peer = iroh::SecretKey::generate().public();
        let peer_binding =
            approve_test_peer(&root, &config.idp, approved_peer_id, device_only_peer).await;
        let persisted_idp_config = config.idp.clone();
        let mut public_context_grant = None;
        {
            let owner = super::open_service_engine(&config.idp.data_dir, "idp.redb")
                .expect("owner fixture");
            owner
                .client()
                .translate_and_execute(
                    &format!(
                        "UPDATE devices SET owner_subject = '{}'",
                        fixture.administrator
                    ),
                    &db::SqlTranslator,
                )
                .await
                .expect("bind real active fixture owner");
            let policy = super::open_service_engine(&config.management.data_dir, "management.redb")
                .expect("policy fixture");
            let service = management_service::ManagementService::new(
                management_service::replica::DbPermissionRepo::new(policy.clone()),
                management_service::replica::DbRoleRepo::new(policy),
            );
            let role = service
                .create_role(
                    idp_model::contract::INSTALLATION_POLICY_ID,
                    "Node approval and public contexts",
                    None,
                )
                .await
                .expect("explicit test role");
            service
                .add_role_to_user(
                    idp_model::contract::INSTALLATION_POLICY_ID,
                    fixture.administrator,
                    role.id,
                )
                .await
                .expect("explicit User grant");
            for action in [
                idp_model::contract::IdentityAction::ReplicaSignersEnroll,
                idp_model::contract::IdentityAction::IdpSecuritySync,
                idp_model::contract::IdentityAction::ManagementSecuritySync,
            ] {
                let permission = service
                    .create_permission(
                        idp_model::contract::INSTALLATION_POLICY_ID,
                        action.permission(),
                        None,
                    )
                    .await
                    .expect("exact permission");
                service
                    .add_permission_to_role(
                        idp_model::contract::INSTALLATION_POLICY_ID,
                        role.id,
                        permission.id,
                    )
                    .await
                    .expect("exact role permission");
                if action == idp_model::contract::IdentityAction::IdpSecuritySync {
                    public_context_grant = Some((role.id, permission.id));
                }
            }
        }
        endpoint.close().await;

        let listener = TcpListener::bind(config.listen_addr)
            .await
            .expect("bind host-owned unified listener");
        let api_base = loopback_base(listener.local_addr().expect("read host listener address"));
        let mut runtime = UnifiedRuntime::build_on_listener(config, listener, api_base)
            .await
            .expect("build unified runtime on host-owned listener");
        assert_eq!(runtime.endpoint_id(), endpoint_id);
        assert!(
            runtime.endpoint.server().peers().contains(approved_peer_id),
            "trusted peers restored before handler composition without manual refresh"
        );
        assert!(
            !runtime.endpoint.server().peers().contains(device_only_peer),
            "Device-only approval must not grant Node admission"
        );
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
        let serve_task = tokio::spawn(api::serve_listener(
            runtime.router(),
            runtime.take_listener().expect("host listener"),
            cancellation_token.clone(),
        ));
        runtime
            .start_background_tasks()
            .await
            .expect("start composed runtime tasks");
        let client = reqwest::Client::new();
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
            if !path.starts_with("/storage/")
                && let Some(directory) = std::env::var_os("OF04_OPENAPI_OUTPUT")
            {
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory)
                    .expect("create requested API snapshot directory");
                let name = path.trim_start_matches('/').replace('/', "-");
                std::fs::write(
                    directory.join(name),
                    serde_json::to_vec_pretty(&openapi)
                        .expect("serialize live owner specification"),
                )
                .expect("export live owner specification");
            }
            if path.starts_with("/storage/") {
                assert!(openapi["paths"].get("/databases").is_some());
                assert!(openapi["paths"].get("/storage/databases").is_none());
            }
        }

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

        let bearer = crate::permission_http_tests::user_token(
            &client,
            &format!("http://{server_address}"),
            "administrator",
            "idp-services",
        )
        .await;
        assert!(
            runtime
                .node_public_ready()
                .await
                .expect("current initial Node readiness")
        );
        assert!(
            !runtime
                .node_join_public_ready()
                .await
                .expect("initial Node has no join receipt")
        );
        assert!(
            runtime
                .node_join_accepting("forged", Some(true))
                .await
                .is_err()
        );
        assert!(runtime.pending_node_joins("forged").await.is_err());
        let ordinary = crate::permission_http_tests::user_token(
            &client,
            &format!("http://{server_address}"),
            "unassigned",
            "idp-services",
        )
        .await;
        assert!(
            runtime
                .node_join_accepting(&ordinary, Some(true))
                .await
                .is_err(),
            "ordinary authentication cannot authorize joining"
        );
        assert!(runtime.pending_node_joins(&ordinary).await.is_err());
        assert!(
            runtime
                .node_join_accepting(&bearer, Some(true))
                .await
                .expect("authorized pairing acceptance")
        );
        let joining_config = idp_server::AppConfig {
            data_dir: root.join("joining-idp").to_string_lossy().into_owned(),
            oauth2: idp_service::oauth2::OAuth2Config {
                issuer: issuer.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        let joining = iroh_chain::Server::bind(
            iroh::endpoint::presets::Minimal,
            iroh_chain::EndpointIdStore::default(),
        )
        .await
        .expect("independent joining endpoint");
        joining.set_pairing_enabled(true);
        let joining_owner = idp_server::OwnerProvisioner::open(&joining_config)
            .await
            .expect("joining owner");
        joining_owner
            .prepare_fresh_setup_secret_inventory(fixture.administrator, &[])
            .await
            .expect("fresh pending joining owner inventory");
        joining_owner
            .prepare_setup_client_slots(&[])
            .await
            .expect("complete pending join inventory before private signing");
        let request = joining_owner
            .prepare_node_join(
                &idp_service::oauth2::NodeSignerBinding {
                    member_id: idp_model::model::Id::now_v7(),
                    key_id: idp_model::model::Id::now_v7(),
                    endpoint_id: joining.endpoint().id().to_string(),
                },
                "Pending equal Node",
                runtime.endpoint_id(),
            )
            .expect("independent joining signer");
        let sending = tokio::spawn({
            let joining = joining.clone();
            let address = runtime.endpoint.server().endpoint().addr();
            let request = request.clone();
            async move { request.send(&joining, address).await }
        });
        let pending = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let offers = runtime
                    .pending_node_joins(&bearer)
                    .await
                    .expect("authorized pending display");
                if !offers.as_array().expect("display list").is_empty() {
                    break offers;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated offer arrives");
        assert_eq!(
            pending[0]["authenticated_endpoint"],
            joining.endpoint().id().to_string()
        );
        assert_eq!(
            pending[0]["request"],
            serde_json::to_value(&request).expect("display exact request")
        );
        let offer_id = pending[0]["offer_id"]
            .as_str()
            .expect("opaque offer ID")
            .parse()
            .expect("offer UUID");
        assert!(
            runtime
                .approve_pending_node_join("forged", offer_id)
                .await
                .is_err()
        );
        assert!(
            runtime
                .approve_pending_node_join(&ordinary, offer_id)
                .await
                .is_err()
        );
        assert!(
            runtime
                .reject_pending_node_join(&ordinary, offer_id)
                .await
                .is_err()
        );
        assert_eq!(
            runtime
                .pending_node_joins(&bearer)
                .await
                .expect("failed auth preserves offer"),
            pending
        );
        let approval = runtime
            .approve_pending_node_join(&bearer, offer_id)
            .await
            .expect("authorized approval of retained transport offer");
        assert_eq!(
            sending.await.expect("sender task").expect("signed reply"),
            approval
        );
        assert!(
            runtime
                .endpoint
                .server()
                .peers()
                .contains(joining.endpoint().id()),
            "approval refreshes admission immediately"
        );
        assert!(
            runtime
                .pending_node_joins(&bearer)
                .await
                .expect("consumed pending list")
                .as_array()
                .expect("list")
                .is_empty()
        );
        assert!(
            runtime
                .approve_pending_node_join(&bearer, offer_id)
                .await
                .is_err(),
            "no replay of consumed offer"
        );
        let rejected_sender = tokio::spawn({
            let joining = joining.clone();
            let address = runtime.endpoint.server().endpoint().addr();
            async move { request.send(&joining, address).await }
        });
        let rejected_id: idp_model::model::Id =
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    let pending = runtime
                        .pending_node_joins(&bearer)
                        .await
                        .expect("rejection display");
                    if let Some(id) = pending[0]["offer_id"].as_str() {
                        break id.parse().expect("retained rejection offer ID");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("rejection offer arrives");
        runtime
            .reject_pending_node_join(&bearer, rejected_id)
            .await
            .expect("authorized rejection");
        assert!(
            rejected_sender
                .await
                .expect("rejected sender task")
                .is_err(),
            "rejection cannot produce an approval receipt"
        );
        assert!(
            runtime
                .pending_node_joins(&bearer)
                .await
                .expect("rejected offers removed")
                .as_array()
                .expect("list")
                .is_empty()
        );
        assert!(
            !runtime
                .node_join_accepting(&bearer, Some(false))
                .await
                .expect("disable acceptance")
        );
        joining.close().await;
        drop(joining_owner);

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

        let policy = runtime.management_fixture.clone();
        let service = management_service::ManagementService::new(
            management_service::replica::DbPermissionRepo::new(policy.clone()),
            management_service::replica::DbRoleRepo::new(policy),
        );
        let (role_id, permission_id) = public_context_grant.expect("exact context grant");
        service
            .remove_permission_from_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role_id,
                permission_id,
            )
            .await
            .expect("learn context permission removal");
        assert!(
            !runtime
                .node_public_ready()
                .await
                .expect("live current grant readiness"),
            "old completion cannot override learned grant denial"
        );
        service
            .add_permission_to_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role_id,
                permission_id,
            )
            .await
            .expect("authorized grant restoration");
        assert!(
            runtime
                .node_public_ready()
                .await
                .expect("live restored grant readiness")
        );

        cancellation_token.cancel();
        serve_task
            .await
            .expect("join unified server")
            .expect("serve and stop unified runtime");
        runtime.shutdown().await.expect("close shared runtime");
        let restored_endpoint =
            crate::UnifiedEndpoint::open(&root.join("endpoint"), &persisted_idp_config)
                .await
                .expect("reopen unified endpoint after shutdown");
        assert_eq!(restored_endpoint.endpoint_id(), endpoint_id);
        let reopened_engine =
            super::open_service_engine(&persisted_idp_config.data_dir, "idp.redb")
                .expect("reopen persisted IdP without peer contact");
        let restored_idp = idp_server::build_runtime(
            &persisted_idp_config,
            std::sync::Arc::clone(&reopened_engine),
            std::sync::Arc::new(restored_endpoint.identity().expect("restored identity")),
            restored_endpoint.server().clone(),
            None,
        )
        .await
        .expect("reopen local signing and trust runtime");
        restored_endpoint
            .refresh_approved_peers(&restored_idp)
            .await
            .expect("restore persisted membership offline");
        assert!(
            restored_endpoint
                .server()
                .peers()
                .contains(approved_peer_id)
        );
        assert!(
            !restored_endpoint
                .server()
                .peers()
                .contains(device_only_peer)
        );
        idp_service::replica::DbReplicaSignerRepo::new(reopened_engine)
            .revoke(peer_binding.member_id, &issuer, 2)
            .await
            .expect("learn local member revocation");
        restored_endpoint
            .refresh_approved_peers(&restored_idp)
            .await
            .expect("apply learned admission removal");
        assert!(
            !restored_endpoint
                .server()
                .peers()
                .contains(approved_peer_id)
        );
        assert!(restored_endpoint.server().peers().contains(endpoint_id));
        restored_endpoint.close().await;
        drop(restored_idp);
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
