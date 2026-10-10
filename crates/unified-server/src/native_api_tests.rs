use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::Router;
use db::Database;
use futures_util::{SinkExt, StreamExt};
use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        TokenEndpointAuthMethod,
    },
    model::Id,
};
use idp_service::{
    oauth2::NodeSignerBinding,
    replica::{DbClientRepo, DbKeyRepo, DbUserRepo},
    repo::{ClientRepo, KeyService, PrivateKeyKeyringRepo, UserRepo},
};
use iroh::{SecretKey, endpoint::presets};
use iroh_chain::{EndpointIdStore, Server};
use management_service::LocalPermissions;
use model::contract::{
    AuthorizationDetail, StorageAuthorizationAction, StorageAuthorizationDetail, TokenResponse,
};
use storage_model::{StorageRequest, StorageResponse, StorageSession};
use storage_service::{DatabaseRuntime, FileSystemId, ScopedFileSystemRuntime};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};
use tokio_util::sync::CancellationToken;

use storage_server::{
    IdpClient, RouterState, StorageSocketAccess, StorageSocketAuthorizationError,
    StorageSocketAuthorizer, resource_router, scoped_file_system_socket_authorizer, storage_router,
};

struct StorageNamespace {
    user_sub: String,
    application_id: Id,
}
impl storage_model::StorageNamespace for StorageNamespace {
    fn user_sub(&self) -> &str {
        &self.user_sub
    }
    fn application_id(&self) -> Id {
        self.application_id
    }
}

struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("native-api-{}", Id::now_v7()));
        std::fs::create_dir_all(&root).expect("isolated owner stores");
        Self(root)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove isolated owner stores");
    }
}

#[derive(Clone, Default)]
struct Gate {
    reached: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}
impl Gate {
    async fn pause(&self) {
        self.reached.notify_one();
        self.resume.notified().await;
    }
    async fn reached(&self) {
        self.reached.notified().await;
    }
    fn release(&self) {
        self.resume.notify_one();
    }
}

struct SecretStore(Arc<keyring_core::mock::Store>);
impl keyring_core::api::CredentialStoreApi for SecretStore {
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

fn registration(
    name: &str,
    grants: Vec<GrantType>,
    scopes: Vec<String>,
    audiences: Vec<String>,
    method: TokenEndpointAuthMethod,
) -> ClientRegistration {
    ClientRegistration {
        application: ApplicationRegistration {
            name: Some(name.into()),
            uri: format!("https://{name}.test"),
            description: None,
        },
        client_id: Some(name.into()),
        client_secret: Some(format!("{name}-secret")),
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: name.into(),
        client_uri: None,
        logo_uri: None,
        contacts: vec![],
        terms_of_service_uri: None,
        policy_uri: None,
        client_type: ClientType::Confidential,
        profile: ClientProfile::Web,
        redirect_uris: vec![],
        allowed_grant_types: grants,
        response_types: vec![],
        allowed_scopes: scopes,
        allowed_audiences: audiences,
        token_endpoint_auth_method: method,
        software_statement: None,
        software_id: None,
        software_version: None,
    }
}

struct Listener {
    base: String,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Listener {
    async fn start(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("isolated local listener");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .expect("serve native local APIs");
        });
        Self {
            base,
            cancellation,
            task: Some(task),
        }
    }
    async fn stop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.await.expect("local listener joins");
        }
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Fixture {
    runtime: Arc<idp_server::IdpRuntime>,
    issuer: String,
    keys: Arc<KeyService<DbKeyRepo, PrivateKeyKeyringRepo>>,
    idp: Arc<Database>,
    management: Arc<Database>,
    clients: DbClientRepo,
    device: idp_model::contract::DeviceEndpointIdentity,
    owner: Id,
    scope: StorageNamespace,
    resource: FileSystemId,
    files: Arc<ScopedFileSystemRuntime<iroh::EndpointId>>,
    databases: Arc<DatabaseRuntime>,
    client: IdpClient,
    http: reqwest::Client,
    identity: Server,
    idp_listener: Listener,
    storage_listener: Listener,
    _directory: TestDirectory,
}
impl Fixture {
    async fn new(gate: Gate) -> Self {
        Self::with_catalog_gate(gate, None).await
    }
    async fn with_catalog_gate(gate: Gate, catalog_gate: Option<Gate>) -> Self {
        let directory = TestDirectory::new();
        let secret = SecretKey::generate();
        let identity = Server::bind_with_secret_key(
            presets::Minimal,
            secret.clone(),
            EndpointIdStore::default(),
        )
        .await
        .expect("Node endpoint");
        let mut config = idp_server::AppConfig {
            data_dir: directory.0.join("idp").to_string_lossy().into_owned(),
            ..Default::default()
        };
        config.oauth2.issuer = format!("https://installation-{}.test/idp", Id::now_v7());
        config.service_audience = Some("idp-services".into());
        let binding = NodeSignerBinding {
            member_id: Id::now_v7(),
            key_id: Id::now_v7(),
            endpoint_id: identity.endpoint().id().to_string(),
        };
        config.oauth2.local_signer = Some(binding.clone());
        static STORE: OnceLock<Arc<keyring_core::CredentialStore>> = OnceLock::new();
        let store = STORE.get_or_init(|| {
            Arc::new(SecretStore(
                keyring_core::mock::Store::new().expect("test secret adapter"),
            ))
        });
        let private = PrivateKeyKeyringRepo::new_with_store(&config.oauth2.issuer, store.clone());
        let provisioner = idp_server::OwnerProvisioner::open_with_private_keys(&config, private)
            .await
            .expect("native owner provisioning");
        let owner = Id::now_v7();
        let service_client = Id::now_v7();
        assert!(provisioner.prepare_node_signer(&binding).is_err());
        provisioner
            .prepare_fresh_setup_secret_inventory(owner, &[service_client])
            .await
            .expect("fresh exact User and service Client inventory");
        provisioner
            .prepare_setup_client_slots(&[service_client])
            .await
            .expect("complete inventory before private production");
        assert!(provisioner.prepare_setup_client_slots(&[]).await.is_err());
        provisioner
            .ensure_initial_user(owner, Id::now_v7(), "administrator", "valid-password")
            .await
            .expect("real local User");
        provisioner
            .ensure_initial_user_signing_key(owner)
            .await
            .expect("captured initial User signing key");
        provisioner
            .ensure_initial_node(&binding, owner, "API Node")
            .await
            .expect("independent locally trusted signer");
        let mut service_registration = registration(
            "storage-service",
            vec![GrantType::ClientCredentials],
            vec![
                "idp.device.lookup".into(),
                "idp.device.list".into(),
                "idp.token.validate".into(),
            ],
            vec![
                "idp-services".into(),
                "storage:filesystems".into(),
                "storage:databases".into(),
            ],
            TokenEndpointAuthMethod::ClientSecretPost,
        );
        service_registration.client_id = Some(service_client.to_string());
        provisioner
            .ensure_setup_infrastructure_client(service_registration.clone())
            .await
            .expect("captured least-privilege service OAuth");
        let public = provisioner
            .verify_node_signer(&binding)
            .await
            .expect("initial signer");
        drop(provisioner);
        let provisioner = idp_server::OwnerProvisioner::open(&config)
            .await
            .expect("existing native owner reopen");
        provisioner
            .prepare_setup_client_slots(&[service_client])
            .await
            .expect("retained exact inventory");
        assert!(
            provisioner
                .prepare_fresh_setup_secret_inventory(owner, &[service_client])
                .await
                .is_err()
        );
        assert_eq!(
            provisioner
                .verify_node_signer(&binding)
                .await
                .expect("retained signer"),
            public
        );
        provisioner
            .ensure_setup_infrastructure_client(service_registration)
            .await
            .expect("exact captured Client retry");
        drop(provisioner);
        let idp = Arc::new(
            Database::open(directory.0.join("idp/idp.redb")).expect("reopen native IdP owner"),
        );
        let keys = Arc::new(KeyService::new(
            DbKeyRepo::new(idp.clone()),
            PrivateKeyKeyringRepo::new(&config.oauth2.issuer).expect("retained local private keys"),
            config.key_namespace.clone(),
        ));

        let clients = DbClientRepo::new(idp.clone(), Arc::clone(&keys));
        let human = clients
            .create_client(registration(
                "human",
                vec![GrantType::Password, GrantType::TokenExchange],
                vec!["openid".into()],
                vec!["storage:filesystems".into(), "storage:databases".into()],
                TokenEndpointAuthMethod::ClientSecretBasic,
            ))
            .await
            .expect("native human Application client");
        let management = Arc::new(
            Database::open(directory.0.join("management.redb")).expect("separate Management store"),
        );
        management_service::replica::up(&management)
            .await
            .expect("native policy schema");
        let runtime = idp_server::build_runtime(
            &config,
            idp.clone(),
            Arc::new(
                idp_server::device_identity_from_server(&identity, secret)
                    .expect("injected endpoint identity"),
            ),
            identity.clone(),
            Some(LocalPermissions::new(management.clone())),
        )
        .await
        .expect("integrated owner-local IdP runtime");
        let device = runtime
            .approved_device_owner(identity.endpoint().id())
            .await
            .expect("current locally trusted Device owner");
        let mut idp_router = runtime.router();
        if let Some(gate) = catalog_gate {
            let calls = Arc::new(AtomicUsize::new(0));
            idp_router = idp_router.layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let calls = calls.clone();
                    let gate = gate.clone();
                    async move {
                        if request.uri().path() == "/oauth2/introspect"
                            && calls.fetch_add(1, Ordering::SeqCst) == 1
                        {
                            gate.pause().await;
                        }
                        next.run(request).await
                    }
                },
            ));
        }
        let idp_listener = Listener::start(idp_router).await;
        let client = IdpClient::new(
            &idp_listener.base,
            &service_client.to_string(),
            "storage-service-secret",
            &config.oauth2.issuer,
            "idp-services",
        )
        .expect("Node-local IdP client");
        let files = Arc::new(
            ScopedFileSystemRuntime::new(directory.0.join("files"), identity.endpoint().id())
                .expect("native filesystems"),
        );
        let databases = Arc::new(
            DatabaseRuntime::new(directory.0.join("databases")).expect("native databases"),
        );
        let scope = StorageNamespace {
            user_sub: owner.to_string(),
            application_id: human.application_id,
        };
        let resource = files
            .create_resource(&scope, None)
            .await
            .expect("real resource")
            .id;
        let actual = scoped_file_system_socket_authorizer(client.clone(), files.clone());
        let gated = storage_router(Arc::new(GatedAuthorizer { actual, gate }));
        let router = resource_router(
            RouterState::new("https://storage.test").with_idp_client(client.clone()),
            Some(databases.clone()),
            Some(files.clone()),
        )
        .nest("/gated", gated);
        let storage_listener = Listener::start(router).await;
        Self {
            runtime: Arc::new(runtime),
            issuer: config.oauth2.issuer,
            keys,
            idp,
            management,
            clients,
            device,
            owner,
            scope,
            resource,
            files,
            databases,
            client,
            http: reqwest::Client::new(),
            identity,
            idp_listener,
            storage_listener,
            _directory: directory,
        }
    }
    async fn token(&self, resource: &str, actions: Vec<StorageAuthorizationAction>) -> String {
        self.token_for_client(resource, actions, "human").await
    }

    async fn token_for_client(
        &self,
        resource: &str,
        actions: Vec<StorageAuthorizationAction>,
        client_id: &str,
    ) -> String {
        let url = format!("{}/oauth2/token", self.idp_listener.base);
        let response = self
            .http
            .post(&url)
            .basic_auth(client_id, Some(format!("{client_id}-secret")))
            .form(&[
                ("grant_type", "password"),
                ("client_id", client_id),
                ("username", "administrator"),
                ("password", "valid-password"),
                ("scope", "openid"),
            ])
            .send()
            .await
            .expect("local password token request");
        let status = response.status();
        let body = response.text().await.expect("token body");
        assert!(status.is_success(), "native User token: {status} {body}");
        let subject: TokenResponse = serde_json::from_str(&body).expect("User token response");
        let details =
            serde_json::to_string(&[AuthorizationDetail::Storage(StorageAuthorizationDetail {
                actions,
            })])
            .expect("exact actions");
        let response = self
            .http
            .post(url)
            .basic_auth(client_id, Some(format!("{client_id}-secret")))
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", &subject.access_token.0),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("resource", resource),
                ("authorization_details", &details),
            ])
            .send()
            .await
            .expect("native local exchange");
        let status = response.status();
        let body = response.text().await.expect("exchange body");
        assert!(status.is_success(), "native storage token: {status} {body}");
        serde_json::from_str::<TokenResponse>(&body)
            .expect("Storage token response")
            .access_token
            .0
    }
    fn socket_url(&self, token: &str, gated: bool) -> String {
        let mut url = reqwest::Url::parse(&self.storage_listener.base.replace("http:", "ws:"))
            .expect("WebSocket URL");
        url.set_path(if gated { "/gated/storage" } else { "/storage" });
        url.query_pairs_mut()
            .append_pair("access_token", token)
            .append_pair("filesystem_id", &self.resource.as_uuid().to_string());
        url.to_string()
    }
    async fn socket(&self, token: &str, gated: bool) -> Socket {
        tokio_tungstenite::connect_async(self.socket_url(token, gated))
            .await
            .expect("real authorized WebSocket upgrade")
            .0
    }
    async fn file(&self) -> Arc<file_system::FileSystem<iroh::EndpointId>> {
        self.files
            .open_resource(&self.scope, self.resource)
            .await
            .expect("public local resource observation")
    }
    async fn revoke_user(&self) {
        DbUserRepo::new(self.idp.clone(), Default::default())
            .delete_user_by_id(self.owner)
            .await
            .expect("learn native User revocation");
    }
    async fn request(&self, method: reqwest::Method, path: &str, token: &str) -> reqwest::Response {
        self.http
            .request(method, format!("{}{path}", self.storage_listener.base))
            .bearer_auth(token)
            .json(&serde_json::json!({"name": "non-unique name"}))
            .send()
            .await
            .expect("native Storage API request")
    }
    async fn stop(mut self) {
        self.storage_listener.stop().await;
        self.idp_listener.stop().await;
        self.identity.endpoint().close().await;
    }
}

struct GatedAuthorizer<A> {
    actual: A,
    gate: Gate,
}
struct GatedSession<S> {
    actual: S,
    gate: Gate,
}
impl<A: StorageSocketAuthorizer> StorageSocketAuthorizer for GatedAuthorizer<A> {
    type Session = GatedSession<A::Session>;
    async fn authorize(
        &self,
        token: String,
        resource: String,
    ) -> Result<StorageSocketAccess<Self::Session>, StorageSocketAuthorizationError> {
        let access = self.actual.authorize(token, resource).await?;
        Ok(StorageSocketAccess {
            subject: access.subject,
            application_id: access.application_id,
            read: access.read,
            write: access.write,
            expires_at: access.expires_at,
            session: GatedSession {
                actual: access.session,
                gate: self.gate.clone(),
            },
        })
    }
}
impl<S: StorageSession> StorageSession for GatedSession<S> {
    async fn execute_session(&self, request: StorageRequest) -> StorageResponse {
        let result = self.actual.execute_session(request).await;
        self.gate.pause().await;
        result
    }
}
async fn send(socket: &mut Socket, request: StorageRequest) {
    socket
        .send(Message::Text(
            serde_json::to_string(&request).expect("request").into(),
        ))
        .await
        .expect("send established socket request");
}
async fn response(socket: &mut Socket) -> StorageResponse {
    let message = socket
        .next()
        .await
        .expect("socket response")
        .expect("valid response frame");
    serde_json::from_str(message.to_text().expect("text response")).expect("resource response")
}
async fn assert_no_response(socket: &mut Socket) {
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(_) | Message::Binary(_)) => {
                panic!("learned denial must prevent resource response transmission: {message:?}");
            }
            Ok(Message::Close(_)) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[path = "policy_cleanup_http_tests.rs"]
mod policy_cleanup_tests;
#[path = "native_api_qualification_tests.rs"]
mod qualification_tests;
#[path = "residency_http_tests.rs"]
mod residency_tests;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_owner_cutover_captures_initial_secrets_and_reuses_reopened_owner() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let fixture = Fixture::new(Gate::default()).await;
        let inventory: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture._directory.0.join("idp/setup-secret-inventory.json"))
                .expect("retained preparation manifest"),
        )
        .expect("exact inventory JSON");
        assert_eq!(inventory["owner"], fixture.owner.to_string());
        assert_eq!(inventory["phase"], "ready");
        let slots = inventory["clients"]
            .as_array()
            .expect("ordered Client slots");
        assert_eq!(slots.len(), 1);
        for slot in [
            slots[0].as_str().expect("canonical Client ID").to_owned(),
            format!("user:{}", fixture.owner),
        ] {
            let reference: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    fixture
                        ._directory
                        .0
                        .join("idp/local-client-key-references")
                        .join(format!("{}.json", slot.replace(':', "-"))),
                )
                .expect("captured initial secret reference"),
            )
            .expect("reference JSON");
            assert_eq!(reference["state"], "resolved");
        }
        fixture
            .token(
                "storage:filesystems",
                vec![StorageAuthorizationAction::Read],
            )
            .await;
        fixture.stop().await;
    })
    .await
    .expect("native owner cutover completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_local_token_read_response_denies_learned_revocation_before_transmission() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let fixture = Fixture::new(gate.clone()).await;
        let token = fixture
            .token(
                "storage:filesystems",
                vec![StorageAuthorizationAction::Read],
            )
            .await;
        let file = fixture.file().await;
        file.write("private.txt", b"must not disclose")
            .await
            .expect("native resource content");
        let mut socket = fixture.socket(&token, true).await;
        send(
            &mut socket,
            StorageRequest::Read {
                path: "private.txt".into(),
            },
        )
        .await;
        gate.reached().await;
        fixture.revoke_user().await;
        gate.release();
        assert_no_response(&mut socket).await;
        assert_eq!(
            file.read("private.txt").await.expect("source retained"),
            b"must not disclose"
        );
        drop(socket);
        fixture.stop().await;
    })
    .await
    .expect("native API denial completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_local_tokens_bound_api_actions_resource_kind_and_existing_socket_operations() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let fixture = Fixture::new(Gate::default()).await;
        let read = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Read]).await;
        let write = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Write]).await;
        let database_read = fixture.token("storage:databases", vec![StorageAuthorizationAction::Read]).await;
        let database_write = fixture.token("storage:databases", vec![StorageAuthorizationAction::Write]).await;
        for (kind, read, write, wrong_kind) in [
            ("filesystems", &read, &write, &database_read),
            ("databases", &database_read, &database_write, &read),
        ] {
            let path = format!("/storage/{kind}");
            assert_eq!(fixture.request(reqwest::Method::GET, &path, wrong_kind).await.status(), reqwest::StatusCode::UNAUTHORIZED, "token must bind the actual resource kind");
            assert_eq!(fixture.request(reqwest::Method::POST, &path, read).await.status(), reqwest::StatusCode::FORBIDDEN);
            assert_eq!(fixture.request(reqwest::Method::GET, &path, write).await.status(), reqwest::StatusCode::FORBIDDEN);
            let created = fixture.request(reqwest::Method::POST, &path, write).await;
            assert_eq!(created.status(), reqwest::StatusCode::CREATED);
            let created: serde_json::Value = created.json().await.expect("actual catalog resource");
            let id = created["id"].as_str().expect("stable resource ID");
            let detail = format!("{path}/{id}");
            assert_eq!(fixture.request(reqwest::Method::GET, &path, read).await.status(), reqwest::StatusCode::OK);
            let detail_response = fixture.request(reqwest::Method::GET, &detail, read).await;
            assert_eq!(detail_response.status(), reqwest::StatusCode::OK);
            let detail_response: serde_json::Value = detail_response.json().await.expect("namespace-bound detail");
            assert_eq!(detail_response["applicationId"], fixture.scope.application_id.to_string());
            assert_eq!(fixture.request(reqwest::Method::DELETE, &detail, read).await.status(), reqwest::StatusCode::FORBIDDEN);
            assert_eq!(fixture.request(reqwest::Method::DELETE, &detail, write).await.status(), reqwest::StatusCode::NO_CONTENT);
            assert_eq!(fixture.request(reqwest::Method::GET, &detail, read).await.status(), reqwest::StatusCode::NOT_FOUND);
        }
        let wrong_socket = tokio_tungstenite::connect_async(fixture.socket_url(&database_read, false)).await;
        assert!(matches!(wrong_socket, Err(tokio_tungstenite::tungstenite::Error::Http(ref response)) if response.status() == reqwest::StatusCode::UNAUTHORIZED), "database token must not open a filesystem socket");
        let file = fixture.file().await;
        file.write("shared.txt", b"before").await.expect("native resource");
        let mut reader = fixture.socket(&read, false).await;
        send(&mut reader, StorageRequest::Read { path: "shared.txt".into() }).await;
        assert_eq!(response(&mut reader).await, StorageResponse::Read { content: b"before".to_vec() });
        send(&mut reader, StorageRequest::Write { path: "shared.txt".into(), content: b"denied".to_vec() }).await;
        assert!(matches!(response(&mut reader).await, StorageResponse::Error { .. }));
        assert_eq!(file.read("shared.txt").await.expect("read-only mutation denied"), b"before");
        let mut writer = fixture.socket(&write, false).await;
        send(&mut writer, StorageRequest::Write { path: "shared.txt".into(), content: b"after".to_vec() }).await;
        assert!(matches!(response(&mut writer).await, StorageResponse::Written { .. }));
        send(&mut writer, StorageRequest::Read { path: "shared.txt".into() }).await;
        assert!(matches!(response(&mut writer).await, StorageResponse::Error { .. }));
        assert_eq!(file.read("shared.txt").await.expect("real API write"), b"after");
        fixture.revoke_user().await;
        send(&mut reader, StorageRequest::Read { path: "shared.txt".into() }).await;
        assert_no_response(&mut reader).await;
        send(&mut writer, StorageRequest::Write { path: "shared.txt".into(), content: b"revoked".to_vec() }).await;
        assert_no_response(&mut writer).await;
        assert_eq!(file.read("shared.txt").await.expect("revoked mutation absent"), b"after");
        assert_eq!(fixture.request(reqwest::Method::GET, "/storage/filesystems", &read).await.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(matches!(storage_server::authorize_storage_token(&fixture.client, &read).await, Err(storage_server::StorageAuthorizationError::InvalidToken)));
        drop(reader); drop(writer); fixture.stop().await;
    }).await.expect("native local API actions complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_local_token_authorized_write_survives_revoked_response_and_next_operation_denial() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let fixture = Fixture::new(gate.clone()).await;
        let token = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Write]).await;
        let file = fixture.file().await;
        let mut socket = fixture.socket(&token, true).await;
        send(&mut socket, StorageRequest::Write { path: "committed.txt".into(), content: b"authorized in-flight content".to_vec() }).await;
        gate.reached().await;
        assert_eq!(file.read("committed.txt").await.expect("actual write completed before learning denial"), b"authorized in-flight content");
        fixture.revoke_user().await;
        gate.release();
        assert_no_response(&mut socket).await;
        let next = fixture.request(reqwest::Method::POST, "/storage/filesystems", &token).await;
        assert_eq!(next.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(matches!(tokio_tungstenite::connect_async(fixture.socket_url(&token, false)).await, Err(tokio_tungstenite::tungstenite::Error::Http(ref response)) if response.status() == reqwest::StatusCode::UNAUTHORIZED), "revoked token cannot reconnect for another write");
        assert_eq!(file.read("committed.txt").await.expect("earlier write retained"), b"authorized in-flight content");
        drop(socket); fixture.stop().await;
    }).await.expect("native in-flight API write completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_local_owner_service_loss_denies_response_and_api_without_cached_fallback() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let mut fixture = Fixture::new(gate.clone()).await;
        let token = fixture
            .token(
                "storage:filesystems",
                vec![StorageAuthorizationAction::Read],
            )
            .await;
        let file = fixture.file().await;
        file.write("private.txt", b"native content")
            .await
            .expect("real filesystem content");
        let mut socket = fixture.socket(&token, true).await;
        send(
            &mut socket,
            StorageRequest::Read {
                path: "private.txt".into(),
            },
        )
        .await;
        gate.reached().await;
        fixture.idp_listener.stop().await;
        gate.release();
        assert_no_response(&mut socket).await;
        assert_eq!(
            fixture
                .request(reqwest::Method::GET, "/storage/filesystems", &token)
                .await
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            matches!(
                storage_server::authorize_storage_token(&fixture.client, &token).await,
                Err(storage_server::StorageAuthorizationError::ServiceUnavailable)
            ),
            "cached service credential is not cached resource authorization"
        );
        assert_eq!(
            file.read("private.txt").await.expect("source retained"),
            b"native content"
        );
        drop(socket);
        fixture.stop().await;
    })
    .await
    .expect("failed local owner evaluation denies safely");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_create_response_denies_learned_user_deletion_without_rollback() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let fixture = Fixture::with_catalog_gate(Gate::default(), Some(gate.clone())).await;
        let token = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Write]).await;
        let source = fixture.file().await;
        source.write("source.txt", b"earlier content").await.expect("existing resource content");
        let mut request = Box::pin(fixture.request(reqwest::Method::POST, "/storage/filesystems", &token));
        tokio::select! {
            response = &mut request => panic!("catalog result transmitted without post-execution authorization: {}", response.status()),
            () = gate.reached() => {}
        }
        assert_eq!(fixture.files.list_resources(&fixture.scope).await.expect("observe completed creation before learned denial").len(), 2);
        fixture.revoke_user().await;
        gate.release();
        let response = request.await;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(response.bytes().await.expect("denial body").is_empty(), "catalog result must not be disclosed");
        assert_eq!(fixture.files.list_resources(&fixture.scope).await.expect("authorized creation retained").len(), 2);
        assert_eq!(source.read("source.txt").await.expect("earlier source retained"), b"earlier content");
        fixture.stop().await;
    }).await.expect("native catalog response boundary completes");
}

async fn catalog_response_denial(kind: &str, operation: &str) {
    let gate = Gate::default();
    let fixture = Fixture::with_catalog_gate(Gate::default(), Some(gate.clone())).await;
    let write = matches!(operation, "create" | "delete");
    let token = fixture
        .token(
            &format!("storage:{kind}"),
            vec![if write {
                StorageAuthorizationAction::Write
            } else {
                StorageAuthorizationAction::Read
            }],
        )
        .await;
    let source = fixture.file().await;
    source
        .write("source.txt", b"earlier source content")
        .await
        .expect("prior content");
    let target = if kind == "databases" {
        fixture
            .databases
            .create(&fixture.scope, Some("target".into()))
            .expect("native database catalog")
            .0
            .id
            .to_string()
    } else {
        fixture
            .files
            .create_resource(&fixture.scope, Some("target".into()))
            .await
            .expect("native filesystem catalog")
            .id
            .as_uuid()
            .to_string()
    };
    let before = if kind == "databases" { 1 } else { 2 };
    let expected = match operation {
        "create" => before + 1,
        "delete" => before - 1,
        _ => before,
    };
    let method = match operation {
        "create" => reqwest::Method::POST,
        "delete" => reqwest::Method::DELETE,
        _ => reqwest::Method::GET,
    };
    let path = if matches!(operation, "get" | "delete") {
        format!("/storage/{kind}/{target}")
    } else {
        format!("/storage/{kind}")
    };
    let mut request = Box::pin(fixture.request(method, &path, &token));
    tokio::select! {
        response = &mut request => panic!("{kind}/{operation} returned before current response authorization: {}", response.status()),
        () = gate.reached() => {}
    }
    let observed = if kind == "databases" {
        fixture
            .databases
            .list(&fixture.scope)
            .expect("completed database operation")
            .len()
    } else {
        fixture
            .files
            .list_resources(&fixture.scope)
            .await
            .expect("completed filesystem operation")
            .len()
    };
    assert_eq!(
        observed, expected,
        "actual {kind}/{operation} completed before learning denial"
    );
    fixture.revoke_user().await;
    gate.release();
    let response = request.await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "current {kind}/{operation} result must deny"
    );
    assert!(
        response.bytes().await.expect("denial body").is_empty(),
        "catalog data and successful operation status must not disclose"
    );
    let retained = if kind == "databases" {
        fixture
            .databases
            .list(&fixture.scope)
            .expect("retained database mutation")
            .len()
    } else {
        fixture
            .files
            .list_resources(&fixture.scope)
            .await
            .expect("retained filesystem mutation")
            .len()
    };
    assert_eq!(
        retained, expected,
        "response denial must not roll back authorized {kind}/{operation}"
    );
    assert_eq!(
        source
            .read("source.txt")
            .await
            .expect("prior source preserved"),
        b"earlier source content"
    );
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_all_result_kinds_recheck_after_execution_and_retain_mutations() {
    tokio::time::timeout(Duration::from_secs(600), async {
        for kind in ["databases", "filesystems"] {
            for operation in ["create", "get", "list", "delete"] {
                if kind != "filesystems" || operation != "create" {
                    catalog_response_denial(kind, operation).await;
                }
            }
        }
    })
    .await
    .expect("native catalog result matrix completes");
}
