use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        INSTALLATION_POLICY_ID, IdentityAction, IdpSignerRecord, ReplicaMembership,
        TokenEndpointAuthMethod,
    },
    model::Id,
};
use idp_server::{AppConfig, OwnerProvisioner, RouterState};
use idp_service::{
    oauth2::{NodeSignerBinding, OAuth2Service},
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbReplicaSignerRepo, DbUserRepo,
    },
    repo::{ClientRepo, KeyService, PrivateKeyKeyringRepo},
};
use management_service::{
    DeviceRepo, LocalPermissions, ManagementService,
    replica::{DbDeviceRepo, DbPermissionRepo, DbRoleRepo},
};
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::localhost_server::{
    LocalhostServer, localhost_server_base_url, prepare_test_tls, reserve_localhost_listener,
    start_unified_localhost_server,
};

use super::{load_or_create_setup_ids, reset};

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

struct Peer {
    root: PathBuf,
    data: PathBuf,
    api: String,
    client: reqwest::Client,
    server: Option<LocalhostServer>,
    state: Option<RouterState>,
    policy: Option<Arc<db::Database>>,
    config: AppConfig,
    store: Arc<keyring_core::CredentialStore>,
    secret: iroh::SecretKey,
    role: Id,
    faults: Arc<Faults>,
    endpoint: iroh_chain::Server,
    target: Id,
    bearer: String,
}

impl Peer {
    async fn open(actions: &[IdentityAction]) -> Self {
        let root = std::env::temp_dir().join(format!("queued-peer-{}", Id::now_v7()));
        let data = root.join("reset-node");
        let ids = load_or_create_setup_ids(&data).expect("stable reset identities");
        let tls = root.join("tls");
        let ca = prepare_test_tls(&tls).await;
        let (listener, port) = reserve_localhost_listener(&tls)
            .await
            .expect("desktop TLS listener");
        let api = format!("{}/idp", localhost_server_base_url(port));
        let issuer = format!("https://{}.test/idp", ids.installation_id);
        let mut config = AppConfig {
            data_dir: root.join("idp").to_string_lossy().into_owned(),
            ..AppConfig::default()
        };
        config.oauth2.issuer = issuer.clone();
        config.api_public_uri = api.clone();
        let store: Arc<keyring_core::CredentialStore> = Arc::new(TestStore(
            keyring_core::mock::Store::new().expect("isolated private provider"),
        ));
        let keys = PrivateKeyKeyringRepo::new_with_store(&issuer, store.clone());
        let owner = OwnerProvisioner::open_with_private_keys(
            &config,
            PrivateKeyKeyringRepo::new_with_store(&issuer, store.clone()),
        )
        .await
        .expect("native IdP owner");
        owner
            .prepare_fresh_setup_secret_inventory(ids.administrator_id, &[])
            .await
            .expect("captured User inventory");
        owner
            .prepare_setup_client_slots(&[])
            .await
            .expect("complete inventory");
        owner
            .ensure_initial_user(
                ids.administrator_id,
                ids.credential_id,
                "admin",
                "valid-password",
            )
            .await
            .expect("surviving User");
        owner
            .ensure_initial_user_signing_key(ids.administrator_id)
            .await
            .expect("real User signing key");
        let secret = iroh::SecretKey::generate();
        let endpoint = iroh_chain::Server::bind_with_secret_key(
            iroh::endpoint::presets::Minimal,
            secret.clone(),
            iroh_chain::EndpointIdStore::default(),
        )
        .await
        .expect("real peer identity");

        let target = NodeSignerBinding {
            member_id: ids.member_id,
            key_id: ids.signer_key_id,
            endpoint_id: iroh::SecretKey::generate().public().to_string(),
        };
        owner
            .ensure_initial_node(&target, ids.administrator_id, "Reset Node")
            .await
            .expect("exact target signer and Device");
        drop(owner);

        let engine =
            Arc::new(db::Database::open(root.join("idp/idp.redb")).expect("native IdP reopen"));
        let peer_devices = DbDeviceRepo::new(engine.clone());
        let peer_device = peer_devices
            .create(
                ids.administrator_id.to_string(),
                "Surviving peer".into(),
                endpoint.endpoint().id().to_string(),
                "".into(),
                vec![1],
                i64::MAX,
            )
            .await
            .expect("real peer Device");
        peer_devices
            .approve(peer_device.id, &[1])
            .await
            .expect("approve peer Device")
            .expect("pending peer approved");
        let binding = NodeSignerBinding {
            member_id: peer_device.id,
            key_id: Id::now_v7(),
            endpoint_id: endpoint.endpoint().id().to_string(),
        };
        let peer_config = AppConfig {
            data_dir: root.join("peer-private").to_string_lossy().into_owned(),
            ..config.clone()
        };
        let peer_owner = OwnerProvisioner::open_with_private_keys(
            &peer_config,
            PrivateKeyKeyringRepo::new_with_store(&issuer, store.clone()),
        )
        .await
        .expect("independent surviving Node private owner");
        peer_owner
            .prepare_fresh_setup_secret_inventory(ids.administrator_id, &[])
            .await
            .expect("peer private inventory");
        peer_owner
            .prepare_setup_client_slots(&[])
            .await
            .expect("peer complete inventory");
        let public_jwk = peer_owner
            .prepare_node_signer(&binding)
            .expect("real independent peer signer");
        DbReplicaSignerRepo::new(engine.clone())
            .enroll(
                &ReplicaMembership {
                    installation_id: issuer.clone(),
                    member_id: binding.member_id,
                    endpoint_id: binding.endpoint_id.clone(),
                    issuer: issuer.clone(),
                    approved_at: 1,
                    revoked_at: None,
                },
                &IdpSignerRecord {
                    member_id: binding.member_id,
                    key_id: binding.key_id,
                    issuer: issuer.clone(),
                    public_jwk,
                    approved_at: Some(1),
                    revoked_at: None,
                    expires_at: None,
                },
            )
            .await
            .expect("public owner peer enrollment");
        drop(peer_owner);
        config.oauth2.local_signer = Some(binding);
        let key_service = Arc::new(KeyService::new(
            DbKeyRepo::new(engine.clone()),
            keys,
            config.key_namespace.clone(),
        ));
        let clients = DbClientRepo::new(engine.clone(), key_service.clone());
        clients
            .create_client(ClientRegistration {
                application: ApplicationRegistration {
                    name: Some("Reset operator".into()),
                    uri: "https://operator.test".into(),
                    description: None,
                },
                client_id: Some("human-client".into()),
                client_secret: None,
                client_id_issued_at: None,
                client_secret_expires_at: None,
                client_name: "Reset operator".into(),
                client_uri: None,
                logo_uri: None,
                contacts: vec![],
                terms_of_service_uri: None,
                policy_uri: None,
                client_type: ClientType::Public,
                profile: ClientProfile::Native,
                redirect_uris: vec![],
                allowed_grant_types: vec![GrantType::Password, GrantType::TokenExchange],
                response_types: vec![],
                allowed_scopes: vec!["openid".into()],
                allowed_audiences: vec![api.clone()],
                token_endpoint_auth_method: TokenEndpointAuthMethod::None,
                software_statement: None,
                software_id: None,
                software_version: None,
            })
            .await
            .expect("real operator client");
        let oauth2 = OAuth2Service::new(
            DbApplicationRepo::new(engine.clone()),
            clients,
            DbOAuth2AuthorizationCodeRepo::new(engine.clone()),
            DbOAuth2RefreshTokenRepo::new(engine.clone()),
            DbUserRepo::new(engine.clone(), config.password.clone()),
            DbOAuth2UserConsentRepo::new(engine.clone()),
            key_service,
            config.oauth2.clone(),
        );
        let management = management_server::AppConfig {
            data_dir: root.join("management").to_string_lossy().into_owned(),
            ..Default::default()
        };
        management_server::provision_initial_administrator(
            &management,
            ids.administrator_id,
            ids.role_id,
            &[
                IdentityAction::DevicePairingRead,
                IdentityAction::DevicePairingUpdate,
            ]
            .iter()
            .chain(actions.iter())
            .map(|action| (Id::now_v7(), *action))
            .collect::<Vec<_>>(),
        )
        .await
        .expect("exact owner grants");
        let policy = Arc::new(
            db::Database::open(root.join("management/management.redb"))
                .expect("separate native policy owner"),
        );
        let state = RouterState::new(
            "https://operator.test",
            &api,
            engine.clone(),
            Arc::new(oauth2),
            Arc::new(DbDeviceRepo::new(engine)),
            Arc::new(
                idp_server::device_identity_from_server(&endpoint, secret.clone())
                    .expect("peer identity"),
            ),
        )
        .with_local_permissions(LocalPermissions::new(policy.clone()));
        let faults = Arc::new(Faults::default());
        let router = idp_server::openapi_router(state.clone(), "/idp")
            .split_for_parts()
            .0
            .layer(axum::middleware::from_fn_with_state(
                faults.clone(),
                observe_response,
            ));
        let server = start_unified_localhost_server(router, listener, &tls)
            .expect("current desktop HTTPS path");
        let client = super::peer_revocation::client_builder()
            .add_root_certificate(ca)
            .build()
            .expect("explicitly trusted TLS client");
        let response = client
            .post(format!("{api}/oauth2/token"))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "human-client"),
                ("username", "admin"),
                ("password", "valid-password"),
                ("scope", "openid"),
            ])
            .send()
            .await
            .expect("real HTTPS User login");
        let status = response.status();
        let token: Value = response.json().await.expect("User token response");
        assert!(status.is_success(), "real login denied: {status}: {token}");
        let bearer = token["access_token"]
            .as_str()
            .expect("real User bearer")
            .to_owned();
        let references = json!({"version":1,"phase":"secrets-pending","issuer":issuer,"ids":serde_json::from_slice::<Value>(&fs::read(data.join("setup-ids.json")).expect("retained IDs")).expect("IDs")});
        reset::queue_revocation(&data, &references).expect("actual durable public queue");
        Self {
            root,
            data,
            api,
            client,
            server: Some(server),
            state: Some(state),
            policy: Some(policy),
            config,
            store,
            secret,
            role: ids.role_id,
            faults,
            endpoint,
            target: ids.member_id,
            bearer,
        }
    }

    async fn close(mut self) {
        self.server
            .take()
            .expect("running listener")
            .close()
            .await
            .expect("close desktop TLS listener");
        self.endpoint.endpoint().close().await;
        drop(self.state.take());
        drop(self.policy.take());
        fs::remove_dir_all(self.root).expect("remove isolated native fixture");
    }
}

#[derive(Default)]
struct Faults {
    hold_device_ack: Mutex<bool>,
    committed: Notify,
    release: Notify,
    tokens: AtomicUsize,
    deletes: AtomicUsize,
}

async fn observe_response(
    axum::extract::State(faults): axum::extract::State<Arc<Faults>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let device = request.method() == axum::http::Method::DELETE
        && request.uri().path().starts_with("/idp/devices/");
    if request.uri().path() == "/idp/oauth2/token" {
        faults.tokens.fetch_add(1, Ordering::SeqCst);
    }
    if request.method() == axum::http::Method::DELETE {
        faults.deletes.fetch_add(1, Ordering::SeqCst);
    }
    let response = next.run(request).await;
    let hold = device
        && response.status().is_success()
        && std::mem::take(&mut *faults.hold_device_ack.lock().expect("response fault"));
    if hold {
        faults.committed.notify_one();
        faults.release.notified().await;
    }
    response
}

impl Peer {
    async fn revoke(&self) -> Result<(), String> {
        super::peer_revocation::revoke(
            &self.data,
            "https://localhost:1/idp",
            &self.api,
            &self.bearer,
            self.target,
            &self.client,
        )
        .await
    }

    fn status(&self) -> Value {
        let targets = reset::revocations(&self.data).expect("reopened durable queue");
        assert_eq!(targets.len(), 1, "one exact retained public target");
        assert_eq!(targets[0]["member_id"], self.target.to_string());
        assert_eq!(
            targets[0].as_object().expect("public target record").len(),
            4
        );
        assert_eq!(targets[0]["issuer"], self.config.oauth2.issuer);
        assert_eq!(targets[0]["version"], 1);
        targets[0]["status"].clone()
    }

    async fn assert_remote(&self, signer_active: bool, device_approved: bool) {
        let state = self.state.as_ref().expect("open native owner");
        let signers = state
            .replica_signers
            .trusted_signers(&self.config.oauth2.issuer, i64::MAX)
            .await
            .expect("public owner signer state");
        assert_eq!(
            signers
                .iter()
                .any(|(member, _)| member.member_id == self.target),
            signer_active
        );
        let devices = state
            .devices
            .list()
            .await
            .expect("public owner Device state");
        let device = devices
            .iter()
            .find(|device| device.id == self.target)
            .expect("exact retained Device");
        assert_eq!(
            device.state,
            if device_approved {
                idp_model::contract::DeviceState::Approved
            } else {
                idp_model::contract::DeviceState::Revoked
            }
        );
        assert_eq!(device.revoked_at.is_none(), device_approved);
        let surviving = self
            .config
            .oauth2
            .local_signer
            .as_ref()
            .expect("independent surviving signer");
        assert!(
            signers
                .iter()
                .any(|(member, _)| member.member_id == surviving.member_id)
        );
        assert_eq!(
            devices
                .iter()
                .find(|device| device.id == surviving.member_id)
                .expect("surviving Device")
                .state,
            idp_model::contract::DeviceState::Approved
        );
    }

    async fn set_grant(&self, action: IdentityAction, enabled: bool) {
        let engine = self.policy.as_ref().expect("open policy owner").clone();
        let service = ManagementService::new(
            DbPermissionRepo::new(engine.clone()),
            DbRoleRepo::new(engine),
        );
        let existing = service
            .list_permissions(INSTALLATION_POLICY_ID, 0, 100)
            .await
            .expect("public current permission catalog")
            .into_iter()
            .find(|permission| permission.name == action.permission());
        let permission = match existing {
            Some(permission) => permission,
            None => service
                .create_permission(INSTALLATION_POLICY_ID, action.permission(), None)
                .await
                .expect("exact current grant"),
        };
        if enabled {
            service
                .add_permission_to_role(INSTALLATION_POLICY_ID, self.role, permission.id)
                .await
                .expect("assign exact grant");
        } else {
            service
                .remove_permission_from_role(INSTALLATION_POLICY_ID, self.role, permission.id)
                .await
                .expect("remove current exact grant");
        }
    }

    async fn reopen(&mut self) {
        self.server
            .take()
            .expect("running peer")
            .close()
            .await
            .expect("stop peer HTTPS");
        drop(self.state.take());
        drop(self.policy.take());
        let engine = Arc::new(
            db::Database::open(self.root.join("idp/idp.redb"))
                .expect("native IdP reopen after response loss"),
        );
        let key_service = Arc::new(KeyService::new(
            DbKeyRepo::new(engine.clone()),
            PrivateKeyKeyringRepo::new_with_store(&self.config.oauth2.issuer, self.store.clone()),
            self.config.key_namespace.clone(),
        ));
        let oauth2 = OAuth2Service::new(
            DbApplicationRepo::new(engine.clone()),
            DbClientRepo::new(engine.clone(), key_service.clone()),
            DbOAuth2AuthorizationCodeRepo::new(engine.clone()),
            DbOAuth2RefreshTokenRepo::new(engine.clone()),
            DbUserRepo::new(engine.clone(), self.config.password.clone()),
            DbOAuth2UserConsentRepo::new(engine.clone()),
            key_service,
            self.config.oauth2.clone(),
        );
        let policy = Arc::new(
            db::Database::open(self.root.join("management/management.redb"))
                .expect("native policy reopen"),
        );
        let state = RouterState::new(
            "https://operator.test",
            &self.api,
            engine.clone(),
            Arc::new(oauth2),
            Arc::new(DbDeviceRepo::new(engine)),
            Arc::new(
                idp_server::device_identity_from_server(&self.endpoint, self.secret.clone())
                    .expect("retained peer identity"),
            ),
        )
        .with_local_permissions(LocalPermissions::new(policy.clone()));
        let router = idp_server::openapi_router(state.clone(), "/idp")
            .split_for_parts()
            .0
            .layer(axum::middleware::from_fn_with_state(
                self.faults.clone(),
                observe_response,
            ));
        let tls = self.root.join("tls");
        let (listener, port) = reserve_localhost_listener(&tls)
            .await
            .expect("reopen persisted HTTPS port");
        assert_eq!(format!("{}/idp", localhost_server_base_url(port)), self.api);
        self.client = super::peer_revocation::client_builder()
            .add_root_certificate(prepare_test_tls(&tls).await)
            .build()
            .expect("new explicitly trusted HTTPS client");
        self.server = Some(
            start_unified_localhost_server(router, listener, &tls).expect("reopened desktop TLS"),
        );
        self.state = Some(state);
        self.policy = Some(policy);
    }
}

#[tokio::test]
async fn queued_peer_revocation_partial_success_reopens_and_retries_with_current_grant() {
    let mut peer = Peer::open(&[IdentityAction::ReplicaSignersRevoke]).await;
    peer.assert_remote(true, true).await;
    let error = peer
        .revoke()
        .await
        .expect_err("Device revoke lacks current grant");
    assert!(error.contains("403"), "actual grant denial: {error}");
    assert_eq!(peer.status(), "pending");
    peer.assert_remote(false, true).await;
    peer.reopen().await;
    assert_eq!(peer.status(), "pending");
    peer.assert_remote(false, true).await;
    peer.set_grant(IdentityAction::DevicesRevoke, true).await;
    peer.revoke()
        .await
        .expect("authorized exact retry after native reopen");
    peer.assert_remote(false, false).await;
    assert_eq!(peer.status(), "acknowledged");
    peer.reopen().await;
    assert_eq!(peer.status(), "acknowledged");
    peer.assert_remote(false, false).await;
    peer.close().await;
}

#[tokio::test]
async fn queued_peer_revocation_lost_device_ack_reopens_and_retries_exact_revoked_target() {
    let mut peer = Peer::open(&[
        IdentityAction::ReplicaSignersRevoke,
        IdentityAction::DevicesRevoke,
    ])
    .await;
    *peer
        .faults
        .hold_device_ack
        .lock()
        .expect("arm response loss") = true;
    {
        let operation = peer.revoke();
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => panic!("response must remain held after real commit: {result:?}"),
            committed = tokio::time::timeout(std::time::Duration::from_secs(30), peer.faults.committed.notified()) => { committed.expect("bounded actual Device commit before response"); }
        }
        peer.assert_remote(false, false).await;
        assert_eq!(
            peer.status(),
            "pending",
            "remote commit is not a durable local acknowledgement"
        );
        operation
            .await
            .expect_err("HTTPS response acknowledgement lost to actual client timeout");
    }
    peer.faults.release.notify_one();
    peer.reopen().await;
    peer.assert_remote(false, false).await;
    assert_eq!(peer.status(), "pending");
    peer.set_grant(IdentityAction::ReplicaSignersRevoke, false)
        .await;
    let denied = peer
        .revoke()
        .await
        .expect_err("already-revoked state does not bypass current grants");
    assert!(
        denied.contains("403"),
        "current exact grant denial: {denied}"
    );
    assert_eq!(peer.status(), "pending");
    peer.assert_remote(false, false).await;
    peer.set_grant(IdentityAction::ReplicaSignersRevoke, true)
        .await;
    peer.revoke()
        .await
        .expect("authorized exact already-revoked retry");
    assert_eq!(peer.status(), "acknowledged");
    peer.reopen().await;
    assert_eq!(peer.status(), "acknowledged");
    peer.assert_remote(false, false).await;
    peer.close().await;
}

#[tokio::test]
async fn queued_peer_revocation_wrong_installation_sends_no_bearer_and_keeps_pending() {
    let peer = Peer::open(&[
        IdentityAction::ReplicaSignersRevoke,
        IdentityAction::DevicesRevoke,
    ])
    .await;
    let foreign = Peer::open(&[
        IdentityAction::ReplicaSignersRevoke,
        IdentityAction::DevicesRevoke,
    ])
    .await;
    let tokens = foreign.faults.tokens.load(Ordering::SeqCst);
    let deletes = foreign.faults.deletes.load(Ordering::SeqCst);
    let error = super::peer_revocation::revoke(
        &peer.data,
        "https://localhost:1/idp",
        &foreign.api,
        &peer.bearer,
        peer.target,
        &foreign.client,
    )
    .await
    .expect_err("different Installation metadata");
    assert!(
        error.contains("different Installation; no bearer was sent"),
        "{error}"
    );
    assert_eq!(foreign.faults.tokens.load(Ordering::SeqCst), tokens);
    assert_eq!(foreign.faults.deletes.load(Ordering::SeqCst), deletes);
    assert_eq!(peer.status(), "pending");
    peer.assert_remote(true, true).await;
    foreign.assert_remote(true, true).await;
    foreign.close().await;
    peer.close().await;
}

#[tokio::test]
async fn queued_peer_revocation_missing_signer_grant_keeps_both_targets_active() {
    let mut peer = Peer::open(&[IdentityAction::DevicesRevoke]).await;
    let error = peer
        .revoke()
        .await
        .expect_err("ordinary User authentication does not grant signer revocation");
    assert!(error.contains("403"), "real permission denial: {error}");
    peer.assert_remote(true, true).await;
    assert_eq!(peer.status(), "pending");
    peer.reopen().await;
    peer.assert_remote(true, true).await;
    assert_eq!(peer.status(), "pending");
    peer.close().await;
}

#[tokio::test]
async fn queued_peer_revocation_unknown_device_404_is_not_acknowledgement() {
    let peer = Peer::open(&[
        IdentityAction::ReplicaSignersRevoke,
        IdentityAction::DevicesRevoke,
    ])
    .await;
    let unknown_data = peer.root.join("unknown-reset-node");
    let unknown = load_or_create_setup_ids(&unknown_data).expect("independent unknown target IDs");
    let references = json!({"version":1,"phase":"secrets-pending","issuer":peer.config.oauth2.issuer,"ids":serde_json::from_slice::<Value>(&fs::read(unknown_data.join("setup-ids.json")).expect("retained unknown IDs")).expect("unknown IDs")});
    reset::queue_revocation(&unknown_data, &references)
        .expect("actual unknown public queue target");
    let error = super::peer_revocation::revoke(
        &unknown_data,
        "https://localhost:1/idp",
        &peer.api,
        &peer.bearer,
        unknown.member_id,
        &peer.client,
    )
    .await
    .expect_err("missing Device is not exact revoked state");
    assert!(
        error.contains("404"),
        "actual unknown Device owner response: {error}"
    );
    assert_eq!(
        reset::revocations(&unknown_data).expect("retained unknown queue")[0]["status"],
        "pending"
    );
    peer.assert_remote(true, true).await;
    assert_eq!(peer.status(), "pending");
    peer.close().await;
}

#[tokio::test]
async fn queued_peer_revocation_authorized_https_acknowledges_durably() {
    let peer = Peer::open(&[
        IdentityAction::ReplicaSignersRevoke,
        IdentityAction::DevicesRevoke,
    ])
    .await;
    super::peer_revocation::revoke(
        &peer.data,
        "https://localhost:1/idp",
        &peer.api,
        &peer.bearer,
        peer.target,
        &peer.client,
    )
    .await
    .expect("actual authorized workflow");
    assert_eq!(
        reset::revocations(&peer.data).expect("durable queue read")[0]["status"],
        "acknowledged"
    );
    peer.close().await;
}
