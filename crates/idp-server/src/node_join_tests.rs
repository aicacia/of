use std::sync::Arc;

use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        INSTALLATION_POLICY_ID, IdentityAction, OAuth2ClientAuth, PasswordGrantRequest,
        TokenEndpointAuthMethod, TokenRequest,
    },
    model::Id,
};
use idp_service::oauth2::NodeSignerBinding;
use idp_service::repo::ClientRepo;
use iroh::SecretKey;

use crate::{AppConfig, OwnerProvisioner, node_provisioning_tests::Secrets};

#[tokio::test]
async fn node_join_invalid_bearer_cannot_approve_pairing() {
    let fixture = approval_fixture().await;
    let peer = &fixture.server;
    let joining = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::Minimal,
        SecretKey::generate(),
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("bind joining endpoint");
    joining.set_pairing_enabled(true);
    let router = peer.router(crate::BootstrapProtocolHandler);
    peer.set_pairing_enabled(true);
    let mut offers = peer.subscribe_pairing_offers();
    let send = tokio::spawn({
        let joining = joining.clone();
        let address = peer.endpoint().addr();
        async move { joining.send_pairing_offer(address, b"{}").await }
    });
    let offer = tokio::time::timeout(std::time::Duration::from_secs(15), offers.recv())
        .await
        .expect("bounded pairing offer")
        .expect("pairing offer");
    assert!(
        fixture
            .state
            .approve_node_join(&offer, "forged-bearer")
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .state
            .replica_signers
            .trusted_signers(&fixture.issuer, i64::MAX)
            .await
            .expect("trust")
            .len(),
        1
    );
    send.abort();
    let _ = send.await;
    router.shutdown().await.expect("stop pairing router");
    joining.endpoint().close().await;
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root).expect("remove native fixture");
}

#[tokio::test]
async fn node_join_secure_store_loss_and_corrupt_journal_fail_closed() {
    use std::sync::atomic::Ordering;
    let root = std::env::temp_dir().join(format!("node-join-failure-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let secrets = Secrets::default();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: SecretKey::generate().public().to_string(),
    };
    let peer = SecretKey::generate().public();
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("native owner");
    secrets.fail.store(true, Ordering::SeqCst);
    assert!(
        owner
            .prepare_node_join(&binding, "Joining Node", peer)
            .is_err()
    );
    assert!(
        !root.join("node-join-request.json").exists(),
        "secure-store failure must not publish request"
    );
    secrets.fail.store(false, Ordering::SeqCst);
    std::fs::write(
        root.join("node-join-request.interrupted.tmp"),
        b"partial interrupted temporary write",
    )
    .expect("interrupted pre-publish stage");
    let request = owner
        .prepare_node_join(&binding, "Joining Node", peer)
        .expect("retry after secure-store failure");
    drop(owner);
    let missing = OwnerProvisioner::open_with_private_keys(&config, Secrets::default())
        .await
        .expect("native reopen with missing secrets");
    assert!(
        missing
            .prepare_node_join(&binding, "Joining Node", peer)
            .is_err(),
        "missing persisted key cannot be replaced"
    );
    assert_eq!(
        serde_json::from_slice::<crate::NodeJoinRequest>(
            &std::fs::read(root.join("node-join-request.json")).expect("preserved journal")
        )
        .expect("request"),
        request
    );
    drop(missing);
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets)
        .await
        .expect("reopen retained secrets");
    std::fs::write(root.join("node-join-request.json"), b"corrupt-final")
        .expect("inject corrupt final journal");
    assert!(
        owner
            .prepare_node_join(&binding, "Joining Node", peer)
            .is_err()
    );
    assert_eq!(
        std::fs::read(root.join("node-join-request.json")).expect("preserved corrupt final"),
        b"corrupt-final"
    );
    drop(owner);
    std::fs::remove_dir_all(root).expect("remove isolated owner");
}

pub(crate) struct ApprovalFixture {
    pub(crate) state: crate::RouterState,
    pub(crate) server: iroh_chain::Server,
    pub(crate) issuer: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) owner: Id,
    pub(crate) management: Arc<db::Database>,
}

pub(crate) async fn approval_fixture() -> ApprovalFixture {
    approval_fixture_for_issuer(format!("https://installation-{}.test/idp", Id::now_v7())).await
}

pub(crate) async fn approval_fixture_for_issuer(issuer: String) -> ApprovalFixture {
    let root = std::env::temp_dir().join(format!("node-join-approval-{}", Id::now_v7()));
    let mut config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    config.oauth2.issuer = issuer.clone();
    let store: Arc<keyring_core::CredentialStore> = Arc::new(TestStore(
        keyring_core::mock::Store::new().expect("test keyring"),
    ));
    let mut provisioner = OwnerProvisioner::open_with_private_keys(
        &config,
        idp_service::repo::PrivateKeyKeyringRepo::new_with_store(&issuer, store),
    )
    .await
    .expect("native owner");
    let secret = SecretKey::generate();
    let server = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::Minimal,
        secret.clone(),
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("peer endpoint");
    let owner = Id::now_v7();
    provisioner
        .ensure_initial_user(owner, Id::now_v7(), "admin", "valid-password")
        .await
        .expect("initial owner");
    provisioner
        .oauth2
        .key_service
        .ensure_entity_master_key(
            idp_model::contract::EntityType::User,
            owner,
            "valid-password",
        )
        .expect("User local master key");
    provisioner
        .oauth2
        .key_service
        .create_key(
            None,
            idp_model::contract::EntityType::User,
            owner,
            true,
            "User session key".into(),
            None,
        )
        .await
        .expect("real User session signing key");
    let peer_binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: server.endpoint().id().to_string(),
    };
    provisioner.oauth2.oauth_config.local_signer = Some(peer_binding.clone());
    provisioner
        .ensure_initial_node(&peer_binding, owner, "Approving Node")
        .await
        .expect("independent trusted peer signer");
    provisioner
        .oauth2
        .client_repo
        .create_client(ClientRegistration {
            application: ApplicationRegistration {
                name: Some("Join approval".into()),
                uri: "https://approval.test".into(),
                description: None,
            },
            client_id: Some("human-client".into()),
            client_secret: Some("human-secret".into()),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Join approval".into(),
            client_uri: None,
            logo_uri: None,
            contacts: vec![],
            terms_of_service_uri: None,
            policy_uri: None,
            client_type: ClientType::Confidential,
            profile: ClientProfile::Web,
            redirect_uris: vec![],
            allowed_grant_types: vec![GrantType::Password, GrantType::TokenExchange],
            response_types: vec![],
            allowed_scopes: vec!["openid".into()],
            allowed_audiences: vec!["idp-services".into(), "wrong-audience".into()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            software_statement: None,
            software_id: None,
            software_version: None,
        })
        .await
        .expect("human session client");
    std::fs::create_dir_all(root.join("management")).expect("separate policy directory");
    let management = Arc::new(
        db::Database::open(root.join("management/management.redb"))
            .expect("native Management owner"),
    );
    management_service::replica::up(&management)
        .await
        .expect("policy schema");
    let engine = provisioner.engine.clone();
    let state = crate::RouterState::new(
        "https://ui.test",
        "idp-services",
        engine.clone(),
        Arc::new(provisioner.oauth2),
        Arc::new(management_service::replica::DbDeviceRepo::new(engine)),
        Arc::new(crate::device_identity_from_server(&server, secret).expect("peer identity")),
    )
    .with_local_permissions(management_service::LocalPermissions::new(
        management.clone(),
    ));
    ApprovalFixture {
        state,
        server,
        issuer,
        root,
        owner,
        management,
    }
}

pub(crate) async fn user_token(fixture: &ApprovalFixture, audience: &str) -> String {
    let token = fixture
        .state
        .oauth2_service
        .token(
            TokenRequest::Password(PasswordGrantRequest {
                client_id: "human-client".into(),
                username: "admin".into(),
                password: "valid-password".into(),
                scope: Some("openid".into()),
                resource: Some(audience.into()),
            }),
            Some(OAuth2ClientAuth {
                client_id: "human-client".into(),
                client_secret: Some("human-secret".into()),
                method: TokenEndpointAuthMethod::ClientSecretBasic,
            }),
        )
        .await
        .expect("production User session token")
        .access_token
        .0;
    fixture
        .state
        .oauth2_service
        .token(
            TokenRequest::TokenExchange(idp_model::contract::TokenExchangeGrantRequest {
                subject_token: token,
                subject_token_type: idp_model::contract::SubjectTokenType::AccessToken,
                actor_token: None,
                actor_token_type: None,
                resource: Some(audience.into()),
                audience: None,
                authorization_details: None,
                scope: None,
                requested_token_type: None,
            }),
            Some(OAuth2ClientAuth {
                client_id: "human-client".into(),
                client_secret: Some("human-secret".into()),
                method: TokenEndpointAuthMethod::ClientSecretBasic,
            }),
        )
        .await
        .expect("purpose-audience User session token")
        .access_token
        .0
}

#[tokio::test]
async fn node_join_requires_both_permissions_and_retries_after_disconnected_reply() {
    use management_service::{
        DeviceRepo, ManagementService,
        replica::{DbPermissionRepo, DbRoleRepo},
    };
    let fixture = approval_fixture().await;
    let peer_router = fixture.server.router(crate::BootstrapProtocolHandler);
    fixture.server.set_pairing_enabled(true);
    let mut offers = fixture.server.subscribe_pairing_offers();
    let joining_secret = SecretKey::generate();
    let joining = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::Minimal,
        joining_secret.clone(),
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("joining endpoint");
    joining.set_pairing_enabled(true);
    let config = AppConfig {
        data_dir: fixture.root.join("joining").to_string_lossy().into_owned(),
        oauth2: idp_service::oauth2::OAuth2Config {
            issuer: fixture.issuer.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    let secrets = Secrets::default();
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("separate joining owner");
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: joining.endpoint().id().to_string(),
    };
    let request = provisioner
        .prepare_node_join(&binding, "Joining Node", fixture.server.endpoint().id())
        .expect("durable independent join request");
    let sending = tokio::spawn({
        let joining = joining.clone();
        let address = fixture.server.endpoint().addr();
        let request = request.clone();
        async move { request.send(&joining, address).await }
    });
    let offer = tokio::time::timeout(std::time::Duration::from_secs(15), offers.recv())
        .await
        .expect("offer timeout")
        .expect("authenticated offer");
    let bearer = user_token(&fixture, "idp-services").await;
    let actor = crate::authorize_bearer(&fixture.state, &bearer)
        .await
        .expect("ordinary authentication succeeds");
    assert_eq!(actor.claims.aud, "idp-services");
    assert_eq!(actor.claims.sub, fixture.owner.to_string());
    assert!(
        fixture
            .state
            .approve_node_join(&offer, &bearer)
            .await
            .is_err(),
        "ordinary authentication must not approve"
    );
    let policy = ManagementService::new(
        DbPermissionRepo::new(fixture.management.clone()),
        DbRoleRepo::new(fixture.management.clone()),
    );
    let role = policy
        .create_role(INSTALLATION_POLICY_ID, "Join approver", None)
        .await
        .expect("explicit role");
    policy
        .add_role_to_user(INSTALLATION_POLICY_ID, fixture.owner, role.id)
        .await
        .expect("assign role");
    let permission = policy
        .create_permission(
            INSTALLATION_POLICY_ID,
            IdentityAction::DevicePairingUpdate.permission(),
            None,
        )
        .await
        .expect("pairing grant");
    policy
        .add_permission_to_role(INSTALLATION_POLICY_ID, role.id, permission.id)
        .await
        .expect("assign pairing grant");
    assert!(
        fixture
            .state
            .approve_node_join(&offer, &bearer)
            .await
            .is_err(),
        "pairing permission cannot enroll independent signer"
    );
    let permission = policy
        .create_permission(
            INSTALLATION_POLICY_ID,
            IdentityAction::ReplicaSignersEnroll.permission(),
            None,
        )
        .await
        .expect("signer grant");
    policy
        .add_permission_to_role(INSTALLATION_POLICY_ID, role.id, permission.id)
        .await
        .expect("assign signer grant");
    let mut missing_policy = fixture.state.clone();
    missing_policy.local_permissions = None;
    assert!(
        missing_policy
            .approve_node_join(&offer, &bearer)
            .await
            .is_err(),
        "missing local policy fails closed"
    );
    drop(missing_policy);
    let wrong_audience = user_token(&fixture, "wrong-audience").await;
    assert!(
        fixture
            .state
            .approve_node_join(&offer, &wrong_audience)
            .await
            .is_err()
    );
    let mut forged = offer.clone();
    let mut unsupported = serde_json::to_value(&request).expect("request value");
    unsupported["role"] = serde_json::json!("storage-only");
    forged.payload = serde_json::to_vec(&unsupported).expect("retired role offer");
    assert!(
        fixture
            .state
            .approve_node_join(&forged, &bearer)
            .await
            .is_err()
    );
    unsupported
        .as_object_mut()
        .expect("request object")
        .remove("role");
    unsupported["purpose"] = serde_json::json!("other-pairing-purpose");
    forged.payload = serde_json::to_vec(&unsupported).expect("foreign purpose");
    assert!(
        fixture
            .state
            .approve_node_join(&forged, &bearer)
            .await
            .is_err()
    );
    let mut foreign = request.clone();
    foreign.installation = "https://foreign.test/idp".into();
    forged.payload = serde_json::to_vec(&foreign).expect("foreign offer");
    assert!(
        fixture
            .state
            .approve_node_join(&forged, &bearer)
            .await
            .is_err()
    );
    foreign = request.clone();
    foreign.endpoint_id = SecretKey::generate().public().to_string();
    forged.payload = serde_json::to_vec(&foreign).expect("forged endpoint offer");
    assert!(
        fixture
            .state
            .approve_node_join(&forged, &bearer)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .state
            .replica_signers
            .trusted_signers(&fixture.issuer, i64::MAX)
            .await
            .expect("unchanged trust")
            .len(),
        1
    );
    assert!(
        !fixture.server.peers().contains(joining.endpoint().id()),
        "pairing and denied offers cannot add general admission"
    );
    if let Ok(connection) = joining
        .endpoint()
        .connect(fixture.server.endpoint().addr(), iroh_chain::DATA_ALPN)
        .await
    {
        tokio::time::timeout(std::time::Duration::from_secs(15), connection.closed())
            .await
            .expect("pairing must not admit general DATA connection");
        assert!(connection.close_reason().is_some());
    }
    joining.endpoint().close().await;
    sending.abort();
    let _ = sending.await;
    let reply_error = fixture
        .state
        .approve_node_join(&offer, &bearer)
        .await
        .expect_err("disconnected reply fails after durable enrollment");
    eprintln!("disconnected approval: {reply_error}");
    assert!(
        fixture
            .state
            .replica_signers
            .is_trusted_peer(
                &fixture.issuer,
                binding.member_id,
                &binding.endpoint_id,
                i64::MAX
            )
            .await
            .expect("durable enrollment despite lost reply")
    );
    let joining = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::Minimal,
        joining_secret,
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("reopen endpoint identity");
    joining.set_pairing_enabled(true);
    let sending = tokio::spawn({
        let joining = joining.clone();
        let address = fixture.server.endpoint().addr();
        let request = request.clone();
        async move { request.send(&joining, address).await }
    });
    let offer = tokio::time::timeout(std::time::Duration::from_secs(15), offers.recv())
        .await
        .expect("retry timeout")
        .expect("retry offer");
    let approved = fixture
        .state
        .approve_node_join(&offer, &bearer)
        .await
        .expect("authorized exact retry");
    let received = sending
        .await
        .expect("pairing sender")
        .expect("pinned peer reply verification");
    let mut changed = request.clone();
    changed.name = "Replaced name".into();
    let mut changed_offer = offer.clone();
    changed_offer.payload = serde_json::to_vec(&changed).expect("changed retry");
    assert!(
        fixture
            .state
            .approve_node_join(&changed_offer, &bearer)
            .await
            .is_err(),
        "persisted approval intent binds exact request"
    );
    assert!(
        fixture
            .state
            .replica_signers
            .is_trusted_peer(
                &fixture.issuer,
                binding.member_id,
                &binding.endpoint_id,
                i64::MAX
            )
            .await
            .expect("valid enrollment remains trusted"),
        "rejected mismatched retry must not revoke an existing valid enrollment"
    );
    let mut changed_receipt = received.clone();
    changed_receipt.request.approving_peer = SecretKey::generate().public().to_string();
    assert!(
        changed_receipt.verify(&request).is_err(),
        "receipt cannot change pinned trusted peer"
    );
    changed_receipt = received.clone();
    changed_receipt.request.public_signer.kid = Id::now_v7().to_string();
    assert!(
        changed_receipt.verify(&request).is_err(),
        "receipt cannot substitute independent signer"
    );
    assert_eq!(approved, received);
    assert_eq!(received.owner_subject, fixture.owner);
    assert_eq!(
        fixture
            .state
            .devices
            .list()
            .await
            .expect("public Device owner list")
            .len(),
        2,
        "retry cannot duplicate Device"
    );
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut forged = received.clone();
    forged.signature = URL_SAFE_NO_PAD.encode(
        SecretKey::generate()
            .sign(
                &crate::NodeJoinApproval::payload(&request, received.owner_subject)
                    .expect("approval purpose payload"),
            )
            .to_bytes(),
    );
    assert!(
        provisioner.record_node_join_approval(&forged).is_err(),
        "untrusted peer cannot forge pinned-peer approval"
    );
    let mut forged = received.clone();
    forged.owner_subject = Id::now_v7();
    assert!(provisioner.record_node_join_approval(&forged).is_err());
    assert!(
        provisioner
            .node_join_approval()
            .expect("no forged receipt")
            .is_none()
    );
    provisioner
        .record_node_join_approval(&received)
        .expect("persist verified receipt");
    provisioner
        .record_node_join_approval(&received)
        .expect("exact receipt retry");
    assert!(
        provisioner.verify_node_signer(&binding).await.is_err(),
        "receipt alone is not local trust or all-context readiness"
    );
    drop(provisioner);
    joining.endpoint().close().await;
    peer_router.shutdown().await.expect("stop peer");
    let provisioner = OwnerProvisioner::open_with_private_keys(&config, secrets)
        .await
        .expect("offline native reopen");
    assert_eq!(
        provisioner
            .node_join_approval()
            .expect("persisted approval"),
        Some(received)
    );
    assert_eq!(
        provisioner
            .prepare_node_join(&binding, "Joining Node", fixture.server.endpoint().id())
            .expect("retained independent private signer"),
        request
    );
    drop(provisioner);
    fixture
        .state
        .devices
        .revoke(
            &fixture.owner.to_string(),
            binding.member_id,
            &fixture.server.endpoint().id().to_string(),
        )
        .await
        .expect("learned Device revocation");
    assert!(
        fixture
            .state
            .approve_node_join(&offer, &bearer)
            .await
            .is_err(),
        "exact retry must not resurrect learned revocation"
    );
    assert!(
        !fixture
            .state
            .replica_signers
            .is_trusted_peer(
                &fixture.issuer,
                binding.member_id,
                &binding.endpoint_id,
                i64::MAX
            )
            .await
            .expect("revoked trust")
    );
    let root = fixture.root.clone();
    drop(policy);
    drop(fixture);
    std::fs::remove_dir_all(root).expect("remove isolated native owners");
}

struct TestStore(std::sync::Arc<keyring_core::mock::Store>);
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
        _: Option<&std::collections::HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        keyring_core::api::CredentialStoreApi::build(&*self.0, service, user, None)
    }
    fn search(
        &self,
        spec: &std::collections::HashMap<&str, &str>,
    ) -> keyring_core::Result<Vec<keyring_core::Entry>> {
        self.0.search(spec)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test]
async fn node_join_preparation_is_durable_exact_and_not_readiness() {
    let root = std::env::temp_dir().join(format!("node-join-{}", Id::now_v7()));
    let config = AppConfig {
        data_dir: root.to_string_lossy().into_owned(),
        ..AppConfig::default()
    };
    let secrets = Secrets::default();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: SecretKey::generate().public().to_string(),
    };
    let peer = SecretKey::generate().public();
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets.clone())
        .await
        .expect("open joining owner");
    let request = owner
        .prepare_node_join(&binding, "Joining Node", peer)
        .expect("persist request and independent private signer");
    assert_eq!(
        owner
            .prepare_node_join(&binding, "Joining Node", peer)
            .expect("exact retry"),
        request
    );
    assert!(
        owner
            .prepare_node_join(&binding, "Changed Node", peer)
            .is_err()
    );
    assert!(
        owner
            .prepare_node_join(&binding, "Joining Node", SecretKey::generate().public())
            .is_err()
    );
    assert!(
        owner.verify_node_signer(&binding).await.is_err(),
        "request is not trust/readiness"
    );
    drop(owner);
    let owner = OwnerProvisioner::open_with_private_keys(&config, secrets)
        .await
        .expect("reopen native owner without peer contact");
    assert_eq!(
        owner
            .prepare_node_join(&binding, "Joining Node", peer)
            .expect("offline exact retry"),
        request
    );
    drop(owner);
    std::fs::remove_dir_all(root).expect("remove isolated join store");
}
