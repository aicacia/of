use std::{io::ErrorKind, sync::Arc, time::Duration};

use db::Database;
use idp_model::{contract::IdentityAction, model::Id};
use idp_server::{AppConfig, OwnerProvisioner};
use idp_service::{oauth2::NodeSignerBinding, replica::DbReplicaSignerRepo};
use iroh::{SecretKey, endpoint::presets::Minimal};
use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};
use tokio_util::sync::CancellationToken;

use crate::{
    SecurityContext, SecurityProtocol,
    permission_http_tests::{seed_idp, seed_permissions, user_token},
};

#[tokio::test]
async fn authorized_node_bootstrap_imports_both_contexts_and_reopens_offline() {
    tokio::time::timeout(Duration::from_secs(600), receipt_boundary(false))
        .await
        .expect("native approval, context denial and offline reopen complete");
}

#[tokio::test]
async fn owner_cutover_node_bootstrap_reopens_offline() {
    tokio::time::timeout(Duration::from_secs(600), receipt_boundary(true))
        .await
        .expect("initial native bootstrap and offline owner retry complete");
}

async fn issue_local_token(
    config: &AppConfig,
    owner: &OwnerProvisioner,
    server: &Server,
    secret: &SecretKey,
    binding: &NodeSignerBinding,
    client: Id,
    policy: Arc<Database>,
) {
    use idp_model::contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        TokenEndpointAuthMethod,
    };
    use tower::ServiceExt;
    owner
        .ensure_setup_infrastructure_client(ClientRegistration {
            application: ApplicationRegistration {
                name: Some("Joining local service".into()),
                uri: "https://joining-service.test".into(),
                description: None,
            },
            client_id: Some(client.to_string()),
            client_secret: Some("local-secret".into()),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Joining local service".into(),
            client_uri: None,
            logo_uri: None,
            contacts: vec![],
            terms_of_service_uri: None,
            policy_uri: None,
            client_type: ClientType::Confidential,
            profile: ClientProfile::Web,
            redirect_uris: vec![],
            allowed_grant_types: vec![GrantType::ClientCredentials],
            response_types: vec![],
            allowed_scopes: vec!["idp.token.validate".into()],
            allowed_audiences: vec!["https://joining-service.test".into()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            software_statement: None,
            software_id: None,
            software_version: None,
        })
        .await
        .expect("explicit independent local client verifier, never imported from peer");
    let mut issuing = config.clone();
    issuing.oauth2.local_signer = Some(binding.clone());
    issuing.server.prefix = Some("/idp".into());
    let runtime = idp_server::build_runtime(
        &issuing,
        owner.node_join_database(),
        Arc::new(
            idp_server::device_identity_from_server(server, secret.clone())
                .expect("retained local endpoint identity"),
        ),
        server.clone(),
        Some(management_service::LocalPermissions::new(policy)),
    )
    .await
    .expect("production independent local issuance runtime");
    let response = runtime.router().oneshot(http::Request::builder().method("POST").uri("/idp/oauth2/token")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("grant_type=client_credentials&client_id={client}&client_secret=local-secret&scope=idp.token.validate&audience=https%3A%2F%2Fjoining-service.test")))
        .expect("production client-credentials request")).await.expect("local token route");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("local token response");
    assert_eq!(
        status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let token: serde_json::Value = serde_json::from_slice(&body).expect("token JSON");
    let public = owner
        .verify_node_signer(binding)
        .await
        .expect("local signing material and imported trust");
    let (header, claims) = idp_service::oauth2::verify_jwt::<model::contract::StandardClaims>(
        &public,
        token["access_token"].as_str().expect("issued access token"),
    )
    .expect("independent local signature");
    assert_eq!(header.kid, binding.key_id.to_string());
    assert_eq!(claims.iss, config.oauth2.issuer);
    assert_ne!(claims.sub, binding.member_id.to_string());
}

async fn receipt_boundary(initial_and_offline_only: bool) {
    let started = std::time::Instant::now();
    let root = std::env::temp_dir().join(format!("of-node-join-bootstrap-{}", Id::now_v7()));
    let issuer = format!("https://join-{}.example", Id::now_v7());
    let source_secret = SecretKey::generate();
    let joining_secret = SecretKey::generate();
    let source_root = root.join("source");
    let joining_root = root.join("joining");
    let mut fixture = seed_idp(
        &source_root,
        &issuer,
        &source_secret.public().to_string(),
        &SecretKey::generate().public().to_string(),
    )
    .await;
    seed_permissions(&source_root, &mut fixture).await;
    let source_idp =
        Arc::new(Database::open(source_root.join("idp/idp.redb")).expect("source IdP"));
    let source_policy = Arc::new(
        Database::open(source_root.join("management/management.redb")).expect("source policy"),
    );
    let policy = ManagementService::new(
        DbPermissionRepo::new(source_policy.clone()),
        DbRoleRepo::new(source_policy.clone()),
    );
    let role = policy
        .create_role(
            idp_model::contract::INSTALLATION_POLICY_ID,
            "Explicit join approval",
            None,
        )
        .await
        .expect("purpose-specific source role");
    policy
        .add_role_to_user(
            idp_model::contract::INSTALLATION_POLICY_ID,
            fixture.administrator,
            role.id,
        )
        .await
        .expect("source User role");
    for action in [
        IdentityAction::ReplicaSignersEnroll,
        IdentityAction::IdpSecuritySync,
    ] {
        let permission = policy
            .create_permission(
                idp_model::contract::INSTALLATION_POLICY_ID,
                action.permission(),
                None,
            )
            .await
            .expect("explicit Installation permission");
        policy
            .add_permission_to_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role.id,
                permission.id,
            )
            .await
            .expect("explicit source grant");
    }
    source_idp
        .client()
        .translate_and_execute(
            &format!(
                "UPDATE devices SET owner_subject = '{}'",
                fixture.administrator
            ),
            &db::SqlTranslator,
        )
        .await
        .expect("all source fixture Devices bind a real active User, not invalid placeholders");

    let source_allowed = EndpointIdStore::default();
    let source =
        Server::bind_with_secret_key(Minimal, source_secret.clone(), source_allowed.clone())
            .await
            .expect("ordinary source admission hooks");
    let config = AppConfig {
        data_dir: joining_root.to_string_lossy().into_owned(),
        oauth2: idp_service::oauth2::OAuth2Config {
            issuer: issuer.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    let joining = idp_server::bind_node_join_endpoint(
        &config,
        Minimal,
        joining_secret.clone(),
        EndpointIdStore::default(),
    )
    .await
    .expect("shared endpoint with purpose-only persisted join admission");
    source.set_pairing_enabled(true);
    joining.set_pairing_enabled(true);
    let mut offers = source.subscribe_pairing_offers();
    let cancellation = CancellationToken::new();
    let storage = storage_server::build_runtime(
        storage_server::RouterState::new("http://localhost/storage")
            .with_idp_client(
                storage_server::IdpClient::new(
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    &issuer,
                    "idp",
                )
                .expect("unused resource client"),
            )
            .with_management_client(
                storage_server::ManagementClient::new(
                    "http://127.0.0.1:1/management",
                    "http://127.0.0.1:1/idp",
                    "storage",
                    "local",
                    &issuer,
                    "management",
                )
                .expect("unused resource policy client"),
            ),
        &source_root.join("storage"),
        "/storage",
        "",
        Some(source.clone()),
        cancellation.clone(),
    )
    .expect("existing DATA dispatcher; no resource access authorized");
    let source_security = SecurityProtocol::new(
        source.clone(),
        source_idp.clone(),
        source_policy.clone(),
        issuer.clone(),
        Some(fixture.local_signer.clone()),
        source_root.join("security-staging"),
        cancellation.clone(),
    );
    let peer_router = source.router_with_protocol(
        source_security.attach(storage.data_handler().expect("DATA handler")),
        idp_server::BOOTSTRAP_ALPN,
        source_security.node_bootstrap_handler(),
    );
    let mut source_config = AppConfig::default();
    source_config.oauth2.issuer = issuer.clone();
    source_config.oauth2.local_signer = Some(fixture.local_signer.clone());
    source_config.service_audience = Some("idp-services".into());
    source_config.server.prefix = Some("/idp".into());
    let runtime = idp_server::build_runtime(
        &source_config,
        source_idp.clone(),
        Arc::new(
            idp_server::device_identity_from_server(&source, source_secret)
                .expect("source identity"),
        ),
        source.clone(),
        Some(management_service::LocalPermissions::new(
            source_policy.clone(),
        )),
    )
    .await
    .expect("production approving owner runtime");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("source HTTP listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("source HTTP address")
    );
    let router = runtime.router();
    let http = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("source HTTP");
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client");
    let bearer = user_token(&client, &base, "administrator", "idp-services").await;
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: joining.endpoint().id().to_string(),
    };
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("fresh native joining owner with injected keyring");
    let local_client = Id::now_v7();
    assert!(
        provisioner
            .prepare_node_join(&binding, "Joining Node", source.endpoint().id())
            .is_err()
    );
    provisioner
        .prepare_fresh_setup_secret_inventory(fixture.administrator, &[local_client])
        .await
        .expect("fresh joining User and exact local Client inventory");
    provisioner
        .prepare_setup_client_slots(&[local_client])
        .await
        .expect("complete inventory before independent Node private work");
    let request = provisioner
        .prepare_node_join(&binding, "Joining Node", source.endpoint().id())
        .expect("durable independent private signer");
    let sending = tokio::spawn({
        let joining = joining.clone();
        let address = source.endpoint().addr();
        let request = request.clone();
        async move { request.send(&joining, address).await }
    });
    let offer = offers
        .recv()
        .await
        .expect("real authenticated pairing offer");
    assert!(
        joining
            .endpoint()
            .connect(source.endpoint().addr(), idp_server::BOOTSTRAP_ALPN)
            .await
            .is_err(),
        "no bootstrap admission before verified persisted receipt"
    );
    let approved = runtime
        .approve_node_join(&offer, &bearer)
        .await
        .expect("purpose-specific authorized enrollment");
    let received = sending
        .await
        .expect("pairing sender")
        .expect("pinned peer signed reply");
    assert_eq!(approved, received);
    source_allowed.replace(
        runtime
            .approved_peer_ids()
            .await
            .expect("source admission restored only from real durable trust"),
    );
    provisioner
        .record_node_join_approval(&received)
        .expect("persist receipt");
    provisioner
        .record_node_join_approval(&received)
        .expect("exact receipt retry");
    assert!(
        provisioner.verify_node_signer(&binding).await.is_err(),
        "receipt is not local signer trust"
    );
    let joining_idp = provisioner.node_join_database();
    let joining_policy = Arc::new(
        Database::open(joining_root.join("management.redb")).expect("joining policy owner"),
    );
    management_service::replica::up(&joining_policy)
        .await
        .expect("empty fixed public policy schema");
    let protocol = SecurityProtocol::new(
        joining.clone(),
        joining_idp.clone(),
        joining_policy.clone(),
        issuer.clone(),
        Some(binding.clone()),
        joining_root.join("security-staging"),
        cancellation.clone(),
    );
    assert!(
        joining
            .endpoint()
            .connect(source.endpoint().addr(), DATA_ALPN)
            .await
            .is_err(),
        "receipt/pairing cannot allow ordinary DATA"
    );
    let connection = joining
        .endpoint()
        .connect(source.endpoint().addr(), idp_server::BOOTSTRAP_ALPN)
        .await
        .expect("authenticated purpose-specific bootstrap connection");
    assert_eq!(connection.remote_id(), source.endpoint().id());
    for context in [SecurityContext::Idp, SecurityContext::Management] {
        let error = protocol
            .synchronize(&connection, context)
            .await
            .expect_err("receipt cannot authorize public context bootstrap");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(
            error
                .to_string()
                .contains("local node signer/member is not currently trusted"),
            "{context:?}: {error}"
        );
    }
    assert!(
        DbReplicaSignerRepo::new(joining_idp.clone())
            .trusted_signers(&issuer, i64::MAX)
            .await
            .expect("local trust remains empty")
            .is_empty()
    );
    for (database, table) in [
        (&joining_idp, "users"),
        (&joining_idp, "devices"),
        (&joining_policy, "roles"),
        (&joining_policy, "permissions"),
    ] {
        let rows = database
            .client()
            .translate_and_execute(&format!("SELECT * FROM {table}"), &db::SqlTranslator)
            .await
            .expect("public owner evidence");
        assert!(
            rows[0].rows.is_empty(),
            "denied bootstrap must not import {table}"
        );
    }
    assert!(
        !joining_root.join("security-staging").exists(),
        "denial precedes native staging"
    );
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("incomplete receipt")
    );
    protocol
        .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
        .await
        .expect("authorized initial IdP import");
    eprintln!("bootstrap IdP imported: {:?}", started.elapsed());
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("one context is incomplete")
    );
    assert!(
        protocol
            .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Management)
            .await
            .is_err(),
        "receipt alone cannot grant missing source context permission"
    );
    assert!(
        protocol
            .complete_node_join_public_bootstrap(&provisioner)
            .await
            .is_err(),
        "partial import cannot publish readiness"
    );
    drop(protocol);
    drop(provisioner);
    drop(joining_idp);
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("native restart between context imports");
    provisioner
        .prepare_setup_client_slots(&[local_client])
        .await
        .expect("partial restart retains exact preparation");
    let joining_idp = provisioner.node_join_database();
    let protocol = SecurityProtocol::new(
        joining.clone(),
        joining_idp.clone(),
        joining_policy.clone(),
        issuer.clone(),
        Some(binding.clone()),
        joining_root.join("security-staging"),
        cancellation.clone(),
    );
    assert!(
        !protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("reopened partial setup remains incomplete")
    );
    let permission = policy
        .create_permission(
            idp_model::contract::INSTALLATION_POLICY_ID,
            IdentityAction::ManagementSecuritySync.permission(),
            None,
        )
        .await
        .expect("explicit missing context grant");
    policy
        .add_permission_to_role(
            idp_model::contract::INSTALLATION_POLICY_ID,
            role.id,
            permission.id,
        )
        .await
        .expect("authorized independent policy bootstrap");
    protocol
        .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Management)
        .await
        .expect("authorized policy import after partial restart");
    eprintln!("bootstrap policy imported: {:?}", started.elapsed());
    protocol
        .complete_node_join_public_bootstrap(&provisioner)
        .await
        .expect("both contexts, current exact grants and independent signer");
    assert!(
        protocol
            .node_join_public_ready(&provisioner)
            .await
            .expect("durable public readiness")
    );
    issue_local_token(
        &config,
        &provisioner,
        &joining,
        &joining_secret,
        &binding,
        local_client,
        joining_policy.clone(),
    )
    .await;
    eprintln!("bootstrap locally issued token: {:?}", started.elapsed());
    if !initial_and_offline_only {
        let updated = Id::now_v7();
        crate::security_sync_tests::sql(&source_idp, &format!("INSERT INTO users (id, handle, name, created_at, updated_at) VALUES (CAST('{updated}' AS UUID), 'source-update', 'New Public User', 2, 2)")).await;
        let retry = protocol
            .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
            .await
            .expect("retained history and local-only client do not block source update retry");
        assert_eq!(
            retry.sent_units, 0,
            "receiver cannot publish application/catalog history"
        );
        assert_eq!(
            retry.sent_changes, 0,
            "receiver cannot publish local mutations"
        );
        assert_eq!(
            crate::security_sync_tests::sql(
                &joining_idp,
                &format!("SELECT id FROM users WHERE id = CAST('{updated}' AS UUID)")
            )
            .await[0]
                .rows
                .len(),
            1
        );
        assert!(
            crate::security_sync_tests::sql(
                &source_idp,
                &format!("SELECT id FROM clients WHERE client_id = '{local_client}'")
            )
            .await[0]
                .rows
                .is_empty(),
            "joining local client is never published to source"
        );
        protocol
            .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
            .await
            .expect("exact unchanged retry");
        eprintln!(
            "bootstrap source update and exact retry: {:?}",
            started.elapsed()
        );
        assert_eq!(
            crate::security_sync_tests::sql(
                &joining_idp,
                &format!(
                    "SELECT id FROM idp_replica_members WHERE member_id = CAST('{}' AS UUID)",
                    binding.member_id
                )
            )
            .await[0]
                .rows
                .len(),
            1,
            "retries cannot duplicate member"
        );
        policy
            .remove_permission_from_role(
                idp_model::contract::INSTALLATION_POLICY_ID,
                role.id,
                permission.id,
            )
            .await
            .expect("learned source context revocation");
        assert!(
            protocol
                .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Management)
                .await
                .is_err(),
            "existing connection cannot reuse receipt after source grant revocation"
        );
        DbReplicaSignerRepo::new(source_idp.clone())
            .revoke(binding.member_id, &issuer, 10)
            .await
            .expect("source learns joined membership revocation");
        assert!(
            protocol
                .receive_node_bootstrap(&connection, &provisioner, SecurityContext::Idp)
                .await
                .is_err(),
            "revoked source membership denies receipt retry"
        );
        eprintln!(
            "bootstrap revocation denials complete: {:?}",
            started.elapsed()
        );
    }
    connection.close(0u32.into(), b"test complete");
    drop(protocol);
    drop(provisioner);
    drop(joining_idp);
    drop(joining_policy);
    http.abort();
    let _ = http.await;
    cancellation.cancel();
    peer_router
        .shutdown()
        .await
        .expect("disconnect approving peer");
    eprintln!("bootstrap source disconnected: {:?}", started.elapsed());
    joining.endpoint().close().await;
    drop(runtime);
    drop(storage);
    drop(policy);
    drop(source_idp);
    drop(source_policy);
    drop(source_security);
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("offline native reopen");
    provisioner
        .prepare_setup_client_slots(&[local_client])
        .await
        .expect("offline retained preparation");
    assert!(
        provisioner
            .prepare_fresh_setup_secret_inventory(fixture.administrator, &[local_client])
            .await
            .is_err()
    );
    eprintln!("bootstrap offline owner reopened: {:?}", started.elapsed());
    let restarted = idp_server::bind_node_join_endpoint(
        &config,
        Minimal,
        joining_secret.clone(),
        EndpointIdStore::default(),
    )
    .await
    .expect("offline restored endpoint and durable purpose admission");
    let reopened_policy = Arc::new(
        Database::open(joining_root.join("management.redb")).expect("offline policy reopen"),
    );
    let offline = SecurityProtocol::new(
        restarted.clone(),
        provisioner.node_join_database(),
        reopened_policy.clone(),
        issuer.clone(),
        Some(binding.clone()),
        joining_root.join("security-staging"),
        CancellationToken::new(),
    );
    assert!(
        offline
            .node_join_public_ready(&provisioner)
            .await
            .expect("persisted local readiness requires no peer lookup")
    );
    issue_local_token(
        &config,
        &provisioner,
        &restarted,
        &joining_secret,
        &binding,
        local_client,
        reopened_policy.clone(),
    )
    .await;
    assert_eq!(
        provisioner.node_join_approval().expect("durable receipt"),
        Some(received)
    );
    assert_eq!(
        provisioner
            .prepare_node_join(&binding, "Joining Node", source.endpoint().id())
            .expect("retained independent private key; no regeneration"),
        request
    );
    assert_eq!(
        provisioner
            .verify_node_signer(&binding)
            .await
            .expect("imported trust and retained private signer work offline"),
        request.public_signer
    );
    DbReplicaSignerRepo::new(provisioner.node_join_database())
        .revoke(binding.member_id, &issuer, 11)
        .await
        .expect("locally learned signer/member revocation");
    eprintln!(
        "bootstrap offline issuance and local revocation: {:?}",
        started.elapsed()
    );
    assert!(
        !offline
            .node_join_public_ready(&provisioner)
            .await
            .expect("completion marker cannot undo learned revocation")
    );
    assert!(
        offline
            .complete_node_join_public_bootstrap(&provisioner)
            .await
            .is_err()
    );
    drop(offline);
    drop(provisioner);
    drop(reopened_policy);
    restarted.endpoint().close().await;
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("revoked native reopen");
    assert!(
        provisioner.verify_node_signer(&binding).await.is_err(),
        "durable revocation not resurrected by retained receipt/import markers"
    );
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove isolated native stores");
}
