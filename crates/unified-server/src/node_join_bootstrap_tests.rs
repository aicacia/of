use std::{io::ErrorKind, sync::Arc, time::Duration};

use db::Database;
use idp_model::{contract::IdentityAction, model::Id};
use idp_server::{AppConfig, OwnerProvisioner};
use idp_service::{oauth2::NodeSignerBinding, replica::DbReplicaSignerRepo};
use iroh::{Endpoint, SecretKey, endpoint::presets::Minimal};
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
async fn node_join_receipt_cannot_bootstrap_context_trust_even_after_native_reopen() {
    tokio::time::timeout(Duration::from_secs(180), receipt_boundary())
        .await
        .expect("native approval, context denial and offline reopen complete");
}

async fn receipt_boundary() {
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
        IdentityAction::ManagementSecuritySync,
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
                "UPDATE devices SET owner_subject = '{}' WHERE id = CAST('{}' AS UUID)",
                fixture.administrator, fixture.local_signer.member_id
            ),
            &db::SqlTranslator,
        )
        .await
        .expect("source Device binds the real active User, not fixture placeholder");

    // Raw authenticated endpoints isolate domain admission from endpoint allowlist admission.
    let source = Server::new(
        Endpoint::builder(Minimal)
            .secret_key(source_secret.clone())
            .bind()
            .await
            .expect("source endpoint"),
        EndpointIdStore::default(),
    );
    let joining = Server::new(
        Endpoint::builder(Minimal)
            .secret_key(joining_secret.clone())
            .bind()
            .await
            .expect("independent joining endpoint"),
        EndpointIdStore::default(),
    );
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
    let peer_router = source.router(storage.data_handler().expect("DATA handler"));
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
    let mut config = AppConfig::default();
    config.data_dir = joining_root.to_string_lossy().into_owned();
    config.oauth2.issuer = issuer.clone();
    let binding = NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: joining.endpoint().id().to_string(),
    };
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("fresh native joining owner with injected keyring");
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
    let approved = runtime
        .approve_node_join(&offer, &bearer)
        .await
        .expect("purpose-specific authorized enrollment");
    let received = sending
        .await
        .expect("pairing sender")
        .expect("pinned peer signed reply");
    assert_eq!(approved, received);
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
    drop(provisioner);

    let joining_idp =
        Arc::new(Database::open(joining_root.join("idp.redb")).expect("joining IdP owner"));
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
    let connection = joining
        .endpoint()
        .connect(source.endpoint().addr(), DATA_ALPN)
        .await
        .expect("authenticated DATA connection");
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
    connection.close(0u32.into(), b"test complete");
    drop(protocol);
    drop(joining_idp);
    drop(joining_policy);
    http.abort();
    let _ = http.await;
    cancellation.cancel();
    peer_router
        .shutdown()
        .await
        .expect("disconnect approving peer");
    joining.endpoint().close().await;
    drop(runtime);
    drop(storage);
    drop(policy);
    drop(source_idp);
    drop(source_policy);
    let provisioner = OwnerProvisioner::open(&config)
        .await
        .expect("offline native reopen");
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
    assert!(
        provisioner.verify_node_signer(&binding).await.is_err(),
        "offline reopen must remain incomplete without public trust/policy bootstrap"
    );
    drop(provisioner);
    std::fs::remove_dir_all(root).expect("remove isolated native stores");
}
