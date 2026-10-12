use std::{collections::HashMap, fs, sync::Arc, time::Duration};

use idp_model::{
    contract::{
        ClientRegistration, IdentityAction, IdentityResource, PermissionEvaluationRequest,
        PermissionSubject, PermissionTarget,
    },
    model::Id,
};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{ClientRepo, KeyService, PrivateKeyKeyringRepo},
};
use management_service::{HostedControlPlane, LocalPermissions, replica::DbDeviceRepo};
use serde_json::{Value, json};

use super::{IdpAppConfig, MANAGEMENT_APPLICATION_URI, OwnerProvisioner, ServiceRelationship};

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

#[test]
fn desktop_relationship_audiences_authorize_only_local_consumers() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("bounded relationship runtime")
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(120), check_relationships())
                        .await
                        .expect("desktop relationship check completes within its bound");
                });
        })
        .expect("relationship test thread")
        .join()
        .expect("desktop relationship check did not panic");
}

async fn issue(
    http: &reqwest::Client,
    base: &str,
    registration: &ClientRegistration,
    audience: &str,
) -> String {
    let response = http
        .post(format!("{base}/idp/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            (
                "client_id",
                registration
                    .client_id
                    .as_deref()
                    .expect("fixture Client ID"),
            ),
            (
                "client_secret",
                registration
                    .client_secret
                    .as_deref()
                    .expect("fixture secret"),
            ),
            ("audience", audience),
            ("scope", &registration.allowed_scopes.join(" ")),
        ])
        .send()
        .await
        .expect("real local Client authentication");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Client issuance"
    );
    let body: Value = response.json().await.expect("Client token response");
    body["access_token"]
        .as_str()
        .expect("signed Client bearer")
        .to_owned()
}

async fn check_relationships() {
    let root = std::env::temp_dir().join(format!("desktop-audiences-{}", Id::now_v7()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let idp_audience = format!("{base}/idp");
    let storage_audience = format!("{base}/storage");
    let issuer = format!("https://{}.test/idp", Id::now_v7());
    let mut config = IdpAppConfig {
        data_dir: root.join("idp").to_string_lossy().into_owned(),
        ..IdpAppConfig::default()
    };
    config.oauth2.issuer = issuer.clone();
    config.api_public_uri = idp_audience.clone();
    let store: Arc<keyring_core::CredentialStore> = Arc::new(TestStore(
        keyring_core::mock::Store::new().expect("isolated mock private-key provider"),
    ));
    let owner = OwnerProvisioner::open_with_private_keys(
        &config,
        PrivateKeyKeyringRepo::new_with_store(&issuer, store.clone()),
    )
    .await
    .expect("native IdP owner");
    let administrator = Id::now_v7();
    let relationships = [
        ServiceRelationship::ManagementToIdp,
        ServiceRelationship::StorageToIdp,
        ServiceRelationship::StorageToManagement,
        ServiceRelationship::IdpToManagement,
    ];
    let registrations = relationships.map(|relationship| {
        super::service_client_registration(
            Id::now_v7(),
            format!("fixture-secret-{}", Id::now_v7()),
            relationship,
            &base,
            &idp_audience,
            &storage_audience,
        )
    });
    let clients = registrations.each_ref().map(|request| {
        request
            .client_id
            .as_deref()
            .expect("desktop Client ID")
            .parse::<Id>()
            .expect("canonical Client ID")
    });
    owner
        .prepare_fresh_setup_secret_inventory(administrator, &clients)
        .await
        .expect("fresh inventory");
    owner
        .prepare_setup_client_slots(&clients)
        .await
        .expect("exact desktop Client slots");
    owner
        .ensure_initial_user(administrator, Id::now_v7(), "admin", "fixture-password")
        .await
        .expect("initial User");
    owner
        .ensure_initial_user_signing_key(administrator)
        .await
        .expect("User signer");
    for request in &registrations {
        owner
            .ensure_setup_infrastructure_client(request.clone())
            .await
            .expect("actual desktop relationship request");
    }
    let secret = iroh::SecretKey::generate();
    let endpoint = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::Minimal,
        secret.clone(),
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("local identity endpoint");
    let binding = idp_service::oauth2::NodeSignerBinding {
        member_id: Id::now_v7(),
        key_id: Id::now_v7(),
        endpoint_id: endpoint.endpoint().id().to_string(),
    };
    owner
        .ensure_initial_node(&binding, administrator, "Audience fixture")
        .await
        .expect("approved local Node signer");
    drop(owner);
    config.oauth2.local_signer = Some(binding);
    let engine =
        Arc::new(db::Database::open(root.join("idp/idp.redb")).expect("native IdP reopen"));
    let keys = Arc::new(KeyService::new(
        DbKeyRepo::new(engine.clone()),
        PrivateKeyKeyringRepo::new_with_store(&issuer, store),
        config.key_namespace.clone(),
    ));
    let client_repo = DbClientRepo::new(engine.clone(), keys.clone());
    let mut subject = registrations[2].clone();
    subject.client_id = Some(Id::now_v7().to_string());
    subject.client_secret = Some("subject-fixture-secret".into());
    subject.allowed_audiences = [
        "storage:databases",
        "storage:filesystems",
        "unrelated:service",
    ]
    .map(str::to_owned)
    .into();
    client_repo
        .create_client(subject.clone())
        .await
        .expect("independent inspected-token fixture");
    let oauth2 = OAuth2Service::new(
        DbApplicationRepo::new(engine.clone()),
        client_repo,
        DbOAuth2AuthorizationCodeRepo::new(engine.clone()),
        DbOAuth2RefreshTokenRepo::new(engine.clone()),
        DbUserRepo::new(engine.clone(), config.password.clone()),
        DbOAuth2UserConsentRepo::new(engine.clone()),
        keys,
        config.oauth2.clone(),
    );
    let management = super::ManagementAppConfig {
        data_dir: root.join("management").to_string_lossy().into_owned(),
        storage_audience: storage_audience.clone(),
        ..super::ManagementAppConfig::default()
    };
    management_server::provision_initial_administrator(
        &management,
        administrator,
        Id::now_v7(),
        &[(Id::now_v7(), IdentityAction::InfrastructureClientsRead)],
    )
    .await
    .expect("real explicit local grant");
    let policy = Arc::new(
        db::Database::open(root.join("management/management.redb"))
            .expect("native Management owner"),
    );
    let state = idp_server::RouterState::new(
        &base,
        &idp_audience,
        engine.clone(),
        Arc::new(oauth2),
        Arc::new(DbDeviceRepo::new(engine.clone())),
        Arc::new(
            idp_server::device_identity_from_server(&endpoint, secret).expect("local identity"),
        ),
    )
    .with_local_permissions(LocalPermissions::new(policy.clone()));
    let control_plane =
        HostedControlPlane::new_with_services(&idp_audience, &storage_audience, &issuer)
            .expect("local Management consumer")
            .with_idp_service_client(
                registrations[0]
                    .client_id
                    .as_deref()
                    .expect("Management Client ID"),
                registrations[0]
                    .client_secret
                    .as_deref()
                    .expect("Management secret"),
                &idp_audience,
            )
            .expect("actual desktop introspection credentials")
            .with_permission_evaluator(
                registrations[3]
                    .client_id
                    .as_deref()
                    .expect("evaluator Client ID"),
            )
            .expect("distinct evaluator relationship");
    let management_router = management_server::build_router(
        policy.clone(),
        &format!("{base}/management"),
        "/management",
        &storage_audience,
        Arc::new(control_plane),
    )
    .await
    .expect("real Management router");
    let router = idp_server::openapi_router(state.clone(), "/idp")
        .split_for_parts()
        .0
        .merge(management_router);
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("local owner HTTP server");
    });
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .expect("bounded HTTP client");
    let management_token = issue(&http, &base, &registrations[0], &idp_audience).await;
    let storage_token = issue(&http, &base, &registrations[1], &idp_audience).await;
    let storage_management_token = issue(&http, &base, &registrations[2], &storage_audience).await;
    let evaluator = issue(&http, &base, &registrations[3], MANAGEMENT_APPLICATION_URI).await;
    for (subject_id, allowed) in [(administrator, true), (Id::now_v7(), false)] {
        let request = PermissionEvaluationRequest {
            request_id: Id::now_v7(),
            subject: PermissionSubject::User { id: subject_id },
            action: IdentityAction::InfrastructureClientsRead,
            target: PermissionTarget::Installation {
                resource: IdentityResource::Client { client_id: None },
            },
        };
        let response = http
            .post(format!("{base}/management/permissions/evaluate"))
            .bearer_auth(&evaluator)
            .json(&request)
            .send()
            .await
            .expect("real local permission evaluation");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "Management must inspect the desktop evaluator's idp-management bearer"
        );
        let decision: Value = response.json().await.expect("real permission decision");
        assert_eq!(
            decision["allowed"], allowed,
            "only explicitly granted User is permitted"
        );
    }
    let database = issue(&http, &base, &subject, "storage:databases").await;
    let filesystem = issue(&http, &base, &subject, "storage:filesystems").await;
    let unrelated = issue(&http, &base, &subject, "unrelated:service").await;
    for (caller, inspected, permitted) in [
        (&management_token, &evaluator, true),
        (&management_token, &storage_management_token, true),
        (&storage_token, &database, true),
        (&storage_token, &filesystem, true),
        (&management_token, &database, false),
        (&management_token, &filesystem, false),
        (&storage_token, &evaluator, false),
        (&storage_token, &storage_management_token, false),
        (&management_token, &unrelated, false),
        (&storage_token, &unrelated, false),
    ] {
        let response = http
            .post(format!("{base}/idp/oauth2/introspect"))
            .bearer_auth(caller)
            .json(&json!({"token": inspected}))
            .send()
            .await
            .expect("real owner introspection");
        assert_eq!(
            response.status(),
            if permitted {
                reqwest::StatusCode::OK
            } else {
                reqwest::StatusCode::UNAUTHORIZED
            },
            "least-privilege inspected audience"
        );
    }
    for (request, audiences, scopes) in [
        (
            &registrations[0],
            vec![
                idp_audience.as_str(),
                "idp-management",
                storage_audience.as_str(),
            ],
            vec!["idp.token.validate", "idp.device.lookup"],
        ),
        (
            &registrations[1],
            vec![
                idp_audience.as_str(),
                "storage:databases",
                "storage:filesystems",
            ],
            vec!["idp.token.validate", "idp.device.lookup", "idp.device.list"],
        ),
        (
            &registrations[2],
            vec![storage_audience.as_str()],
            vec![
                "management.replication.read",
                "management.replication.admit",
            ],
        ),
        (
            &registrations[3],
            vec!["idp-management"],
            vec!["management.permission.evaluate"],
        ),
    ] {
        assert_eq!(
            request.allowed_audiences, audiences,
            "exact desktop audience allowlist"
        );
        assert_eq!(
            request.allowed_scopes, scopes,
            "unchanged desktop least-privilege scopes"
        );
    }
    task.abort();
    let _ = task.await;
    endpoint.endpoint().close().await;
    drop(state);
    drop(engine);
    drop(policy);
    fs::remove_dir_all(root).expect("isolated owner fixture cleanup");
}
