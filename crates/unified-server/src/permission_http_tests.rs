use db::open_native_engine;
use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, EntityType,
        GrantType, INSTALLATION_POLICY_ID, IdentityAction, IdentityResource,
        MANAGEMENT_PERMISSION_EVALUATE_SCOPE, PermissionEvaluationRequest,
        PermissionEvaluationResponse, PermissionSubject, PermissionTarget, TokenEndpointAuthMethod,
    },
    replica::up,
};
use idp_service::{
    PasswordConfig,
    replica::{DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2UserConsentRepo, DbUserRepo},
    repo::{
        ApplicationRepo, ClientRepo, KeyService, OAuth2UserConsentRepo, PrivateKeyKeyringRepo,
        UserRepo,
    },
};
use management_service::{DeviceRepo, replica::DbDeviceRepo};
use std::{
    any::Any,
    collections::HashMap,
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
#[test]
fn normal_permission_http_administration() {
    run_http_test(false);
}

#[test]
fn normal_identity_and_infrastructure_lifecycle() {
    run_http_test(true);
}

fn run_http_test(lifecycle_only: bool) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build HTTP test runtime")
                .block_on(run_separate_permission_acceptance(lifecycle_only));
        })
        .expect("spawn HTTP acceptance")
        .join()
        .expect("HTTP acceptance did not panic");
}

async fn run_separate_permission_acceptance(lifecycle_only: bool) {
    let root = std::env::temp_dir().join(format!(
        "permission-http-{}",
        idp_model::model::Id::now_v7()
    ));
    let issuer = format!(
        "https://permission-{}.example",
        idp_model::model::Id::now_v7()
    );
    let idp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind IdP listener");
    let management_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Management listener");
    let idp_address = idp_listener.local_addr().expect("IdP address");
    let management_address = management_listener
        .local_addr()
        .expect("Management address");
    let idp_base = format!("http://{idp_address}");
    let management_base = format!("http://{management_address}");
    let secret = iroh::SecretKey::generate();
    let mut fixture = seed_idp(
        &root,
        &issuer,
        &secret.public().to_string(),
        &iroh::SecretKey::generate().public().to_string(),
    )
    .await;
    seed_permissions(&root, &mut fixture).await;
    eprintln!("permission HTTP fixtures ready");
    let server = iroh_chain::Server::bind_with_secret_key(
        iroh::endpoint::presets::N0,
        secret.clone(),
        iroh_chain::EndpointIdStore::default(),
    )
    .await
    .expect("bind test endpoint");
    let mut config = idp_server::AppConfig::default();
    config.oauth2.issuer = issuer.clone();
    config.service_audience = Some("idp-services".into());
    config.server.prefix = Some("/idp".into());
    let idp_engine =
        Arc::new(open_native_engine(root.join("idp/idp.redb")).expect("open IdP owner engine"));
    let runtime = idp_server::build_runtime(
        &config,
        Arc::clone(&idp_engine),
        Arc::new(
            idp_server::device_identity_from_server(&server, secret.clone())
                .expect("create local identity"),
        ),
        server.clone(),
        Some(
            management_service::PermissionClient::new(
                &format!("{management_base}/management"),
                &format!("{idp_base}/idp"),
                &issuer,
                "idp-evaluator",
                "idp-evaluator-secret",
            )
            .expect("normal IdP permission client"),
        ),
    )
    .await
    .expect("build independent IdP runtime");
    let control_plane = management_service::HostedControlPlane::new_with_services(
        &format!("{idp_base}/idp"),
        &format!("{idp_base}/unused-storage"),
        &issuer,
    )
    .expect("normal Management IdP client")
    .with_idp_service_client("management-idp", "management-idp-secret", "idp-services")
    .expect("configure introspection relationship")
    .with_permission_evaluator("idp-evaluator")
    .expect("pin distinct assertion client");
    let management_engine = Arc::new(
        open_native_engine(root.join("management/management.redb"))
            .expect("open Management owner engine"),
    );
    let router = management_server::build_router(
        management_engine,
        &management_base,
        "/management",
        "storage-service",
        Arc::new(control_plane),
    )
    .await
    .expect("build independent Management router");
    let idp_router = runtime.router();
    let mut idp_task = tokio::spawn(async move {
        axum::serve(idp_listener, idp_router)
            .await
            .expect("serve IdP");
    });
    let management_task = tokio::spawn(async move {
        axum::serve(management_listener, router)
            .await
            .expect("serve Management");
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .expect("bounded test client");
    if lifecycle_only {
        run_lifecycle_http_checks(&client, &idp_base, &management_base, &fixture).await;
        let actor = user_token(&client, &idp_base, "administrator", "idp-services").await;
        let unconfigured = idp_server::build_runtime(
            &config,
            Arc::clone(&idp_engine),
            Arc::new(
                idp_server::device_identity_from_server(&server, secret).expect("local identity"),
            ),
            server.clone(),
            None,
        )
        .await
        .expect("build without permission relationship");
        let response = unconfigured
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/idp/applications")
                    .header("authorization", format!("Bearer {actor}"))
                    .body(axum::body::Body::empty())
                    .expect("normal authenticated admin request"),
            )
            .await
            .expect("call unconfigured owner API");
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        drop(unconfigured);
        idp_task.abort();
        management_task.abort();
        let _ = idp_task.await;
        let _ = management_task.await;
        server.endpoint().close().await;
        drop(runtime);
        std::fs::remove_dir_all(root).expect("remove lifecycle fixture data");
        return;
    }
    run_permission_http_checks(&client, &idp_base, &management_base, &fixture).await;
    let admin = user_token(&client, &idp_base, "administrator", "idp-services").await;
    let management_user = user_token(&client, &idp_base, "administrator", "idp-management").await;
    idp_task.abort();
    let _ = idp_task.await;
    let evaluation = PermissionEvaluationRequest {
        request_id: idp_model::model::Id::now_v7(),
        subject: PermissionSubject::User {
            id: fixture.administrator,
        },
        action: IdentityAction::ClientsRead,
        target: PermissionTarget::Application {
            application_id: fixture.application_id,
            resource: IdentityResource::Client {
                client_id: Some("human-client".into()),
            },
        },
    };
    expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&management_user)
            .json(&evaluation)
            .send()
            .await
            .expect("IdP outage request"),
        http::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let idp_listener = tokio::net::TcpListener::bind(idp_address)
        .await
        .expect("restart IdP listener");
    let idp_router = runtime.router();
    idp_task = tokio::spawn(async move {
        axum::serve(idp_listener, idp_router)
            .await
            .expect("serve restarted IdP");
    });
    management_task.abort();
    let _ = management_task.await;
    expect_status(
        client
            .get(format!("{idp_base}/idp/oauth2/register/human-client"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("Management outage request"),
        http::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let fresh_user = user_token(&client, &idp_base, "administrator", "idp-services").await;
    let token = expect_status(
        client
            .post(format!("{idp_base}/idp/oauth2/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "management-idp"),
                ("client_secret", "management-idp-secret"),
                ("audience", "idp-services"),
                ("scope", "idp.token.validate idp.device.lookup"),
            ])
            .send()
            .await
            .expect("issue introspection client token without Management"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .post(format!("{idp_base}/idp/oauth2/introspect"))
            .bearer_auth(token["access_token"].as_str().expect("service token"))
            .json(&idp_model::contract::IntrospectionRequest {
                token: fresh_user,
                token_type_hint: None,
            })
            .send()
            .await
            .expect("introspection without Management"),
        http::StatusCode::OK,
    )
    .await;
    idp_task.abort();
    let _ = idp_task.await;
    eprintln!("closing permission HTTP endpoint");
    server.endpoint().close().await;
    eprintln!("permission HTTP endpoint closed");
    drop(runtime);
    std::fs::remove_dir_all(root).expect("remove HTTP fixture data");
}

pub(crate) struct PermissionFixture {
    application_id: idp_model::model::Id,
    other_application_id: idp_model::model::Id,
    administrator: idp_model::model::Id,
    app_administrator: idp_model::model::Id,
    application_role: idp_model::model::Id,
    unassigned_user: idp_model::model::Id,
    consent_id: idp_model::model::Id,
}

pub(crate) async fn seed_idp(
    root: &std::path::Path,
    issuer: &str,
    endpoint_id: &str,
    approved_peer_id: &str,
) -> PermissionFixture {
    let database_path = root.join("idp/idp.redb");
    fs::create_dir_all(database_path.parent().expect("IdP data directory"))
        .expect("create IdP data directory");
    let engine = Arc::new(open_native_engine(database_path).expect("open IdP fixture database"));
    up(&engine).await.expect("initialize IdP schema");
    let applications = DbApplicationRepo::new(Arc::clone(&engine));
    let application = applications
        .create_application(
            "Unified test application".to_owned(),
            "https://example.test/unified".to_owned(),
            None,
        )
        .await
        .expect("create canonical application");
    let key_service = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        PrivateKeyKeyringRepo::new_with_store(issuer, test_keyring_store()),
        "lidp".to_owned(),
    ));
    let clients = DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service));
    for (client_id, secret, audiences, scopes) in [
        (
            "management-idp",
            "management-idp-secret",
            vec!["idp-services", "storage-service", "idp-management"],
            vec!["idp.token.validate", "idp.device.lookup"],
        ),
        (
            "storage-idp",
            "storage-idp-secret",
            vec!["idp-services"],
            vec!["idp.token.validate", "idp.device.list"],
        ),
        (
            "idp-evaluator",
            "idp-evaluator-secret",
            vec!["idp-management"],
            vec![MANAGEMENT_PERMISSION_EVALUATE_SCOPE],
        ),
        (
            "untrusted-evaluator",
            "untrusted-evaluator-secret",
            vec!["idp-management"],
            vec![MANAGEMENT_PERMISSION_EVALUATE_SCOPE],
        ),
        (
            "human-client",
            "human-secret",
            vec!["idp-services", "idp-management"],
            vec!["openid"],
        ),
        (
            "storage-management",
            "storage-management-secret",
            vec!["storage-service"],
            vec![
                "management.replication.read",
                "management.replication.admit",
            ],
        ),
    ] {
        clients
            .create_client(ClientRegistration {
                application: ApplicationRegistration {
                    name: Some("Unified test application".to_owned()),
                    uri: "https://example.test/unified".to_owned(),
                    description: None,
                },
                client_id: Some(client_id.to_owned()),
                client_secret: Some(secret.to_owned()),
                client_id_issued_at: None,
                client_secret_expires_at: None,
                client_name: client_id.to_owned(),
                client_uri: None,
                logo_uri: None,
                contacts: Vec::new(),
                terms_of_service_uri: None,
                policy_uri: None,
                client_type: ClientType::Confidential,
                profile: ClientProfile::Web,
                redirect_uris: Vec::new(),
                allowed_grant_types: if client_id == "human-client" {
                    vec![GrantType::Password, GrantType::TokenExchange]
                } else {
                    vec![GrantType::ClientCredentials]
                },
                response_types: Vec::new(),
                allowed_scopes: scopes.into_iter().map(str::to_owned).collect(),
                allowed_audiences: audiences.into_iter().map(str::to_owned).collect(),
                token_endpoint_auth_method: if client_id == "human-client" {
                    TokenEndpointAuthMethod::ClientSecretBasic
                } else {
                    TokenEndpointAuthMethod::ClientSecretPost
                },
                software_statement: None,
                software_id: None,
                software_version: None,
            })
            .await
            .expect("provision IdP service client");
    }
    let other_application = applications
        .create_application(
            "Other application".into(),
            "https://example.test/other".into(),
            None,
        )
        .await
        .expect("create other application");
    let mut other_client: ClientRegistration = clients
        .find_client_by_client_id("human-client")
        .await
        .expect("read human client")
        .expect("human client exists")
        .into();
    other_client.application.uri = other_application.uri;
    other_client.client_id = Some("other-client".into());
    other_client.client_secret = Some("other-secret".into());
    clients
        .create_client(other_client)
        .await
        .expect("create cross-application client");
    let users = DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default());
    let mut user_ids = Vec::new();
    for name in ["administrator", "app-administrator", "unassigned"] {
        let user = users
            .create_user_with_password(name, "user-password")
            .await
            .expect("create user");
        key_service
            .ensure_entity_master_key(EntityType::User, user.id, "user-password")
            .expect("create user master");
        key_service
            .create_key(
                None,
                EntityType::User,
                user.id,
                true,
                "user signing key".into(),
                None,
            )
            .await
            .expect("create user signing key");
        user_ids.push(user.id);
    }
    let consent = DbOAuth2UserConsentRepo::new(Arc::clone(&engine))
        .upsert_user_consent(
            user_ids[0],
            "human-client",
            "https://example.test/callback",
            "openid",
        )
        .await
        .expect("seed owner consent");
    let devices = DbDeviceRepo::new(engine);
    devices
        .create(
            "unified-test-owner".to_owned(),
            "unified-host".to_owned(),
            endpoint_id.to_owned(),
            "test-address".to_owned(),
            Vec::new(),
            0,
        )
        .await
        .expect("approve unified endpoint identity");
    let pending_peer = devices
        .create(
            "unified-test-owner".to_owned(),
            "approved-peer".to_owned(),
            approved_peer_id.to_owned(),
            "test-address".to_owned(),
            vec![1],
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time is after Unix epoch")
                .as_secs() as i64
                + 60,
        )
        .await
        .expect("create pending test peer");
    devices
        .approve(pending_peer.id, &[1])
        .await
        .expect("approve test peer")
        .expect("pending test peer exists");
    PermissionFixture {
        application_id: application.id,
        other_application_id: other_application.id,
        administrator: user_ids[0],
        app_administrator: user_ids[1],
        unassigned_user: user_ids[2],
        consent_id: consent.id,
        application_role: idp_model::model::Id::now_v7(),
    }
}

pub(crate) async fn seed_permissions(root: &std::path::Path, fixture: &mut PermissionFixture) {
    use management_service::{
        ManagementService,
        replica::{DbPermissionRepo, DbRoleRepo},
    };
    fs::create_dir_all(root.join("management")).expect("create Management data directory");
    let engine = Arc::new(
        open_native_engine(root.join("management/management.redb"))
            .expect("open Management fixture"),
    );
    management_service::replica::up(&engine)
        .await
        .expect("initialize Management schema");
    let service = ManagementService::new(
        DbPermissionRepo::new(Arc::clone(&engine)),
        DbRoleRepo::new(engine),
    );
    let role = service
        .create_role(fixture.application_id, "application administrator", None)
        .await
        .expect("create application role");
    fixture.application_role = role.id;
    for name in [
        "roles.write",
        "idp.clients.read",
        "idp.clients.create",
        "idp.clients.update",
        "idp.clients.delete",
        "idp.infrastructure_clients.create",
    ] {
        let permission = service
            .create_permission(fixture.application_id, name, None)
            .await
            .expect("create application permission");
        service
            .add_permission_to_role(fixture.application_id, role.id, permission.id)
            .await
            .expect("assign application permission");
    }
    for user in [fixture.administrator, fixture.app_administrator] {
        service
            .add_role_to_user(fixture.application_id, user, role.id)
            .await
            .expect("assign application role");
    }
    let role = service
        .create_role(INSTALLATION_POLICY_ID, "initial administrator", None)
        .await
        .expect("create installation role");
    for action in [
        IdentityAction::ApplicationsRead,
        IdentityAction::ApplicationsCreate,
        IdentityAction::ApplicationsUpdate,
        IdentityAction::ApplicationsDelete,
        IdentityAction::InfrastructureClientsRead,
        IdentityAction::InfrastructureClientsCreate,
        IdentityAction::InfrastructureClientsUpdate,
        IdentityAction::InfrastructureClientsDelete,
        IdentityAction::UsersRead,
        IdentityAction::UsersUpdate,
        IdentityAction::UsersResetPassword,
        IdentityAction::ConsentsRead,
        IdentityAction::ConsentsRevoke,
        IdentityAction::KeysRead,
        IdentityAction::KeysRotate,
        IdentityAction::KeysRevoke,
        IdentityAction::UsersDelete,
        IdentityAction::DevicePairingRead,
        IdentityAction::DevicePairingUpdate,
    ] {
        let permission = service
            .create_permission(INSTALLATION_POLICY_ID, action.permission(), None)
            .await
            .expect("create explicit installation permission");
        service
            .add_permission_to_role(INSTALLATION_POLICY_ID, role.id, permission.id)
            .await
            .expect("assign installation permission");
    }
    service
        .add_role_to_user(INSTALLATION_POLICY_ID, fixture.administrator, role.id)
        .await
        .expect("assign initial administrator");
}

async fn user_token(
    client: &reqwest::Client,
    base: &str,
    username: &str,
    resource: &str,
) -> String {
    let response = client
        .post(format!("{base}/idp/oauth2/token"))
        .basic_auth("human-client", Some("human-secret"))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "human-client"),
            ("client_secret", "human-secret"),
            ("username", username),
            ("password", "user-password"),
            ("scope", "openid"),
            ("resource", resource),
        ])
        .send()
        .await
        .expect("obtain normal user token");
    let status = response.status();
    let body = response.text().await.expect("read user token response");
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let token =
        serde_json::from_str::<serde_json::Value>(&body).expect("parse token")["access_token"]
            .as_str()
            .expect("access token present")
            .to_owned();
    let response = client
        .post(format!("{base}/idp/oauth2/token"))
        .basic_auth("human-client", Some("human-secret"))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", resource),
        ])
        .send()
        .await
        .expect("exchange for API audience");
    expect_status(response, http::StatusCode::OK).await["access_token"]
        .as_str()
        .expect("API access token present")
        .to_owned()
}

async fn expect_status(
    response: reqwest::Response,
    expected: http::StatusCode,
) -> serde_json::Value {
    let url = response.url().clone();
    eprintln!("HTTP check: {url} -> {}", response.status());
    let status = response.status();
    let body = response.text().await.expect("read HTTP response");
    assert_eq!(status, expected, "{url}: {body}");
    if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body).expect("parse response JSON")
    }
}

async fn infrastructure_token(
    client: &reqwest::Client,
    base: &str,
    id: &str,
    secret: &str,
) -> String {
    let response = client
        .post(format!("{base}/idp/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", id),
            ("client_secret", secret),
            ("audience", "idp-management"),
            ("scope", MANAGEMENT_PERMISSION_EVALUATE_SCOPE),
        ])
        .send()
        .await
        .expect("normal infrastructure client token");
    expect_status(response, http::StatusCode::OK).await["access_token"]
        .as_str()
        .expect("service bearer")
        .to_owned()
}

async fn run_lifecycle_http_checks(
    client: &reqwest::Client,
    base: &str,
    management_base: &str,
    fixture: &PermissionFixture,
) {
    let admin = user_token(client, base, "administrator", "idp-services").await;
    let app_admin = user_token(client, base, "app-administrator", "idp-services").await;
    let deleted_user = user_token(client, base, "unassigned", "idp-services").await;
    let mut registration = expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/human-client"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read registration template"),
        http::StatusCode::OK,
    )
    .await;
    registration
        .as_object_mut()
        .expect("registration object")
        .remove("client_id");
    registration["allowed_grant_types"] = serde_json::json!(["client_credentials"]);
    registration["allowed_scopes"] = serde_json::json!([MANAGEMENT_PERMISSION_EVALUATE_SCOPE]);
    registration["allowed_audiences"] = serde_json::json!(["idp-management"]);
    registration["token_endpoint_auth_method"] = "client_secret_post".into();
    registration["client_name"] = "new infrastructure relationship".into();
    expect_status(
        client
            .post(format!("{base}/idp/oauth2/register"))
            .bearer_auth(&app_admin)
            .json(&registration)
            .send()
            .await
            .expect("application-scoped infrastructure grant rejected"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    let mut created = expect_status(
        client
            .post(format!("{base}/idp/oauth2/register"))
            .bearer_auth(&admin)
            .json(&registration)
            .send()
            .await
            .expect("installation-authorized infrastructure creation"),
        http::StatusCode::OK,
    )
    .await;
    let id = created["client_id"]
        .as_str()
        .expect("infrastructure client ID")
        .to_owned();
    let secret = created["client_secret"]
        .as_str()
        .expect("one-time client secret")
        .to_owned();
    assert_ne!(id, "idp-evaluator");
    let machine_token = infrastructure_token(client, base, &id, &secret).await;
    expect_status(
        client
            .get(format!("{base}/idp/applications"))
            .bearer_auth(&machine_token)
            .send()
            .await
            .expect("service token cannot use user administration API"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    let registration_url = format!("{base}/idp/oauth2/register/{id}");
    let read = expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read infrastructure client"),
        http::StatusCode::OK,
    )
    .await;
    assert!(read.get("client_secret").is_none());
    created["client_secret"] = "rotated-infrastructure-secret".into();
    let rotated = expect_status(
        client
            .put(&registration_url)
            .bearer_auth(&admin)
            .json(&created)
            .send()
            .await
            .expect("rotate client secret"),
        http::StatusCode::OK,
    )
    .await;
    assert_eq!(rotated["client_secret"], "rotated-infrastructure-secret");
    expect_status(
        client
            .post(format!("{base}/idp/oauth2/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", id.as_str()),
                ("client_secret", secret.as_str()),
                ("audience", "idp-management"),
                ("scope", MANAGEMENT_PERMISSION_EVALUATE_SCOPE),
            ])
            .send()
            .await
            .expect("old client secret rejected"),
        http::StatusCode::BAD_REQUEST,
    )
    .await;
    let old_token = infrastructure_token(client, base, &id, "rotated-infrastructure-secret").await;
    let evaluation = PermissionEvaluationRequest {
        request_id: idp_model::model::Id::now_v7(),
        subject: PermissionSubject::User {
            id: fixture.administrator,
        },
        action: IdentityAction::ClientsRead,
        target: PermissionTarget::Application {
            application_id: fixture.application_id,
            resource: IdentityResource::Client {
                client_id: Some("human-client".into()),
            },
        },
    };
    let evaluation_url = format!("{management_base}/management/permissions/evaluate");
    expect_status(
        client
            .post(&evaluation_url)
            .bearer_auth(&old_token)
            .json(&evaluation)
            .send()
            .await
            .expect("new service cannot assert a human"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .post(format!("{base}/idp/clients/{id}/keys/rotate"))
            .bearer_auth(&app_admin)
            .send()
            .await
            .expect("key escalation denied"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .post(format!("{base}/idp/clients/{id}/keys/rotate"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("rotate client signing root"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .post(&evaluation_url)
            .bearer_auth(&old_token)
            .json(&evaluation)
            .send()
            .await
            .expect("old root bearer rejected"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    let new_token = infrastructure_token(client, base, &id, "rotated-infrastructure-secret").await;
    expect_status(
        client
            .delete(format!("{base}/idp/clients/{id}/keys"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("revoke client signing keys"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .post(&evaluation_url)
            .bearer_auth(&new_token)
            .json(&evaluation)
            .send()
            .await
            .expect("revoked key bearer rejected"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    expect_status(
        client
            .delete(&registration_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("delete infrastructure client"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/applications"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("list applications"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(client.put(format!("{base}/idp/applications/{}", fixture.other_application_id)).bearer_auth(&admin)
        .json(&serde_json::json!({"name":"updated application", "uri":"https://example.test/other"}))
        .send().await.expect("update application"), http::StatusCode::OK).await;
    expect_status(
        client
            .get(format!(
                "{base}/idp/applications/{}",
                fixture.other_application_id
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("get application"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .delete(format!(
                "{base}/idp/users/{}/consents/{}",
                fixture.app_administrator, fixture.consent_id
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("consent remains bound to its owner"),
        http::StatusCode::NOT_FOUND,
    )
    .await;
    let consents = expect_status(
        client
            .get(format!(
                "{base}/idp/users/{}/consents",
                fixture.administrator
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read unchanged consent"),
        http::StatusCode::OK,
    )
    .await;
    assert_eq!(consents.as_array().expect("consent array").len(), 1);
    expect_status(
        client
            .delete(format!(
                "{base}/idp/users/{}/consents/{}",
                fixture.administrator, fixture.consent_id
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("revoke owner consent"),
        http::StatusCode::OK,
    )
    .await;
    let consents = expect_status(
        client
            .get(format!(
                "{base}/idp/users/{}/consents",
                fixture.administrator
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read revoked consent"),
        http::StatusCode::OK,
    )
    .await;
    assert!(consents.as_array().expect("consent array").is_empty());
    expect_status(
        client
            .delete(format!("{base}/idp/users/{}", fixture.unassigned_user))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("delete user"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/human-client"))
            .bearer_auth(&deleted_user)
            .send()
            .await
            .expect("deleted user bearer rejected"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    let mut evaluator = expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/idp-evaluator"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read dedicated evaluator"),
        http::StatusCode::OK,
    )
    .await;
    evaluator["allowed_scopes"] = serde_json::json!([]);
    expect_status(
        client
            .put(format!("{base}/idp/oauth2/register/idp-evaluator"))
            .bearer_auth(&admin)
            .json(&evaluator)
            .send()
            .await
            .expect("remove evaluator capability"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/human-client"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("cached service bearer cannot retain removed capability"),
        http::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}

pub(crate) async fn run_permission_http_checks(
    client: &reqwest::Client,
    base: &str,
    management_base: &str,
    fixture: &PermissionFixture,
) {
    let admin = user_token(client, base, "administrator", "idp-services").await;
    let app_admin = user_token(client, base, "app-administrator", "idp-services").await;
    let unassigned = user_token(client, base, "unassigned", "idp-services").await;
    let pairing_url = format!("{base}/idp/devices/pairing-accepting");
    expect_status(
        client
            .get(&pairing_url)
            .send()
            .await
            .expect("reject unauthenticated pairing read"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    expect_status(
        client
            .get(&pairing_url)
            .bearer_auth(&app_admin)
            .send()
            .await
            .expect("deny application administrator pairing read"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .get(&pairing_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("allow installation administrator pairing read"),
        http::StatusCode::OK,
    )
    .await;
    let pairing_update = idp_model::contract::PairingAcceptance { accepting: false };
    expect_status(
        client
            .put(&pairing_url)
            .json(&pairing_update)
            .send()
            .await
            .expect("reject unauthenticated pairing update"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    expect_status(
        client
            .put(&pairing_url)
            .bearer_auth(&app_admin)
            .json(&pairing_update)
            .send()
            .await
            .expect("deny application administrator pairing update"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .put(&pairing_url)
            .bearer_auth(&admin)
            .json(&pairing_update)
            .send()
            .await
            .expect("allow installation administrator pairing update"),
        http::StatusCode::OK,
    )
    .await;
    let registration_url = format!("{base}/idp/oauth2/register/human-client");
    let registration = expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read permitted client"),
        http::StatusCode::OK,
    )
    .await;
    assert!(registration.get("client_secret").is_none());
    expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&unassigned)
            .send()
            .await
            .expect("read denied client"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/other-client"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("cross-app read"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/oauth2/register/idp-evaluator"))
            .bearer_auth(&app_admin)
            .send()
            .await
            .expect("infrastructure read"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/users/{}", fixture.administrator))
            .bearer_auth(&app_admin)
            .send()
            .await
            .expect("installation escalation"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/users/{}", fixture.administrator))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("installation user read"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(format!(
                "{base}/idp/users/{}/consents",
                fixture.administrator
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("consent read"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(format!("{base}/idp/clients/human-client/keys"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("key metadata read"),
        http::StatusCode::OK,
    )
    .await;
    let mut elevated = registration.clone();
    elevated["allowed_grant_types"] = serde_json::json!(["client_credentials"]);
    elevated["allowed_scopes"] = serde_json::json!([MANAGEMENT_PERMISSION_EVALUATE_SCOPE]);
    expect_status(
        client
            .put(&registration_url)
            .bearer_auth(&app_admin)
            .json(&elevated)
            .send()
            .await
            .expect("escalating client update"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    let unchanged = expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("read unchanged client"),
        http::StatusCode::OK,
    )
    .await;
    assert_eq!(
        unchanged["allowed_grant_types"],
        registration["allowed_grant_types"]
    );
    let mut create = registration.clone();
    create
        .as_object_mut()
        .expect("registration object")
        .remove("client_id");
    create["client_name"] = "created through normal RBAC".into();
    expect_status(
        client
            .post(format!("{base}/idp/oauth2/register"))
            .bearer_auth(&unassigned)
            .json(&create)
            .send()
            .await
            .expect("deny client create without permission"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    let created = expect_status(
        client
            .post(format!("{base}/idp/oauth2/register"))
            .bearer_auth(&admin)
            .json(&create)
            .send()
            .await
            .expect("create client"),
        http::StatusCode::OK,
    )
    .await;
    let created_id = created["client_id"].as_str().expect("created ID");
    let created_url = format!("{base}/idp/oauth2/register/{created_id}");
    let mut update = created.clone();
    update["client_name"] = "updated without permission".into();
    expect_status(
        client
            .put(&created_url)
            .bearer_auth(&unassigned)
            .json(&update)
            .send()
            .await
            .expect("deny client update without permission"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .delete(&created_url)
            .bearer_auth(&unassigned)
            .send()
            .await
            .expect("deny client delete without permission"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    let still_created = expect_status(
        client
            .get(&created_url)
            .bearer_auth(&admin)
            .send()
            .await
            .expect("verify denied mutations preserved client"),
        http::StatusCode::OK,
    )
    .await;
    assert_eq!(still_created["client_name"], "created through normal RBAC");
    update["client_name"] = "updated through normal RBAC".into();
    expect_status(
        client
            .put(format!("{base}/idp/oauth2/register/{created_id}"))
            .bearer_auth(&admin)
            .json(&update)
            .send()
            .await
            .expect("update client"),
        http::StatusCode::OK,
    )
    .await;
    update["application"]["uri"] = "https://example.test/other".into();
    expect_status(
        client
            .put(format!("{base}/idp/oauth2/register/{created_id}"))
            .bearer_auth(&admin)
            .json(&update)
            .send()
            .await
            .expect("cross-app update"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .delete(format!("{base}/idp/oauth2/register/{created_id}"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("delete client"),
        http::StatusCode::OK,
    )
    .await;
    let created_app = expect_status(client.post(format!("{base}/idp/applications")).bearer_auth(&admin)
        .json(&serde_json::json!({"name":"Created application", "uri":"https://example.test/created"}))
        .send().await.expect("create application"), http::StatusCode::OK).await;
    let app_id = created_app["id"].as_str().expect("created application ID");
    expect_status(
        client
            .delete(format!("{base}/idp/applications/{app_id}"))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("delete application"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .put(format!("{base}/idp/users/{}", fixture.app_administrator))
            .bearer_auth(&admin)
            .json(&serde_json::json!({"name":"updated user"}))
            .send()
            .await
            .expect("update user"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .put(format!(
                "{base}/idp/users/{}/password",
                fixture.app_administrator
            ))
            .bearer_auth(&admin)
            .json(&serde_json::json!({"password":"replacement-password"}))
            .send()
            .await
            .expect("reset user password"),
        http::StatusCode::OK,
    )
    .await;
    let service_token = client
        .post(format!("{base}/idp/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "idp-evaluator"),
            ("client_secret", "idp-evaluator-secret"),
            ("audience", "idp-management"),
            ("scope", MANAGEMENT_PERMISSION_EVALUATE_SCOPE),
        ])
        .send()
        .await
        .expect("issue evaluator token");
    let service_token = expect_status(service_token, http::StatusCode::OK).await["access_token"]
        .as_str()
        .expect("service token")
        .to_owned();
    expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&service_token)
            .header("x-actor-subject", fixture.administrator.to_string())
            .send()
            .await
            .expect("service cannot impersonate human"),
        http::StatusCode::UNAUTHORIZED,
    )
    .await;
    let mut evaluation = PermissionEvaluationRequest {
        request_id: idp_model::model::Id::now_v7(),
        subject: PermissionSubject::User {
            id: fixture.administrator,
        },
        action: IdentityAction::ClientsRead,
        target: PermissionTarget::Application {
            application_id: fixture.application_id,
            resource: IdentityResource::Client {
                client_id: Some("human-client".into()),
            },
        },
    };
    let decision = expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&service_token)
            .json(&evaluation)
            .send()
            .await
            .expect("normal service evaluation"),
        http::StatusCode::OK,
    )
    .await;
    let decision: PermissionEvaluationResponse =
        serde_json::from_value(decision).expect("typed decision");
    assert!(decision.allowed);
    assert_eq!(decision.request, evaluation);
    assert_eq!(decision.audit.actor, evaluation.subject);
    assert_ne!(decision.audit.service_subject, fixture.administrator);
    evaluation.target = PermissionTarget::Application {
        application_id: fixture.other_application_id,
        resource: IdentityResource::Client {
            client_id: Some("other-client".into()),
        },
    };
    let decision = expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&service_token)
            .json(&evaluation)
            .send()
            .await
            .expect("cross-app evaluation"),
        http::StatusCode::OK,
    )
    .await;
    assert_eq!(decision["allowed"], false);
    evaluation.target = PermissionTarget::Application {
        application_id: fixture.application_id,
        resource: IdentityResource::Client {
            client_id: Some("human-client".into()),
        },
    };
    let attacker_token = client
        .post(format!("{base}/idp/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "untrusted-evaluator"),
            ("client_secret", "untrusted-evaluator-secret"),
            ("audience", "idp-management"),
            ("scope", MANAGEMENT_PERMISSION_EVALUATE_SCOPE),
        ])
        .send()
        .await
        .expect("issue nontrusted service token");
    let attacker_token = expect_status(attacker_token, http::StatusCode::OK).await["access_token"]
        .as_str()
        .expect("nontrusted token")
        .to_owned();
    expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&attacker_token)
            .header("x-actor-subject", fixture.administrator.to_string())
            .json(&evaluation)
            .send()
            .await
            .expect("untrusted actor assertion"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    let management_user = user_token(client, base, "administrator", "idp-management").await;
    expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&management_user)
            .json(&evaluation)
            .send()
            .await
            .expect("same user evaluation"),
        http::StatusCode::OK,
    )
    .await;
    evaluation.subject = PermissionSubject::User {
        id: fixture.app_administrator,
    };
    expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&management_user)
            .json(&evaluation)
            .send()
            .await
            .expect("different user assertion"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    evaluation.action = IdentityAction::InfrastructureClientsRead;
    expect_status(
        client
            .post(format!("{management_base}/management/permissions/evaluate"))
            .bearer_auth(&service_token)
            .json(&evaluation)
            .send()
            .await
            .expect("scope escalation"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
    expect_status(
        client
            .delete(format!(
                "{management_base}/management/applications/{}/users/{}/roles/{}",
                fixture.application_id, fixture.app_administrator, fixture.application_role
            ))
            .bearer_auth(&management_user)
            .send()
            .await
            .expect("revoke role through normal API"),
        http::StatusCode::OK,
    )
    .await;
    expect_status(
        client
            .get(&registration_url)
            .bearer_auth(&app_admin)
            .send()
            .await
            .expect("immediate role revocation"),
        http::StatusCode::FORBIDDEN,
    )
    .await;
}

struct ModifierTolerantTestStore {
    inner: Arc<keyring_core::mock::Store>,
}

impl keyring_core::api::CredentialStoreApi for ModifierTolerantTestStore {
    fn vendor(&self) -> String {
        self.inner.vendor()
    }

    fn id(&self) -> String {
        self.inner.id()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        keyring_core::api::CredentialStoreApi::build(&*self.inner, service, user, None)
    }

    fn search(&self, spec: &HashMap<&str, &str>) -> keyring_core::Result<Vec<keyring_core::Entry>> {
        keyring_core::api::CredentialStoreApi::search(&*self.inner, spec)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn test_keyring_store() -> Arc<keyring_core::CredentialStore> {
    Arc::new(ModifierTolerantTestStore {
        inner: keyring_core::mock::Store::new().expect("create test keyring"),
    })
}
