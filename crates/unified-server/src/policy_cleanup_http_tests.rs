use std::sync::{Arc, OnceLock};

use idp_model::{
    contract::{EntityType, GrantType, IdentityAction, TokenEndpointAuthMethod},
    model::Id,
};
use idp_service::{
    replica::DbUserRepo,
    repo::{ClientRepo, UserRepo},
};
use management_service::{
    HostedControlPlane, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo, SelectionPolicy},
};
use model::contract::{StorageAuthorizationAction, TokenResponse};
use storage_server::{RouterState, StorageCopyRetirement, resource_router};

use super::{Fixture, Gate, Listener, registration};

async fn actor_token(fixture: &Fixture, audience: &str) -> String {
    user_token(fixture, "administrator", "valid-password", audience, false).await
}

async fn user_token(
    fixture: &Fixture,
    username: &str,
    password: &str,
    audience: &str,
    storage_read: bool,
) -> String {
    let url = format!("{}/oauth2/token", fixture.idp_listener.base);
    let response = fixture
        .http
        .post(&url)
        .basic_auth("human", Some("human-secret"))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "human"),
            ("username", username),
            ("password", password),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("real User token");
    let status = response.status();
    let body = response.text().await.expect("token body");
    assert!(status.is_success(), "{status}: {body}");
    let subject: TokenResponse = serde_json::from_str(&body).expect("User token");
    let details = serde_json::json!([{"type":"storage", "actions":["read"]}]).to_string();
    let mut exchange = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", subject.access_token.0.as_str()),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("resource", audience),
    ];
    if storage_read {
        exchange.push(("authorization_details", &details));
    }
    let response = fixture
        .http
        .post(url)
        .basic_auth("human", Some("human-secret"))
        .form(&exchange)
        .send()
        .await
        .expect("real actor exchange");
    let status = response.status();
    let body = response.text().await.expect("exchange body");
    assert!(status.is_success(), "{status}: {body}");
    serde_json::from_str::<TokenResponse>(&body)
        .expect("actor token")
        .access_token
        .0
}

async fn require_success(response: reqwest::Response) {
    let url = response.url().to_string();
    let status = response.status();
    let body = response.text().await.expect("HTTP body");
    assert!(status.is_success(), "{url}: {status}: {body}");
}

#[tokio::test]
async fn real_policy_http_chain_retires_copies_reselects_generation_and_gates_transfer() {
    let mut fixture = Fixture::new(Gate::default()).await;
    let policies = DbSelectionPolicyRepo::new(Arc::clone(&fixture.management));
    policies
        .set_prevalidated(SelectionPolicy {
            device_id: fixture.device.device_id,
            owner_subject: fixture.owner.to_string(),
            application_id: None,
            selected_kind: None,
            selected_id: None,
            admin_allowed: true,
        })
        .await
        .expect("trusted empty local policy");
    let copies = Arc::new(OnceLock::new());
    assert!(
        copies
            .set(StorageCopyRetirement::new(
                fixture.databases.clone(),
                fixture.files.clone()
            ))
            .is_ok()
    );
    let authorizer = crate::runtime::owner_replication_authorizer(
        fixture.runtime.clone(),
        fixture.management.clone(),
        fixture.identity.endpoint().id(),
        copies.clone(),
    );
    fixture.client = fixture
        .client
        .clone()
        .with_local_device_policy(fixture.identity.endpoint().id(), authorizer.clone());
    fixture.storage_listener.stop().await;
    fixture.storage_listener = Listener::start(resource_router(
        RouterState::new("https://storage.test").with_idp_client(fixture.client.clone()),
        Some(fixture.databases.clone()),
        Some(fixture.files.clone()),
    ))
    .await;
    fixture
        .clients
        .create_client(registration(
            "management-lookup",
            vec![GrantType::ClientCredentials],
            vec!["idp.token.validate".into(), "idp.device.lookup".into()],
            vec![
                "idp-services".into(),
                management_service::MANAGEMENT_APPLICATION_URI.into(),
                "storage:filesystems".into(),
            ],
            TokenEndpointAuthMethod::ClientSecretPost,
        ))
        .await
        .expect("scoped local Management service");
    let mut human = fixture
        .clients
        .find_client_by_client_id("human")
        .await
        .expect("client lookup")
        .expect("human");
    human.allowed_audiences.extend([
        management_service::MANAGEMENT_APPLICATION_URI.into(),
        "idp-services".into(),
    ]);
    fixture
        .clients
        .update_client(human)
        .await
        .expect("actor audiences");
    let service = ManagementService::new(
        DbPermissionRepo::new(fixture.management.clone()),
        DbRoleRepo::new(fixture.management.clone()),
    );
    for (app, actions) in [
        (fixture.scope.application_id, vec!["devices.select"]),
        (
            Id::nil(),
            vec![
                IdentityAction::DeviceRestrictionsRead.permission(),
                IdentityAction::DeviceRestrictionsUpdate.permission(),
                IdentityAction::DevicesTransfer.permission(),
            ],
        ),
    ] {
        let role = service
            .create_role(app, "policy-chain", None)
            .await
            .expect("explicit role");
        for action in actions {
            let permission = service
                .create_permission(app, action, None)
                .await
                .expect("explicit action");
            service
                .add_permission_to_role(app, role.id, permission.id)
                .await
                .expect("grant action");
        }
        service
            .add_role_to_user(app, fixture.owner, role.id)
            .await
            .expect("grant actual actor");
    }
    let control = HostedControlPlane::new_with_services(
        &fixture.idp_listener.base,
        &format!("{}/storage", fixture.storage_listener.base),
        &fixture.issuer,
    )
    .expect("real owner services")
    .with_idp_service_client(
        "management-lookup",
        "management-lookup-secret",
        "idp-services",
    )
    .expect("scoped introspection");
    let control = Arc::new(control);
    let mut management = Listener::start(
        management_server::build_router(
            fixture.management.clone(),
            "https://management.test",
            "",
            "storage-service",
            control.clone(),
        )
        .await
        .expect("Management routes"),
    )
    .await;
    let actor = actor_token(&fixture, management_service::MANAGEMENT_APPLICATION_URI).await;
    let storage_token = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Read],
        )
        .await;
    assert_eq!(
        control
            .validate_actor_token(&actor)
            .await
            .expect("real actor introspection")
            .1,
        fixture.scope.application_id
    );
    control
        .get_storage_device_identity(fixture.device.device_id)
        .await
        .expect("real trusted Device lookup");
    control
        .validate_storage_resource(
            &storage_token,
            &fixture.owner.to_string(),
            "storage:filesystems",
            fixture.scope.application_id,
            storage_model::ResourceKind::FileSystem,
            &fixture.resource.as_uuid().to_string(),
        )
        .await
        .expect("real catalog resource validation");
    let selection_url = format!(
        "{}/devices/{}/selection",
        management.base, fixture.device.device_id
    );
    let selection = serde_json::json!({"applicationId": fixture.scope.application_id, "kind": "filesystem", "id": fixture.resource.as_uuid(), "storageAccessToken": storage_token});
    require_success(
        fixture
            .http
            .put(&selection_url)
            .bearer_auth(&actor)
            .json(&selection)
            .send()
            .await
            .expect("real selection"),
    )
    .await;
    let selected = [(
        fixture.owner.to_string(),
        fixture.scope.application_id,
        fixture.resource,
    )];
    fixture
        .files
        .remove_unselected_projected_resources(&selected)
        .await
        .expect("observed trusted selection");
    let old_file = fixture.file().await;
    old_file
        .write("retired.txt", b"old copy")
        .await
        .expect("Full copy");
    let restriction_url = format!(
        "{}/devices/{}/restriction",
        management.base, fixture.device.device_id
    );
    require_success(
        fixture
            .http
            .put(&restriction_url)
            .bearer_auth(&actor)
            .json(&serde_json::json!({"adminAllowed": false}))
            .send()
            .await
            .expect("learn restriction"),
    )
    .await;
    assert!(
        fixture.client.introspect(&storage_token).await.is_err(),
        "real bearer observes native restriction"
    );
    require_success(
        fixture
            .http
            .put(&restriction_url)
            .bearer_auth(&actor)
            .json(&serde_json::json!({"adminAllowed": true}))
            .send()
            .await
            .expect("explicit restore"),
    )
    .await;
    assert!(fixture.client.introspect(&storage_token).await.is_ok());
    let deselect_url = format!(
        "{}/{}/filesystem/{}",
        selection_url,
        fixture.scope.application_id,
        fixture.resource.as_uuid()
    );
    require_success(
        fixture
            .http
            .delete(deselect_url)
            .bearer_auth(&actor)
            .send()
            .await
            .expect("resource-specific deselection"),
    )
    .await;
    fixture
        .files
        .remove_unselected_projected_resources(&[])
        .await
        .expect("public cleanup after learned deselection");
    assert!(
        old_file.read("retired.txt").await.is_err(),
        "issued owner handle retired"
    );
    require_success(
        fixture
            .http
            .put(&selection_url)
            .bearer_auth(&actor)
            .json(&selection)
            .send()
            .await
            .expect("causally later same-ID selection"),
    )
    .await;
    fixture
        .files
        .remove_unselected_projected_resources(&selected)
        .await
        .expect("new copy generation");
    let new_file = fixture.file().await;
    new_file
        .write("new.txt", b"fresh generation")
        .await
        .expect("fresh Full root");
    assert!(old_file.write("resurrect.txt", b"no").await.is_err());
    let (database_resource, sql) = fixture
        .databases
        .create(&fixture.scope, None)
        .expect("old owner created SQL copy");
    let database_token = fixture
        .token("storage:databases", vec![StorageAuthorizationAction::Read])
        .await;
    require_success(fixture.http.put(&selection_url).bearer_auth(&actor).json(&serde_json::json!({"applicationId": fixture.scope.application_id, "kind": "database", "id": database_resource.id, "storageAccessToken": database_token})).send().await.expect("same Management service selects the database kind")).await;
    let new_owner = DbUserRepo::new(fixture.idp.clone(), Default::default())
        .create_user_with_password("next-owner", "next-password")
        .await
        .expect("active next User");
    fixture
        .keys
        .ensure_entity_master_key(EntityType::User, new_owner.id, "next-password")
        .expect("test User key");
    fixture
        .keys
        .create_key(
            None,
            EntityType::User,
            new_owner.id,
            true,
            "next User session".into(),
            None,
        )
        .await
        .expect("test session key");
    let next_token = user_token(
        &fixture,
        "next-owner",
        "next-password",
        "storage:filesystems",
        true,
    )
    .await;
    let foreign_runtime =
        storage_service::DatabaseRuntime::new(fixture._directory.0.join("databases"))
            .expect("independent managed native owner");
    let foreign_kv = foreign_runtime
        .open_kv_selected(&fixture.scope, database_resource.id)
        .expect("foreign KV phase")
        .expect("foreign KV owner");
    let transfer_actor = actor_token(&fixture, "idp-services").await;
    require_success(
        fixture
            .http
            .put(format!(
                "{}/devices/{}/owner",
                fixture.idp_listener.base, fixture.device.device_id
            ))
            .bearer_auth(transfer_actor)
            .json(&serde_json::json!({"ownerSubject": new_owner.id}))
            .send()
            .await
            .expect("authorized native transfer"),
    )
    .await;
    assert!(
        fixture.client.introspect(&storage_token).await.is_err(),
        "learned transfer denies retained old bearer"
    );
    assert!(
        fixture.client.introspect(&next_token).await.is_err(),
        "next User denied while KV cleanup is incomplete"
    );
    assert_eq!(
        policies
            .pending_cleanup_owner(fixture.device.device_id)
            .await
            .expect("durable pending intent"),
        Some(fixture.owner.to_string())
    );
    assert!(
        new_file.read("new.txt").await.is_err(),
        "filesystem retirement is attempted despite the KV-phase failure"
    );
    fixture.client = fixture.client.clone().with_local_device_policy(
        fixture.identity.endpoint().id(),
        crate::runtime::owner_replication_authorizer(
            fixture.runtime.clone(),
            fixture.management.clone(),
            fixture.identity.endpoint().id(),
            copies.clone(),
        ),
    );
    drop(foreign_kv);
    drop(foreign_runtime);
    assert!(
        fixture.client.introspect(&next_token).await.is_err(),
        "retry finishes cleanup but explicit restriction remains"
    );
    assert!(
        sql.client()
            .translate_and_execute("SELECT 1", &db::SqlTranslator)
            .await
            .is_err(),
        "created SQL handle revoked"
    );
    assert!(
        new_file.read("new.txt").await.is_err(),
        "current filesystem generation retired"
    );
    let policy = policies
        .get(
            fixture.device.device_id,
            &new_owner.id.to_string(),
            Id::nil(),
        )
        .await
        .expect("completed native policy")
        .expect("new owner binding");
    assert!(!policy.admin_allowed);
    assert!(policy.selected_id.is_none());
    assert!(
        policies
            .pending_cleanup_owner(fixture.device.device_id)
            .await
            .expect("completion marker")
            .is_none()
    );
    assert!(
        authorizer
            .local_owner(fixture.identity.endpoint().id())
            .await
            .is_err(),
        "completion does not grant admin allowance"
    );
    require_success(
        fixture
            .http
            .put(&restriction_url)
            .bearer_auth(&actor)
            .json(&serde_json::json!({"adminAllowed": true}))
            .send()
            .await
            .expect("explicit post-cleanup allowance"),
    )
    .await;
    assert_eq!(
        authorizer
            .local_owner(fixture.identity.endpoint().id())
            .await
            .expect("new owner allowed only after cleanup"),
        new_owner.id.to_string()
    );
    assert!(
        fixture.client.introspect(&storage_token).await.is_err(),
        "old owner never regains access"
    );
    require_success(
        fixture
            .request(reqwest::Method::GET, "/storage/filesystems", &next_token)
            .await,
    )
    .await;
    assert!(
        fixture
            .files
            .create_resource(&fixture.scope, None)
            .await
            .is_err(),
        "old owner cannot admit fresh copies after transfer"
    );
    assert!(fixture.databases.create(&fixture.scope, None).is_err());
    management.stop().await;
    fixture.stop().await;
}
