use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use idp_model::{
    contract::{DeviceEnrollmentRequest, ErrorCode, IdentityAction, UpdateDeviceRequest},
    model::Id,
};
use management_service::{
    DeviceRepo, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo},
};

use crate::{
    node_join_tests::{approval_fixture, user_token},
    router::middleware::authorize_bearer,
};

use super::{enroll_device, revoke_device, update_device};

#[tokio::test]
async fn device_transfer_http_requires_exact_action_and_active_new_owner() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use idp_service::repo::UserRepo;
    use tower::ServiceExt;
    let fixture = approval_fixture().await;
    let token = user_token(&fixture, "idp-services").await;
    let device = fixture
        .state
        .devices
        .find_approved_by_public_key(&fixture.server.endpoint().id().to_string())
        .await
        .expect("local binding")
        .expect("approved Device");
    let new = fixture
        .state
        .oauth2_service
        .user_repo
        .create_user_with_password("new-owner", "valid-password")
        .await
        .expect("active local target User");
    let router: axum::Router = crate::openapi_router(fixture.state.clone(), "").into();
    let call = |target: Id| {
        Request::builder()
            .method("PUT")
            .uri(format!("/devices/{}/owner", device.id))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"ownerSubject":"{target}"}}"#)))
            .expect("typed transfer request")
    };
    assert_eq!(
        router
            .clone()
            .oneshot(call(new.id))
            .await
            .expect("real denied route")
            .status(),
        StatusCode::FORBIDDEN
    );
    let service = ManagementService::new(
        DbPermissionRepo::new(Arc::clone(&fixture.management)),
        DbRoleRepo::new(Arc::clone(&fixture.management)),
    );
    let role = service
        .create_role(Id::nil(), "transfer", None)
        .await
        .expect("role");
    let permission = service
        .create_permission(
            Id::nil(),
            IdentityAction::DevicesTransfer.permission(),
            None,
        )
        .await
        .expect("exact action");
    service
        .add_permission_to_role(Id::nil(), role.id, permission.id)
        .await
        .expect("grant");
    service
        .add_role_to_user(Id::nil(), fixture.owner, role.id)
        .await
        .expect("actor");
    assert!(
        !router
            .clone()
            .oneshot(call(Id::now_v7()))
            .await
            .expect("unknown target")
            .status()
            .is_success()
    );
    assert_eq!(
        fixture
            .state
            .devices
            .find_approved_by_public_key(&device.public_key)
            .await
            .expect("owner intact")
            .expect("Device")
            .owner_subject,
        fixture.owner.to_string()
    );
    assert_eq!(
        router
            .clone()
            .oneshot(call(new.id))
            .await
            .expect("real transfer route")
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fixture
            .state
            .devices
            .find_approved_by_public_key(&device.public_key)
            .await
            .expect("new binding")
            .expect("Device")
            .owner_subject,
        new.id.to_string()
    );
    assert!(
        !router
            .oneshot(call(fixture.owner))
            .await
            .expect("old actor cannot take it back")
            .status()
            .is_success()
    );
    fixture.server.endpoint().close().await;
    let root = fixture.root.clone();
    drop(service);
    drop(fixture);
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[tokio::test]
async fn management_device_identity_uses_real_local_idp_and_learned_revocation() {
    use idp_model::contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        TokenEndpointAuthMethod,
    };
    use idp_service::repo::ClientRepo;
    let fixture = approval_fixture().await;
    fixture
        .state
        .oauth2_service
        .client_repo
        .create_client(ClientRegistration {
            application: ApplicationRegistration {
                name: Some("Management lookup".into()),
                uri: "https://management-lookup.test".into(),
                description: None,
            },
            client_id: Some("management-lookup".into()),
            client_secret: Some("lookup-secret".into()),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Management lookup".into(),
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
            allowed_scopes: vec!["idp.token.validate".into(), "idp.device.lookup".into()],
            allowed_audiences: vec!["idp-services".into()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            software_statement: None,
            software_id: None,
            software_version: None,
        })
        .await
        .expect("least-privilege local service client");
    let device = fixture
        .state
        .devices
        .find_approved_by_public_key(&fixture.server.endpoint().id().to_string())
        .await
        .expect("trusted Device")
        .expect("Device");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local owner listener");
    let address = listener.local_addr().expect("listener address");
    let router: axum::Router = crate::openapi_router(fixture.state.clone(), "").into();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("local IdP HTTP");
    });
    let local = format!("http://{address}");
    let control =
        management_service::HostedControlPlane::new_with_services(&local, &local, &fixture.issuer)
            .expect("local control plane")
            .with_idp_service_client("management-lookup", "lookup-secret", "idp-services")
            .expect("scoped service");
    let identity = control
        .get_storage_device_identity(device.id)
        .await
        .expect("locally verified owner");
    assert_eq!(identity.device_id, device.id);
    assert_eq!(identity.owner_subject, fixture.owner.to_string());
    assert_eq!(
        identity.endpoint_id,
        fixture.server.endpoint().id().to_string()
    );
    assert!(
        control
            .get_storage_device_identity(Id::now_v7())
            .await
            .is_err()
    );
    fixture
        .state
        .devices
        .revoke_self(&device.public_key)
        .await
        .expect("learn local revocation");
    assert!(
        control
            .get_storage_device_identity(device.id)
            .await
            .is_err(),
        "cached service token is not cached Device trust"
    );
    server.abort();
    let _ = server.await;
    fixture.server.endpoint().close().await;
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root).expect("remove isolated native fixture");
}

#[tokio::test]
async fn device_policy_api_requires_action_grant_and_owner_and_preserves_denied_mutations() {
    let fixture = approval_fixture().await;
    let token = user_token(&fixture, "idp-services").await;
    let device = fixture
        .state
        .devices
        .create(
            fixture.owner.to_string(),
            "Original".into(),
            iroh::SecretKey::generate().public().to_string(),
            "address".into(),
            vec![],
            0,
        )
        .await
        .expect("owner Device");
    let rename = || {
        Json(UpdateDeviceRequest {
            name: "Renamed".into(),
        })
    };
    let result = update_device(
        State(fixture.state.clone()),
        Path(device.id),
        authorize_bearer(&fixture.state, &token)
            .await
            .expect("real actor"),
        rename(),
    )
    .await;
    assert_eq!(
        result
            .err()
            .expect("generic User bearer does not grant rename")
            .error,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        fixture
            .state
            .devices
            .list_owned(&fixture.owner.to_string())
            .await
            .expect("retained Device")
            .into_iter()
            .find(|row| row.id == device.id)
            .expect("Device")
            .name,
        "Original"
    );
    let service = ManagementService::new(
        DbPermissionRepo::new(Arc::clone(&fixture.management)),
        DbRoleRepo::new(Arc::clone(&fixture.management)),
    );
    let role = service
        .create_role(Id::nil(), "device-admin", None)
        .await
        .expect("installation role");
    for action in [IdentityAction::DevicesRename, IdentityAction::DevicesRevoke] {
        let permission = service
            .create_permission(Id::nil(), action.permission(), None)
            .await
            .expect("explicit permission");
        service
            .add_permission_to_role(Id::nil(), role.id, permission.id)
            .await
            .expect("grant action");
    }
    service
        .add_role_to_user(Id::nil(), fixture.owner, role.id)
        .await
        .expect("grant actor");
    let updated = update_device(
        State(fixture.state.clone()),
        Path(device.id),
        authorize_bearer(&fixture.state, &token)
            .await
            .expect("same actor"),
        rename(),
    )
    .await
    .expect("authorized rename");
    assert_eq!(updated.0.name, "Renamed");
    let other = fixture
        .state
        .devices
        .create(
            Id::now_v7().to_string(),
            "Other".into(),
            iroh::SecretKey::generate().public().to_string(),
            "address".into(),
            vec![],
            0,
        )
        .await
        .expect("unrelated owner");
    assert!(
        update_device(
            State(fixture.state.clone()),
            Path(other.id),
            authorize_bearer(&fixture.state, &token)
                .await
                .expect("same actor"),
            rename()
        )
        .await
        .is_err()
    );
    assert!(
        enroll_device(
            State(fixture.state.clone()),
            authorize_bearer(&fixture.state, &token)
                .await
                .expect("same actor"),
            Json(DeviceEnrollmentRequest {
                name: "New".into(),
                public_key: iroh::SecretKey::generate().public().to_string(),
                address: "address".into()
            })
        )
        .await
        .is_err()
    );
    revoke_device(
        State(fixture.state.clone()),
        Path(device.id),
        authorize_bearer(&fixture.state, &token)
            .await
            .expect("same actor"),
    )
    .await
    .expect("authorized revoke");
    assert!(
        fixture
            .state
            .devices
            .list_owned(&fixture.owner.to_string())
            .await
            .expect("Device state")
            .into_iter()
            .find(|row| row.id == device.id)
            .expect("Device")
            .revoked_at
            .is_some()
    );
    assert_eq!(
        fixture
            .state
            .devices
            .list_owned(&other.owner_subject)
            .await
            .expect("unrelated Device survives")[0]
            .name,
        "Other"
    );
    fixture.server.endpoint().close().await;
    let root = fixture.root.clone();
    drop(service);
    drop(fixture);
    std::fs::remove_dir_all(root).expect("remove isolated native fixture");
}
