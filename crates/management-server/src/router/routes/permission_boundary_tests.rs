use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use idp_model::{
    contract::{
        ErrorCode, INSTALLATION_POLICY_ID, IdentityAction, IdentityResource,
        PermissionEvaluationRequest, PermissionSubject, PermissionTarget,
    },
    model::Id,
};
use management_service::{
    HostedControlPlane, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo, up},
};

use crate::router::{
    RouterState,
    middleware::ManagementAuthorization,
    routes::{permissions, roles, users},
};

#[tokio::test]
async fn typed_evaluation_separates_application_and_installation_assignments() {
    let root = std::env::temp_dir().join(format!("management-evaluation-{}", Id::now_v7()));
    std::fs::create_dir_all(&root).expect("create isolated test directory");
    let engine =
        Arc::new(db::Database::open(root.join("management.redb")).expect("open test engine"));
    up(&engine).await.expect("initialize policy schema");
    let state = state(Arc::clone(&engine));
    let service = &state.management_service;
    let app = Id::now_v7();
    let user = Id::now_v7();
    let role = service
        .create_role(app, "app-admin", None)
        .await
        .expect("create role");
    for action in [
        IdentityAction::ClientsRead,
        IdentityAction::InfrastructureClientsCreate,
    ] {
        let permission = service
            .create_permission(app, action.permission(), None)
            .await
            .expect("create permission");
        service
            .add_permission_to_role(app, role.id, permission.id)
            .await
            .expect("assign permission");
    }
    service
        .add_role_to_user(app, user, role.id)
        .await
        .expect("assign role");
    let mut request = PermissionEvaluationRequest {
        request_id: Id::now_v7(),
        subject: PermissionSubject::User { id: user },
        action: IdentityAction::ClientsRead,
        target: PermissionTarget::Application {
            application_id: app,
            resource: IdentityResource::Client {
                client_id: Some("client".into()),
            },
        },
    };
    assert!(
        service
            .evaluate_permission(&request)
            .await
            .expect("evaluate same app")
    );
    request.target = PermissionTarget::Application {
        application_id: Id::now_v7(),
        resource: IdentityResource::Client {
            client_id: Some("client".into()),
        },
    };
    assert!(
        !service
            .evaluate_permission(&request)
            .await
            .expect("evaluate cross app")
    );
    request.action = IdentityAction::InfrastructureClientsCreate;
    request.target = PermissionTarget::Installation {
        resource: IdentityResource::Client { client_id: None },
    };
    assert!(
        !service
            .evaluate_permission(&request)
            .await
            .expect("app grant cannot escalate")
    );
    let installation_role = service
        .create_role(INSTALLATION_POLICY_ID, "installation-admin", None)
        .await
        .expect("create installation role");
    let permission = service
        .create_permission(INSTALLATION_POLICY_ID, request.action.permission(), None)
        .await
        .expect("create explicit installation permission");
    service
        .add_permission_to_role(INSTALLATION_POLICY_ID, installation_role.id, permission.id)
        .await
        .expect("assign installation permission");
    service
        .add_role_to_user(INSTALLATION_POLICY_ID, user, installation_role.id)
        .await
        .expect("assign installation role");
    assert!(
        service
            .evaluate_permission(&request)
            .await
            .expect("evaluate installation assignment")
    );
    assert!(
        !service
            .has_user_application_permission(
                user,
                INSTALLATION_POLICY_ID,
                request.action.permission()
            )
            .await
            .expect("application API excludes installation")
    );
    assert!(
        roles::require_application_permission(
            service,
            &ManagementAuthorization::new(user, INSTALLATION_POLICY_ID),
            INSTALLATION_POLICY_ID,
            request.action.permission()
        )
        .await
        .is_err()
    );
    service
        .remove_role_from_user(INSTALLATION_POLICY_ID, user, installation_role.id)
        .await
        .expect("revoke installation role");
    assert!(
        !service
            .evaluate_permission(&request)
            .await
            .expect("revocation is immediate")
    );
    drop(state);
    drop(engine);
    std::fs::remove_dir_all(root).expect("remove test database");
}

fn state(engine: Arc<db::Database>) -> RouterState {
    RouterState::new(
        "http://127.0.0.1",
        Arc::new(ManagementService::new(
            DbPermissionRepo::new(Arc::clone(&engine)),
            DbRoleRepo::new(Arc::clone(&engine)),
        )),
        Arc::new(DbSelectionPolicyRepo::new(engine)),
        Arc::new(
            HostedControlPlane::new_with_services(
                "http://127.0.0.1",
                "http://127.0.0.1",
                "https://installation.example",
            )
            .expect("construct unused control plane"),
        ),
        "storage-api",
    )
}

#[tokio::test]
async fn all_rbac_routes_reject_cross_application_before_repository_access() {
    let root = std::env::temp_dir().join(format!("management-scope-{}", Id::now_v7()));
    std::fs::create_dir_all(&root).expect("create isolated test directory");
    let engine =
        Arc::new(db::Database::open(root.join("management.redb")).expect("open empty engine"));
    let state = state(Arc::clone(&engine));
    let caller_app = Id::now_v7();
    let target_app = Id::now_v7();
    let subject = Id::now_v7();
    let role = Id::now_v7();
    let permission = Id::now_v7();
    let authorization = || ManagementAuthorization::new(subject, caller_app);
    macro_rules! denied {
        ($request:expr) => {
            assert_eq!(
                $request
                    .await
                    .err()
                    .expect("cross-application request must fail")
                    .error,
                ErrorCode::AccessDenied
            );
        };
    }
    denied!(roles::list_roles(
        State(state.clone()),
        Path(target_app),
        Query(roles::ListRolesQuery {
            offset: 0,
            limit: 10
        }),
        authorization()
    ));
    denied!(roles::create_role(
        State(state.clone()),
        Path(target_app),
        authorization(),
        Json(roles::CreateRoleRequest {
            name: "unauthorized".into(),
            description: None
        })
    ));
    denied!(roles::delete_role(
        State(state.clone()),
        Path((target_app, role)),
        authorization()
    ));
    denied!(roles::list_user_roles(
        State(state.clone()),
        Path((target_app, subject)),
        authorization()
    ));
    denied!(roles::assign_role_to_user(
        State(state.clone()),
        Path((target_app, subject, role)),
        authorization()
    ));
    denied!(roles::revoke_role_from_user(
        State(state.clone()),
        Path((target_app, subject, role)),
        authorization()
    ));
    denied!(permissions::list_permissions(
        State(state.clone()),
        Path(target_app),
        Query(permissions::ListPermissionsQuery {
            offset: 0,
            limit: 10
        }),
        authorization()
    ));
    denied!(permissions::create_permission(
        State(state.clone()),
        Path(target_app),
        authorization(),
        Json(permissions::CreatePermissionRequest {
            name: "unauthorized".into(),
            description: None
        })
    ));
    denied!(permissions::delete_permission(
        State(state.clone()),
        Path((target_app, permission)),
        authorization()
    ));
    denied!(permissions::list_role_permissions(
        State(state.clone()),
        Path((target_app, role)),
        authorization()
    ));
    denied!(permissions::assign_permission_to_role(
        State(state.clone()),
        Path((target_app, role, permission)),
        authorization()
    ));
    denied!(permissions::revoke_permission_from_role(
        State(state.clone()),
        Path((target_app, role, permission)),
        authorization()
    ));
    let device = Id::now_v7();
    let resource = Id::now_v7();
    let selection = serde_json::from_value(serde_json::json!({
        "applicationId": target_app,
        "kind": "database",
        "id": resource,
        "storageAccessToken": "not-an-authorization-substitute",
    }))
    .expect("build valid selection request");
    denied!(
        crate::router::routes::device_selection::put_device_selection(
            State(state.clone()),
            Path(device),
            authorization(),
            Json(selection),
        )
    );
    denied!(
        crate::router::routes::device_selection::delete_device_resource_selection(
            State(state.clone()),
            Path((
                device,
                target_app,
                crate::router::routes::device_selection::SelectionKind::Database,
                resource
            )),
            authorization(),
        )
    );
    denied!(
        crate::router::routes::device_selection::delete_device_selection(
            Path(device),
            authorization(),
        )
    );
    drop(state);
    drop(engine);
    std::fs::remove_dir_all(root).expect("remove isolated test database");
}

#[tokio::test]
async fn restriction_api_updates_exact_device_with_separate_read_and_update_grants() {
    use crate::router::routes::device_restriction::{
        DeviceRestriction, get_device_restriction, put_device_restriction,
    };
    let root = std::env::temp_dir().join(format!("restriction-api-{}.redb", Id::now_v7()));
    let engine = Arc::new(db::Database::open(&root).expect("open policy"));
    up(&engine).await.expect("initialize policy");
    let mut state = state(Arc::clone(&engine));
    let owner = Id::now_v7();
    let administrator = Id::now_v7();
    let device = Id::now_v7();
    // The IdP response seam is controlled here; real native IdP lookup is separately qualified.
    let owner_api = axum::Router::new().route("/oauth2/token", axum::routing::post(|| async { Json(serde_json::json!({
        "access_token":"lookup-token", "token_type":"Bearer", "expires_in":300,
        "scope":"idp.token.validate idp.device.lookup", "iss":"https://installation.example"
    })) })).route("/devices/identities/{device}", axum::routing::get(move || async move { Json(serde_json::json!({
        "deviceId": device, "ownerSubject": owner,
        "endpointId":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    })) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owner seam listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        axum::serve(listener, owner_api)
            .await
            .expect("owner seam HTTP");
    });
    let url = format!("http://{address}");
    state.control_plane = Arc::new(
        HostedControlPlane::new_with_services(&url, &url, "https://installation.example")
            .expect("control plane")
            .with_idp_service_client("lookup", "secret", "idp-services")
            .expect("scoped lookup"),
    );
    state
        .selection_policies
        .set_admin_allowed_prevalidated(device, &owner.to_string(), true)
        .await
        .expect("prior policy");
    let role = state
        .management_service
        .create_role(Id::nil(), "restriction-admin", None)
        .await
        .expect("role");
    let update = state
        .management_service
        .create_permission(
            Id::nil(),
            IdentityAction::DeviceRestrictionsUpdate.permission(),
            None,
        )
        .await
        .expect("update action");
    state
        .management_service
        .add_permission_to_role(Id::nil(), role.id, update.id)
        .await
        .expect("grant update");
    state
        .management_service
        .add_role_to_user(Id::nil(), administrator, role.id)
        .await
        .expect("grant administrator");
    let actor = || ManagementAuthorization::new(administrator, Id::now_v7());
    assert!(
        get_device_restriction(State(state.clone()), Path(device), actor())
            .await
            .is_err(),
        "update does not grant read"
    );
    put_device_restriction(
        State(state.clone()),
        Path(device),
        actor(),
        Json(DeviceRestriction {
            admin_allowed: false,
        }),
    )
    .await
    .expect("authorized exact update");
    let read = state
        .management_service
        .create_permission(
            Id::nil(),
            IdentityAction::DeviceRestrictionsRead.permission(),
            None,
        )
        .await
        .expect("read action");
    state
        .management_service
        .add_permission_to_role(Id::nil(), role.id, read.id)
        .await
        .expect("grant read");
    assert!(
        !get_device_restriction(State(state.clone()), Path(device), actor())
            .await
            .expect("read current restriction")
            .0
            .admin_allowed
    );
    assert!(
        put_device_restriction(
            State(state.clone()),
            Path(Id::now_v7()),
            actor(),
            Json(DeviceRestriction {
                admin_allowed: true
            })
        )
        .await
        .is_err(),
        "mismatched owner target rejected"
    );
    assert!(
        !get_device_restriction(State(state.clone()), Path(device), actor())
            .await
            .expect("wrong target preserves policy")
            .0
            .admin_allowed
    );
    server.abort();
    let _ = server.await;
    drop(state);
    drop(engine);
    std::fs::remove_file(root).expect("remove fixture");
}

#[tokio::test]
async fn restriction_api_denies_without_installation_grant_and_preserves_policy() {
    let root = std::env::temp_dir().join(format!("restriction-policy-{}.redb", Id::now_v7()));
    let engine = Arc::new(db::Database::open(&root).expect("open policy"));
    up(&engine).await.expect("initialize policy");
    let state = state(Arc::clone(&engine));
    let owner = Id::now_v7();
    let device = Id::now_v7();
    state
        .selection_policies
        .set_admin_allowed_prevalidated(device, &owner.to_string(), false)
        .await
        .expect("prior restriction");
    let request =
        serde_json::from_value(serde_json::json!({"adminAllowed":true})).expect("typed request");
    let result = crate::router::routes::device_restriction::put_device_restriction(
        State(state.clone()),
        Path(device),
        ManagementAuthorization::new(owner, Id::now_v7()),
        Json(request),
    )
    .await;
    assert_eq!(
        result.err().expect("requires installation grant").error,
        ErrorCode::AccessDenied
    );
    assert!(
        !state
            .selection_policies
            .get(device, &owner.to_string(), Id::nil())
            .await
            .expect("policy unchanged")
            .expect("policy")
            .admin_allowed
    );
    drop(state);
    drop(engine);
    std::fs::remove_file(root).expect("remove fixture");
}

#[tokio::test]
async fn deselection_cannot_use_stale_policy_owner_when_idp_binding_is_unavailable() {
    let root = std::env::temp_dir().join(format!("stale-device-owner-{}.redb", Id::now_v7()));
    let engine = Arc::new(db::Database::open(&root).expect("open policy"));
    up(&engine).await.expect("initialize policy");
    let state = state(Arc::clone(&engine));
    let owner = Id::now_v7();
    let app = Id::now_v7();
    let device = Id::now_v7();
    let resource = Id::now_v7();
    let role = state
        .management_service
        .create_role(app, "selector", None)
        .await
        .expect("role");
    let permission = state
        .management_service
        .create_permission(app, "devices.select", None)
        .await
        .expect("permission");
    state
        .management_service
        .add_permission_to_role(app, role.id, permission.id)
        .await
        .expect("grant action");
    state
        .management_service
        .add_role_to_user(app, owner, role.id)
        .await
        .expect("grant actor");
    state
        .selection_policies
        .set_prevalidated(management_service::replica::SelectionPolicy {
            device_id: device,
            owner_subject: owner.to_string(),
            application_id: Some(app),
            selected_kind: Some("database".into()),
            selected_id: Some(resource),
            admin_allowed: true,
        })
        .await
        .expect("previous locally stored selection");
    let result = crate::router::routes::device_selection::delete_device_resource_selection(
        State(state.clone()),
        Path((
            device,
            app,
            crate::router::routes::device_selection::SelectionKind::Database,
            resource,
        )),
        ManagementAuthorization::new(owner, app),
    )
    .await;
    assert!(
        result.is_err(),
        "policy owner is not current IdP ownership evidence"
    );
    assert_eq!(
        state
            .selection_policies
            .selected_resources_for_device(device)
            .await
            .expect("selection unchanged")
            .len(),
        1
    );
    drop(state);
    drop(engine);
    std::fs::remove_file(root).expect("remove fixture");
}

#[tokio::test]
async fn application_permission_requires_live_assignment_and_does_not_expose_other_roles() {
    let root = std::env::temp_dir().join(format!("management-permission-{}", Id::now_v7()));
    std::fs::create_dir_all(&root).expect("create isolated test directory");
    let engine = Arc::new(db::Database::open(root.join("management.redb")).expect("open engine"));
    up(&engine).await.expect("initialize Management schema");
    let state = state(Arc::clone(&engine));
    let service = state.management_service.as_ref();
    let app = Id::now_v7();
    let other_app = Id::now_v7();
    let subject = Id::now_v7();
    let role = service
        .create_role(app, "reader", None)
        .await
        .expect("create application role");
    let other_role = service
        .create_role(other_app, "other-reader", None)
        .await
        .expect("create other role");
    for name in ["roles.read", "users.read"] {
        let permission = service
            .create_permission(app, name, None)
            .await
            .expect("create permission");
        service
            .add_permission_to_role(app, role.id, permission.id)
            .await
            .expect("grant explicit permission");
    }
    let authorization = || ManagementAuthorization::new(subject, app);
    assert_eq!(
        roles::require_application_permission(service, &authorization(), app, "roles.read")
            .await
            .expect_err("unassigned role must not authorize")
            .error,
        ErrorCode::AccessDenied
    );
    service
        .add_role_to_user(app, subject, role.id)
        .await
        .expect("assign role");
    service
        .add_role_to_user(other_app, subject, other_role.id)
        .await
        .expect("assign other role");
    roles::require_application_permission(service, &authorization(), app, "roles.read")
        .await
        .expect("explicit assignment authorizes same application");
    assert_eq!(
        roles::require_application_permission(service, &authorization(), other_app, "roles.read")
            .await
            .expect_err("assignment in another application is not installation permission")
            .error,
        ErrorCode::AccessDenied
    );
    assert_eq!(
        roles::require_application_permission(service, &authorization(), app, "roles.write")
            .await
            .expect_err("read permission must not authorize writes")
            .error,
        ErrorCode::AccessDenied
    );
    let Json(visible) = users::list_user_roles_across_applications(
        State(state.clone()),
        Path(subject),
        authorization(),
    )
    .await
    .expect("read application roles");
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].application_id, app);
    service
        .remove_role_from_user(app, subject, role.id)
        .await
        .expect("revoke assignment");
    assert_eq!(
        roles::require_application_permission(service, &authorization(), app, "roles.read")
            .await
            .expect_err("revoked assignment must deny without a cached decision")
            .error,
        ErrorCode::AccessDenied
    );
    drop(state);
    drop(engine);
    std::fs::remove_dir_all(root).expect("remove isolated test database");
}
