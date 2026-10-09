use std::time::Duration;

use idp_model::{
    contract::{GrantType, TokenEndpointAuthMethod},
    model::Id,
};
use idp_service::repo::ClientRepo;
use management_service::replica::DbSelectionPolicyRepo;
use model::contract::StorageAuthorizationAction;
use storage_model::{StorageRequest, StorageResponse};

use super::{Fixture, Gate, registration};

async fn reassign_application(fixture: &Fixture) -> Id {
    let other = fixture
        .clients
        .create_client(registration(
            "other-application",
            vec![GrantType::Password, GrantType::TokenExchange],
            vec!["openid".into()],
            vec!["storage:filesystems".into(), "storage:databases".into()],
            TokenEndpointAuthMethod::ClientSecretBasic,
        ))
        .await
        .expect("real distinct Application");
    assert_ne!(other.application_id, fixture.scope.application_id);
    let mut human = fixture
        .clients
        .find_client_by_client_id("human")
        .await
        .expect("current Client")
        .expect("human Client exists");
    human.application_id = other.application_id;
    fixture
        .clients
        .update_client(human)
        .await
        .expect("learn Client Application reassignment");
    let current = fixture
        .clients
        .find_client_by_client_id("human")
        .await
        .expect("reassigned Client read")
        .expect("Client retained");
    assert_eq!(current.application_id, other.application_id);
    other.application_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_response_denies_learned_application_reassignment_without_rollback() {
    tokio::time::timeout(Duration::from_secs(240), async {
        for kind in ["databases", "filesystems"] {
        let gate = Gate::default();
        let fixture = Fixture::with_catalog_gate(Gate::default(), Some(gate.clone())).await;
        let token = fixture.token(&format!("storage:{kind}"), vec![StorageAuthorizationAction::Write]).await;
        let path = format!("/storage/{kind}");
        let mut request = Box::pin(fixture.request(reqwest::Method::POST, &path, &token));
        tokio::select! {
            response = &mut request => panic!("catalog result returned before response gate: {}", response.status()),
            () = gate.reached() => {}
        }
        let expected = if kind == "databases" { 1 } else { 2 };
        assert_eq!(catalog_count(&fixture, kind, &fixture.scope).await, expected);
        let other = reassign_application(&fixture).await;
        gate.release();
        let response = request.await;

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED, "old namespace result cannot be disclosed under current Application");
        assert!(response.bytes().await.expect("denial body").is_empty());
        let current = storage_server::authorize_storage_token(&fixture.client, &token).await.expect("same bearer remains valid in current namespace");
        assert_eq!(current.subject, fixture.scope.user_sub);
        assert_eq!(current.application_id, other.to_string());
        assert_eq!(catalog_count(&fixture, kind, &fixture.scope).await, expected);
        assert_eq!(catalog_count(&fixture, kind, &super::StorageNamespace { user_sub: fixture.scope.user_sub.clone(), application_id: other }).await, 0);
        fixture.stop().await;
        }
    }).await.expect("native namespace interleaving completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_paused_local_introspection_timeout_returns_503_without_rollback() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let gate = Gate::default();
        let fixture = Fixture::with_catalog_gate(Gate::default(), Some(gate.clone())).await;
        let token = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Write]).await;
        let started = std::time::Instant::now();
        let mut request = Box::pin(fixture.request(reqwest::Method::POST, "/storage/filesystems", &token));
        tokio::select! {
            response = &mut request => panic!("result returned before real response-time introspection: {}", response.status()),
            () = gate.reached() => {}
        }
        assert_eq!(catalog_count(&fixture, "filesystems", &fixture.scope).await, 2, "authorized mutation completed before the paused local evaluation");
        let response = request.await;
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.bytes().await.expect("safe denial body").is_empty());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(10), "existing HTTP request deadline, not token/policy denial: {elapsed:?}");
        eprintln!("paused native introspection returned safe503 after {elapsed:?}; owner evaluation was still gated");
        gate.release();
        let current = storage_server::authorize_storage_token(&fixture.client, &token).await.expect("same bearer remains genuinely valid after the gate releases");
        assert_eq!(current.subject, fixture.scope.user_sub);
        assert_eq!(current.application_id, fixture.scope.application_id.to_string());
        assert_eq!(catalog_count(&fixture, "filesystems", &fixture.scope).await, 2);
        fixture.stop().await;
    }).await.expect("native timeout diagnostic completes");
}

async fn catalog_count(fixture: &Fixture, kind: &str, scope: &super::StorageNamespace) -> usize {
    if kind == "databases" {
        fixture
            .databases
            .list(scope)
            .expect("native database catalog")
            .len()
    } else {
        fixture
            .files
            .list_resources(scope)
            .await
            .expect("native filesystem catalog")
            .len()
    }
}

async fn set_device_allowed(fixture: &Fixture, allowed: bool) {
    assert!(
        DbSelectionPolicyRepo::new(fixture.management.clone())
            .set_admin_allowed_prevalidated(
                fixture.device.device_id,
                &fixture.device.owner_subject,
                allowed
            )
            .await
            .expect("persist real owner-bound Management restriction")
    );
    let (current, selected) =
        management_server::replication_policy(fixture.management.clone(), &fixture.device)
            .await
            .expect("current local Management evaluation");
    assert_eq!(current, allowed);
    assert!(
        selected.is_empty(),
        "bearer API discovery does not require Device selection"
    );
}

async fn catalog_device_restriction(kind: &str, operation: &str) {
    let gate = Gate::default();
    let fixture = Fixture::with_catalog_gate(Gate::default(), Some(gate.clone())).await;
    set_device_allowed(&fixture, true).await;
    let token = fixture
        .token(
            &format!("storage:{kind}"),
            vec![
                StorageAuthorizationAction::Read,
                StorageAuthorizationAction::Write,
            ],
        )
        .await;
    let target = if kind == "databases" {
        fixture
            .databases
            .create(&fixture.scope, Some("target".into()))
            .expect("database catalog target")
            .0
            .id
            .to_string()
    } else {
        fixture.resource.as_uuid().to_string()
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
        response = &mut request => panic!("{kind}/{operation} returned before response gate: {}", response.status()),
        () = gate.reached() => {}
    }
    let expected_count = match operation {
        "create" => 2,
        "delete" => 0,
        _ => 1,
    };
    let completed_count = catalog_count(&fixture, kind, &fixture.scope).await;
    assert_eq!(completed_count, expected_count);
    set_device_allowed(&fixture, false).await;
    gate.release();
    let response = request.await;
    let expected_status = match operation {
        "create" => reqwest::StatusCode::CREATED,
        "delete" => reqwest::StatusCode::NO_CONTENT,
        _ => reqwest::StatusCode::OK,
    };
    assert_eq!(
        response.status(),
        expected_status,
        "Device replication restriction is not Storage bearer revocation"
    );
    if operation != "delete" {
        let body: serde_json::Value = response.json().await.expect("real catalog response");
        if operation == "list" {
            assert_eq!(body.as_array().expect("catalog list").len(), 1);
        } else if operation == "get" {
            assert_eq!(body["id"], target);
        } else {
            assert!(body["id"].as_str().is_some());
        }
    }
    set_device_allowed(&fixture, false).await;
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_device_restrictions_do_not_revoke_bearer_results() {
    tokio::time::timeout(Duration::from_secs(600), async {
        for kind in ["databases", "filesystems"] {
            for operation in ["create", "get", "list", "delete"] {
                catalog_device_restriction(kind, operation).await;
            }
        }
    })
    .await
    .expect("native Management/catalog response matrix completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_socket_device_restriction_preserves_bearer_response_and_next_operation() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let fixture = Fixture::new(gate.clone()).await;
        set_device_allowed(&fixture, true).await;
        let token = fixture
            .token(
                "storage:filesystems",
                vec![
                    StorageAuthorizationAction::Read,
                    StorageAuthorizationAction::Write,
                ],
            )
            .await;
        let file = fixture.file().await;
        file.write("source.txt", b"source content")
            .await
            .expect("native source content");
        let mut socket = fixture.socket(&token, true).await;
        super::send(
            &mut socket,
            StorageRequest::Read {
                path: "source.txt".into(),
            },
        )
        .await;
        gate.reached().await;
        set_device_allowed(&fixture, false).await;
        gate.release();
        assert_eq!(
            super::response(&mut socket).await,
            StorageResponse::Read {
                content: b"source content".to_vec()
            }
        );
        super::send(
            &mut socket,
            StorageRequest::Write {
                path: "committed.txt".into(),
                content: b"bearer-authorized content".to_vec(),
            },
        )
        .await;
        gate.reached().await;
        assert_eq!(
            file.read("committed.txt")
                .await
                .expect("next write committed on same socket"),
            b"bearer-authorized content"
        );
        set_device_allowed(&fixture, false).await;
        gate.release();
        assert!(matches!(
            super::response(&mut socket).await,
            StorageResponse::Written { .. }
        ));
        fixture.revoke_user().await;
        super::send(
            &mut socket,
            StorageRequest::Write {
                path: "denied.txt".into(),
                content: b"must not commit".to_vec(),
            },
        )
        .await;
        super::assert_no_response(&mut socket).await;
        assert!(file.read("denied.txt").await.is_err());
        assert_eq!(
            file.read("committed.txt")
                .await
                .expect("earlier write retained"),
            b"bearer-authorized content"
        );
        drop(socket);
        fixture.stop().await;
    })
    .await
    .expect("native Management/socket policy distinction completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_socket_response_binds_namespace_even_when_resource_id_exists_in_new_application() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let gate = Gate::default();
        let fixture = Fixture::new(gate.clone()).await;
        let token = fixture
            .token(
                "storage:filesystems",
                vec![
                    StorageAuthorizationAction::Read,
                    StorageAuthorizationAction::Write,
                ],
            )
            .await;
        let original = fixture.file().await;
        original
            .write("retained.txt", b"original namespace secret")
            .await
            .expect("original content");
        let mut idle = fixture.socket(&token, false).await;
        let mut socket = fixture.socket(&token, true).await;
        super::send(
            &mut socket,
            StorageRequest::Read {
                path: "retained.txt".into(),
            },
        )
        .await;
        gate.reached().await;
        let other = reassign_application(&fixture).await;
        let scope = super::StorageNamespace {
            user_sub: fixture.scope.user_sub.clone(),
            application_id: other,
        };
        fixture
            .files
            .register_selected_resource(&scope, fixture.resource)
            .await
            .expect("native resource projection in new namespace");
        let current_file = fixture
            .files
            .open_resource(&scope, fixture.resource)
            .await
            .expect("same ID in genuinely distinct namespace");
        current_file
            .write("retained.txt", b"new namespace content")
            .await
            .expect("distinct namespace content");
        let current = storage_server::authorize_storage_token(&fixture.client, &token)
            .await
            .expect("same signed bearer is valid in new Application");
        assert_eq!(current.application_id, other.to_string());
        gate.release();
        super::assert_no_response(&mut socket).await;
        assert_eq!(
            original
                .read("retained.txt")
                .await
                .expect("source retained"),
            b"original namespace secret"
        );
        super::send(
            &mut idle,
            StorageRequest::Write {
                path: "must-not-rebind.txt".into(),
                content: b"denied".to_vec(),
            },
        )
        .await;
        super::assert_no_response(&mut idle).await;
        assert!(current_file.read("must-not-rebind.txt").await.is_err());
        assert!(original.read("must-not-rebind.txt").await.is_err());
        drop(idle);
        let mut fresh = fixture.socket(&token, false).await;
        super::send(
            &mut fresh,
            StorageRequest::Read {
                path: "retained.txt".into(),
            },
        )
        .await;
        assert_eq!(
            super::response(&mut fresh).await,
            StorageResponse::Read {
                content: b"new namespace content".to_vec()
            }
        );
        drop(fresh);
        drop(socket);
        fixture.stop().await;
    })
    .await
    .expect("native overlapping-ID namespace boundary completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_socket_response_denies_application_reassignment_and_retains_completed_write() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let gate = Gate::default();
        let fixture = Fixture::new(gate.clone()).await;
        let token = fixture.token("storage:filesystems", vec![StorageAuthorizationAction::Read, StorageAuthorizationAction::Write]).await;
        let file = fixture.file().await;
        let mut socket = fixture.socket(&token, true).await;
        super::send(&mut socket, StorageRequest::Write { path: "committed.txt".into(), content: b"old namespace write".to_vec() }).await;
        gate.reached().await;
        assert_eq!(file.read("committed.txt").await.expect("write completed before reassignment"), b"old namespace write");
        let other = reassign_application(&fixture).await;
        gate.release();
        super::assert_no_response(&mut socket).await;
        let current = storage_server::authorize_storage_token(&fixture.client, &token).await.expect("bearer remains valid after namespace change");
        assert_eq!(current.application_id, other.to_string());
        assert_eq!(current.subject, fixture.scope.user_sub);
        assert!(matches!(tokio_tungstenite::connect_async(fixture.socket_url(&token, false)).await, Err(tokio_tungstenite::tungstenite::Error::Http(ref response)) if response.status() == reqwest::StatusCode::UNAUTHORIZED), "current Application cannot reopen old namespace resource");
        assert_eq!(file.read("committed.txt").await.expect("completed old namespace write retained"), b"old namespace write");
        drop(socket);
        fixture.stop().await;
    }).await.expect("native socket namespace interleaving completes");
}
