use std::sync::{Arc, OnceLock};

use idp_model::contract::{GrantType, TokenEndpointAuthMethod};
use idp_service::repo::ClientRepo;
use management_service::replica::{DbSelectionPolicyRepo, SelectionPolicy};
use model::contract::StorageAuthorizationAction;
use storage_server::{RouterState, StorageCopyRetirement, openapi_router, resource_router};
use storage_service::ScopedFileSystemRuntime;

use super::{Fixture, Gate, Listener};

async fn start_storage(fixture: &mut Fixture) -> Arc<OnceLock<StorageCopyRetirement>> {
    fixture.storage_listener.stop().await;
    let copies = Arc::new(OnceLock::new());
    assert!(
        copies
            .set(StorageCopyRetirement::new(
                fixture.databases.clone(),
                fixture.files.clone()
            ))
            .is_ok()
    );
    let policy = crate::runtime::owner_replication_authorizer(
        fixture.runtime.clone(),
        fixture.management.clone(),
        fixture.identity.endpoint().id(),
        copies.clone(),
    );
    let state = RouterState::new("https://storage.test").with_idp_client(
        fixture
            .client
            .clone()
            .with_local_device_policy(fixture.identity.endpoint().id(), policy),
    );
    fixture.storage_listener = Listener::start(
        openapi_router(state.clone(), "/storage")
            .split_for_parts()
            .0
            .merge(resource_router(
                state,
                Some(fixture.databases.clone()),
                Some(fixture.files.clone()),
            )),
    )
    .await;
    copies
}

async fn ready_fixture() -> (Fixture, Arc<OnceLock<StorageCopyRetirement>>) {
    ready_fixture_with_gate(None).await
}

async fn ready_fixture_with_gate(
    gate: Option<Gate>,
) -> (Fixture, Arc<OnceLock<StorageCopyRetirement>>) {
    let mut fixture = Fixture::with_catalog_gate(Gate::default(), gate).await;
    DbSelectionPolicyRepo::new(fixture.management.clone())
        .set_prevalidated(SelectionPolicy {
            device_id: fixture.device.device_id,
            owner_subject: fixture.owner.to_string(),
            application_id: None,
            selected_kind: None,
            selected_id: None,
            admin_allowed: true,
        })
        .await
        .expect("trusted current local Device policy");
    let copies = start_storage(&mut fixture).await;
    (fixture, copies)
}

fn url(fixture: &Fixture) -> String {
    format!(
        "{}/storage/filesystems/{}/residency",
        fixture.storage_listener.base,
        fixture.resource.as_uuid()
    )
}

async fn put(fixture: &Fixture, token: &str, mode: &str) -> reqwest::Response {
    fixture
        .http
        .put(url(fixture))
        .bearer_auth(token)
        .json(&serde_json::json!({"mode": mode}))
        .send()
        .await
        .expect("public Storage Residency request")
}

#[tokio::test]
async fn authorized_whole_filesystem_residency_uses_public_storage_owner() {
    let (fixture, _copies) = ready_fixture().await;
    let token = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Write],
        )
        .await;
    assert_eq!(
        put(&fixture, &token, "passthrough").await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        fixture
            .file()
            .await
            .residency("")
            .expect("whole-resource mode"),
        file_system::Residency::Passthrough
    );
    let response = fixture
        .http
        .get(format!(
            "{}/storage/openapi.json",
            fixture.storage_listener.base
        ))
        .send()
        .await
        .expect("live composed Storage OpenAPI");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let document: serde_json::Value = response.json().await.expect("live Storage contract");
    assert!(
        document["paths"]
            .as_object()
            .expect("OpenAPI paths")
            .keys()
            .all(|path| path.starts_with('/')),
        "prefixed owner contract must retain valid OpenAPI paths"
    );
    let route = &document["paths"]["/filesystems/{filesystem_id}/residency"];
    assert_eq!(route["get"]["operationId"], "get_file_system_residency");
    assert_eq!(route["put"]["operationId"], "put_file_system_residency");
    assert_eq!(
        document["servers"][0]["url"],
        "https://storage.test/storage"
    );
    assert!(
        document["paths"]
            .get("/storage/filesystems/{filesystem_id}/residency")
            .is_none()
    );
    if let Some(directory) = std::env::var_os("OF04_RESIDENCY_OUTPUT") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::write(
            directory.join("storage-openapi.json"),
            serde_json::to_vec_pretty(&document).expect("serialize live contract"),
        )
        .expect("save live owner contract");
        std::fs::write(
            directory.join("listener.txt"),
            format!(
                "{}\nGET /storage/openapi.json\n",
                fixture.storage_listener.base
            ),
        )
        .expect("save actual listener source");
    }
    fixture.stop().await;
}

#[tokio::test]
async fn public_residency_read_reports_durable_mode_after_native_reopen() {
    let (mut fixture, copies) = ready_fixture().await;
    let token = fixture
        .token(
            "storage:filesystems",
            vec![
                StorageAuthorizationAction::Read,
                StorageAuthorizationAction::Write,
            ],
        )
        .await;
    assert_eq!(
        put(&fixture, &token, "passthrough").await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    fixture.storage_listener.stop().await;
    drop(copies);
    fixture.files = Arc::new(
        ScopedFileSystemRuntime::new(
            fixture._directory.0.join("files"),
            fixture.identity.endpoint().id(),
        )
        .expect("native Storage reopen"),
    );
    let _copies = start_storage(&mut fixture).await;
    let response = fixture
        .http
        .get(url(&fixture))
        .bearer_auth(&token)
        .send()
        .await
        .expect("authorized public mode read");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .json::<serde_json::Value>()
            .await
            .expect("current Residency"),
        serde_json::json!({"mode": "passthrough"})
    );
    assert_eq!(
        put(&fixture, &token, "full").await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        fixture.file().await.residency("").expect("restored Full"),
        file_system::Residency::Full
    );
    fixture.stop().await;
}

#[tokio::test]
async fn residency_denials_preserve_mode_and_cleanup_fences() {
    let (fixture, _copies) = ready_fixture().await;
    let read = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Read],
        )
        .await;
    assert_eq!(
        put(&fixture, &read, "passthrough").await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let write = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Write],
        )
        .await;
    assert_eq!(
        fixture
            .http
            .get(url(&fixture))
            .bearer_auth(&write)
            .send()
            .await
            .expect("write-only GET")
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        put(&fixture, "invalid-token", "passthrough").await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let wrong_kind = fixture
        .token("storage:databases", vec![StorageAuthorizationAction::Write])
        .await;
    assert_eq!(
        put(&fixture, &wrong_kind, "passthrough").await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let unknown = format!(
        "{}/storage/filesystems/{}/residency",
        fixture.storage_listener.base,
        idp_model::model::Id::now_v7()
    );
    assert_eq!(
        fixture
            .http
            .put(unknown)
            .bearer_auth(&write)
            .json(&serde_json::json!({"mode":"passthrough"}))
            .send()
            .await
            .expect("unknown target")
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    fixture
        .clients
        .create_client(super::registration(
            "other-application",
            vec![GrantType::Password, GrantType::TokenExchange],
            vec!["openid".into()],
            vec!["storage:filesystems".into()],
            TokenEndpointAuthMethod::ClientSecretBasic,
        ))
        .await
        .expect("real second Application client");
    let other_application = fixture
        .token_for_client(
            "storage:filesystems",
            vec![
                StorageAuthorizationAction::Read,
                StorageAuthorizationAction::Write,
            ],
            "other-application",
        )
        .await;
    assert_eq!(
        put(&fixture, &other_application, "passthrough")
            .await
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture
            .http
            .get(url(&fixture))
            .bearer_auth(&other_application)
            .send()
            .await
            .expect("wrong-Application read")
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    for body in [
        serde_json::json!({"mode":"invalid"}),
        serde_json::json!({"mode":"passthrough", "path":"/"}),
    ] {
        assert_eq!(
            fixture
                .http
                .put(url(&fixture))
                .bearer_auth(&write)
                .json(&body)
                .send()
                .await
                .expect("malformed mode request")
                .status(),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    assert_eq!(
        fixture
            .file()
            .await
            .residency("")
            .expect("denials preserve Full"),
        file_system::Residency::Full
    );
    fixture
        .files
        .remove_local_copy(&fixture.scope, fixture.resource)
        .await
        .expect("owner local-copy retirement");
    assert_eq!(
        put(&fixture, &write, "full").await.status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .http
            .get(url(&fixture))
            .bearer_auth(&read)
            .send()
            .await
            .expect("retired read")
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    assert!(
        fixture
            .files
            .open_resource(&fixture.scope, fixture.resource)
            .await
            .is_err(),
        "mode controls cannot reactivate retired copy"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn residency_rechecks_learned_user_denial_before_owner_mutation() {
    let gate = Gate::default();
    let (fixture, _copies) = ready_fixture_with_gate(Some(gate.clone())).await;
    let token = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Write],
        )
        .await;
    let pending = fixture
        .http
        .put(url(&fixture))
        .bearer_auth(token)
        .json(&serde_json::json!({"mode":"passthrough"}));
    let request =
        tokio::spawn(async move { pending.send().await.expect("paused public mutation") });
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.reached())
        .await
        .expect("mutation reaches execution authorization");
    fixture.revoke_user().await;
    gate.release();
    assert_eq!(
        request.await.expect("mutation task").status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .file()
            .await
            .residency("")
            .expect("denied mode preserved"),
        file_system::Residency::Full
    );
    fixture.stop().await;
}

#[tokio::test]
async fn residency_rechecks_deleted_target_before_owner_mutation() {
    let gate = Gate::default();
    let (fixture, _copies) = ready_fixture_with_gate(Some(gate.clone())).await;
    let token = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Write],
        )
        .await;
    let pending = fixture
        .http
        .put(url(&fixture))
        .bearer_auth(token)
        .json(&serde_json::json!({"mode":"passthrough"}));
    let request =
        tokio::spawn(async move { pending.send().await.expect("paused public mutation") });
    tokio::time::timeout(std::time::Duration::from_secs(30), gate.reached())
        .await
        .expect("execution check reached");
    assert!(
        fixture
            .files
            .delete_resource(&fixture.scope, fixture.resource)
            .await
            .expect("learned exact target deletion")
    );
    gate.release();
    assert_eq!(
        request.await.expect("mutation task").status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert!(
        fixture
            .files
            .is_tombstoned(&fixture.scope, fixture.resource)
            .await
            .expect("Tombstone survives denial")
    );
    fixture.stop().await;
}

#[tokio::test]
async fn residency_owner_write_failure_preserves_prior_policy_and_content() {
    let (fixture, _copies) = ready_fixture().await;
    let token = fixture
        .token(
            "storage:filesystems",
            vec![StorageAuthorizationAction::Write],
        )
        .await;
    fixture
        .file()
        .await
        .write("retained.txt", b"retained content")
        .await
        .expect("existing local Full content");
    assert_eq!(
        put(&fixture, &token, "full").await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    let policy = fixture
        ._directory
        .0
        .join("files/filesystem-local-copies.json");
    let bytes = std::fs::read(&policy).expect("persisted owner policy");
    let temporary = policy.with_extension("tmp");
    std::fs::create_dir(&temporary).expect("inject publication failure without changing policy");
    assert_eq!(
        put(&fixture, &token, "passthrough").await.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        std::fs::read(&policy).expect("prior policy survives"),
        bytes
    );
    assert_eq!(
        fixture
            .file()
            .await
            .read("retained.txt")
            .await
            .expect("content survives failure"),
        b"retained content"
    );
    std::fs::remove_dir(&temporary).expect("remove own failure injection");
    assert_eq!(
        put(&fixture, &token, "passthrough").await.status(),
        reqwest::StatusCode::NO_CONTENT
    );
    fixture.stop().await;
}
