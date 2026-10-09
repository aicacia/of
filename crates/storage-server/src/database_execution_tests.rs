use std::sync::Arc;

use idp_model::model::Id;
use iroh::protocol::ProtocolHandler;
use iroh_chain::{EndpointIdStore, Server};
use model::contract::SelectedResource;

use storage_service::DatabaseRuntime;
use tokio_util::sync::CancellationToken;

use super::{AuthorizedTransport, FrameAuthorizer, KvAuthorizedTransport, Namespace, check_apply};
use crate::execution_test_support::{
    DomainNode, Gate, IrohPair, TestDirectory, approved_signers, sql,
};

struct Fixture {
    peers: IrohPair,
    nodes: [DomainNode; 2],
    runtimes: [Arc<DatabaseRuntime>; 2],
    databases: [Arc<ofdb_sql::Database>; 2],
    kv: [Arc<ofdb_kv::Database>; 2],
    resource: SelectedResource,
    _directory: TestDirectory,
}
impl Fixture {
    async fn new() -> Self {
        let directory = TestDirectory::new();
        let peers = IrohPair::new().await;
        let owner = Id::now_v7();
        let devices = [Id::now_v7(), Id::now_v7()];
        let signers = approved_signers(devices);
        let nodes = [
            DomainNode::new(
                directory.0.join("left"),
                owner,
                devices,
                peers.ids(),
                &signers,
            )
            .await,
            DomainNode::new(
                directory.0.join("right"),
                owner,
                devices,
                peers.ids(),
                &signers,
            )
            .await,
        ];
        let scope = Namespace {
            owner_subject: owner.to_string(),
            application_id: Id::now_v7(),
        };
        let left =
            Arc::new(DatabaseRuntime::new(nodes[0].root.join("storage")).expect("left Storage"));
        let right =
            Arc::new(DatabaseRuntime::new(nodes[1].root.join("storage")).expect("right Storage"));
        let (catalog, a) = left.create(&scope, None).expect("actual resource");
        let b = right
            .open_selected(&scope, catalog.id)
            .expect("selected resource")
            .expect("right database");
        let kv = [
            left.open_kv_selected(&scope, catalog.id)
                .expect("left KV")
                .expect("KV"),
            right
                .open_kv_selected(&scope, catalog.id)
                .expect("right KV")
                .expect("KV"),
        ];
        let resource = SelectedResource {
            owner_subject: scope.owner_subject,
            application_id: scope.application_id.to_string(),
            kind: "database".into(),
            resource_id: catalog.id.to_string(),
        };
        for node in &nodes {
            node.select(&resource).await;
        }
        Self {
            peers,
            nodes,
            runtimes: [left, right],
            databases: [a, b],
            kv,
            resource,
            _directory: directory,
        }
    }
    fn authorize(&self, side: usize) -> FrameAuthorizer {
        let owner = self.nodes[side].authorizer();
        let local = self.peers.ids()[side];
        let remote = self.peers.connections[side].remote_id();
        let resource = self.resource.clone();
        Arc::new(move || {
            let owner = owner.clone();
            let resource = resource.clone();
            Box::pin(async move { owner.authorize(local, remote, &resource).await })
        })
    }
    async fn transports(&self) -> [AuthorizedTransport; 2] {
        let [left, right] = self.peers.streams().await;
        [
            AuthorizedTransport {
                transport: left,
                authorize: self.authorize(0),
            },
            AuthorizedTransport {
                transport: right,
                authorize: self.authorize(1),
            },
        ]
    }
    async fn sync_sql(&self, role: ofdb_sql::SyncRole) {
        let [mut source, mut target] = self.transports().await;
        let config = ofdb_sql::SessionConfig::default();
        let (a, b) = tokio::join!(
            self.databases[0].synchronize_with_stage_directory_checked(
                &mut source,
                &config,
                sql_opposite(role),
                self.nodes[0].root.join("staging"),
                || check_apply(self.authorize(0), CancellationToken::new())
            ),
            self.databases[1].synchronize_with_stage_directory_checked(
                &mut target,
                &config,
                role,
                self.nodes[1].root.join("staging"),
                || check_apply(self.authorize(1), CancellationToken::new())
            ),
        );
        a.expect("authorized source SQL sync");
        b.expect("authorized target SQL sync");
    }
    async fn retry_kv(&self, receiver_role: ofdb_kv::SyncRole) {
        let [mut left, mut right] = self.transports().await;
        let config = ofdb_kv::SyncConfig {
            max_snapshots_per_batch: 1,
            ..Default::default()
        };
        let mut left_kv = KvAuthorizedTransport {
            transport: &mut left,
        };
        let mut right_kv = KvAuthorizedTransport {
            transport: &mut right,
        };
        let (a, b) = tokio::join!(
            self.kv[0].synchronize_checked(&mut left_kv, opposite(receiver_role), config, || {
                check_apply(self.authorize(0), CancellationToken::new())
            }),
            self.kv[1].synchronize_checked(&mut right_kv, receiver_role, config, || check_apply(
                self.authorize(1),
                CancellationToken::new()
            )),
        );
        a.expect("authorized source retry");
        b.expect("authorized receiver retry");
    }
}
fn opposite(role: ofdb_kv::SyncRole) -> ofdb_kv::SyncRole {
    match role {
        ofdb_kv::SyncRole::Initiator => ofdb_kv::SyncRole::Responder,
        ofdb_kv::SyncRole::Responder => ofdb_kv::SyncRole::Initiator,
    }
}

fn sql_opposite(role: ofdb_sql::SyncRole) -> ofdb_sql::SyncRole {
    match role {
        ofdb_sql::SyncRole::Initiator => ofdb_sql::SyncRole::Responder,
        ofdb_sql::SyncRole::Responder => ofdb_sql::SyncRole::Initiator,
    }
}
async fn values(database: &ofdb_sql::Database) -> Vec<db::Value> {
    database
        .client()
        .translate_and_execute(
            "SELECT value FROM documents ORDER BY value",
            &db::SqlTranslator,
        )
        .await
        .expect("public SQL observation")[0]
        .rows
        .iter()
        .map(|row| row.values[0].clone())
        .collect()
}

async fn production_session(fixture: &Fixture) -> std::io::Result<()> {
    production_session_claim(fixture, 0, &fixture.resource).await
}

async fn production_session_claim(
    fixture: &Fixture,
    source: usize,
    resource: &SelectedResource,
) -> std::io::Result<()> {
    let (mut send, mut recv) = fixture.peers.connections[source]
        .open_bi()
        .await
        .map_err(std::io::Error::other)?;
    send.write_all(&[crate::data_protocol::DATABASE_STREAM_KIND])
        .await
        .map_err(std::io::Error::other)?;
    super::write_frame(
        &mut send,
        &serde_json::to_vec(&super::DatabaseSyncHandshake {
            resource: super::descriptor(resource),
            deleted: false,
        })
        .map_err(std::io::Error::other)?,
    )
    .await?;
    if super::read_frame(&mut recv, super::MAX_HANDSHAKE_BYTES).await? != b"OK" {
        return Err(std::io::Error::other("DATA handshake denied"));
    }
    let mut transport = AuthorizedTransport {
        transport: crate::DatabaseTransport::new(send, recv),
        authorize: fixture.authorize(source),
    };
    fixture.databases[source]
        .synchronize_with_stage_directory_checked(
            &mut transport,
            &ofdb_sql::SessionConfig::default(),
            ofdb_sql::SyncRole::Initiator,
            fixture.nodes[source].root.join("staging"),
            || check_apply(fixture.authorize(source), CancellationToken::new()),
        )
        .await
        .map_err(super::sql_sync_error)?;
    fixture.kv[source]
        .synchronize_checked(
            &mut KvAuthorizedTransport {
                transport: &mut transport,
            },
            ofdb_kv::SyncRole::Initiator,
            ofdb_kv::SyncConfig::default(),
            || check_apply(fixture.authorize(source), CancellationToken::new()),
        )
        .await
        .map_err(super::kv_sync_error)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_production_data_handler_uses_injected_local_policy_on_existing_connection() {
    tokio::time::timeout(std::time::Duration::from_secs(240), async {
        let fixture = Fixture::new().await;
        let peers = EndpointIdStore::default(); peers.add(fixture.peers.ids()[0]);
        let server = Server::new(fixture.peers.endpoints[1].clone(), peers);
        let management = crate::ManagementClient::new("http://127.0.0.1:9/management", "http://127.0.0.1:9/idp", "storage", "isolated-test-secret", "https://of03-installation.example", "https://management.example").expect("remote endpoints intentionally unavailable").with_local_replication_authorizer(fixture.nodes[1].authorizer());
        let cancellation = CancellationToken::new();
        let database = super::DatabaseProtocolHandler::new(server.clone(), management.clone(), fixture.runtimes[1].clone(), fixture.nodes[1].root.join("staging"), cancellation.clone());
        let filesystem = crate::storage_protocol::StorageProtocolHandler::new(server, management, Arc::new(storage_service::ScopedFileSystemRuntime::new(fixture.nodes[1].root.join("unused-filesystems"), fixture.peers.ids()[1]).expect("filesystem runtime")), cancellation.clone());
        let handler = crate::DataProtocolHandler::new(database, filesystem, cancellation.clone());
        let connection = fixture.peers.connections[1].clone();
        let task = tokio::spawn(async move { handler.accept(connection).await });
        sql(&fixture.databases[0], &format!("CREATE TABLE documents (id UUID PRIMARY KEY, value TEXT); INSERT INTO documents VALUES (CAST('{}' AS UUID), 'kept')", Id::now_v7())).await;
        eprintln!("DATA: first selected session");
        production_session(&fixture).await.expect("actual handler allows locally selected resource without remote authority");
        eprintln!("DATA: initial SQL/KV session completed");
        fixture.nodes[1].restrict(0, false).await;
        sql(&fixture.databases[0], &format!("INSERT INTO documents VALUES (CAST('{}' AS UUID), 'denied')", Id::now_v7())).await;
        assert!(production_session(&fixture).await.is_err(), "actual handler rejects the next stream on its already-open connection");
        assert_eq!(values(&fixture.databases[1]).await, [db::Value::Text("kept".into())]);
        fixture.nodes[1].restrict(0, true).await;
        eprintln!("DATA: restriction denied; retrying");
        production_session(&fixture).await.expect("same connection retries when local policy permits");
        assert_eq!(values(&fixture.databases[0]).await, values(&fixture.databases[1]).await);
        cancellation.cancel(); task.await.expect("DATA handler joins").expect("clean handler shutdown");
        fixture.peers.close().await;
    }).await.expect("production DATA callback integration completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_production_database_retirement_denies_existing_connection_with_selection_still_allowed()
 {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let fixture = Fixture::new().await;
        let peers = EndpointIdStore::default();
        peers.add(fixture.peers.ids()[0]);
        let server = Server::new(fixture.peers.endpoints[1].clone(), peers);
        let management = crate::ManagementClient::new(
            "http://127.0.0.1:9/management",
            "http://127.0.0.1:9/idp",
            "storage",
            "isolated-test-secret",
            "https://of03-installation.example",
            "https://management.example",
        )
        .expect("unreachable remote owners")
        .with_local_replication_authorizer(fixture.nodes[1].authorizer());
        let cancellation = CancellationToken::new();
        let database = super::DatabaseProtocolHandler::new(
            server.clone(),
            management.clone(),
            fixture.runtimes[1].clone(),
            fixture.nodes[1].root.join("staging"),
            cancellation.clone(),
        );
        let filesystem = crate::storage_protocol::StorageProtocolHandler::new(
            server,
            management,
            Arc::new(
                storage_service::ScopedFileSystemRuntime::new(
                    fixture.nodes[1].root.join("unused-filesystems"),
                    fixture.peers.ids()[1],
                )
                .expect("filesystem runtime"),
            ),
            cancellation.clone(),
        );
        let handler = crate::DataProtocolHandler::new(database, filesystem, cancellation.clone());
        let connection = fixture.peers.connections[1].clone();
        let task = tokio::spawn(async move { handler.accept(connection).await });
        let scope = Namespace {
            owner_subject: fixture.resource.owner_subject.clone(),
            application_id: fixture
                .resource
                .application_id
                .parse()
                .expect("Application"),
        };
        let id = fixture.resource.resource_id.parse().expect("resource ID");
        let before = fixture.databases[0]
            .sync_manifest()
            .await
            .expect("source state");
        assert!(
            fixture.nodes[1]
                .authorizer()
                .authorize(
                    fixture.peers.ids()[1],
                    fixture.peers.ids()[0],
                    &fixture.resource
                )
                .await
        );
        assert_eq!(
            fixture.runtimes[1]
                .remove_local_copy(&scope, id)
                .expect_err("missing owner capability")
                .kind(),
            std::io::ErrorKind::Unsupported
        );
        assert!(
            production_session(&fixture).await.is_err(),
            "pending cleanup denies DATA even with unchanged allowed selections"
        );
        assert_eq!(
            fixture.databases[0]
                .sync_manifest()
                .await
                .expect("source retained"),
            before
        );
        assert!(
            !fixture.runtimes[1]
                .is_tombstoned(&scope, id)
                .expect("catalog survives")
        );
        cancellation.cancel();
        task.await.expect("DATA task").expect("shutdown");
        fixture.peers.close().await;
    })
    .await
    .expect("bounded retirement integration");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_production_database_admission_checks_identity_both_selections_and_local_failure() {
    tokio::time::timeout(std::time::Duration::from_secs(600), async {
        let started = std::time::Instant::now();
        for receiver in 0..2 {
            let fixture = Fixture::new().await;
            let source = 1 - receiver;
            sql(&fixture.databases[source], &format!("CREATE TABLE documents (id UUID PRIMARY KEY, value TEXT); INSERT INTO documents VALUES (CAST('{}' AS UUID), 'retained')", Id::now_v7())).await;
            fixture.kv[source].client().set("retained", ofdb_kv::Value::Integer(1), None).await.expect("native KV source");
            eprintln!("admission receiver {receiver}: initialized {:?}", started.elapsed());
            let peers = EndpointIdStore::default(); peers.add(fixture.peers.ids()[source]);
            let server = Server::new(fixture.peers.endpoints[receiver].clone(), peers);
            assert!(server.peers().ids().contains(&fixture.peers.ids()[source]));
            let management = crate::ManagementClient::new("http://127.0.0.1:9/management", "http://127.0.0.1:9/idp", "storage", "isolated-secret", "https://of03-installation.example", "management").expect("independent remote services unavailable").with_local_replication_authorizer(fixture.nodes[receiver].authorizer());
            let cancellation = CancellationToken::new();
            let database = super::DatabaseProtocolHandler::new(server.clone(), management.clone(), fixture.runtimes[receiver].clone(), fixture.nodes[receiver].root.join("staging"), cancellation.clone());
            let filesystem = crate::storage_protocol::StorageProtocolHandler::new(server, management, Arc::new(storage_service::ScopedFileSystemRuntime::new(fixture.nodes[receiver].root.join("unused-files"), fixture.peers.ids()[receiver]).expect("filesystem runtime")), cancellation.clone());
            let handler = crate::DataProtocolHandler::new(database, filesystem, cancellation.clone());
            let connection = fixture.peers.connections[receiver].clone();
            let task = tokio::spawn(async move { handler.accept(connection).await });

            production_session_claim(&fixture, source, &fixture.resource).await.expect("current native state permits SQL/KV with remote HTTP services unreachable");
            eprintln!("admission receiver {receiver}: positive {:?}", started.elapsed());
            for field in 0..3 {
                let mut claimed = fixture.resource.clone();
                match field { 0 => claimed.owner_subject = Id::now_v7().to_string(), 1 => claimed.application_id = Id::now_v7().to_string(), _ => claimed.resource_id = Id::now_v7().to_string() }
                assert!(production_session_claim(&fixture, source, &claimed).await.is_err(), "forged namespace/target claim cannot replace local evidence");
            }
            for device in 0..2 {
                let node = &fixture.nodes[receiver];
                assert!(management_service::replica::DbSelectionPolicyRepo::new(node.management.clone()).deselect_resource_owned(node.devices[device], &fixture.resource.owner_subject, fixture.resource.application_id.parse().expect("Application"), "database", fixture.resource.resource_id.parse().expect("database ID")).await.expect("real local deselection"));
                assert!(production_session_claim(&fixture, source, &fixture.resource).await.is_err(), "allowlisted authenticated peer requires BOTH current selections");
                node.select(&fixture.resource).await;
                node.restrict(device, false).await;
                assert!(production_session_claim(&fixture, source, &fixture.resource).await.is_err(), "both independently learned Device restrictions deny");
                node.restrict(device, true).await;
            }
            eprintln!("admission receiver {receiver}: namespace/selections/restrictions denied {:?}", started.elapsed());
            let device = fixture.nodes[receiver].devices[source];
            let forged_endpoint = iroh::SecretKey::generate().public();
            sql(&fixture.nodes[receiver].idp, &format!("UPDATE devices SET public_key = '{forged_endpoint}' WHERE id = CAST('{device}' AS UUID)")).await;
            assert!(production_session_claim(&fixture, source, &fixture.resource).await.is_err(), "actual Connection remote_id cannot impersonate another approved endpoint");
            sql(&fixture.nodes[receiver].idp, &format!("UPDATE devices SET public_key = '{}' WHERE id = CAST('{device}' AS UUID)", fixture.peers.ids()[source])).await;
            production_session_claim(&fixture, source, &fixture.resource).await.expect("restored exact local binding permits existing-connection retry");
            eprintln!("admission receiver {receiver}: identity restoration {:?}", started.elapsed());
            sql(&fixture.nodes[receiver].management, "DROP TABLE device_resource_selections").await;
            assert!(production_session_claim(&fixture, source, &fixture.resource).await.is_err(), "failed LOCAL evaluation denies instead of falling back to unreachable HTTP");
            assert_eq!(values(&fixture.databases[receiver]).await, [db::Value::Text("retained".into())]);
            assert_eq!(fixture.kv[receiver].client().scan_all().await.expect("KV retained"), vec![("retained".into(), ofdb_kv::Value::Integer(1))]);
            cancellation.cancel(); task.await.expect("production handler joins").expect("clean shutdown");
            fixture.peers.close().await;
            eprintln!("admission receiver {receiver}: local failure preserved stores {:?}", started.elapsed());
        }
    }).await.expect("real production admission cases complete");
}

struct QueuedPayload {
    transport: AuthorizedTransport,
    gate: Gate,
    sends: usize,
    paused: bool,
}
impl ofdb_sql::SyncTransport for QueuedPayload {
    type Error = std::io::Error;
    async fn receive(&mut self) -> std::io::Result<Vec<u8>> {
        ofdb_sql::SyncTransport::receive(&mut self.transport).await
    }
    async fn send(&mut self, frame: Vec<u8>) -> std::io::Result<()> {
        let message =
            postcard::from_bytes::<ofdb_sql::SyncMessage>(&frame).expect("actual owner SQL frame");
        if !self.paused
            && matches!(message, ofdb_sql::SyncMessage::State(ref rows) if !rows.is_empty())
        {
            self.paused = true;
            self.gate.pause().await;
        }
        ofdb_sql::SyncTransport::send(&mut self.transport, frame).await
    }
}
impl ofdb_kv::SyncTransport for QueuedPayload {
    type Error = std::io::Error;
    async fn receive(&mut self) -> std::io::Result<Vec<u8>> {
        ofdb_sql::SyncTransport::receive(&mut self.transport).await
    }
    async fn send(&mut self, frame: Vec<u8>) -> std::io::Result<()> {
        self.sends += 1;
        // With one native source key, owner KV v2 sends Hello then its snapshot batch in both roles.
        if self.sends == 2 {
            self.gate.pause().await;
        }
        ofdb_sql::SyncTransport::send(&mut self.transport, frame).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_sql_and_kv_queued_payloads_recheck_native_sender_policy_on_both_peers() {
    tokio::time::timeout(std::time::Duration::from_secs(600), async {
        for kv in [false, true] {
            for sender in 0..2 {
                let receiver = 1 - sender;
                let fixture = Fixture::new().await;
                if kv {
                    fixture.kv[sender].client().set("source", ofdb_kv::Value::Integer(7), None).await.expect("native source payload");
                } else {
                    sql(&fixture.databases[sender], &format!("CREATE TABLE documents (id UUID PRIMARY KEY, value TEXT); INSERT INTO documents VALUES (CAST('{}' AS UUID), 'source')", Id::now_v7())).await;
                }
                let manifest = fixture.databases[receiver].sync_manifest().await.expect("recipient baseline");
                let [left, right] = fixture.transports().await;
                let (source, mut target) = if sender == 0 { (left, right) } else { (right, left) };
                let gate = Gate::default();
                let mut source = QueuedPayload { transport: source, gate: gate.clone(), sends: 0, paused: false };
                let mut run = Box::pin(async {
                    if kv {
                        let source_role = if sender == 0 { ofdb_kv::SyncRole::Initiator } else { ofdb_kv::SyncRole::Responder };
                        let (a, b) = tokio::join!(
                            async { let result = fixture.kv[sender].synchronize_checked(&mut source, source_role, ofdb_kv::SyncConfig::default(), || check_apply(fixture.authorize(sender), CancellationToken::new())).await; drop(source); result },
                            async { let result = fixture.kv[receiver].synchronize_checked(&mut KvAuthorizedTransport { transport: &mut target }, opposite(source_role), ofdb_kv::SyncConfig::default(), || check_apply(fixture.authorize(receiver), CancellationToken::new())).await; drop(target); result },
                        );
                        assert!(matches!(a, Err(ofdb_kv::SyncError::Transport(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied), "native sender denies its already-prepared KV payload: {a:?}");
                        assert!(b.is_err());
                    } else {
                        let source_role = if sender == 0 { ofdb_sql::SyncRole::Initiator } else { ofdb_sql::SyncRole::Responder };
                        let config = ofdb_sql::SessionConfig::default();
                        let (a, b) = tokio::join!(
                            async { let result = fixture.databases[sender].synchronize_with_stage_directory_checked(&mut source, &config, source_role, fixture.nodes[sender].root.join("staging"), || check_apply(fixture.authorize(sender), CancellationToken::new())).await; drop(source); result },
                            async { let result = fixture.databases[receiver].synchronize_with_stage_directory_checked(&mut target, &config, sql_opposite(source_role), fixture.nodes[receiver].root.join("staging"), || check_apply(fixture.authorize(receiver), CancellationToken::new())).await; drop(target); result },
                        );
                        assert!(matches!(a, Err(ofdb_sql::SyncError::Transport(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied), "native sender denies its already-prepared SQL payload: {a:?}");
                        assert!(b.is_err());
                    }
                });
                tokio::select! { () = gate.reached() => {}, () = &mut run => panic!("actual owner payload did not reach queued send gate") }
                assert_eq!(fixture.databases[receiver].sync_manifest().await.expect("no SQL import before release"), manifest);
                assert!(fixture.kv[receiver].client().scan_all().await.expect("no KV import before release").is_empty());
                fixture.nodes[sender].restrict(if kv { sender } else { receiver }, false).await;
                assert!(fixture.authorize(receiver)().await, "independent recipient still permits its own local view");
                gate.release(); run.await;
                assert_eq!(fixture.databases[receiver].sync_manifest().await.expect("denied SQL payload absent"), manifest);
                assert!(fixture.kv[receiver].client().scan_all().await.expect("denied KV payload absent").is_empty());
                fixture.nodes[sender].restrict(if kv { sender } else { receiver }, true).await;
                if kv {
                    assert_eq!(fixture.kv[sender].client().scan_all().await.expect("source retained"), vec![("source".into(), ofdb_kv::Value::Integer(7))]);
                    fixture.retry_kv(ofdb_kv::SyncRole::Responder).await;
                    assert_eq!(fixture.kv[sender].client().scan_all().await.expect("source"), fixture.kv[receiver].client().scan_all().await.expect("same-connection retry"));
                } else {
                    assert_eq!(values(&fixture.databases[sender]).await, [db::Value::Text("source".into())]);
                    fixture.sync_sql(ofdb_sql::SyncRole::Responder).await;
                    assert_eq!(values(&fixture.databases[sender]).await, values(&fixture.databases[receiver]).await);
                }
                eprintln!("native queued payload denial and retry: KV={kv}, sender={sender}");
                fixture.peers.close().await;
            }
        }
    }).await.expect("native queued SQL/KV payload tests complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_identity_namespace_and_local_evaluation_failures_deny() {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let fixture = Fixture::new().await;
        let authorizer = fixture.nodes[1].authorizer();
        let [remote, local] = fixture.peers.ids();
        assert!(authorizer.authorize(local, remote, &fixture.resource).await);
        for field in 0..4 {
            let mut forged = fixture.resource.clone();
            match field {
                0 => forged.owner_subject = Id::now_v7().to_string(),
                1 => forged.application_id = Id::now_v7().to_string(),
                2 => forged.resource_id = Id::now_v7().to_string(),
                _ => forged.kind = "filesystem".into(),
            }
            assert!(
                !authorizer.authorize(local, remote, &forged).await,
                "exact persisted owner/Application/kind/ID required"
            );
        }
        assert!(
            !authorizer
                .authorize(
                    local,
                    iroh::SecretKey::generate().public(),
                    &fixture.resource
                )
                .await,
            "unapproved/pairing-only endpoint has no selected resource access"
        );
        fixture.nodes[1].revoke_signer(0).await;
        assert!(
            !authorizer.authorize(local, remote, &fixture.resource).await,
            "approved Device alone is not signer-backed Installation membership"
        );
        sql(
            &fixture.nodes[0].management,
            "DROP TABLE device_resource_selections",
        )
        .await;
        assert!(
            fixture.nodes[0]
                .authorizer()
                .selected_resources(remote)
                .await
                .is_err(),
            "failed genuine local policy evaluation propagates"
        );
        assert!(
            !fixture.authorize(0)().await,
            "local policy failure denies execution"
        );
        fixture.peers.close().await;
    })
    .await
    .expect("native identity and policy-failure test completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_sql_denies_received_apply_and_retries_on_existing_connection() {
    tokio::time::timeout(std::time::Duration::from_secs(600), async {
        let started = std::time::Instant::now();
        for (device, role) in [ofdb_sql::SyncRole::Initiator, ofdb_sql::SyncRole::Responder].into_iter().enumerate() {
            let mut fixture = Fixture::new().await;
            eprintln!("SQL {role:?}: initialized {:?}", started.elapsed());
            let kept = Id::now_v7(); let denied = Id::now_v7();
            sql(&fixture.databases[0], &format!("CREATE TABLE documents (id UUID PRIMARY KEY, value TEXT); INSERT INTO documents VALUES (CAST('{kept}' AS UUID), 'kept')")).await;
            fixture.sync_sql(role).await;
            eprintln!("SQL {role:?}: baseline synchronized {:?}", started.elapsed());
            sql(&fixture.databases[0], &format!("INSERT INTO documents VALUES (CAST('{denied}' AS UUID), 'denied')")).await;
            let [mut source, mut target] = fixture.transports().await;
            let gate = Gate::default(); let hook_gate = gate.clone();
            let authorize = fixture.authorize(1);
            let config = ofdb_sql::SessionConfig::default();
            let mut calls = 0;
            let mut run = Box::pin(async {
                tokio::join!(
                    async {
                        let result = fixture.databases[0].synchronize_with_stage_directory_checked(&mut source, &config, sql_opposite(role), fixture.nodes[0].root.join("staging"), || check_apply(fixture.authorize(0), CancellationToken::new())).await;
                        drop(source); result
                    },
                    async {
                        let result = fixture.databases[1].synchronize_with_stage_directory_checked(&mut target, &config, role, fixture.nodes[1].root.join("staging"), || {
                            calls += 1; let pause = calls == 1; let gate = hook_gate.clone(); let authorize = authorize.clone();
                            async move { if pause { gate.pause().await; } check_apply(authorize, CancellationToken::new()).await }
                        }).await;
                        drop(target); result
                    },
                )
            });
            tokio::select! { result = &mut run => panic!("SQL ended before actual apply gate: {result:?}"), () = gate.reached() => {} }
            assert_eq!(values(&fixture.databases[1]).await, [db::Value::Text("kept".into())]);
            fixture.nodes[1].restrict(device, false).await;
            gate.release();
            let (_, result) = run.await;
            assert!(matches!(result, Err(ofdb_sql::SyncError::PreApply(_))), "actual selected SQL apply denied: {result:?}");
            assert_eq!(values(&fixture.databases[1]).await, [db::Value::Text("kept".into())]);
            assert_eq!(values(&fixture.databases[0]).await, [db::Value::Text("denied".into()), db::Value::Text("kept".into())]);
            fixture.nodes[1].restrict(device, true).await;
            fixture.sync_sql(role).await;
            assert_eq!(values(&fixture.databases[0]).await, values(&fixture.databases[1]).await);
            eprintln!("SQL {role:?}: same-connection retry completed {:?}; reconnecting", started.elapsed());
            fixture.peers.reconnect().await;
            fixture.sync_sql(role).await;
            eprintln!("SQL {role:?}: new-connection retry completed {:?}", started.elapsed());
            assert_eq!(values(&fixture.databases[0]).await, values(&fixture.databases[1]).await);
            fixture.peers.close().await;
        }
    }).await.expect("SQL domain acceptance completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_kv_first_commit_survives_learned_denial_and_same_connection_retry() {
    tokio::time::timeout(std::time::Duration::from_secs(600), async {
        for role in [ofdb_kv::SyncRole::Initiator, ofdb_kv::SyncRole::Responder] {
            for device in 0..2 {
                eprintln!("KV case {role:?} Device {device}: setup");
                let mut fixture = Fixture::new().await;
                for (key, value) in [("a", 1), ("b", 2), ("c", 3)] { fixture.kv[0].client().set(key, ofdb_kv::Value::Integer(value), None).await.expect("source write"); }
                let config = ofdb_kv::SyncConfig { max_snapshots_per_batch: 1, ..Default::default() };
                let [mut source, mut target] = fixture.transports().await;
                let gate = Gate::default();
                let hook_gate = gate.clone();
                let target_authorize = fixture.authorize(1);
                let mut calls = 0;
                let mut run = Box::pin(async {
                    tokio::join!(
                        async {
                            let mut source_kv = KvAuthorizedTransport { transport: &mut source };
                            let result = fixture.kv[0].synchronize_checked(&mut source_kv, opposite(role), config, || check_apply(fixture.authorize(0), CancellationToken::new())).await;
                            drop(source_kv); drop(source); result
                        },
                        async {
                        let mut target_kv = KvAuthorizedTransport { transport: &mut target };
                        let result = fixture.kv[1].synchronize_checked(&mut target_kv, role, config, || {
                            calls += 1;
                            let pause = calls == 2;
                            let gate = hook_gate.clone(); let authorize = target_authorize.clone();
                            async move { if pause { gate.pause().await; } check_apply(authorize, CancellationToken::new()).await }
                        }).await;
                        drop(target_kv); drop(target); result
                        },
                    )
                });
                tokio::select! { result = &mut run => panic!("session ended before second apply gate: {result:?}"), () = gate.reached() => {} }
                assert_eq!(fixture.kv[1].client().scan_all().await.expect("observe committed first batch before learning denial"), vec![("a".into(), ofdb_kv::Value::Integer(1))]);
                eprintln!("KV: first commit observed, learning denial");
                fixture.nodes[1].restrict(device, false).await;
                assert!(fixture.authorize(0)().await, "independent source Node still has its earlier locally trusted view");
                gate.release();
                let (_, result) = run.await;
                eprintln!("KV: denied session ended: {result:?}");
                assert!(matches!(result, Err(ofdb_kv::SyncError::PreApply(_))), "later owner apply must deny: {result:?}");
                assert_eq!(fixture.kv[1].client().scan_all().await.expect("retained first batch"), vec![("a".into(), ofdb_kv::Value::Integer(1))]);
                assert_eq!(fixture.kv[0].client().scan_all().await.expect("source preserved").len(), 3);

                fixture.nodes[1].restrict(device, true).await;
                eprintln!("KV: retrying on existing connection");
                fixture.retry_kv(role).await;
                eprintln!("KV: retry completed");
                assert_eq!(fixture.kv[0].client().scan_all().await.expect("source"), fixture.kv[1].client().scan_all().await.expect("retry converges"));
                assert_eq!(fixture.peers.connections[1].remote_id(), fixture.peers.ids()[0]);
                if device == 0 && matches!(role, ofdb_kv::SyncRole::Responder) {
                    fixture.peers.reconnect().await;
                    fixture.retry_kv(role).await;
                    assert_eq!(fixture.kv[0].client().scan_all().await.expect("source after reconnect"), fixture.kv[1].client().scan_all().await.expect("new authenticated connection converges"));
                }
                fixture.peers.close().await;
            }
        }
    }).await.expect("deterministic KV acceptance completes");
}
