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
    let (mut send, mut recv) = fixture.peers.connections[0]
        .open_bi()
        .await
        .map_err(std::io::Error::other)?;
    send.write_all(&[crate::data_protocol::DATABASE_STREAM_KIND])
        .await
        .map_err(std::io::Error::other)?;
    super::write_frame(
        &mut send,
        &serde_json::to_vec(&super::DatabaseSyncHandshake {
            resource: super::descriptor(&fixture.resource),
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
        authorize: fixture.authorize(0),
    };
    fixture.databases[0]
        .synchronize_with_stage_directory_checked(
            &mut transport,
            &ofdb_sql::SessionConfig::default(),
            ofdb_sql::SyncRole::Initiator,
            fixture.nodes[0].root.join("staging"),
            || check_apply(fixture.authorize(0), CancellationToken::new()),
        )
        .await
        .map_err(super::sql_sync_error)?;
    fixture.kv[0]
        .synchronize_checked(
            &mut KvAuthorizedTransport {
                transport: &mut transport,
            },
            ofdb_kv::SyncRole::Initiator,
            ofdb_kv::SyncConfig::default(),
            || check_apply(fixture.authorize(0), CancellationToken::new()),
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
    tokio::time::timeout(std::time::Duration::from_secs(300), async {
        for (device, role) in [ofdb_sql::SyncRole::Initiator, ofdb_sql::SyncRole::Responder].into_iter().enumerate() {
            let fixture = Fixture::new().await;
            let kept = Id::now_v7(); let denied = Id::now_v7();
            sql(&fixture.databases[0], &format!("CREATE TABLE documents (id UUID PRIMARY KEY, value TEXT); INSERT INTO documents VALUES (CAST('{kept}' AS UUID), 'kept')")).await;
            fixture.sync_sql(role).await;
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
                let fixture = Fixture::new().await;
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
                fixture.peers.close().await;
            }
        }
    }).await.expect("deterministic KV acceptance completes");
}
