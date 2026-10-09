use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use file_system::{
    FileHandle, FileOperation, FileSessionService, FileSystem, OpenRequest, OperationControl,
    RemoteOperation, SyncMessage, Transport,
};
use idp_model::model::Id;
use iroh::{EndpointId, protocol::ProtocolHandler};
use iroh_chain::{EndpointIdStore, Server};
use model::contract::SelectedResource;
use storage_model::StorageNamespace;
use storage_service::{DatabaseRuntime, ScopedFileSystemRuntime};
use tokio_util::sync::CancellationToken;

use super::{FILESYSTEM_STREAM_KIND, FrameAuthorizer, IrohFileTransport, IrohResourceDescriptor};
use crate::execution_test_support::{DomainNode, Gate, IrohPair, TestDirectory, approved_signers};

struct Scope {
    owner: String,
    application: Id,
}
impl StorageNamespace for Scope {
    fn user_sub(&self) -> &str {
        &self.owner
    }
    fn application_id(&self) -> Id {
        self.application
    }
}
struct Fixture {
    peers: IrohPair,
    nodes: [DomainNode; 2],
    files: [Arc<FileSystem<EndpointId>>; 2],
    runtimes: [Arc<ScopedFileSystemRuntime<EndpointId>>; 2],
    resource: SelectedResource,
    _directory: TestDirectory,
}
struct Released(Option<tokio::sync::oneshot::Sender<()>>);
impl Drop for Released {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[derive(Clone, Copy)]
enum Hook {
    Import,
    Publish,
    Write,
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
        let scope = Scope {
            owner: owner.to_string(),
            application: Id::now_v7(),
        };
        let left = Arc::new(
            ScopedFileSystemRuntime::new(nodes[0].root.join("storage"), peers.ids()[0])
                .expect("left Storage"),
        );
        let right = Arc::new(
            ScopedFileSystemRuntime::new(nodes[1].root.join("storage"), peers.ids()[1])
                .expect("right Storage"),
        );
        let catalog = left
            .create_resource(&scope, None)
            .await
            .expect("real filesystem resource");
        right
            .register_selected_resource(&scope, catalog.id)
            .await
            .expect("selected local resource projection");
        let files = [
            left.open_resource(&scope, catalog.id)
                .await
                .expect("left filesystem"),
            right
                .open_resource(&scope, catalog.id)
                .await
                .expect("right filesystem"),
        ];
        let resource = SelectedResource {
            owner_subject: scope.owner,
            application_id: scope.application.to_string(),
            kind: "filesystem".into(),
            resource_id: catalog.id.as_uuid().to_string(),
        };
        for node in &nodes {
            node.select(&resource).await;
        }
        Self {
            peers,
            nodes,
            files,
            runtimes: [left, right],
            resource,
            _directory: directory,
        }
    }
    fn descriptor(&self) -> IrohResourceDescriptor {
        IrohResourceDescriptor {
            owner_subject: self.resource.owner_subject.clone(),
            application_id: self.resource.application_id.clone(),
            filesystem_id: self.resource.resource_id.clone(),
        }
    }
    fn authorize(&self, side: usize) -> FrameAuthorizer {
        let authorizer = self.nodes[side].authorizer();
        let resource = self.resource.clone();
        let local = self.peers.ids()[side];
        let remote = self.peers.connections[side].remote_id();
        Arc::new(move || {
            let authorizer = authorizer.clone();
            let resource = resource.clone();
            Box::pin(async move { authorizer.authorize(local, remote, &resource).await })
        })
    }
    fn control(
        &self,
        side: usize,
        gate: Option<(Gate, Hook, bool)>,
    ) -> OperationControl<EndpointId> {
        let authorize = self.authorize(side);
        let remote = self.peers.connections[side].remote_id();
        let first = Arc::new(AtomicBool::new(true));
        OperationControl::new(move |peer, operation| {
            let authorize = authorize.clone();
            let gate = gate.clone();
            let first = first.clone();
            Box::pin(async move {
                if peer != remote {
                    return false;
                }
                if let Some((gate, hook, admitted)) = gate {
                    let matches = matches!(
                        (hook, operation),
                        (Hook::Import, RemoteOperation::ImportSnapshots)
                            | (Hook::Publish, RemoteOperation::PublishContent { .. })
                            | (
                                Hook::Write,
                                RemoteOperation::Session {
                                    operation: FileOperation::Write { .. },
                                    ..
                                }
                            )
                    );
                    if matches && first.swap(false, Ordering::SeqCst) {
                        if admitted {
                            let allowed = authorize().await;
                            assert!(
                                allowed,
                                "operation authorized by genuine current local domain state"
                            );
                            gate.pause().await;
                            return allowed;
                        }
                        gate.pause().await;
                    }
                }
                authorize().await
            })
        })
    }
    async fn transports(&self) -> [IrohFileTransport; 2] {
        let authorize = self.authorize(0);
        let expected = self.descriptor();
        let left = IrohFileTransport::open_authorized(
            &self.peers.connections[0],
            expected.clone(),
            move |resource| {
                let authorize = authorize.clone();
                let expected = expected.clone();
                async move { resource == expected && authorize().await }
            },
        )
        .await
        .expect("selected resource authorized on source Node");
        let (send, mut recv) = self.peers.connections[1]
            .accept_bi()
            .await
            .expect("same-connection stream");
        let mut marker = [0];
        recv.read_exact(&mut marker).await.expect("marker");
        assert_eq!(marker[0], FILESYSTEM_STREAM_KIND);
        let authorize = self.authorize(1);
        let expected = self.descriptor();
        let (right, resource, deleted) = IrohFileTransport::accept_authorized_after_marker(
            &self.peers.connections[1],
            send,
            recv,
            move |resource| {
                let authorize = authorize.clone();
                let expected = expected.clone();
                async move { resource == expected && authorize().await }
            },
        )
        .await
        .expect("selected resource independently authorized on target Node");
        assert_eq!(resource, self.descriptor());
        assert!(!deleted);
        [left, right]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_passthrough_read_uses_authorized_reachable_full_peer_without_local_content() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let fixture = Fixture::new().await;
        fixture.files[1]
            .write("remote.txt", b"authorized Full content")
            .await
            .expect("source Full");
        let scope = Scope {
            owner: fixture.resource.owner_subject.clone(),
            application: fixture
                .resource
                .application_id
                .parse()
                .expect("Application"),
        };
        let id =
            file_system::FileSystemId::parse(&fixture.resource.resource_id).expect("resource ID");
        fixture.runtimes[0]
            .set_resource_residency(&scope, id, file_system::Residency::Passthrough)
            .await
            .expect("local Passthrough");
        let cancellation = CancellationToken::new();
        let handlers = (0..2)
            .map(|side| {
                let peers = EndpointIdStore::default();
                peers.add(fixture.peers.ids()[1 - side]);
                let server = Server::new(fixture.peers.endpoints[side].clone(), peers);
                let management = crate::ManagementClient::new(
                    "http://127.0.0.1:9/management",
                    "http://127.0.0.1:9/idp",
                    "storage",
                    "isolated-secret",
                    "https://of03-installation.example",
                    "management",
                )
                .expect("remote authority unavailable")
                .with_local_replication_authorizer(fixture.nodes[side].authorizer());
                crate::storage_protocol::StorageProtocolHandler::new(
                    server,
                    management,
                    Arc::clone(&fixture.runtimes[side]),
                    cancellation.clone(),
                )
            })
            .collect::<Vec<_>>();
        let database = crate::database_protocol::DatabaseProtocolHandler::new(
            Server::new(
                fixture.peers.endpoints[1].clone(),
                EndpointIdStore::default(),
            ),
            crate::ManagementClient::new(
                "http://127.0.0.1:9/management",
                "http://127.0.0.1:9/idp",
                "storage",
                "isolated-secret",
                "https://of03-installation.example",
                "management",
            )
            .expect("local facade")
            .with_local_replication_authorizer(fixture.nodes[1].authorizer()),
            Arc::new(
                DatabaseRuntime::new(fixture.nodes[1].root.join("unused-sql")).expect("runtime"),
            ),
            fixture.nodes[1].root.join("staging"),
            cancellation.clone(),
        );
        let data =
            crate::DataProtocolHandler::new(database, handlers[1].clone(), cancellation.clone());
        let router = iroh::protocol::Router::builder(fixture.peers.endpoints[1].clone())
            .accept(iroh_chain::DATA_ALPN, data)
            .spawn();
        handlers[0]
            .install_passthrough_reader()
            .expect("production reader wiring");
        let session =
            storage_service::ScopedStorageService::open_resource(&fixture.runtimes[0], scope, id)
                .await
                .expect("scoped Passthrough");
        let read = || storage_model::StorageRequest::Read {
            path: "remote.txt".into(),
        };
        let result = session.execute(read()).await;
        if result.is_err() {
            eprintln!(
                "remote read failure: {result:?}; source read: {:?}",
                fixture.files[1].read("remote.txt").await
            );
            let source_handle = fixture.files[1]
                .open_handle(OpenRequest {
                    path: "remote.txt".into(),
                    revision: None,
                })
                .await;
            match source_handle {
                Ok(mut handle) => eprintln!(
                    "source public handle Read: {:?}",
                    handle.read(0, file_system::MAX_FILE_READ_LENGTH).await
                ),
                Err(error) => eprintln!("source public handle Open: {error:?}"),
            }
        }
        assert_eq!(
            result.expect("real authorized DATA content"),
            storage_model::StorageResponse::Read {
                content: b"authorized Full content".to_vec()
            }
        );
        assert!(
            fixture.files[0].read("remote.txt").await.is_err(),
            "remote read does not materialize a Full copy"
        );
        fixture.nodes[0].restrict(1, false).await;
        assert!(
            session.execute(read()).await.is_err(),
            "learned native permission denies existing peer"
        );
        fixture.nodes[0].restrict(1, true).await;
        fixture.runtimes[1]
            .set_resource_residency(
                &Scope {
                    owner: fixture.resource.owner_subject.clone(),
                    application: fixture
                        .resource
                        .application_id
                        .parse()
                        .expect("Application"),
                },
                id,
                file_system::Residency::Passthrough,
            )
            .await
            .expect("provider no longer Full");
        assert!(
            session.execute(read()).await.is_err(),
            "reachable Passthrough peer cannot provide content"
        );
        cancellation.cancel();
        router.shutdown().await.expect("router shutdown");
        drop(session);
        fixture.peers.close().await;
    })
    .await
    .expect("bounded public Passthrough integration");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_filesystem_parent_cancellation_releases_admitted_session() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let fixture = Fixture::new().await;
        let server = Server::new(
            fixture.peers.endpoints[1].clone(),
            EndpointIdStore::default(),
        );
        let runtime = Arc::new(
            ScopedFileSystemRuntime::new(
                fixture.nodes[1].root.join("production-files"),
                fixture.peers.ids()[1],
            )
            .expect("production filesystem runtime"),
        );
        let scope = Scope {
            owner: fixture.resource.owner_subject.clone(),
            application: fixture
                .resource
                .application_id
                .parse()
                .expect("Application"),
        };
        let id =
            file_system::FileSystemId::parse(&fixture.resource.resource_id).expect("resource ID");
        runtime
            .register_selected_resource(&scope, id)
            .await
            .expect("real selected resource");
        let file = runtime.open_resource(&scope, id).await.expect("resource");
        file.write("retained.txt", b"source retained")
            .await
            .expect("content");
        file.open_handle(OpenRequest {
            path: "retained.txt".into(),
            revision: None,
        })
        .await
        .expect("native source handle opens");
        let (released, release) = tokio::sync::oneshot::channel();
        let lifetime = Arc::new(Released(Some(released)));
        let policy = fixture.nodes[1].authorizer_retaining(lifetime);
        let management = crate::ManagementClient::new(
            "http://127.0.0.1:9/management",
            "http://127.0.0.1:9/idp",
            "storage",
            "isolated-secret",
            "https://of03-installation.example",
            "management",
        )
        .expect("unreachable remote services")
        .with_local_replication_authorizer(policy);
        let cancellation = CancellationToken::new();
        let database = crate::database_protocol::DatabaseProtocolHandler::new(
            server.clone(),
            management.clone(),
            Arc::new(
                DatabaseRuntime::new(fixture.nodes[1].root.join("unused-databases"))
                    .expect("database runtime"),
            ),
            fixture.nodes[1].root.join("stage"),
            cancellation.clone(),
        );
        let filesystem = crate::storage_protocol::StorageProtocolHandler::new(
            server,
            management,
            runtime,
            cancellation.clone(),
        );
        let handler = crate::DataProtocolHandler::new(database, filesystem, cancellation);
        let connection = fixture.peers.connections[1].clone();
        let task = tokio::spawn(async move { handler.accept(connection).await });
        let authorize = fixture.authorize(0);
        let transport = IrohFileTransport::open_authorized(
            &fixture.peers.connections[0],
            fixture.descriptor(),
            move |_| {
                let authorize = authorize.clone();
                async move { authorize().await }
            },
        )
        .await
        .expect("native selected admission");
        let mut metadata = transport.subscribe();
        while !matches!(
            metadata
                .recv()
                .await
                .expect("production session announcement"),
            (_, SyncMessage::SnapshotDelta { .. })
        ) {}
        let mut handle = Box::new(
            transport
                .open(
                    fixture.peers.ids()[1],
                    OpenRequest {
                        path: "retained.txt".into(),
                        revision: None,
                    },
                )
                .await
                .expect("production session is running"),
        );
        assert_eq!(
            handle.read(0, 15).await.expect("authorized resource read"),
            bytes::Bytes::from_static(b"source retained")
        );
        task.abort();
        assert!(task.await.expect_err("host task cancelled").is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), release)
            .await
            .expect("admitted filesystem session must not outlive its DATA parent")
            .expect("owner evaluator released");
        assert_eq!(
            file.read("retained.txt").await.expect("content preserved"),
            b"source retained"
        );
        assert!(
            handle
                .write(0, bytes::Bytes::from_static(b"denied"))
                .await
                .is_err(),
            "cancelled session cannot apply later writes"
        );
        transport.close();
        drop(handle);
        fixture.peers.close().await;
    })
    .await
    .expect("native parent cancellation completes");
}

async fn serve(
    fixture: &Fixture,
    transport: IrohFileTransport,
    control: OperationControl<EndpointId>,
) -> tokio::task::JoinHandle<Result<(), file_system::Error>> {
    let filesystem = fixture.files[0].clone();
    let ready = Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let task = tokio::spawn(async move {
        let sync = filesystem
            .metadata_sync(transport)
            .with_operation_control(control);
        signal.notify_one();
        sync.run().await
    });
    ready.notified().await;
    task
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_filesystem_denies_fetched_content_publication_then_reconnects() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let mut fixture = Fixture::new().await;
        fixture.files[0].write("remote.txt", b"complete source content").await.expect("source write");
        let [left, right] = fixture.transports().await;
        let gate = Gate::default();
        let left_sync = fixture.files[0].metadata_sync(left.clone()).with_operation_control(fixture.control(0, None));
        let mut right_sync = fixture.files[1].metadata_sync(right.clone()).with_operation_control(fixture.control(1, Some((gate.clone(), Hook::Publish, false))));
        let mut delivered = right.subscribe();
        left_sync.announce().await.expect("authorized metadata");
        while !matches!(delivered.recv().await.expect("received metadata"), (_, SyncMessage::SnapshotDelta { .. })) {}
        right_sync.pump().await.expect("authorized metadata apply");
        fixture.files[1].entry("remote.txt").await.expect("metadata applied before content fetch");
        drop(left_sync);
        let task = serve(&fixture, left.clone(), fixture.control(0, None)).await;
        let mut fetch = Box::pin(right_sync.fetch("remote.txt"));
        tokio::select! { result = &mut fetch => panic!("content did not reach publication gate: {result:?}"), () = gate.reached() => {} }
        fixture.nodes[1].restrict(0, false).await;
        gate.release();
        assert!(matches!(fetch.await, Err(file_system::Error::PermissionDenied)), "received/staged content cannot authorize its own publication");
        assert!(fixture.files[1].read("remote.txt").await.is_err(), "denied content was not published");
        assert_eq!(fixture.files[0].read("remote.txt").await.expect("source retained"), b"complete source content");
        left.close(); right.close(); task.await.expect("source task joins").expect("source stream released"); drop(right_sync);
        fixture.nodes[1].restrict(0, true).await;
        fixture.peers.reconnect().await;
        let [left, right] = fixture.transports().await;
        let right_sync = fixture.files[1].metadata_sync(right.clone()).with_operation_control(fixture.control(1, None));
        let task = serve(&fixture, left.clone(), fixture.control(0, None)).await;
        right_sync.fetch("remote.txt").await.expect("authorized retry publishes complete content");
        assert_eq!(fixture.files[1].read("remote.txt").await.expect("retried content"), b"complete source content");
        fixture.nodes[1].revoke(1).await;
        assert!(right.open(fixture.peers.ids()[0], OpenRequest { path: "remote.txt".into(), revision: None }).await.is_err(), "learned local Device revocation denies next existing-connection request");
        left.close(); right.close(); task.await.expect("retry task joins").expect("retry stream released"); drop(right_sync);
        fixture.peers.close().await;
    }).await.expect("content domain acceptance completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_filesystem_admitted_write_finishes_next_write_denies_and_retry_succeeds() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let fixture = Fixture::new().await;
        fixture.files[0].write("shared.txt", b"before").await.expect("source content");
        let [left, right] = fixture.transports().await;
        let gate = Gate::default();
        let task = serve(&fixture, left.clone(), fixture.control(0, Some((gate.clone(), Hook::Write, true)))).await;
        let mut handle = Box::new(right.open(fixture.peers.ids()[0], OpenRequest { path: "shared.txt".into(), revision: None }).await.expect("authorized established file handle"));
        let mut write = Box::pin(handle.write(0, bytes::Bytes::from_static(b"after!")));
        tokio::select! { result = &mut write => panic!("write did not reach admitted operation gate: {result:?}"), () = gate.reached() => {} }
        fixture.nodes[0].restrict(1, false).await;
        gate.release();
        assert!(write.await.is_err(), "a separately denied outbound response must not disclose after restriction");
        assert_eq!(fixture.files[0].read("shared.txt").await.expect("admitted write completed"), b"after!");
        assert!(handle.write(0, bytes::Bytes::from_static(b"denied")).await.is_err(), "next request on existing handle denies");
        assert_eq!(fixture.files[0].read("shared.txt").await.expect("next write absent"), b"after!");
        left.close(); right.close(); task.await.expect("source task joins").expect("source stream released"); drop(handle);
        fixture.nodes[0].restrict(1, true).await;
        let [left, right] = fixture.transports().await;
        let task = serve(&fixture, left.clone(), fixture.control(0, None)).await;
        let mut handle = Box::new(right.open(fixture.peers.ids()[0], OpenRequest { path: "shared.txt".into(), revision: None }).await.expect("fresh stream on same authenticated connection"));
        handle.write(0, bytes::Bytes::from_static(b"retry!")).await.expect("authorized retry write");
        assert_eq!(fixture.files[0].read("shared.txt").await.expect("retry content"), b"retry!");
        fixture.nodes[0].revoke(1).await;
        assert!(handle.write(0, bytes::Bytes::from_static(b"forged")).await.is_err(), "receiver's learned IdP revocation stops subsequent mutation");
        assert_eq!(fixture.files[0].read("shared.txt").await.expect("revocation preserves content"), b"retry!");
        left.close(); right.close(); task.await.expect("retry task joins").expect("retry stream released"); drop(handle);
        fixture.peers.close().await;
    }).await.expect("admitted filesystem operation acceptance completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_selected_filesystem_denies_received_metadata_then_reconciles_on_existing_connection()
{
    tokio::time::timeout(Duration::from_secs(300), async {
        for device in 0..2 {
            let fixture = Fixture::new().await;
            fixture.files[0].write("remote.txt", b"source remains intact").await.expect("source content");
            fixture.files[1].write("local.txt", b"local remains intact").await.expect("local content");
            let [left, right] = fixture.transports().await;
            let gate = Gate::default();
            let left_sync = fixture.files[0].metadata_sync(left.clone()).with_operation_control(fixture.control(0, None));
            let mut right_sync = fixture.files[1].metadata_sync(right.clone()).with_operation_control(fixture.control(1, Some((gate.clone(), Hook::Import, false))));
            let mut delivered = right.subscribe();
            left_sync.announce().await.expect("authenticated source metadata");
            while !matches!(delivered.recv().await.expect("received metadata"), (_, SyncMessage::SnapshotDelta { .. })) {}
            let mut pump = Box::pin(right_sync.pump());
            tokio::select! { result = &mut pump => panic!("metadata execution did not reach gate: {result:?}"), () = gate.reached() => {} }
            fixture.nodes[1].restrict(device, false).await;
            gate.release(); pump.await.expect("owner skips denied metadata apply");
            assert!(fixture.files[1].entry("remote.txt").await.is_err(), "received snapshots were not applied after local denial");
            assert_eq!(fixture.files[1].read("local.txt").await.expect("local retained"), b"local remains intact");
            assert_eq!(fixture.files[0].read("remote.txt").await.expect("source retained"), b"source remains intact");
            left.close(); right.close(); drop(left_sync); drop(right_sync);
            fixture.nodes[1].restrict(device, true).await;
            let [left, right] = fixture.transports().await;
            let left_sync = fixture.files[0].metadata_sync(left.clone()).with_operation_control(fixture.control(0, None));
            let mut right_sync = fixture.files[1].metadata_sync(right.clone()).with_operation_control(fixture.control(1, None));
            let mut delivered = right.subscribe();
            left_sync.announce().await.expect("allowed reconnect metadata");
            while !matches!(delivered.recv().await.expect("retry metadata"), (_, SyncMessage::SnapshotDelta { .. })) {}
            right_sync.pump().await.expect("allowed apply");
            fixture.files[1].entry("remote.txt").await.expect("metadata retry reconciles");
            left.close(); right.close(); drop(left_sync); drop(right_sync);
            fixture.peers.close().await;
        }
    }).await.expect("metadata domain acceptance completes");
}
