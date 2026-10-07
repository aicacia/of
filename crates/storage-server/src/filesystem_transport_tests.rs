use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use file_system::{FileHandle, FileSessionService, FileSystem, OpenRequest, Residency};
use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets};
use uuid::Uuid;

use super::{FILESYSTEM_STREAM_KIND, IrohFileTransport, IrohResourceDescriptor};

fn root() -> std::path::PathBuf {
    env::temp_dir().join(format!("file-system-iroh-{}", Uuid::now_v7()))
}

async fn accept_transport<F, Fut>(
    connection: &iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    authorize: F,
) -> Result<(IrohFileTransport, IrohResourceDescriptor, bool), std::io::Error>
where
    F: Fn(IrohResourceDescriptor) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = bool> + Send + 'static,
{
    let mut marker = [0];
    recv.read_exact(&mut marker)
        .await
        .map_err(std::io::Error::other)?;
    assert_eq!(marker[0], FILESYSTEM_STREAM_KIND);
    IrohFileTransport::accept_authorized_after_marker(connection, send, recv, authorize).await
}

#[tokio::test]
async fn delivered_read_chunk_then_channel_closure_is_not_successful_eof() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let lookup = MemoryLookup::new();
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-truncated-read".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind server");
        let client = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind client");
        lookup.add_endpoint_info(server.addr());
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.id(), b"filesystem-truncated-read"),
            async {
                server
                    .accept()
                    .await
                    .expect("incoming connection")
                    .accept()
                    .expect("accept connection")
                    .await
            }
        );
        let outgoing = outgoing.expect("connect client");
        let incoming = incoming.expect("accept client");
        let resource = IrohResourceDescriptor {
            owner_subject: "owner".into(),
            application_id: Uuid::now_v7().to_string(),
            filesystem_id: Uuid::now_v7().to_string(),
        };
        let transport =
            IrohFileTransport::open_authorized(&outgoing, resource.clone(), |_| async { true })
                .await
                .expect("open file transport");
        let (mut send, mut recv) = incoming.accept_bi().await.expect("accept file stream");
        let mut marker = [0];
        recv.read_exact(&mut marker)
            .await
            .expect("read stream marker");
        assert_eq!(marker[0], FILESYSTEM_STREAM_KIND);
        assert!(matches!(
            super::read_message::<iroh::EndpointId>(&mut recv)
                .await
                .expect("read hello"),
            super::WireMessage::Hello { .. }
        ));
        let directory = root();
        let filesystem = FileSystem::open(&directory, server.id()).expect("open peer filesystem");
        filesystem
            .set_residency("", Residency::Full)
            .await
            .expect("enable local peer content");
        filesystem
            .write("file", b"complete content")
            .await
            .expect("write peer file");
        let entry = filesystem.entry("file").await.expect("read peer entry");
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            async fn send_message(
                send: &mut iroh::endpoint::SendStream,
                message: super::WireMessage<iroh::EndpointId>,
            ) {
                super::write_frame(send, &super::encode(&message).expect("encode peer frame"))
                    .await
                    .expect("send peer frame");
            }
            send_message(
                &mut send,
                super::WireMessage::Hello {
                    version: super::IROH_FILE_PROTOCOL_VERSION,
                    resource,
                    deleted: false,
                },
            )
            .await;
            let super::WireMessage::Request {
                id,
                operation: file_system::FileOperation::Open(_),
            } = super::read_message::<iroh::EndpointId>(&mut recv)
                .await
                .expect("receive open")
            else {
                panic!("expected open");
            };
            send_message(
                &mut send,
                super::WireMessage::Response {
                    id,
                    response: file_system::FileResponse::Opened {
                        handle: file_system::FileHandleId(Uuid::now_v7()),
                        revision: entry.meta.revision,
                        entry: entry.clone(),
                    },
                },
            )
            .await;
            let super::WireMessage::Request {
                id,
                operation: file_system::FileOperation::Read { .. },
            } = super::read_message::<iroh::EndpointId>(&mut recv)
                .await
                .expect("receive read")
            else {
                panic!("expected read");
            };
            send_message(
                &mut send,
                super::WireMessage::Response {
                    id,
                    response: file_system::FileResponse::ReadChunk(Bytes::from_static(b"partial")),
                },
            )
            .await;
            let super::WireMessage::Request {
                id,
                operation: file_system::FileOperation::Open(_),
            } = super::read_message::<iroh::EndpointId>(&mut recv)
                .await
                .expect("receive delivery barrier")
            else {
                panic!("expected barrier open");
            };
            send_message(
                &mut send,
                super::WireMessage::Response {
                    id,
                    response: file_system::FileResponse::Opened {
                        handle: file_system::FileHandleId(Uuid::now_v7()),
                        revision: entry.meta.revision,
                        entry,
                    },
                },
            )
            .await;
            close_rx
                .await
                .expect("client consumed chunk before stream closure");
            send.finish().expect("close peer stream without ReadEnd");
        });
        let mut handle = transport
            .open(
                server.id(),
                OpenRequest {
                    path: "file".into(),
                    revision: None,
                },
            )
            .await
            .expect("open remote file");
        let mut read = handle.read(0, 32);
        core::future::poll_fn(|cx| {
            assert!(core::future::Future::poll(read.as_mut(), cx).is_pending());
            core::task::Poll::Ready(())
        })
        .await;
        let barrier = transport
            .open(
                server.id(),
                OpenRequest {
                    path: "file".into(),
                    revision: None,
                },
            )
            .await
            .expect("ordered response proves the earlier chunk was dispatched");
        core::future::poll_fn(|cx| {
            assert!(
                core::future::Future::poll(read.as_mut(), cx).is_pending(),
                "consume delivered chunk while EOF is held back"
            );
            core::task::Poll::Ready(())
        })
        .await;
        close_tx
            .send(())
            .expect("release EOF after chunk consumption");
        let error = read
            .await
            .expect_err("delivered chunks without ReadEnd must not become successful data");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        peer.await.expect("peer task joins");
        drop(barrier);
        drop(handle);
        transport.close();
        drop(filesystem);
        client.close().await;
        server.close().await;
        std::fs::remove_dir_all(directory).expect("remove peer store");
    })
    .await
    .expect("truncated-read regression finishes");
}

#[tokio::test]
async fn cancelled_sync_closes_its_peer_stream_and_releases_local_filesystem() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let lookup = MemoryLookup::new();
        let responder = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-cancel-test".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind responder");
        lookup.add_endpoint_info(responder.addr());
        let initiator = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-cancel-test".to_vec()])
            .address_lookup(lookup)
            .bind()
            .await
            .expect("bind initiator");
        let (connection, incoming) = tokio::join!(
            initiator.connect(responder.id(), b"filesystem-cancel-test"),
            async {
                responder
                    .accept()
                    .await
                    .expect("incoming connection")
                    .accept()
                    .expect("accept connection")
                    .await
            }
        );
        let connection = connection.expect("connect");
        let incoming = incoming.expect("accept connection");
        let resource = IrohResourceDescriptor {
            owner_subject: "cancel-owner".to_owned(),
            application_id: "cancel-app".to_owned(),
            filesystem_id: "cancel-files".to_owned(),
        };
        let initiator_transport =
            IrohFileTransport::open_authorized(&connection, resource.clone(), |_| async { true })
                .await
                .expect("open authorized stream");
        let (send, recv) = incoming.accept_bi().await.expect("accept stream");
        let (responder_transport, _, _) =
            accept_transport(&incoming, send, recv, |_| async { true })
                .await
                .expect("accept authorized stream");

        let initiator_root = root();
        let responder_root = root();
        let initiator_fs = Arc::new(
            FileSystem::open(&initiator_root, initiator.id()).expect("open initiator filesystem"),
        );
        let responder_fs = Arc::new(
            FileSystem::open(&responder_root, responder.id()).expect("open responder filesystem"),
        );
        initiator_fs
            .set_residency("", Residency::Full)
            .await
            .expect("initiator full residency");
        responder_fs
            .set_residency("", Residency::Full)
            .await
            .expect("responder full residency");
        initiator_fs
            .write("before-cancel.txt", b"sync is active")
            .await
            .expect("write before sync");

        let initiator_sync = {
            let filesystem = Arc::clone(&initiator_fs);
            tokio::spawn(async move { filesystem.sync_peer(initiator_transport).await })
        };
        let responder_sync = {
            let filesystem = Arc::clone(&responder_fs);
            tokio::spawn(async move { filesystem.sync_peer(responder_transport).await })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if responder_fs.entry("before-cancel.txt").await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sync becomes active before cancellation");
        initiator_sync.abort();
        assert!(
            initiator_sync
                .await
                .expect_err("sync task is aborted")
                .is_cancelled()
        );
        tokio::time::timeout(Duration::from_secs(3), responder_sync)
            .await
            .expect("peer sync exits after stream cancellation")
            .expect("peer sync task joins")
            .expect("peer sync exits without an error");

        initiator_fs
            .write("still-usable.txt", b"ok")
            .await
            .expect("canceled sync releases local filesystem");
        assert_eq!(
            initiator_fs
                .read("still-usable.txt")
                .await
                .expect("read local file"),
            b"ok"
        );
        initiator.close().await;
        responder.close().await;
        std::fs::remove_dir_all(initiator_root).expect("remove initiator test data");
        std::fs::remove_dir_all(responder_root).expect("remove responder test data");
    })
    .await
    .expect("sync cancellation cleanup test timed out");
}

#[tokio::test]
async fn syncs_metadata_and_remote_file_sessions_over_one_stream() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let lookup = MemoryLookup::new();
        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-test".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind responder");
        lookup.add_endpoint_info(b.addr());
        let a = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-test".to_vec()])
            .address_lookup(lookup)
            .bind()
            .await
            .expect("bind initiator");

        let (connection, incoming) = tokio::join!(a.connect(b.id(), b"filesystem-test"), async {
            b.accept()
                .await
                .expect("incoming connection")
                .accept()
                .expect("accept")
                .await
        });

        let connection = connection.expect("connect");
        let incoming = incoming.expect("accept connection");
        let resource = IrohResourceDescriptor {
            owner_subject: "test-owner".to_owned(),
            application_id: "test-app".to_owned(),
            filesystem_id: "shared-files".to_owned(),
        };
        let initiator_authorization_checks = Arc::new(AtomicUsize::new(0));
        let initiator_checks = Arc::clone(&initiator_authorization_checks);
        let left_transport =
            IrohFileTransport::open_authorized(&connection, resource.clone(), move |_| {
                let checks = Arc::clone(&initiator_checks);
                async move {
                    checks.fetch_add(1, Ordering::SeqCst);
                    true
                }
            })
            .await
            .expect("open authorized stream");
        let (send, recv) = incoming.accept_bi().await.expect("accept stream");
        let authorization_checks = Arc::new(AtomicUsize::new(0));
        let allowed = Arc::new(AtomicBool::new(true));
        let checks = Arc::clone(&authorization_checks);
        let authorized = Arc::clone(&allowed);
        let (right_transport, accepted_resource, deleted) =
            accept_transport(&incoming, send, recv, move |_| {
                let checks = Arc::clone(&checks);
                let authorized = Arc::clone(&authorized);
                async move {
                    checks.fetch_add(1, Ordering::SeqCst);
                    authorized.load(Ordering::SeqCst)
                }
            })
            .await
            .expect("validate accepted stream");
        assert_eq!(accepted_resource, resource);
        assert!(!deleted);

        let left_root = root();
        let right_root = root();
        let left = Arc::new(FileSystem::open(&left_root, a.id()).expect("open left filesystem"));
        let right = Arc::new(FileSystem::open(&right_root, b.id()).expect("open right filesystem"));
        left.set_residency("", Residency::Full)
            .await
            .expect("left full residency");
        right
            .set_residency("", Residency::Full)
            .await
            .expect("right full residency");

        left.write("shared.txt", b"before")
            .await
            .expect("write initial content");

        let left_sync = {
            let left = Arc::clone(&left);
            tokio::spawn(async move { left.sync_peer(left_transport).await })
        };

        let right_sync = {
            let right = Arc::clone(&right);
            let sync_transport = right_transport.clone();
            tokio::spawn(async move { right.sync_peer(sync_transport).await })
        };

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if right.entry("shared.txt").await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("metadata entry replicated");
        assert!(
            authorization_checks.load(Ordering::SeqCst) > 1,
            "responder authorization is rechecked after the stream handshake"
        );
        assert!(
            initiator_authorization_checks.load(Ordering::SeqCst) > 1,
            "initiator authorization is rechecked during the stream"
        );

        let handle = right_transport
            .open(
                a.id(),
                OpenRequest {
                    path: "shared.txt".to_owned(),
                    revision: None,
                },
            )
            .await
            .expect("open remote file");
        let mut handle = Box::new(handle);
        assert_eq!(
            handle.read(0, 32).await.expect("read remote file"),
            Bytes::from_static(b"before")
        );
        handle
            .write(0, Bytes::from_static(b"after!"))
            .await
            .expect("write remote file");
        assert_eq!(
            left.read("shared.txt")
                .await
                .expect("read updated local file"),
            b"after!"
        );

        let checks_before_revocation = authorization_checks.load(Ordering::SeqCst);
        allowed.store(false, Ordering::SeqCst);
        let denied_write = handle
            .write(0, Bytes::from_static(b"denied"))
            .await
            .expect_err(
                "local revocation must stop an established-handle request before transmission",
            );
        assert_eq!(denied_write.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            left.read("shared.txt")
                .await
                .expect("read retained peer content"),
            b"after!"
        );
        left.write("revoked.txt", b"must not replicate")
            .await
            .expect("write after revocation");
        tokio::time::timeout(Duration::from_secs(5), async {
            while authorization_checks.load(Ordering::SeqCst) == checks_before_revocation {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("revoked frame is checked");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(right.entry("revoked.txt").await.is_err());

        tokio::time::timeout(Duration::from_secs(5), async {
            assert!(
                left_sync.await.expect("initiator sync task").is_ok(),
                "initiator sync ends cleanly when its stream closes"
            );
            assert!(
                right_sync.await.expect("responder sync task").is_ok(),
                "responder sync ends cleanly when its stream closes"
            );
        })
        .await
        .expect("revoked sync tasks close naturally");

        left.write("offline.txt", b"offline progress")
            .await
            .expect("write without a sync session");
        allowed.store(true, Ordering::SeqCst);
        let retry_left =
            IrohFileTransport::open_authorized(&connection, resource.clone(), |_| async { true })
                .await
                .expect("open fresh stream on the same authenticated connection");
        let (send, recv) = incoming.accept_bi().await.expect("accept fresh stream");
        let (retry_right, accepted_resource, _) =
            accept_transport(&incoming, send, recv, move |candidate| {
                let expected = resource.clone();
                async move { candidate == expected }
            })
            .await
            .expect("authorize exact resource on retry");
        assert_eq!(accepted_resource.owner_subject, "test-owner");
        let retry_client = retry_right.clone();
        let left_retry = {
            let left = Arc::clone(&left);
            tokio::spawn(async move { left.sync_peer(retry_left).await })
        };
        let right_retry = {
            let right = Arc::clone(&right);
            tokio::spawn(async move { right.sync_peer(retry_right).await })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while right.entry("offline.txt").await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fresh stream reconciles offline metadata");
        let mut offline = Box::new(
            retry_client
                .open(
                    a.id(),
                    OpenRequest {
                        path: "offline.txt".into(),
                        revision: None,
                    },
                )
                .await
                .expect("open offline content through public session API"),
        );
        assert_eq!(
            offline.read(0, 64).await.expect("read reconciled content"),
            Bytes::from_static(b"offline progress")
        );
        offline.close().await.expect("close remote handle");
        retry_client.close();
        tokio::time::timeout(Duration::from_secs(5), async {
            left_retry
                .await
                .expect("left retry task joins")
                .expect("left retry closes cleanly");
            right_retry
                .await
                .expect("right retry task joins")
                .expect("right retry closes cleanly");
        })
        .await
        .expect("fresh stream resources close");
        drop(handle);
        drop(right_transport);
        drop(retry_client);
        drop(left);
        drop(right);
        a.close().await;
        b.close().await;
        std::fs::remove_dir_all(left_root).expect("remove left test store");
        std::fs::remove_dir_all(right_root).expect("remove right test store");
    })
    .await
    .expect("Iroh file transport test timed out");
}

#[tokio::test]
async fn shutdown_during_live_multichunk_file_read_closes_stream() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let lookup = MemoryLookup::new();
        let responder = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-multichunk-cancel-test".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind responder");
        lookup.add_endpoint_info(responder.addr());
        let initiator = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"filesystem-multichunk-cancel-test".to_vec()])
            .address_lookup(lookup)
            .bind()
            .await
            .expect("bind initiator");
        let (connection, incoming) = tokio::join!(
            initiator.connect(responder.id(), b"filesystem-multichunk-cancel-test"),
            async {
                responder
                    .accept()
                    .await
                    .expect("incoming connection")
                    .accept()
                    .expect("accept connection")
                    .await
            }
        );
        let connection = connection.expect("connect");
        let incoming = incoming.expect("accept connection");
        let resource = IrohResourceDescriptor {
            owner_subject: "multi-chunk-owner".to_owned(),
            application_id: "multi-chunk-app".to_owned(),
            filesystem_id: "multi-chunk-files".to_owned(),
        };
        let pause_authorization = Arc::new(AtomicBool::new(false));
        let checks_after_pause = Arc::new(AtomicUsize::new(0));
        let (paused_tx, paused_rx) = tokio::sync::oneshot::channel();
        let paused_tx = Arc::new(std::sync::Mutex::new(Some(paused_tx)));
        let pause_flag = Arc::clone(&pause_authorization);
        let check_count = Arc::clone(&checks_after_pause);
        let pause_signal = Arc::clone(&paused_tx);
        let initiator_transport =
            IrohFileTransport::open_authorized(&connection, resource.clone(), move |_| {
                let pause_flag = Arc::clone(&pause_flag);
                let check_count = Arc::clone(&check_count);
                let pause_signal = Arc::clone(&pause_signal);
                async move {
                    if pause_flag.load(Ordering::SeqCst)
                        && check_count.fetch_add(1, Ordering::SeqCst) == 3
                    {
                        if let Some(signal) = pause_signal
                            .lock()
                            .expect("pause signal lock poisoned")
                            .take()
                        {
                            let _ = signal.send(());
                        }
                        core::future::pending::<()>().await;
                    }
                    true
                }
            })
            .await
            .expect("open initiator transport");
        let (send, recv) = incoming.accept_bi().await.expect("accept stream");
        let (responder_transport, _, _) =
            accept_transport(&incoming, send, recv, |_| async { true })
                .await
                .expect("accept responder transport");

        let initiator_root = root();
        let responder_root = root();
        let initiator_fs = Arc::new(
            FileSystem::open(&initiator_root, initiator.id()).expect("open initiator filesystem"),
        );
        let responder_fs = Arc::new(
            FileSystem::open(&responder_root, responder.id()).expect("open responder filesystem"),
        );
        initiator_fs
            .set_residency("", Residency::Full)
            .await
            .expect("initiator full residency");
        responder_fs
            .set_residency("", Residency::Full)
            .await
            .expect("responder full residency");
        initiator_fs
            .write("multi-chunk.bin", &vec![0xA5; 1024 * 1024])
            .await
            .expect("write file larger than one response chunk");

        let client_transport = responder_transport.clone();
        let initiator_sync = {
            let filesystem = Arc::clone(&initiator_fs);
            tokio::spawn(async move { filesystem.sync_peer(initiator_transport).await })
        };
        let responder_sync = {
            let filesystem = Arc::clone(&responder_fs);
            tokio::spawn(async move { filesystem.sync_peer(responder_transport).await })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if responder_fs.entry("multi-chunk.bin").await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("file metadata replicates before the read");

        let mut file = client_transport
            .open(
                initiator.id(),
                OpenRequest {
                    path: "multi-chunk.bin".to_owned(),
                    revision: None,
                },
            )
            .await
            .expect("open remote file");
        pause_authorization.store(true, Ordering::SeqCst);
        let read_task = tokio::spawn(async move { file.read(0, 1024 * 1024).await });
        tokio::time::timeout(Duration::from_secs(5), paused_rx)
            .await
            .expect("authorization pauses between response chunks")
            .expect("pause signal sent");
        initiator.close().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), read_task)
                .await
                .expect("endpoint shutdown cancels the pending read")
                .expect("read task joins")
                .is_err(),
            "partial multi-chunk read fails when Iroh shuts down"
        );
        tokio::time::timeout(Duration::from_secs(3), responder_sync)
            .await
            .expect("peer sync exits after endpoint shutdown")
            .expect("peer sync task joins")
            .expect("peer sync exits cleanly");
        responder_fs
            .write("still-usable.txt", b"ok")
            .await
            .expect("peer filesystem remains usable");
        assert_eq!(
            responder_fs
                .read("still-usable.txt")
                .await
                .expect("read peer-local file"),
            b"ok"
        );
        let _ = initiator_sync.await;
        responder.close().await;
        std::fs::remove_dir_all(initiator_root).expect("remove initiator data");
        std::fs::remove_dir_all(responder_root).expect("remove responder data");
    })
    .await
    .expect("live multi-chunk shutdown test timed out");
}
