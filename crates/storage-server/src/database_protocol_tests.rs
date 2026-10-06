#[cfg(test)]
mod database_protocol_tests {
    use std::{
        collections::VecDeque,
        future::pending,
        io::{self, Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use iroh::{
        Endpoint,
        address_lookup::MemoryLookup,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler},
    };
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
    use model::contract::{SelectedResource, SelectedResourcesResponse};
    use ofdb_sql::{Database, IrohTransport, SessionConfig, SyncRole, SyncTransport};
    use storage_service::DatabaseRuntime;

    use crate::{
        ManagementClient,
        database_protocol::{
            AuthorizedTransport, DATABASE_STREAM_KIND, DatabaseProtocolHandler,
            DatabaseResourceDescriptor, KvAuthorizedTransport, Namespace, authorize_with_timeout,
        },
        sync_timeout,
    };

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct MemorySyncTransport {
        incoming: VecDeque<Vec<u8>>,
        outgoing: Vec<Vec<u8>>,
    }

    impl SyncTransport for MemorySyncTransport {
        type Error = io::Error;

        async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.incoming
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no test frame"))
        }

        async fn send(&mut self, frame: Vec<u8>) -> Result<(), Self::Error> {
            self.outgoing.push(frame);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestProtocol;

    impl ProtocolHandler for TestProtocol {
        async fn accept(&self, _connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            Ok(())
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read HTTP request");
            if read == 0 {
                return String::from_utf8_lossy(&request).into_owned();
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(headers_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content length"))
                })
                .unwrap_or(0);
            if request.len() >= headers_end + 4 + content_length {
                return String::from_utf8(request).expect("HTTP request is UTF-8");
            }
        }
    }

    fn try_respond(stream: &mut std::net::TcpStream, status: &str, body: &str) -> io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        try_respond(stream, status, body).expect("write HTTP response");
    }

    fn respond_during_shutdown(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        if let Err(error) = try_respond(stream, status, body) {
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ),
                "write Management response during shutdown: {error}"
            );
        }
    }

    #[tokio::test]
    async fn timed_out_policy_check_drops_its_future_and_fails_closed() {
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_signal = DropSignal(Arc::clone(&dropped));
        let authorization = async move {
            let _drop_signal = drop_signal;
            pending::<bool>().await
        };

        assert!(!authorize_with_timeout(std::time::Duration::from_millis(10), authorization).await);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sql_sync_rechecks_policy_between_sends_and_receives() {
        let send_checks = Arc::new(AtomicUsize::new(0));
        let send_authorize = Arc::clone(&send_checks);
        let mut send_transport = AuthorizedTransport {
            transport: MemorySyncTransport::default(),
            authorize: Arc::new(move || {
                let checks = Arc::clone(&send_authorize);
                Box::pin(async move { checks.fetch_add(1, Ordering::SeqCst) == 0 })
            }),
        };
        send_transport
            .send(vec![1])
            .await
            .expect("first operation is allowed");
        let error = send_transport
            .send(vec![2])
            .await
            .expect_err("next operation observes policy revocation");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(send_transport.transport.outgoing, [vec![1]]);

        let receive_checks = Arc::new(AtomicUsize::new(0));
        let receive_authorize = Arc::clone(&receive_checks);
        let mut receive_transport = AuthorizedTransport {
            transport: MemorySyncTransport {
                incoming: VecDeque::from([vec![3]]),
                outgoing: Vec::new(),
            },
            authorize: Arc::new(move || {
                let checks = Arc::clone(&receive_authorize);
                Box::pin(async move { checks.fetch_add(1, Ordering::SeqCst) == 0 })
            }),
        };
        let error = receive_transport
            .receive()
            .await
            .expect_err("revocation after frame receipt rejects the frame");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(receive_transport.transport.incoming.is_empty());
    }

    #[tokio::test]
    async fn revoked_policy_rejects_a_received_frame_and_closes_the_real_iroh_stream() {
        let lookup = MemoryLookup::new();
        let initiator = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind initiator endpoint");
        let responder = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"storage-revocation-test".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind responder endpoint");
        lookup.add_endpoint_info(responder.addr());

        let (connection, peer) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                initiator.connect(responder.id(), b"storage-revocation-test"),
                async {
                    responder
                        .accept()
                        .await
                        .expect("incoming connection")
                        .accept()
                        .expect("start accepting")
                        .await
                }
            )
        })
        .await
        .expect("Iroh connection setup completes");
        let connection = connection.expect("connect endpoints");
        let peer = peer.expect("accept connection");
        let (mut client_send, mut client_receive) =
            tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
                .await
                .expect("open client stream")
                .expect("client stream opens");
        client_send
            .write_all(&3u32.to_be_bytes())
            .await
            .expect("write frame length before peer accepts stream");
        client_send
            .write_all(&[1, 2, 3])
            .await
            .expect("write frame before peer accepts stream");
        let (server_send, server_receive) =
            tokio::time::timeout(Duration::from_secs(10), peer.accept_bi())
                .await
                .expect("accept server stream")
                .expect("server stream opens");
        let checks = Arc::new(AtomicUsize::new(0));
        let authorize_checks = Arc::clone(&checks);
        let mut transport = AuthorizedTransport {
            transport: IrohTransport::new(server_send, server_receive),
            authorize: Arc::new(move || {
                let checks = Arc::clone(&authorize_checks);
                Box::pin(async move { checks.fetch_add(1, Ordering::SeqCst) == 0 })
            }),
        };

        let error = tokio::time::timeout(Duration::from_secs(5), transport.receive())
            .await
            .expect("authorized receive completes")
            .expect_err("revocation after frame receipt rejects the frame");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        drop(transport);

        let mut prefix = [0; 4];
        let peer_closed = tokio::time::timeout(
            Duration::from_secs(2),
            client_receive.read_exact(&mut prefix),
        )
        .await
        .expect("revoked server closes peer stream");
        assert!(peer_closed.is_err());

        drop(client_send);
        connection.close(0u32.into(), b"test complete");
        peer.close(0u32.into(), b"test complete");
        tokio::time::timeout(Duration::from_secs(5), initiator.close())
            .await
            .expect("initiator endpoint closes");
        tokio::time::timeout(Duration::from_secs(5), responder.close())
            .await
            .expect("responder endpoint closes");
    }

    #[tokio::test]
    async fn management_outage_after_sql_sync_denies_kv_and_preserves_data() {
        let application_id = "00000000-0000-0000-0000-000000000001";
        let database_id = "00000000-0000-0000-0000-000000000002";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Management API stub");
        let address = listener.local_addr().expect("read Management address");
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let management_outage = Arc::new(AtomicBool::new(false));
        let stop_api = Arc::new(AtomicBool::new(false));
        let outage_for_api = Arc::clone(&management_outage);
        let stop_api_thread = Arc::clone(&stop_api);
        listener
            .set_nonblocking(true)
            .expect("make Management stub stoppable");
        let api_stub = thread::spawn(move || {
            let mut requests = Vec::new();
            while !stop_api_thread.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept Management request: {error}"),
                };
                let request = read_request(&mut stream);
                if request.starts_with("POST /idp/oauth2/token ") {
                    respond(
                        &mut stream,
                        "200 OK",
                        r#"{"access_token":"storage-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#,
                    );
                } else if outage_for_api.load(Ordering::SeqCst) {
                    respond(&mut stream, "503 Service Unavailable", "{}");
                } else if request.starts_with("GET /management/replication/devices/") {
                    let body = serde_json::to_string(&SelectedResourcesResponse {
                        resources: vec![SelectedResource {
                            owner_subject: String::from("owner-a"),
                            application_id: application_id.to_owned(),
                            kind: String::from("database"),
                            resource_id: database_id.to_owned(),
                        }],
                    })
                    .expect("serialize selection response");
                    respond(&mut stream, "200 OK", &body);
                } else {
                    assert!(request.starts_with("POST /management/replication/admission "));
                    stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .expect("allow Management admission");
                }
                requests.push(request);
            }
            requests_tx
                .send(requests)
                .expect("return Management requests");
        });

        let lookup = MemoryLookup::new();
        let storage_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind Storage endpoint");
        let peer_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind peer endpoint");
        lookup.add_endpoint_info(storage_endpoint.addr());
        let storage_server = Server::new(storage_endpoint, EndpointIdStore::default());
        let storage_id = storage_server.endpoint().id();
        let (peer_connection, storage_connection) =
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(peer_endpoint.connect(storage_id, DATA_ALPN), async {
                    storage_server
                        .endpoint()
                        .accept()
                        .await
                        .expect("incoming connection")
                        .accept()
                        .expect("accept incoming connection")
                        .await
                })
            })
            .await
            .expect("Iroh connection setup completes");
        let peer_connection = peer_connection.expect("peer connects to Storage");
        let storage_connection = storage_connection.expect("Storage accepts peer");
        let (mut peer_send, peer_recv) =
            tokio::time::timeout(Duration::from_secs(5), peer_connection.open_bi())
                .await
                .expect("peer opens bidirectional stream")
                .expect("peer stream opens");
        peer_send
            .write_all(&[DATABASE_STREAM_KIND])
            .await
            .expect("write database stream kind");
        let (storage_send, mut storage_recv) =
            tokio::time::timeout(Duration::from_secs(5), storage_connection.accept_bi())
                .await
                .expect("Storage accepts bidirectional stream")
                .expect("Storage stream opens");
        let mut stream_kind = [0; 1];
        storage_recv
            .read_exact(&mut stream_kind)
            .await
            .expect("read database stream kind");
        assert_eq!(stream_kind[0], DATABASE_STREAM_KIND);
        let peer_transport = IrohTransport::new(peer_send, peer_recv);

        let application_id = application_id.to_owned();
        let database_id = database_id.to_owned();
        let root = std::env::temp_dir().join(format!(
            "storage-management-outage-{}",
            idp_model::model::Id::now_v7()
        ));
        let namespace = Namespace {
            owner_subject: String::from("owner-a"),
            application_id: application_id.parse().expect("valid application ID"),
        };
        let database_id = database_id.parse().expect("valid database ID");
        let source_runtime =
            DatabaseRuntime::new(root.join("source")).expect("create source DB runtime");
        let destination_runtime =
            DatabaseRuntime::new(root.join("destination")).expect("create destination DB runtime");
        let source_database = source_runtime
            .open_selected(&namespace, database_id)
            .expect("open source selected DB")
            .expect("source DB remains selected");
        let destination_database = destination_runtime
            .open_selected(&namespace, database_id)
            .expect("open destination selected DB")
            .expect("destination DB remains selected");
        let source_kv = source_runtime
            .open_kv_selected(&namespace, database_id)
            .expect("open source KV store")
            .expect("source KV store remains selected");
        let destination_kv = destination_runtime
            .open_kv_selected(&namespace, database_id)
            .expect("open destination KV store")
            .expect("destination KV store remains selected");
        let databases = Arc::new(
            DatabaseRuntime::new(root.join("handler")).expect("create handler DB runtime"),
        );
        let management = ManagementClient::new(
            &format!("http://{address}/management/"),
            &format!("http://{address}/idp/"),
            "storage-client",
            "test-secret",
            "https://idp.example",
            "management-api",
        )
        .expect("create Management client");
        let handler = DatabaseProtocolHandler::new(
            storage_server.clone(),
            management,
            databases,
            root.join("sync-staging"),
            tokio_util::sync::CancellationToken::new(),
        );
        let resource = DatabaseResourceDescriptor {
            owner_subject: String::from("owner-a"),
            application_id,
            database_id: database_id.to_string(),
        };
        assert!(
            handler
                .authorize_bounded(&resource, &storage_connection)
                .await,
            "initial Management authorization succeeds before the injected outage"
        );
        let authorizer_handler = handler.clone();
        let authorizer_resource = resource.clone();
        let authorizer_connection = storage_connection.clone();
        let mut transport = AuthorizedTransport {
            transport: IrohTransport::new(storage_send, storage_recv),
            authorize: Arc::new(move || {
                let handler = authorizer_handler.clone();
                let resource = authorizer_resource.clone();
                let connection = authorizer_connection.clone();
                Box::pin(async move { handler.authorize_bounded(&resource, &connection).await })
            }),
        };

        source_database
            .client()
            .execute_sql(
                "CREATE TABLE outage_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");
        source_database
            .client()
            .execute_sql(
                "INSERT INTO outage_rows VALUES (CAST('018f0f8e-7b6d-7c4a-8f12-123456789abc' AS UUID), 'retained')",
                None,
            )
            .await
            .expect("insert source row");
        let mut source_kv_transaction = source_kv
            .transaction()
            .await
            .expect("open source KV transaction");
        source_kv_transaction
            .set("outage-key", ofdb_sql::Value::Blob(vec![1, 2, 3]), None)
            .await
            .expect("write source KV value");
        source_kv_transaction
            .commit()
            .await
            .expect("commit source KV value");
        let destination_for_sync = Arc::clone(&destination_database);
        let destination_kv_for_sync = Arc::clone(&destination_kv);
        let peer_sync = tokio::spawn(async move {
            let mut transport = AuthorizedTransport {
                transport: peer_transport,
                authorize: Arc::new(|| Box::pin(async { true })),
            };
            destination_for_sync
                .synchronize(
                    &mut transport,
                    &SessionConfig::default(),
                    SyncRole::Responder,
                )
                .await
                .expect("peer completes the SQL phase before KV begins");
            let kv_result = ofdb_kv_sync::synchronize(
                &destination_kv_for_sync,
                &mut KvAuthorizedTransport {
                    transport: &mut transport,
                },
                ofdb_kv_sync::SyncRole::Responder,
                ofdb_kv_sync::Config::default(),
            )
            .await;
            (kv_result, transport.transport)
        });
        source_database
            .synchronize(
                &mut transport,
                &SessionConfig::default(),
                SyncRole::Initiator,
            )
            .await
            .expect("live SQL phase completes before the Management outage");
        management_outage.store(true, Ordering::SeqCst);
        let kv_error = ofdb_kv_sync::synchronize(
            &source_kv,
            &mut KvAuthorizedTransport {
                transport: &mut transport,
            },
            ofdb_kv_sync::SyncRole::Initiator,
            ofdb_kv_sync::Config::default(),
        )
        .await
        .expect_err("Management outage denies the next KV operation");
        assert!(
            format!("{kv_error:?}").to_lowercase().contains("transport"),
            "unexpected KV sync error: {kv_error:?}"
        );
        drop(transport);
        let destination_rows = destination_database
            .client()
            .execute_sql("SELECT value FROM outage_rows", None)
            .await
            .expect("completed SQL phase remains committed");
        assert_eq!(destination_rows[0].rows.len(), 1);
        let source_rows = source_database
            .client()
            .execute_sql("SELECT value FROM outage_rows", None)
            .await
            .expect("source table remains available");
        assert_eq!(source_rows[0].rows.len(), 1, "source row is retained");
        let destination_kv_transaction = destination_kv
            .transaction()
            .await
            .expect("open destination KV transaction");
        assert!(
            destination_kv_transaction
                .get("outage-key", 0)
                .await
                .expect("read destination KV value")
                .is_none(),
            "KV data is not applied after Management denies the session"
        );
        let source_kv_transaction = source_kv
            .transaction()
            .await
            .expect("open source KV transaction");
        assert!(
            source_kv_transaction
                .get("outage-key", 0)
                .await
                .expect("read source KV value")
                .is_some(),
            "source KV data remains available"
        );
        destination_kv_transaction
            .rollback()
            .await
            .expect("rollback destination KV read transaction");
        source_kv_transaction
            .rollback()
            .await
            .expect("rollback source KV read transaction");
        let (peer_error, mut peer_transport) = peer_sync.await.expect("peer sync task joins");
        assert!(peer_error.is_err(), "peer KV phase observes stream closure");

        stop_api.store(true, Ordering::SeqCst);
        let requests = requests_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("Management handles policy outage requests");
        api_stub.join().expect("Management API stub completes");
        assert!(requests.len() > 6, "SQL phase completes with policy checks");
        assert!(
            requests.iter().any(|request| {
                request.starts_with("GET /management/replication/devices/")
                    && requests.last().is_some_and(|last| last == request)
            }),
            "final policy request is the denied Management lookup"
        );
        let closed = tokio::time::timeout(Duration::from_secs(2), peer_transport.receive())
            .await
            .expect("peer stream closes after policy outage");
        assert!(closed.is_err());

        storage_server.endpoint().close().await;
        peer_endpoint.close().await;
        std::fs::remove_dir_all(root).expect("remove temporary database root");
    }

    #[tokio::test]
    async fn timed_out_sql_frame_read_closes_the_real_iroh_stream() {
        let lookup = MemoryLookup::new();
        let initiator = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind initiator endpoint");
        let responder = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"storage-timeout-test".to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind responder endpoint");
        lookup.add_endpoint_info(responder.addr());

        let (connection, peer) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                initiator.connect(responder.id(), b"storage-timeout-test"),
                async {
                    responder
                        .accept()
                        .await
                        .expect("incoming connection")
                        .accept()
                        .expect("start accepting")
                        .await
                }
            )
        })
        .await
        .expect("Iroh connection setup completes");
        let connection = connection.expect("connect endpoints");
        let peer = peer.expect("accept connection");
        let (mut client_send, mut client_receive) =
            tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
                .await
                .expect("open client stream")
                .expect("client stream opens");
        client_send
            .write_all(&[0, 0])
            .await
            .expect("send incomplete frame prefix");
        let (server_send, server_receive) =
            tokio::time::timeout(Duration::from_secs(10), peer.accept_bi())
                .await
                .expect("accept server stream")
                .expect("server stream opens");
        let mut transport = AuthorizedTransport {
            transport: IrohTransport::new(server_send, server_receive),
            authorize: Arc::new(|| Box::pin(async { true })),
        };

        let error = sync_timeout::run(
            Duration::from_millis(20),
            "database sync operation timed out",
            async { transport.receive().await },
        )
        .await
        .expect_err("stalled authorized frame read must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(transport);

        let mut prefix = [0; 4];
        let peer_closed = tokio::time::timeout(
            Duration::from_secs(2),
            client_receive.read_exact(&mut prefix),
        )
        .await
        .expect("timed-out server read closes peer stream");
        assert!(peer_closed.is_err());

        drop(client_send);
        connection.close(0u32.into(), b"test complete");
        peer.close(0u32.into(), b"test complete");
        tokio::time::timeout(Duration::from_secs(5), initiator.close())
            .await
            .expect("initiator endpoint closes");
        tokio::time::timeout(Duration::from_secs(5), responder.close())
            .await
            .expect("responder endpoint closes");
    }

    #[test]
    fn server_shutdown_cancels_active_database_staging() {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build test runtime")
            .block_on(async {
        let application_id = idp_model::model::Id::now_v7();
        let namespace = Namespace {
            owner_subject: String::from("owner-a"),
            application_id,
        };
        let root = std::env::temp_dir().join(format!(
            "storage-database-handler-timeout-{}",
            idp_model::model::Id::now_v7()
        ));
        let databases = Arc::new(DatabaseRuntime::new(root.clone()).expect("create runtime"));
        let (resource, _) = databases
            .create(&namespace, Some(String::from("timeout test")))
            .expect("create selected database");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Management API stub");
        let address = listener.local_addr().expect("read API stub address");
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let api_shutdown = Arc::new(AtomicBool::new(false));
        let api_shutdown_thread = Arc::clone(&api_shutdown);
        listener
            .set_nonblocking(true)
            .expect("make Management stub cancellable");
        let application_id_text = application_id.to_string();
        let database_id_text = resource.id.to_string();
        let api_application_id = application_id_text.clone();
        let api_database_id = database_id_text.clone();
        let api_stub = thread::spawn(move || {
            let mut requests = Vec::new();
            while !api_shutdown_thread.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept Management request: {error}"),
                };
                let request = read_request(&mut stream);
                if !request.contains("\r\n\r\n") {
                    continue;
                }
                if request.starts_with("POST /idp/oauth2/token ") {
                    respond_during_shutdown(
                        &mut stream,
                        "200 OK",
                        r#"{"access_token":"storage-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#,
                    );
                } else if request.starts_with("GET /management/replication/devices/") {
                    let body = serde_json::to_string(&SelectedResourcesResponse {
                        resources: vec![SelectedResource {
                            owner_subject: String::from("owner-a"),
                            application_id: api_application_id.clone(),
                            kind: String::from("database"),
                            resource_id: api_database_id.clone(),
                        }],
                    })
                    .expect("serialize selected resource");
                    respond_during_shutdown(&mut stream, "200 OK", &body);
                } else {
                    assert!(request.starts_with("POST /management/replication/admission "));
                    if let Err(error) = stream.write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    ) {
                        assert!(
                            matches!(
                                error.kind(),
                                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                            ),
                            "write Management admission response during shutdown: {error}"
                        );
                    }
                }
                requests.push(request);
            }
            requests_tx
                .send(requests)
                .expect("return Management requests");
        });

        let lookup = MemoryLookup::new();
        let storage_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind Storage endpoint");
        let peer_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind peer endpoint");
        lookup.add_endpoint_info(storage_endpoint.addr());
        lookup.add_endpoint_info(peer_endpoint.addr());
        let storage_id = storage_endpoint.id();
        let peer_id = peer_endpoint.id();
        let storage_peers = EndpointIdStore::default();
        storage_peers.add(peer_id);
        let storage_server = Server::new(storage_endpoint, storage_peers);
        let (connection, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(peer_endpoint.connect(storage_id, DATA_ALPN), async {
                storage_server
                    .endpoint()
                    .accept()
                    .await
                    .expect("incoming Iroh connection")
                    .accept()
                    .expect("accept incoming Iroh connection")
                    .await
            })
        })
        .await
        .expect("Iroh connection setup completes");
        let connection = connection.expect("peer connects to Storage");
        let accepted = accepted.expect("Storage accepts peer");
        let (mut client_send, mut client_receive) =
            connection.open_bi().await.expect("open client sync stream");
        let handshake = serde_json::json!({
            "resource": {
                "owner_subject": "owner-a",
                "application_id": application_id_text,
                "database_id": database_id_text
            },
            "deleted": false
        });
        let frame = serde_json::to_vec(&handshake).expect("serialize database handshake");
        client_send
            .write_all(&[DATABASE_STREAM_KIND])
            .await
            .expect("write stream kind");
        client_send
            .write_all(&(frame.len() as u32).to_be_bytes())
            .await
            .expect("write handshake length");
        client_send
            .write_all(&frame)
            .await
            .expect("write handshake frame");
        let (server_send, mut server_receive) = accepted
            .accept_bi()
            .await
            .expect("Storage accepts sync stream");
        let mut stream_kind = [0; 1];
        server_receive
            .read_exact(&mut stream_kind)
            .await
            .expect("read database stream kind");
        assert_eq!(stream_kind[0], DATABASE_STREAM_KIND);

        let management = ManagementClient::new(
            &format!("http://{address}/management/"),
            &format!("http://{address}/idp/"),
            "storage-client",
            "test-secret",
            "https://idp.example",
            "management-api",
        )
        .expect("create Management client");
        let shutdown = tokio_util::sync::CancellationToken::new();
        let staging_directory = root.join("sync-staging");
        let handler = DatabaseProtocolHandler::new(
            storage_server.clone(),
            management,
            Arc::clone(&databases),
            staging_directory.clone(),
            shutdown.clone(),
        );
        handler
            .accept_stream_with_timeout(
                accepted,
                server_send,
                server_receive,
                Duration::from_secs(60),
            )
            .await;

        let mut ack_length = [0; 4];
        client_receive
            .read_exact(&mut ack_length)
            .await
            .expect("read handshake acknowledgement length");
        let mut ack = vec![0; u32::from_be_bytes(ack_length) as usize];
        client_receive
            .read_exact(&mut ack)
            .await
            .expect("read handshake acknowledgement");
        assert_eq!(ack, b"OK");

        let source_database = Database::open(root.join("source.redb")).expect("open source DB");
        source_database
            .client()
            .execute_sql(
                "CREATE TABLE shutdown_rows (id UUID PRIMARY KEY, value TEXT)",
                None,
            )
            .await
            .expect("create source table");
        source_database
            .client()
            .execute_sql(
                "INSERT INTO shutdown_rows VALUES (CAST('018f0f8e-7b6d-7c4a-8f12-123456789abc' AS UUID), 'staged')",
                None,
            )
            .await
            .expect("insert source row");
        let peer_sync = tokio::spawn(async move {
            let mut transport = IrohTransport::new(client_send, client_receive);
            source_database
                .synchronize(
                    &mut transport,
                    &SessionConfig::default(),
                    SyncRole::Initiator,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let files = match std::fs::read_dir(&staging_directory) {
                    Ok(files) => files,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(error) => panic!("read database stage directory: {error}"),
                };
                if files
                    .filter_map(Result::ok)
                    .any(|entry| entry.metadata().is_ok_and(|metadata| metadata.len() > 0))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("database sync writes staged records before shutdown");
        shutdown.cancel();
        let peer_result = tokio::time::timeout(Duration::from_secs(3), peer_sync)
            .await
            .expect("peer sync stops after server shutdown")
            .expect("peer sync task joins");
        assert!(peer_result.is_err(), "shutdown interrupts peer sync");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let remaining = std::fs::read_dir(&staging_directory)
                    .map(|files| files.count())
                    .unwrap_or(0);
                if remaining == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server shutdown removes active sync stage files");

        api_shutdown.store(true, Ordering::SeqCst);
        let requests = requests_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("Management authorization checks complete");
        api_stub.join().expect("Management API stub stops");
        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("POST /idp/oauth2/token "))
        );
        assert!(
            requests
                .iter()
                .filter(|request| request.starts_with("GET /management/replication/devices/"))
                .count()
                >= 2
        );
        assert!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST /management/replication/admission "))
                .count()
                >= 2
        );

        connection.close(0u32.into(), b"test complete");
        storage_server.endpoint().close().await;
        peer_endpoint.close().await;
        std::fs::remove_dir_all(root).expect("remove test database root");
            });
    }

    #[tokio::test]
    async fn data_stream_rejects_management_denial_and_outage() {
        data_stream_rejects_admission_status("403 Forbidden").await;
        data_stream_rejects_admission_status("503 Service Unavailable").await;
    }

    async fn data_stream_rejects_admission_status(admission_status: &str) {
        let application_id = "00000000-0000-0000-0000-000000000001";
        let database_id = "00000000-0000-0000-0000-000000000002";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind API stub");
        let address = listener.local_addr().expect("read API stub address");
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let admission_status = admission_status.to_owned();
        let api_stub = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let token_request = read_request(&mut token_stream);
            respond(
                &mut token_stream,
                "200 OK",
                r#"{"access_token":"storage-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#,
            );
            let selection_response = serde_json::to_string(&SelectedResourcesResponse {
                resources: vec![SelectedResource {
                    owner_subject: "owner-a".to_owned(),
                    application_id: application_id.to_owned(),
                    kind: "database".to_owned(),
                    resource_id: database_id.to_owned(),
                }],
            })
            .expect("serialize selection response");
            let (mut selection_stream, _) = listener.accept().expect("accept selection request");
            let selection_request = read_request(&mut selection_stream);
            respond(&mut selection_stream, "200 OK", &selection_response);
            let (mut admission_stream, _) = listener.accept().expect("accept admission request");
            let admission_request = read_request(&mut admission_stream);
            respond(&mut admission_stream, &admission_status, "{}");
            requests_tx
                .send((token_request, selection_request, admission_request))
                .expect("send captured requests");
        });

        let lookup = MemoryLookup::new();
        let storage_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind Storage endpoint");
        let peer_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind peer endpoint");
        lookup.add_endpoint_info(storage_endpoint.addr());
        lookup.add_endpoint_info(peer_endpoint.addr());
        let storage_id = storage_endpoint.id();
        let peer_id = peer_endpoint.id();
        let storage_peers = EndpointIdStore::default();
        storage_peers.add(peer_id);
        let storage_server = Server::new(storage_endpoint, storage_peers);
        let peer_peers = EndpointIdStore::default();
        peer_peers.add(storage_id);
        let peer_server = Server::new(peer_endpoint, peer_peers);
        let management = ManagementClient::new(
            &format!("http://{address}/management"),
            &format!("http://{address}/idp"),
            "storage-client",
            "test-secret",
            "https://idp.example",
            "management-api",
        )
        .expect("create Management client");
        let root = std::env::temp_dir().join(format!(
            "storage-database-stream-{}",
            idp_model::model::Id::now_v7()
        ));
        let databases =
            Arc::new(DatabaseRuntime::new(root.clone()).expect("create database runtime"));
        let protocol = DatabaseProtocolHandler::new(
            storage_server.clone(),
            management,
            databases,
            root.join("sync-staging"),
            tokio_util::sync::CancellationToken::new(),
        );
        let _router = storage_server.router(protocol);
        let connection = peer_server
            .connect_direct_with_alpn(storage_id, DATA_ALPN)
            .await
            .expect("connect to Storage endpoint");
        let (mut send, mut recv) = connection.open_bi().await.expect("open DATA stream");
        let handshake = serde_json::json!({
            "resource": {
                "owner_subject": "owner-a",
                "application_id": application_id,
                "database_id": database_id
            },
            "deleted": false
        });
        let frame = serde_json::to_vec(&handshake).expect("serialize handshake");
        send.write_all(&[1])
            .await
            .expect("write database stream kind");
        send.write_all(&(frame.len() as u32).to_be_bytes())
            .await
            .expect("write handshake length");
        send.write_all(&frame).await.expect("write handshake");
        send.finish().expect("finish request stream");
        let mut acknowledgement = [0; 6];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv.read_exact(&mut acknowledgement),
        )
        .await
        .expect("server responds to denied stream");
        assert!(
            result.is_err(),
            "denied stream must not receive an acknowledgement"
        );

        let (token_request, selection_request, admission_request) =
            requests_rx.recv().expect("receive captured API requests");
        api_stub.join().expect("API stub completes");
        assert!(token_request.starts_with("POST /idp/oauth2/token HTTP/1.1"));
        assert!(selection_request.starts_with("GET /management/replication/devices/"));
        assert!(admission_request.starts_with("POST /management/replication/admission HTTP/1.1"));
        let admission_body = admission_request
            .split_once("\r\n\r\n")
            .expect("admission request has body")
            .1;
        let admission: serde_json::Value =
            serde_json::from_str(admission_body).expect("admission body is JSON");
        assert_eq!(admission["sourceEndpointId"], storage_id.to_string());
        assert_eq!(admission["targetEndpointId"], peer_id.to_string());

        storage_server.endpoint().close().await;
        peer_server.endpoint().close().await;
        std::fs::remove_dir_all(root).expect("remove database test directory");
    }

    #[tokio::test]
    async fn authorization_rejects_spoofed_descriptor_claims_before_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind API stub");
        let address = listener.local_addr().expect("read API stub address");
        let (requests_tx, requests_rx) = std::sync::mpsc::channel();
        let api_stub = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let token_request = read_request(&mut token_stream);
            respond(
                &mut token_stream,
                "200 OK",
                r#"{"access_token":"storage-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#,
            );

            let selection_response = serde_json::to_string(&SelectedResourcesResponse {
                resources: vec![SelectedResource {
                    owner_subject: "owner-a".to_owned(),
                    application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                    kind: "database".to_owned(),
                    resource_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                }],
            })
            .expect("serialize selection response");
            let mut selection_requests = Vec::new();
            for _ in 0..4 {
                let (mut selection_stream, _) =
                    listener.accept().expect("accept selection request");
                selection_requests.push(read_request(&mut selection_stream));
                respond(&mut selection_stream, "200 OK", &selection_response);
            }
            let (mut admission_stream, _) = listener.accept().expect("accept admission request");
            let admission_request = read_request(&mut admission_stream);
            respond(&mut admission_stream, "403 Forbidden", "{}");
            requests_tx
                .send((token_request, selection_requests, admission_request))
                .expect("send captured requests");
        });

        let lookup = MemoryLookup::new();
        let storage_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind Storage endpoint");
        let peer_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind peer endpoint");
        lookup.add_endpoint_info(storage_endpoint.addr());
        lookup.add_endpoint_info(peer_endpoint.addr());

        let storage_id = storage_endpoint.id();
        let peer_id = peer_endpoint.id();
        let storage_peers = EndpointIdStore::default();
        storage_peers.add(peer_id);
        let storage_server = Server::new(storage_endpoint, storage_peers);
        let peer_peers = EndpointIdStore::default();
        peer_peers.add(storage_id);
        let peer_server = Server::new(peer_endpoint, peer_peers);
        let _router = peer_server.router(TestProtocol);
        let connection = storage_server
            .connect_direct_with_alpn(peer_id, DATA_ALPN)
            .await
            .expect("connect to peer endpoint");

        let management = ManagementClient::new(
            &format!("http://{address}/management"),
            &format!("http://{address}/idp"),
            "storage-client",
            "test-secret",
            "https://idp.example",
            "management-api",
        )
        .expect("create Management client");
        let root = std::env::temp_dir().join(format!(
            "storage-database-protocol-{}",
            idp_model::model::Id::now_v7()
        ));
        let databases =
            Arc::new(DatabaseRuntime::new(root.clone()).expect("create database runtime"));
        let handler = DatabaseProtocolHandler::new(
            storage_server.clone(),
            management,
            databases,
            root.join("sync-staging"),
            tokio_util::sync::CancellationToken::new(),
        );
        for descriptor in [
            DatabaseResourceDescriptor {
                owner_subject: "spoofed-owner".to_owned(),
                application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                database_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            },
            DatabaseResourceDescriptor {
                owner_subject: "owner-a".to_owned(),
                application_id: "00000000-0000-0000-0000-000000000003".to_owned(),
                database_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            },
            DatabaseResourceDescriptor {
                owner_subject: "owner-a".to_owned(),
                application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                database_id: "00000000-0000-0000-0000-000000000004".to_owned(),
            },
        ] {
            assert!(
                !handler.authorize(&descriptor, &connection).await,
                "spoofed owner/application/resource claims must be rejected"
            );
        }
        assert!(
            !handler
                .authorize(
                    &DatabaseResourceDescriptor {
                        owner_subject: "owner-a".to_owned(),
                        application_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                        database_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                    },
                    &connection,
                )
                .await,
            "Management admission denial must reject an otherwise selected resource"
        );

        let (token_request, selection_requests, admission_request) =
            requests_rx.recv().expect("receive captured API requests");
        api_stub.join().expect("API stub completes");
        assert!(token_request.starts_with("POST /idp/oauth2/token HTTP/1.1"));
        assert_eq!(selection_requests.len(), 4);
        assert!(
            selection_requests
                .iter()
                .all(|request| request.starts_with("GET /management/replication/devices/"))
        );
        assert!(admission_request.starts_with("POST /management/replication/admission HTTP/1.1"));

        storage_server.endpoint().close().await;
        peer_server.endpoint().close().await;
        std::fs::remove_dir_all(root).expect("remove database test directory");
    }
}
