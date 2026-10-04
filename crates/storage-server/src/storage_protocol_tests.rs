#[cfg(test)]
mod protocol_tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
        thread,
    };

    use file_system::{FileSessionService, IrohResourceDescriptor, OpenRequest};
    use iroh::{
        Endpoint,
        address_lookup::MemoryLookup,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler},
    };
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
    use model::contract::{SelectedResource, SelectedResourcesResponse};
    use storage_service::{FileSystemId, ScopedFileSystemRuntime};

    use crate::{ManagementClient, storage_protocol::StorageProtocolHandler};

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
            assert_ne!(read, 0, "HTTP request ended before its headers");
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

    fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write HTTP response");
    }

    #[tokio::test]
    async fn data_stream_rejects_management_denial_and_outage() {
        data_stream_rejects_admission_status("403 Forbidden").await;
        data_stream_rejects_admission_status("503 Service Unavailable").await;
    }

    async fn data_stream_rejects_admission_status(admission_status: &str) {
        let application_id = idp_model::model::Id::now_v7().to_string();
        let filesystem_id = FileSystemId::new().as_uuid().to_string();
        let selected_application_id = application_id.clone();
        let selected_filesystem_id = filesystem_id.clone();
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
                    application_id: selected_application_id,
                    kind: "filesystem".to_owned(),
                    resource_id: selected_filesystem_id,
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
            "storage-filesystem-stream-{}",
            idp_model::model::Id::now_v7()
        ));
        let file_systems = Arc::new(
            ScopedFileSystemRuntime::<iroh::EndpointId>::new(root.clone(), storage_id)
                .expect("create filesystem runtime"),
        );
        let protocol =
            StorageProtocolHandler::new(storage_server.clone(), management, file_systems);
        let _router = storage_server.router(protocol);
        let connection = peer_server
            .connect_direct_with_alpn(storage_id, DATA_ALPN)
            .await
            .expect("connect to Storage endpoint");
        let transport = file_system::IrohFileTransport::open_authorized(
            &connection,
            IrohResourceDescriptor {
                owner_subject: "owner-a".to_owned(),
                application_id,
                filesystem_id,
            },
            |_| async { true },
        )
        .await
        .expect("send filesystem handshake");
        let (token_request, selection_request, admission_request) =
            tokio::task::spawn_blocking(move || {
                requests_rx.recv().expect("receive captured API requests")
            })
            .await
            .expect("API stub task completes");
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
        let open_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transport.open(
                storage_id,
                OpenRequest {
                    path: "denied.txt".to_owned(),
                    revision: None,
                },
            ),
        )
        .await
        .expect("denied filesystem stream closes promptly");
        assert!(
            open_result.is_err(),
            "denied stream must not acknowledge file operations"
        );
        assert!(
            !root.join("filesystems").exists(),
            "denied stream must not create a filesystem projection"
        );
        transport.close();

        storage_server.endpoint().close().await;
        peer_server.endpoint().close().await;
        std::fs::remove_dir_all(root).expect("remove filesystem test directory");
    }

    #[tokio::test]
    async fn authorization_rejects_spoofed_descriptor_claims_before_admission() {
        let application_id = idp_model::model::Id::now_v7().to_string();
        let spoofed_application_id = idp_model::model::Id::now_v7().to_string();
        let filesystem_id = FileSystemId::new().as_uuid().to_string();
        let spoofed_filesystem_id = FileSystemId::new().as_uuid().to_string();
        let selected_application_id = application_id.clone();
        let selected_filesystem_id = filesystem_id.clone();
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
                    application_id: selected_application_id,
                    kind: "filesystem".to_owned(),
                    resource_id: selected_filesystem_id,
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
            "storage-filesystem-protocol-{}",
            idp_model::model::Id::now_v7()
        ));
        let file_systems = Arc::new(
            ScopedFileSystemRuntime::<iroh::EndpointId>::new(root.clone(), storage_id)
                .expect("create filesystem runtime"),
        );
        let handler = StorageProtocolHandler::new(storage_server.clone(), management, file_systems);
        for resource in [
            IrohResourceDescriptor {
                owner_subject: "spoofed-owner".to_owned(),
                application_id: application_id.clone(),
                filesystem_id: filesystem_id.clone(),
            },
            IrohResourceDescriptor {
                owner_subject: "owner-a".to_owned(),
                application_id: spoofed_application_id,
                filesystem_id: filesystem_id.clone(),
            },
            IrohResourceDescriptor {
                owner_subject: "owner-a".to_owned(),
                application_id: application_id.clone(),
                filesystem_id: spoofed_filesystem_id,
            },
        ] {
            assert!(
                !handler.authorize(&resource, &connection).await,
                "spoofed owner/application/resource claims must be rejected"
            );
        }
        assert!(
            !handler
                .authorize(
                    &IrohResourceDescriptor {
                        owner_subject: "owner-a".to_owned(),
                        application_id,
                        filesystem_id,
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
        std::fs::remove_dir_all(root).expect("remove filesystem test directory");
    }
}
