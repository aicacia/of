#[cfg(test)]
mod database_protocol_tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
        thread,
    };

    use iroh::{
        Endpoint,
        address_lookup::MemoryLookup,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler},
    };
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
    use model::contract::{SelectedResource, SelectedResourcesResponse};
    use storage_service::DatabaseRuntime;

    use crate::{
        ManagementClient,
        database_protocol::{DatabaseProtocolHandler, DatabaseResourceDescriptor},
    };

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
        let protocol = DatabaseProtocolHandler::new(storage_server.clone(), management, databases);
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
        let handler = DatabaseProtocolHandler::new(storage_server.clone(), management, databases);
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
