use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use iroh::endpoint::Connection;
use iroh_chain::Server;
use model::contract::{
    ReplicationAdmissionRequest, SelectedResourcesResponse, TokenResponse, TokenType,
};
use reqwest::{Client, Url, redirect::Policy};
use serde::Serialize;

const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const RENEWAL_MARGIN: Duration = Duration::from_secs(15);
const REPLICATION_SCOPES: &str = "management.replication.read management.replication.admit";

#[derive(Clone)]
pub struct ManagementClient {
    management_base_url: Url,
    idp_base_url: Url,
    client_id: String,
    client_secret: String,
    issuer: String,
    audience: String,
    client: Client,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
}

struct CachedToken {
    value: String,
    valid_until: SystemTime,
}

#[derive(Serialize)]
struct ClientCredentialsRequest<'a> {
    grant_type: &'static str,
    client_id: &'a str,
    client_secret: &'a str,
    scope: &'static str,
    audience: &'a str,
}

impl ManagementClient {
    pub fn new(
        management_api_base: &str,
        idp_api_base: &str,
        client_id: &str,
        client_secret: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, String> {
        if client_id.trim().is_empty() || client_secret.is_empty() || audience.trim().is_empty() {
            return Err("Management OAuth client ID, secret and audience are required".to_owned());
        }
        let issuer = validate_http_url(issuer, "IdP issuer URL")?;
        let management_base_url = normalize_base_url(management_api_base, "Management API URL")?;
        let idp_base_url = normalize_base_url(idp_api_base, "IdP API URL")?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "could not create Management HTTP client".to_owned())?;
        Ok(Self {
            management_base_url,
            idp_base_url,
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            issuer: issuer.to_string().trim_end_matches('/').to_owned(),
            audience: audience.to_owned(),
            client,
            cached_token: Arc::new(Mutex::new(None)),
        })
    }

    async fn service_access_token(&self) -> Result<String, String> {
        if let Some(token) = self
            .cached_token
            .lock()
            .map_err(|_| "Management service token cache is unavailable".to_owned())?
            .as_ref()
            .filter(|token| {
                token
                    .valid_until
                    .duration_since(SystemTime::now())
                    .is_ok_and(|remaining| remaining > RENEWAL_MARGIN)
            })
            .map(|token| token.value.clone())
        {
            return Ok(token);
        }
        let url = self
            .idp_base_url
            .join("oauth2/token")
            .map_err(|_| "invalid IdP token endpoint URL".to_owned())?;
        let mut response = self
            .client
            .post(url)
            .form(&ClientCredentialsRequest {
                grant_type: "client_credentials",
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                scope: REPLICATION_SCOPES,
                audience: &self.audience,
            })
            .send()
            .await
            .map_err(|_| "IdP token endpoint is unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err("IdP rejected the Storage service client".to_owned());
        }
        let body = read_limited_body(&mut response, "IdP token response").await?;
        let token: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| "invalid IdP token response".to_owned())?;
        if token.token_type != TokenType::Bearer
            || token.issuer.as_deref() != Some(self.issuer.as_str())
            || !token.scope.as_deref().is_some_and(|granted| {
                let granted = granted.split_ascii_whitespace().collect::<Vec<_>>();
                REPLICATION_SCOPES
                    .split_ascii_whitespace()
                    .all(|required| granted.contains(&required))
            })
        {
            return Err("IdP returned an unauthorized Storage service token".to_owned());
        }
        let expires_in = token
            .expires_in
            .ok_or_else(|| "IdP service token has no expiry".to_owned())?;
        let valid_until = SystemTime::now()
            .checked_add(Duration::from_secs(expires_in))
            .ok_or_else(|| "IdP service token expiry is invalid".to_owned())?;
        let value = token.access_token.0;
        *self
            .cached_token
            .lock()
            .map_err(|_| "Management service token cache is unavailable".to_owned())? =
            Some(CachedToken {
                value: value.clone(),
                valid_until,
            });
        Ok(value)
    }

    pub async fn selected_resources(
        &self,
        endpoint_id: &str,
    ) -> Result<SelectedResourcesResponse, String> {
        let mut url = self
            .management_base_url
            .join("replication/devices/")
            .map_err(|_| "invalid Management replication URL".to_owned())?;
        url.path_segments_mut()
            .map_err(|_| "invalid Management replication URL".to_owned())?
            .pop_if_empty()
            .push(endpoint_id)
            .push("selections");
        let token = self.service_access_token().await?;
        let mut response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| "Management replication API is unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 | 403 => "Management rejected Storage replication-read permission".to_owned(),
                _ => "Management selected-resources request failed".to_owned(),
            });
        }
        let body = read_limited_body(&mut response, "Management selections response").await?;
        serde_json::from_slice(&body)
            .map_err(|_| "invalid Management selections response".to_owned())
    }

    pub async fn admit_peer_replication(
        &self,
        server: &Server,
        connection: &Connection,
        application_id: &str,
        kind: &str,
        resource_id: &str,
    ) -> Result<(), String> {
        let request = ReplicationAdmissionRequest {
            source_endpoint_id: server.endpoint().id().to_string(),
            target_endpoint_id: connection.remote_id().to_string(),
            application_id: application_id.to_owned(),
            kind: kind.to_owned(),
            resource_id: resource_id.to_owned(),
            operation: "synchronize".to_owned(),
        };
        let url = self
            .management_base_url
            .join("replication/admission")
            .map_err(|_| "invalid Management replication URL".to_owned())?;
        let token = self.service_access_token().await?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .map_err(|_| "Management replication API is unavailable".to_owned())?;
        if response.status().as_u16() == 204 {
            Ok(())
        } else {
            Err(match response.status().as_u16() {
                401 | 403 => "Management denied Storage replication admission".to_owned(),
                _ => "Management replication admission request failed".to_owned(),
            })
        }
    }
}

async fn read_limited_body(
    response: &mut reqwest::Response,
    description: &str,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("invalid {description}"))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
            return Err(format!("{description} is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn normalize_base_url(value: &str, description: &str) -> Result<Url, String> {
    let mut url = validate_http_url(value, description)?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn validate_http_url(value: &str, description: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("invalid {description}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() == "http" && !is_loopback(&url))
    {
        return Err(format!("{description} must use HTTPS except for loopback"));
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[cfg(feature = "network")]
    use iroh::{
        Endpoint,
        address_lookup::MemoryLookup,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler},
    };
    #[cfg(feature = "network")]
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};

    use super::ManagementClient;

    const CLIENT_ID: &str = "storage-service";
    const CLIENT_SECRET: &str = "test-secret";
    const ISSUER: &str = "https://idp.example";
    const AUDIENCE: &str = "https://management-api.example";

    #[test]
    fn validates_service_urls_and_credentials() {
        assert!(
            ManagementClient::new(
                "http://127.0.0.1:3000/management",
                "http://127.0.0.1:3000/idp",
                CLIENT_ID,
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE,
            )
            .is_ok()
        );
        assert!(
            ManagementClient::new(
                "http://management.example",
                "https://idp.example",
                CLIENT_ID,
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE,
            )
            .is_err()
        );
        assert!(
            ManagementClient::new(
                "https://management.example",
                "https://idp.example",
                CLIENT_ID,
                CLIENT_SECRET,
                "http://issuer.example",
                AUDIENCE,
            )
            .is_err()
        );
        assert!(
            ManagementClient::new(
                "https://management.example",
                "https://idp.example",
                "",
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn reacquires_expired_service_token() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept token request");
                let mut request = [0; 4096];
                let length = stream.read(&mut request).expect("read token request");
                let request = String::from_utf8_lossy(&request[..length]).into_owned();
                assert!(request.starts_with("POST /idp/oauth2/token HTTP/1.1"));
                let body = r#"{"access_token":"service-token","token_type":"Bearer","expires_in":0,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write token response");
            }
        });
        let client = ManagementClient::new(
            "http://127.0.0.1:3000/management",
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test Management client");

        assert_eq!(
            client.service_access_token().await.expect("first token"),
            "service-token"
        );
        assert_eq!(
            client.service_access_token().await.expect("renewed token"),
            "service-token"
        );
        server.join().expect("join test HTTP server");
    }

    #[tokio::test]
    async fn rejects_token_endpoint_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
        let address = listener.local_addr().expect("read token endpoint address");
        let redirect_listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        redirect_listener
            .set_nonblocking(true)
            .expect("make redirect target nonblocking");
        let redirect_address = redirect_listener
            .local_addr()
            .expect("read redirect target address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept token request");
            let mut request = [0; 4096];
            stream.read(&mut request).expect("read token request");
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{redirect_address}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirect response");
        });
        let client = ManagementClient::new(
            "http://127.0.0.1:3000/management",
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test Management client");

        assert!(client.service_access_token().await.is_err());
        server.join().expect("join test HTTP server");
        assert!(matches!(
            redirect_listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_token_response_without_caching() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept token request");
            let mut request = [0; 4096];
            stream.read(&mut request).expect("read token request");
            let mut body = r#"{"access_token":"service-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#.to_owned();
            body.push_str(&" ".repeat(65_537 - body.len()));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                .expect("write oversized token response");
        });
        let client = ManagementClient::new(
            "http://127.0.0.1:3000/management",
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test Management client");

        assert!(client.service_access_token().await.is_err());
        assert!(
            client
                .cached_token
                .lock()
                .expect("lock token cache")
                .is_none()
        );
        server.join().expect("join test HTTP server");
    }

    #[tokio::test]
    async fn rejects_service_token_acquisition_without_caching() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept token request");
            let mut request = [0; 4096];
            stream.read(&mut request).expect("read token request");
            let body = r#"{"error":"invalid_client"}"#;
            write!(stream, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write token rejection");
        });
        let client = ManagementClient::new(
            "http://127.0.0.1:3000/management",
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test Management client");

        assert!(client.service_access_token().await.is_err());
        assert!(
            client
                .cached_token
                .lock()
                .expect("lock token cache")
                .is_none()
        );
        server.join().expect("join test HTTP server");
    }

    #[cfg(feature = "network")]
    #[tokio::test]
    async fn admission_request_uses_local_and_authenticated_iroh_ids() {
        #[derive(Debug)]
        struct TestProtocol;

        impl ProtocolHandler for TestProtocol {
            async fn accept(
                &self,
                _connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
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
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let headers_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("HTTP request headers ended");
            let header_text = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = header_text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content length"))
                })
                .unwrap_or(0);
            let body_start = headers_end + 4;
            while request.len() < body_start + content_length {
                let read = stream.read(&mut buffer).expect("read HTTP request body");
                assert_ne!(read, 0, "HTTP request ended before its body");
                request.extend_from_slice(&buffer[..read]);
            }
            String::from_utf8(request).expect("HTTP request is UTF-8")
        }

        fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write HTTP response");
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP stub");
        let address = listener.local_addr().expect("read HTTP stub address");
        let (server_tx, server_rx) = std::sync::mpsc::channel();
        let http_server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let token_request = read_request(&mut token_stream);
            respond(
                &mut token_stream,
                "200 OK",
                r#"{"access_token":"service-token","token_type":"Bearer","expires_in":3600,"scope":"management.replication.read management.replication.admit","iss":"https://idp.example"}"#,
            );

            let mut admission_requests = Vec::new();
            for _ in 0..2 {
                let (mut admission_stream, _) =
                    listener.accept().expect("accept admission request");
                admission_requests.push(read_request(&mut admission_stream));
                respond(&mut admission_stream, "204 No Content", "");
            }
            server_tx
                .send((token_request, admission_requests))
                .expect("send captured requests");
        });

        let lookup = MemoryLookup::new();
        let source_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind source endpoint");
        let target_endpoint = Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind target endpoint");
        lookup.add_endpoint_info(source_endpoint.addr());
        lookup.add_endpoint_info(target_endpoint.addr());

        let source_id = source_endpoint.id();
        let target_id = target_endpoint.id();
        let source_allowed = EndpointIdStore::default();
        source_allowed.add(target_id);
        let source_server = Server::new(source_endpoint, source_allowed);
        let target_allowed = EndpointIdStore::default();
        target_allowed.add(source_id);
        let target_server = Server::new(target_endpoint, target_allowed);
        let _source_router = source_server.router(TestProtocol);
        let _target_router = target_server.router(TestProtocol);
        let connection = source_server
            .connect_direct_with_alpn(target_id, DATA_ALPN)
            .await
            .expect("connect to target Iroh endpoint");
        let reverse_connection = target_server
            .connect_direct_with_alpn(source_id, DATA_ALPN)
            .await
            .expect("connect to source Iroh endpoint");

        let client = ManagementClient::new(
            &format!("http://{address}/management"),
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("valid Management client configuration");
        client
            .admit_peer_replication(
                &source_server,
                &connection,
                "00000000-0000-0000-0000-000000000001",
                "database",
                "00000000-0000-0000-0000-000000000002",
            )
            .await
            .expect("Management accepts the replication admission request");
        client
            .admit_peer_replication(
                &target_server,
                &reverse_connection,
                "00000000-0000-0000-0000-000000000001",
                "database",
                "00000000-0000-0000-0000-000000000002",
            )
            .await
            .expect("Management accepts the reverse-side admission request");

        let (token_request, admission_requests) =
            server_rx.recv().expect("receive captured requests");
        http_server.join().expect("HTTP stub task completes");
        assert!(token_request.starts_with("POST /idp/oauth2/token HTTP/1.1"));
        assert_eq!(admission_requests.len(), 2);
        for request in &admission_requests {
            assert!(request.starts_with("POST /management/replication/admission HTTP/1.1"));
            assert!(request.contains("authorization: Bearer service-token"));
        }
        let parse_admission = |request: &str| {
            let body = request
                .split_once("\r\n\r\n")
                .expect("admission request has a body")
                .1;
            serde_json::from_str::<model::contract::ReplicationAdmissionRequest>(body)
                .expect("valid admission request body")
        };
        let forward_request = parse_admission(&admission_requests[0]);
        assert_eq!(forward_request.source_endpoint_id, source_id.to_string());
        assert_eq!(
            forward_request.target_endpoint_id,
            connection.remote_id().to_string()
        );
        assert_eq!(forward_request.target_endpoint_id, target_id.to_string());
        let reverse_request = parse_admission(&admission_requests[1]);
        assert_eq!(reverse_request.source_endpoint_id, target_id.to_string());
        assert_eq!(
            reverse_request.target_endpoint_id,
            reverse_connection.remote_id().to_string()
        );
        assert_eq!(reverse_request.target_endpoint_id, source_id.to_string());

        source_server.endpoint().close().await;
        target_server.endpoint().close().await;
    }

    #[test]
    fn retains_service_prefixes() {
        let client = ManagementClient::new(
            "http://127.0.0.1:3000/management",
            "http://127.0.0.1:3000/idp",
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("valid client configuration");
        assert_eq!(
            client
                .management_base_url
                .join("replication/devices/")
                .expect("join management route")
                .path(),
            "/management/replication/devices/"
        );
        assert_eq!(
            client
                .idp_base_url
                .join("oauth2/token")
                .expect("join token route")
                .path(),
            "/idp/oauth2/token"
        );
    }
}
