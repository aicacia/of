use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use iroh::EndpointId;

use idp_model::contract::{ApprovedDeviceEndpoints, IntrospectionRequest, IntrospectionResponse};
use model::contract::{TokenResponse, TokenType};
use reqwest::{Client, Url, redirect::Policy};
use serde::Serialize;

const MAX_RESPONSE_SIZE: usize = 64 * 1024;
const SERVICE_SCOPES: &str = "idp.device.lookup idp.device.list idp.token.validate";
const RENEWAL_MARGIN: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdpIntrospectionError {
    InvalidToken,
    ServiceUnavailable,
}

#[derive(Clone)]
pub struct IdpClient {
    base_url: Url,
    client_id: String,
    client_secret: String,
    issuer: String,
    audience: String,
    client: Client,
    cached_token: std::sync::Arc<Mutex<Option<CachedToken>>>,
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

impl IdpClient {
    pub fn new(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, String> {
        if client_id.trim().is_empty() || client_secret.is_empty() || audience.trim().is_empty() {
            return Err("IdP OAuth client ID, secret and service audience are required".to_owned());
        }
        let issuer_url = validate_http_url(issuer, "IdP issuer URL")?;
        let mut base_url = validate_http_url(base_url, "IdP API URL")?;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "could not create IdP HTTP client".to_owned())?;
        Ok(Self {
            base_url,
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            issuer: issuer_url.to_string().trim_end_matches('/').to_owned(),
            audience: audience.to_owned(),
            client,
            cached_token: std::sync::Arc::new(Mutex::new(None)),
        })
    }

    async fn service_access_token(&self) -> Result<String, String> {
        if let Some(token) = self
            .cached_token
            .lock()
            .map_err(|_| "IdP service token cache is unavailable".to_owned())?
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
            .base_url
            .join("oauth2/token")
            .map_err(|_| "invalid IdP token endpoint URL".to_owned())?;
        let mut response = self
            .client
            .post(url)
            .form(&ClientCredentialsRequest {
                grant_type: "client_credentials",
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                scope: SERVICE_SCOPES,
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
            || !token.scope.as_deref().is_some_and(|scope| {
                let granted = scope.split_ascii_whitespace().collect::<Vec<_>>();
                SERVICE_SCOPES
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
            .map_err(|_| "IdP service token cache is unavailable".to_owned())? =
            Some(CachedToken {
                value: value.clone(),
                valid_until,
            });
        Ok(value)
    }

    pub async fn introspect(
        &self,
        token: &str,
    ) -> Result<IntrospectionResponse, IdpIntrospectionError> {
        let url = self
            .base_url
            .join("oauth2/introspect")
            .map_err(|_| IdpIntrospectionError::ServiceUnavailable)?;
        let caller_token = self
            .service_access_token()
            .await
            .map_err(|_| IdpIntrospectionError::ServiceUnavailable)?;
        let mut response = self
            .client
            .post(url)
            .bearer_auth(caller_token)
            .json(&IntrospectionRequest {
                token: token.to_owned(),
                token_type_hint: Some("access_token".to_owned()),
            })
            .send()
            .await
            .map_err(|_| IdpIntrospectionError::ServiceUnavailable)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 => IdpIntrospectionError::InvalidToken,
                _ => IdpIntrospectionError::ServiceUnavailable,
            });
        }
        let body = read_limited_body(&mut response, "IdP introspection response")
            .await
            .map_err(|_| IdpIntrospectionError::ServiceUnavailable)?;
        serde_json::from_slice(&body).map_err(|_| IdpIntrospectionError::ServiceUnavailable)
    }

    pub async fn approved_storage_endpoints(&self) -> Result<Vec<String>, String> {
        let url = self
            .base_url
            .join("devices/endpoints")
            .map_err(|_| "invalid IdP endpoint list URL".to_owned())?;
        let token = self.service_access_token().await?;
        let mut response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| "IdP endpoint list is unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 | 403 => "IdP rejected Storage device lookup permission".to_owned(),
                _ => "IdP endpoint list failed".to_owned(),
            });
        }
        let body = read_limited_body(&mut response, "IdP endpoint list response").await?;
        let response: ApprovedDeviceEndpoints = serde_json::from_slice(&body)
            .map_err(|_| "invalid IdP endpoint list response".to_owned())?;
        let mut endpoint_ids = HashSet::with_capacity(response.endpoint_ids.len());
        for endpoint_id in &response.endpoint_ids {
            let parsed = endpoint_id
                .parse::<EndpointId>()
                .map_err(|_| "IdP returned an invalid endpoint ID".to_owned())?;
            if parsed.to_string() != *endpoint_id || !endpoint_ids.insert(endpoint_id.as_str()) {
                return Err("IdP returned an invalid or duplicate endpoint ID".to_owned());
            }
        }
        Ok(response.endpoint_ids)
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

    use super::IdpClient;

    const CLIENT_ID: &str = "storage-service";
    const CLIENT_SECRET: &str = "test-secret";
    const ISSUER: &str = "https://idp.example";
    const AUDIENCE: &str = "https://idp-api.example";

    #[test]
    fn validates_service_urls_and_client_configuration() {
        assert!(
            IdpClient::new(
                "http://127.0.0.1:3000/idp",
                CLIENT_ID,
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE
            )
            .is_ok()
        );
        assert!(
            IdpClient::new(
                "https://idp.example/idp",
                CLIENT_ID,
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE
            )
            .is_ok()
        );
        assert!(
            IdpClient::new(
                "http://idp.example",
                CLIENT_ID,
                CLIENT_SECRET,
                ISSUER,
                AUDIENCE
            )
            .is_err()
        );
        assert!(
            IdpClient::new("https://idp.example", "", CLIENT_SECRET, ISSUER, AUDIENCE).is_err()
        );
        assert!(
            IdpClient::new(
                "https://idp.example",
                CLIENT_ID,
                CLIENT_SECRET,
                "http://issuer.example",
                AUDIENCE
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
                let body = r#"{"access_token":"service-token","token_type":"Bearer","expires_in":0,"scope":"idp.device.lookup idp.device.list idp.token.validate","iss":"https://idp.example"}"#;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write token response");
            }
        });
        let client = IdpClient::new(
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test IdP client");

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
        let client = IdpClient::new(
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test IdP client");

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
            let mut body = r#"{"access_token":"service-token","token_type":"Bearer","expires_in":3600,"scope":"idp.device.lookup idp.device.list idp.token.validate","iss":"https://idp.example"}"#.to_owned();
            body.push_str(&" ".repeat(65_537 - body.len()));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                .expect("write oversized token response");
        });
        let client = IdpClient::new(
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test IdP client");

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
        let client = IdpClient::new(
            &format!("http://{address}/idp"),
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("create test IdP client");

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

    #[test]
    fn retains_path_prefix_for_normal_api_and_token_urls() {
        let client = IdpClient::new(
            "http://127.0.0.1:3000/idp",
            CLIENT_ID,
            CLIENT_SECRET,
            ISSUER,
            AUDIENCE,
        )
        .expect("valid client configuration");
        assert_eq!(
            client
                .base_url
                .join("devices/endpoints/")
                .expect("join device endpoint")
                .path(),
            "/idp/devices/endpoints/"
        );
        assert_eq!(
            client
                .base_url
                .join("oauth2/token")
                .expect("join token endpoint")
                .path(),
            "/idp/oauth2/token"
        );
        assert_eq!(
            client
                .base_url
                .join("oauth2/introspect")
                .expect("join introspection endpoint")
                .path(),
            "/idp/oauth2/introspect"
        );
    }
}
