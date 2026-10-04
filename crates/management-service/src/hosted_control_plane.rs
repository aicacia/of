use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use idp_service::oauth2::{decode_jwt, verify_jwt};

use idp_model::{
    contract::{
        DeviceEndpointIdentity, DeviceInfo, DeviceSelfRevocationRequest, DeviceState,
        IntrospectionRequest, IntrospectionResponse, Jwks, TrustedDevice,
    },
    model::Id,
};
use model::contract::{
    AuthorizationDetail, StandardClaims, StorageAuthorizationAction, TokenResponse, TokenType,
    TokenUse,
};
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;
use storage_model::ResourceKind;

#[derive(Clone)]
pub struct HostedControlPlane {
    idp_base_url: Url,
    storage_base_url: Url,
    expected_issuer: String,
    permission_evaluator_client_id: Option<String>,
    service_token_client: Option<Arc<ServiceTokenClient>>,
    client: Client,
}

impl HostedControlPlane {
    pub fn new(base_url: &str) -> Result<Self, String> {
        Self::new_with_services(base_url, base_url, base_url.trim_end_matches('/'))
    }

    pub fn new_with_issuer(base_url: &str, expected_issuer: &str) -> Result<Self, String> {
        Self::new_with_services(base_url, base_url, expected_issuer)
    }

    pub fn new_with_services(
        idp_base_url: &str,
        storage_base_url: &str,
        expected_issuer: &str,
    ) -> Result<Self, String> {
        let issuer = Url::parse(expected_issuer)
            .map_err(|_| "issuer must be an HTTP URL without a query or fragment".to_owned())?;
        if !matches!(issuer.scheme(), "http" | "https")
            || issuer.host().is_none()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
        {
            return Err("issuer must be an HTTP URL without a query or fragment".to_owned());
        }
        let idp_base_url = normalize_service_url(idp_base_url)?;
        let storage_base_url = normalize_service_url(storage_base_url)?;
        Ok(Self {
            idp_base_url,
            storage_base_url,
            expected_issuer: expected_issuer.to_owned(),
            permission_evaluator_client_id: None,
            service_token_client: None,
            client: Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(10))
                .redirect(Policy::none())
                .build()
                .map_err(|error| error.to_string())?,
        })
    }

    pub fn with_permission_evaluator(mut self, client_id: &str) -> Result<Self, String> {
        if client_id.trim().is_empty()
            || self
                .service_token_client
                .as_ref()
                .is_some_and(|client| client.client_id == client_id)
        {
            return Err("IdP permission evaluator must use a distinct client ID".to_owned());
        }
        self.permission_evaluator_client_id = Some(client_id.to_owned());
        Ok(self)
    }

    pub fn permission_evaluator_client_id(&self) -> Option<&str> {
        self.permission_evaluator_client_id.as_deref()
    }

    pub fn with_idp_service_client(
        self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, String> {
        self.with_scoped_service_client(
            client_id,
            client_secret,
            audience,
            "idp.token.validate idp.device.lookup",
        )
    }

    pub(crate) fn with_scoped_service_client(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        audience: impl Into<String>,
        scope: &'static str,
    ) -> Result<Self, String> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        let audience = audience.into();
        if client_id.trim().is_empty()
            || client_secret.is_empty()
            || audience.trim().is_empty()
            || self.permission_evaluator_client_id.as_deref() == Some(client_id.as_str())
        {
            return Err("IdP service client ID, secret and audience are required".to_owned());
        }
        self.service_token_client = Some(Arc::new(ServiceTokenClient {
            client_id,
            client_secret,
            audience,
            scope,
            cached: Mutex::new(None),
        }));
        Ok(self)
    }

    pub(crate) async fn idp_service_access_token(&self) -> Result<String, String> {
        const RENEWAL_MARGIN: Duration = Duration::from_secs(15);

        let token_client = self
            .service_token_client
            .as_ref()
            .ok_or_else(|| "IdP service OAuth client is not configured".to_owned())?;
        let cached_token = {
            let cached = token_client
                .cached
                .lock()
                .map_err(|_| "IdP service token cache is unavailable".to_owned())?;
            cached
                .as_ref()
                .filter(|token| {
                    token
                        .valid_until
                        .duration_since(SystemTime::now())
                        .is_ok_and(|remaining| remaining > RENEWAL_MARGIN)
                })
                .map(|token| token.value.clone())
        };
        if let Some(token) = cached_token {
            return Ok(token);
        }

        let form = [
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            ("client_id".to_owned(), token_client.client_id.clone()),
            (
                "client_secret".to_owned(),
                token_client.client_secret.clone(),
            ),
            ("scope".to_owned(), token_client.scope.to_owned()),
            ("audience".to_owned(), token_client.audience.clone()),
        ];
        let mut response = self
            .client
            .post(service_url(&self.idp_base_url, "oauth2/token")?)
            .form(&form)
            .send()
            .await
            .map_err(|_| "IdP token endpoint is unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err("IdP rejected the Management service client".to_owned());
        }
        let body = read_limited_body(&mut response, "IdP token response").await?;
        let token: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| "invalid IdP token response".to_owned())?;
        if token.token_type != TokenType::Bearer
            || token.issuer.as_deref() != Some(self.expected_issuer.as_str())
            || !token.scope.as_deref().is_some_and(|scope| {
                let granted = scope.split_ascii_whitespace().collect::<Vec<_>>();
                token_client
                    .scope
                    .split_ascii_whitespace()
                    .all(|required| granted.contains(&required))
            })
        {
            return Err("IdP returned an unauthorized service token".to_owned());
        }
        let expires_in = token
            .expires_in
            .ok_or_else(|| "IdP service token has no expiry".to_owned())?;
        let valid_until = SystemTime::now()
            .checked_add(Duration::from_secs(expires_in))
            .ok_or_else(|| "IdP service token expiry is invalid".to_owned())?;
        let value = token.access_token.0;
        *token_client
            .cached
            .lock()
            .map_err(|_| "IdP service token cache is unavailable".to_owned())? =
            Some(CachedServiceToken {
                value: value.clone(),
                valid_until,
            });
        Ok(value)
    }

    /// Validates a user token through IdP's normal OAuth introspection API.
    pub async fn validate_actor_token(
        &self,
        actor_token: &str,
    ) -> Result<(StandardClaims, Id), String> {
        let service_token = self.idp_service_access_token().await?;
        let request = IntrospectionRequest {
            token: actor_token.to_owned(),
            token_type_hint: Some("access_token".to_owned()),
        };
        let mut response = self
            .client
            .post(service_url(&self.idp_base_url, "oauth2/introspect")?)
            .bearer_auth(service_token)
            .json(&request)
            .send()
            .await
            .map_err(|_| "IdP token validation is unavailable".to_owned())?;
        if response.status().as_u16() == 401 {
            return Err("actor token was rejected by IdP".to_owned());
        }
        if !response.status().is_success() {
            return Err("IdP token validation is unavailable".to_owned());
        }
        const MAX_RESPONSE_SIZE: usize = 64 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "invalid IdP token validation response".to_owned())?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err("IdP token validation response is too large".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        let response: IntrospectionResponse = serde_json::from_slice(&body)
            .map_err(|_| "invalid IdP token validation response".to_owned())?;
        let application_id = response
            .application_id
            .parse()
            .map_err(|_| "invalid application ID in IdP response".to_owned())?;
        self.check_issuer(&response.claims)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "invalid local clock".to_owned())?
            .as_secs() as i64;
        if response.claims.r#type != TokenType::Bearer
            || response.claims.r#use != TokenUse::Access
            || response.claims.exp <= now
            || response.claims.nbf > now
            || response.claims.iat > now
            || response.claims.aud.is_empty()
            || response.claims.client_id.is_empty()
            || response.claims.sub.parse::<Id>().is_err()
            || application_id == Id::nil()
        {
            return Err("invalid claims in IdP token validation response".to_owned());
        }
        Ok((response.claims, application_id))
    }

    pub async fn get_storage_endpoint_identity(
        &self,
        endpoint_id: &str,
    ) -> Result<DeviceEndpointIdentity, String> {
        let mut url = service_url(&self.idp_base_url, "devices/endpoints/")?;
        url.path_segments_mut()
            .map_err(|_| "invalid IdP endpoint URL".to_owned())?
            .pop_if_empty()
            .push(endpoint_id);
        let service_token = self.idp_service_access_token().await?;
        let mut response = self
            .client
            .get(url)
            .bearer_auth(service_token)
            .send()
            .await
            .map_err(|_| "IdP endpoint lookup is unavailable".to_owned())?;
        if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
            return Err("IdP rejected Management device lookup permission".to_owned());
        }
        if response.status().as_u16() == 404 {
            return Err("IdP identity was not found".to_owned());
        }
        if !response.status().is_success() {
            return Err("IdP endpoint lookup is unavailable".to_owned());
        }
        const MAX_RESPONSE_SIZE: usize = 64 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "invalid IdP endpoint response".to_owned())?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err("IdP endpoint response is too large".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        let identity: DeviceEndpointIdentity = serde_json::from_slice(&body)
            .map_err(|_| "invalid IdP endpoint response".to_owned())?;
        if identity.endpoint_id != endpoint_id {
            return Err("IdP returned a mismatched endpoint identity".to_owned());
        }
        Ok(identity)
    }

    pub async fn validate_storage_resource(
        &self,
        read_token: &str,
        expected_owner: &str,
        expected_storage_audience: &str,
        expected_application_id: Id,
        kind: ResourceKind,
        resource_id: &str,
    ) -> Result<Id, String> {
        let claims = self.verify_access_token(read_token).await?;
        validate_storage_read_claims(&claims, expected_owner, expected_storage_audience)?;
        self.lookup_storage_resource(read_token, expected_application_id, kind, resource_id)
            .await
    }

    async fn lookup_storage_resource(
        &self,
        read_token: &str,
        expected_application_id: Id,
        kind: ResourceKind,
        resource_id: &str,
    ) -> Result<Id, String> {
        let id: Id = resource_id
            .parse()
            .map_err(|_| "invalid storage resource ID".to_owned())?;
        if resource_id != id.to_string() {
            return Err("invalid storage resource ID".to_owned());
        }
        let collection = match kind {
            ResourceKind::Database => "databases",
            ResourceKind::FileSystem => "filesystems",
        };
        let resource: StorageResourceDetail = self
            .get_storage(&format!("{collection}/{id}"), read_token)
            .await?;
        if resource.id != resource_id {
            return Err("storage resource ID mismatch".to_owned());
        }
        if resource.application_id != expected_application_id {
            return Err("storage application ID mismatch".to_owned());
        }
        Ok(resource.application_id)
    }

    /// Selection-only check. Deselect using the locally persisted owner, without IdP access.
    pub async fn validate_selection_device(
        &self,
        read_token: &str,
        expected_actor_subject: &str,
        expected_storage_audience: &str,
        device_id: Id,
    ) -> Result<(), String> {
        let claims = self.verify_access_token(read_token).await?;
        validate_storage_read_claims(&claims, expected_actor_subject, expected_storage_audience)?;
        self.lookup_approved_device(read_token, device_id).await
    }

    async fn lookup_approved_device(&self, read_token: &str, device_id: Id) -> Result<(), String> {
        let devices: Vec<DeviceInfo> = self.get_idp("devices", read_token).await?;
        if devices
            .iter()
            .any(|device| device.id == device_id && device.state == DeviceState::Approved)
        {
            Ok(())
        } else {
            Err("device is not an approved device of the token subject".to_owned())
        }
    }

    pub async fn trusted_devices(&self, token: &str) -> Result<Vec<TrustedDevice>, String> {
        self.get_idp("devices/trusted", token).await
    }

    pub async fn revoke_self(&self, request: DeviceSelfRevocationRequest) -> Result<(), String> {
        self.post_empty_idp("devices/revoke-self", &request).await
    }

    pub async fn verify_access_token(&self, token: &str) -> Result<StandardClaims, String> {
        let (header, _) =
            decode_jwt::<StandardClaims>(token).map_err(|_| "invalid token".to_owned())?;
        let jwks: Jwks = self.get_idp(".well-known/jwks.json", "").await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|jwk| jwk.kid == header.kid)
            .ok_or_else(|| "token signing key is not trusted".to_owned())?;
        let (_, claims) =
            verify_jwt::<StandardClaims>(jwk, token).map_err(|_| "invalid token".to_owned())?;
        self.check_issuer(&claims)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?
            .as_secs() as i64;
        if claims.r#type != TokenType::Bearer
            || claims.r#use != TokenUse::Access
            || claims.exp <= now
            || claims.iat > now
            || claims.nbf > now
            || claims.sub.is_empty()
            || claims.aud.is_empty()
            || !claims.scope.iter().any(|scope| scope == "storage")
        {
            return Err("invalid storage access token".to_owned());
        }
        Ok(claims)
    }

    fn check_issuer(&self, claims: &StandardClaims) -> Result<(), String> {
        if claims.iss != self.expected_issuer {
            return Err("token issuer is not the configured issuer".to_owned());
        }
        Ok(())
    }

    async fn get_idp<T>(&self, path: &str, token: &str) -> Result<T, String>
    where
        T: serde::de::DeserializeOwned,
    {
        self.get_from(&self.idp_base_url, path, token).await
    }

    async fn get_storage<T>(&self, path: &str, token: &str) -> Result<T, String>
    where
        T: serde::de::DeserializeOwned,
    {
        self.get_from(&self.storage_base_url, path, token).await
    }

    async fn get_from<T>(&self, base_url: &Url, path: &str, token: &str) -> Result<T, String>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut request = self.client.get(service_url(base_url, path)?);
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())
    }

    async fn post_empty_idp<B>(&self, path: &str, body: &B) -> Result<(), String>
    where
        B: serde::Serialize + ?Sized,
    {
        self.client
            .post(service_url(&self.idp_base_url, path)?)
            .json(body)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

pub(crate) fn normalize_service_url(value: &str) -> Result<Url, String> {
    let mut url = Url::parse(value).map_err(|_| "invalid service URI".to_owned())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.scheme() == "http" && !is_loopback(&url))
    {
        return Err("service URI must use HTTPS except for loopback and must not contain credentials, a query, or a fragment".to_owned());
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn service_url(base_url: &Url, path: &str) -> Result<Url, String> {
    base_url.join(path).map_err(|error| error.to_string())
}

struct ServiceTokenClient {
    client_id: String,
    client_secret: String,
    audience: String,
    scope: &'static str,
    cached: Mutex<Option<CachedServiceToken>>,
}

struct CachedServiceToken {
    value: String,
    valid_until: SystemTime,
}

pub(crate) async fn read_limited_body(
    response: &mut reqwest::Response,
    label: &str,
) -> Result<Vec<u8>, String> {
    const MAX_RESPONSE_SIZE: usize = 64 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("invalid {label}"))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
            return Err(format!("{label} is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Deserialize)]
struct StorageResourceDetail {
    id: String,
    #[serde(rename = "applicationId")]
    application_id: Id,
}

fn validate_storage_read_claims(
    claims: &StandardClaims,
    expected_owner: &str,
    expected_storage_audience: &str,
) -> Result<(), String> {
    let [AuthorizationDetail::Storage(detail)] =
        claims.authorization_details.as_deref().unwrap_or(&[])
    else {
        return Err("storage read authorization required".to_owned());
    };
    if expected_owner.is_empty()
        || claims.sub != expected_owner
        || claims.client_id.is_empty()
        || expected_storage_audience.is_empty()
        || claims.aud != expected_storage_audience
        || claims.resource.as_deref() != Some(expected_storage_audience)
        || !detail.actions.contains(&StorageAuthorizationAction::Read)
    {
        return Err("storage read authorization required".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use model::contract::{
        AuthorizationDetail, PrincipalType, StandardClaims, StorageAuthorizationAction,
        StorageAuthorizationDetail, TokenType, TokenUse,
    };
    use storage_model::ResourceKind;

    use super::{HostedControlPlane, normalize_service_url, validate_storage_read_claims};

    const ID: &str = "00000000-0000-0000-0000-000000000001";
    const APP_ID: &str = "00000000-0000-0000-0000-000000000003";

    fn claims() -> StandardClaims {
        StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: i64::MAX,
            iat: 0,
            nbf: 0,
            iss: "https://lidp.example".into(),
            aud: "storage".into(),
            client_id: "verified-client".into(),
            sub: "owner".into(),
            principal_type: PrincipalType::User,
            resource: Some("storage".into()),
            authorization_details: Some(vec![AuthorizationDetail::Storage(
                StorageAuthorizationDetail {
                    actions: vec![StorageAuthorizationAction::Read],
                },
            )]),
            scope: vec!["storage".into()],
        }
    }

    fn check(claims: &StandardClaims) -> Result<(), String> {
        validate_storage_read_claims(claims, "owner", "storage")
    }

    #[test]
    fn storage_read_requires_owner_audience_resource_and_read_detail() {
        let valid = claims();
        assert!(check(&valid).is_ok());
        assert!(validate_storage_read_claims(&valid, "other", "storage").is_err());
        assert!(validate_storage_read_claims(&valid, "owner", "other").is_err());
        assert!(validate_storage_read_claims(&valid, "", "storage").is_err());
        assert!(validate_storage_read_claims(&valid, "owner", "").is_err());
        let mut invalid = valid.clone();
        invalid.client_id.clear();
        assert!(check(&invalid).is_err());
        invalid = valid.clone();
        invalid.resource = None;
        assert!(check(&invalid).is_err());
        invalid = valid.clone();
        invalid.authorization_details = None;
        assert!(check(&invalid).is_err());
        invalid.authorization_details = Some(vec![AuthorizationDetail::Storage(
            StorageAuthorizationDetail {
                actions: vec![StorageAuthorizationAction::Write],
            },
        )]);
        assert!(check(&invalid).is_err());
        invalid.authorization_details = Some(vec![
            AuthorizationDetail::Storage(StorageAuthorizationDetail {
                actions: vec![StorageAuthorizationAction::Read],
            }),
            AuthorizationDetail::Storage(StorageAuthorizationDetail {
                actions: vec![StorageAuthorizationAction::Read],
            }),
        ]);
        assert!(check(&invalid).is_err());
    }

    #[tokio::test]
    async fn introspection_rejection_is_not_treated_as_upstream_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let mut token_request = [0; 4096];
            token_stream
                .read(&mut token_request)
                .expect("read token request");
            let token_response = r#"{"access_token":"management-token","token_type":"Bearer","expires_in":300,"scope":"idp.token.validate idp.device.lookup","iss":"https://issuer.example"}"#;
            write!(token_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token_response}", token_response.len()).expect("write token response");

            let (mut introspection_stream, _) =
                listener.accept().expect("accept introspection request");
            let mut introspection_request = [0; 4096];
            introspection_stream
                .read(&mut introspection_request)
                .expect("read introspection request");
            let error_response = r#"{"error":"invalid_token"}"#;
            write!(introspection_stream, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{error_response}", error_response.len()).expect("write rejection response");
        });

        let base_url = format!("http://{address}");
        let control_plane =
            HostedControlPlane::new_with_services(&base_url, &base_url, "https://issuer.example")
                .expect("create hosted control plane")
                .with_idp_service_client("management-client", "management-secret", "idp-audience")
                .expect("configure IdP service client");

        let error = control_plane
            .validate_actor_token("revoked-or-invalid-token")
            .await
            .expect_err("IdP rejection must fail validation");
        assert_eq!(error, "actor token was rejected by IdP");
        server.join().expect("join test HTTP server");
    }

    async fn lookup_with_response(
        kind: ResourceKind,
        status: &str,
        body: &str,
    ) -> (Result<idp_model::model::Id, String>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let status = status.to_owned();
        let body = body.to_owned();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test request");
            let mut request = [0; 4096];
            let length = stream.read(&mut request).expect("read test request");
            let request = String::from_utf8_lossy(&request[..length]).into_owned();
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write test response");
            request
        });
        let control_plane = HostedControlPlane::new(&format!("http://{address}"))
            .expect("create test control plane");
        let result = control_plane
            .lookup_storage_resource(
                "secret",
                APP_ID.parse().expect("valid application ID"),
                kind,
                ID,
            )
            .await;
        (result, server.join().expect("join test HTTP server"))
    }

    #[tokio::test]
    async fn endpoint_identity_lookup_uses_management_oauth_client() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let mut token_request = [0; 4096];
            let token_length = token_stream
                .read(&mut token_request)
                .expect("read token request");
            let token_request =
                String::from_utf8_lossy(&token_request[..token_length]).into_owned();
            let token_body = serde_json::json!({
                "access_token": "management-service-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "idp.token.validate idp.device.lookup",
                "iss": "https://issuer.example"
            })
            .to_string();
            write!(token_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token_body}", token_body.len()).expect("write token response");

            let (mut lookup_stream, _) = listener.accept().expect("accept endpoint request");
            let mut lookup_request = [0; 4096];
            let lookup_length = lookup_stream
                .read(&mut lookup_request)
                .expect("read endpoint request");
            let lookup_request =
                String::from_utf8_lossy(&lookup_request[..lookup_length]).into_owned();
            let body = format!(
                r#"{{"deviceId":"{ID}","ownerSubject":"owner","endpointId":"endpoint-key"}}"#
            );
            write!(lookup_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write lookup response");
            (token_request, lookup_request)
        });
        let endpoint = format!("http://{address}");
        let control_plane =
            HostedControlPlane::new_with_services(&endpoint, &endpoint, "https://issuer.example")
                .expect("create test control plane")
                .with_idp_service_client("management-client", "management-secret", "idp-audience")
                .expect("configure service OAuth client");
        let identity = control_plane
            .get_storage_endpoint_identity("endpoint-key")
            .await
            .expect("resolve approved endpoint identity");
        assert_eq!(identity.device_id.to_string(), ID);
        assert_eq!(identity.owner_subject, "owner");
        let (token_request, lookup_request) = server.join().expect("join test HTTP server");
        assert!(token_request.starts_with("POST /oauth2/token HTTP/1.1"));
        assert!(token_request.contains("scope=idp.token.validate+idp.device.lookup"));
        assert!(lookup_request.starts_with("GET /devices/endpoints/endpoint-key HTTP/1.1"));
        assert!(
            lookup_request
                .to_ascii_lowercase()
                .contains("authorization: bearer management-service-token")
        );
        assert!(
            !lookup_request
                .to_ascii_lowercase()
                .contains("x-internal-service")
        );
    }

    #[tokio::test]
    async fn actor_validation_uses_scoped_client_bearer_and_returns_verified_claims() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("read test HTTP address");
        let introspection_body =
            serde_json::json!({ "claims": claims(), "applicationId": APP_ID }).to_string();
        let server = thread::spawn(move || {
            let (mut token_stream, _) = listener.accept().expect("accept token request");
            let mut token_request = [0; 4096];
            let token_length = token_stream
                .read(&mut token_request)
                .expect("read token request");
            let token_request =
                String::from_utf8_lossy(&token_request[..token_length]).into_owned();
            let token_body = serde_json::json!({
                "access_token": "service-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "idp.token.validate idp.device.lookup",
                "iss": "https://issuer.example"
            })
            .to_string();
            write!(token_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{token_body}", token_body.len()).expect("write token response");

            let (mut introspection_stream, _) =
                listener.accept().expect("accept introspection request");
            let mut introspection_request = [0; 4096];
            let introspection_length = introspection_stream
                .read(&mut introspection_request)
                .expect("read introspection request");
            let introspection_request =
                String::from_utf8_lossy(&introspection_request[..introspection_length])
                    .into_owned();
            write!(introspection_stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{introspection_body}", introspection_body.len()).expect("write introspection response");
            (token_request, introspection_request)
        });
        let endpoint = format!("http://{address}");
        let control_plane =
            HostedControlPlane::new_with_services(&endpoint, &endpoint, "https://issuer.example")
                .expect("create test control plane")
                .with_idp_service_client("management-client", "management-secret", "idp-audience")
                .expect("configure service OAuth client");
        let (validated, application_id) = control_plane
            .validate_actor_token("actor-token")
            .await
            .expect("IdP validates actor token");
        let (token_request, introspection_request) = server.join().expect("join test HTTP server");
        assert_eq!(validated.client_id, "verified-client");
        assert_eq!(application_id.to_string(), APP_ID);
        assert!(token_request.starts_with("POST /oauth2/token HTTP/1.1"));
        assert!(token_request.contains("grant_type=client_credentials"));
        assert!(token_request.contains("scope=idp.token.validate+idp.device.lookup"));
        assert!(token_request.contains("audience=idp-audience"));
        assert!(introspection_request.starts_with("POST /oauth2/introspect HTTP/1.1"));
        assert!(
            introspection_request
                .to_ascii_lowercase()
                .contains("authorization: bearer service-token")
        );
        assert!(introspection_request.contains("actor-token"));
        assert!(
            !introspection_request
                .to_ascii_lowercase()
                .contains("x-internal-service")
        );
    }

    #[tokio::test]
    async fn lookup_uses_kind_specific_get_and_returns_application_id() {
        for (kind, path) in [
            (ResourceKind::Database, "databases"),
            (ResourceKind::FileSystem, "filesystems"),
        ] {
            let (result, request) = lookup_with_response(
                kind,
                "200 OK",
                &format!(r#"{{"id":"{ID}","applicationId":"{APP_ID}"}}"#),
            )
            .await;
            assert_eq!(result, Ok(APP_ID.parse().expect("valid application ID")));
            assert!(request.starts_with(&format!("GET /{path}/{ID} HTTP/1.1")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer secret")
            );
        }
    }

    #[tokio::test]
    async fn lookup_rejects_wrong_or_missing_id_and_application_id() {
        for body in [
            format!(
                r#"{{"id":"00000000-0000-0000-0000-000000000002","applicationId":"{APP_ID}"}}"#
            ),
            format!(r#"{{"applicationId":"{APP_ID}"}}"#),
            format!(r#"{{"id":"{ID}","applicationId":"00000000-0000-0000-0000-000000000004"}}"#),
            format!(r#"{{"id":"{ID}"}}"#),
            format!(r#"{{"id":"{ID}","applicationId":"not-a-uuid"}}"#),
        ] {
            let (result, _) = lookup_with_response(ResourceKind::Database, "200 OK", &body).await;
            assert!(result.is_err(), "unexpectedly accepted: {body}");
        }
        let (result, _) =
            lookup_with_response(ResourceKind::FileSystem, "404 Not Found", "{}").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn lookup_rejects_invalid_id_and_unavailable_api() {
        let control_plane =
            HostedControlPlane::new("http://127.0.0.1:1").expect("create test control plane");
        assert!(
            control_plane
                .lookup_storage_resource(
                    "secret",
                    APP_ID.parse().expect("valid application ID"),
                    ResourceKind::Database,
                    "../filesystems/id"
                )
                .await
                .is_err()
        );
        assert!(
            control_plane
                .lookup_storage_resource(
                    "secret",
                    APP_ID.parse().expect("valid application ID"),
                    ResourceKind::Database,
                    ID
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn selection_device_lookup_requires_approved_owner_scoped_device() {
        for (body, allowed) in [
            (format!(r#"[{{"id":"{ID}","name":"test","publicKey":"key","address":"addr","state":"approved","createdAt":0,"updatedAt":0,"revokedAt":null}}]"#), true),
            (format!(r#"[{{"id":"{ID}","name":"test","publicKey":"key","address":"addr","state":"pending","createdAt":0,"updatedAt":0,"revokedAt":null}}]"#), false),
            (format!(r#"[{{"id":"{ID}","name":"test","publicKey":"key","address":"addr","state":"revoked","createdAt":0,"updatedAt":0,"revokedAt":0}}]"#), false),
            (r#"[]"#.to_owned(), false),
            (r#"[{"id":"00000000-0000-0000-0000-000000000002","name":"other","publicKey":"key","address":"addr","state":"approved","createdAt":0,"updatedAt":0,"revokedAt":null}]"#.to_owned(), false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
            let address = listener.local_addr().expect("read test HTTP address");
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept test request");
                let mut request = [0; 4096];
                let length = stream.read(&mut request).expect("read test request");
                let request = String::from_utf8_lossy(&request[..length]).into_owned();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write test response");
                request
            });
            let control_plane = HostedControlPlane::new(&format!("http://{address}"))
                .expect("create test control plane");
            let result = control_plane.lookup_approved_device("secret", ID.parse().expect("valid device ID")).await;
            assert_eq!(result.is_ok(), allowed);
            let request = server.join().expect("join test HTTP server");
            assert!(request.starts_with("GET /devices HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("authorization: bearer secret"));
        }
    }

    #[tokio::test]
    async fn selection_device_lookup_rejects_idp_outage() {
        let control_plane =
            HostedControlPlane::new("http://127.0.0.1:1").expect("create test control plane");
        assert!(
            control_plane
                .lookup_approved_device("secret", ID.parse().expect("valid device ID"))
                .await
                .is_err()
        );
    }

    #[test]
    fn service_urls_require_tls_except_for_loopback() {
        for url in ["http://localhost/idp", "http://127.0.0.1:3000/idp"] {
            assert!(normalize_service_url(url).is_ok());
        }
        assert!(normalize_service_url("https://idp.example/idp").is_ok());
        for url in [
            "http://idp.example",
            "http://user:secret@localhost/idp",
            "https://idp.example/idp?token=secret",
            "https://idp.example/idp#fragment",
            "ftp://idp.example/idp",
        ] {
            assert!(normalize_service_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn idp_and_storage_service_urls_keep_independent_prefixes() {
        let control_plane = HostedControlPlane::new_with_services(
            "https://host.example/idp/",
            "https://host.example/storage/",
            "https://issuer.example",
        )
        .expect("create split control plane");

        assert_eq!(
            control_plane
                .idp_base_url
                .join("devices")
                .expect("join IdP route")
                .as_str(),
            "https://host.example/idp/devices"
        );
        assert_eq!(
            control_plane
                .storage_base_url
                .join("databases/00000000-0000-0000-0000-000000000001")
                .expect("join Storage route")
                .as_str(),
            "https://host.example/storage/databases/00000000-0000-0000-0000-000000000001"
        );
    }

    #[test]
    fn issuer_is_independent_of_api_base() {
        let issuer = idp_service::oauth2::OAuth2Config::default().issuer;
        let control_plane = HostedControlPlane::new_with_issuer("https://api.example", &issuer)
            .expect("create control plane with distinct issuer");
        let mut signed_claims = claims();
        signed_claims.iss = issuer.to_owned();
        assert!(control_plane.check_issuer(&signed_claims).is_ok());
        signed_claims.iss = "https://api.example".into();
        assert!(control_plane.check_issuer(&signed_claims).is_err());
        let other_api = HostedControlPlane::new_with_issuer("https://other-api.example", &issuer)
            .expect("create control plane with different API base");
        assert!(other_api.check_issuer(&signed_claims).is_err());
        signed_claims.iss = issuer.to_owned();
        assert!(other_api.check_issuer(&signed_claims).is_ok());
    }

    #[test]
    fn rejects_invalid_issuers() {
        for issuer in [
            "",
            "not-a-url",
            "ftp://idp.example",
            "https://",
            "https://idp.example/?x=1",
            "https://idp.example/#fragment",
            "https://user@idp.example",
        ] {
            assert!(
                HostedControlPlane::new_with_issuer("https://api.example", issuer).is_err(),
                "accepted issuer {issuer}"
            );
        }
        assert!(
            HostedControlPlane::new_with_issuer("ftp://api.example", "https://idp.example")
                .is_err()
        );
    }

    #[test]
    fn accepts_only_http_control_plane_urls() {
        let control_plane = HostedControlPlane::new("https://lidp.example/")
            .expect("create control plane using API URL as issuer");
        let mut signed_claims = claims();
        signed_claims.iss = "https://lidp.example".into();
        assert!(control_plane.check_issuer(&signed_claims).is_ok());
        assert!(HostedControlPlane::new("https://lidp.example").is_ok());
        assert!(HostedControlPlane::new("ftp://lidp.example").is_err());
        assert!(HostedControlPlane::new("https://lidp.example/?x=1").is_err());
    }
}
