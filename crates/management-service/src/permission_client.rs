use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use idp_model::contract::{
    MANAGEMENT_PERMISSION_EVALUATE_SCOPE, PermissionEvaluationRequest, PermissionEvaluationResponse,
};
use idp_service::oauth2::decode_jwt;
use model::contract::{PrincipalType, StandardClaims, TokenType, TokenUse};
use reqwest::{Client, Url, redirect::Policy};

use crate::{
    HostedControlPlane,
    hosted_control_plane::{normalize_service_url, read_limited_body},
};

#[derive(Clone)]
pub struct PermissionClient {
    management_base: Url,
    tokens: HostedControlPlane,
    client_id: String,
    issuer: String,
    client: Client,
}

impl PermissionClient {
    pub fn new(
        management_api_base: &str,
        idp_api_base: &str,
        issuer: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            management_base: normalize_service_url(management_api_base)?,
            tokens: HostedControlPlane::new_with_issuer(idp_api_base, issuer)?
                .with_scoped_service_client(
                    client_id,
                    client_secret,
                    crate::MANAGEMENT_APPLICATION_URI,
                    MANAGEMENT_PERMISSION_EVALUATE_SCOPE,
                )?,
            client_id: client_id.to_owned(),
            issuer: issuer.to_owned(),
            client: Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(10))
                .redirect(Policy::none())
                .build()
                .map_err(|error| error.to_string())?,
        })
    }

    pub async fn evaluate(&self, request: &PermissionEvaluationRequest) -> Result<bool, String> {
        if request.policy_namespace().is_none() {
            return Err("invalid permission scope".to_owned());
        }
        let started = Instant::now();
        let token = self.tokens.idp_service_access_token().await?;
        let (_, claims) = decode_jwt::<StandardClaims>(&token)
            .map_err(|_| "invalid permission service token".to_owned())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "invalid local clock".to_owned())?
            .as_secs() as i64;
        if claims.iss != self.issuer
            || claims.client_id != self.client_id
            || claims.principal_type != PrincipalType::Client
            || claims.r#type != TokenType::Bearer
            || claims.r#use != TokenUse::Access
            || claims.aud != crate::MANAGEMENT_APPLICATION_URI
            || claims.exp <= now
            || claims.nbf > now
            || claims.iat > now
            || claims.scope != [MANAGEMENT_PERMISSION_EVALUATE_SCOPE]
        {
            return Err("unauthorized permission service token".to_owned());
        }
        let service_subject = claims
            .sub
            .parse::<idp_model::model::Id>()
            .map_err(|_| "invalid permission service subject".to_owned())?;
        if service_subject.is_nil() {
            return Err("invalid permission service subject".to_owned());
        }
        let remaining = Duration::from_secs(10)
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "Management permission deadline exceeded".to_owned())?;
        let mut response = self
            .client
            .post(
                self.management_base
                    .join("permissions/evaluate")
                    .map_err(|error| error.to_string())?,
            )
            .timeout(remaining)
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(|_| "Management permission API is unavailable".to_owned())?;
        if response.status().as_u16() != 200 {
            return Err("Management permission request failed".to_owned());
        }
        let body = read_limited_body(&mut response, "Management permission response").await?;
        let decision: PermissionEvaluationResponse = serde_json::from_slice(&body)
            .map_err(|_| "invalid Management permission response".to_owned())?;
        if decision.request != *request
            || decision.audit.actor != request.subject
            || decision.audit.service_client_id != self.client_id
            || decision.audit.service_subject != service_subject
        {
            return Err("Management returned a mismatched permission decision".to_owned());
        }
        Ok(decision.allowed)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::{Read, Write}, net::TcpListener, thread, time::Duration};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use idp_model::{contract::{IdentityAction, IdentityResource, PermissionAuditIdentity,
        PermissionEvaluationRequest, PermissionEvaluationResponse, PermissionSubject, PermissionTarget,
        MANAGEMENT_PERMISSION_EVALUATE_SCOPE}, model::Id};
    use model::contract::{PrincipalType, StandardClaims, TokenType, TokenUse};
    use super::PermissionClient;

    fn request() -> PermissionEvaluationRequest {
        PermissionEvaluationRequest {
            request_id: Id::from_u128(1), subject: PermissionSubject::User { id: Id::from_u128(2) },
            action: IdentityAction::ClientsRead,
            target: PermissionTarget::Application { application_id: Id::from_u128(3),
                resource: IdentityResource::Client { client_id: Some("application-client".into()) } },
        }
    }

    async fn response_with(status: u16, body: String) -> Result<bool, String> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
        let address = listener.local_addr().expect("read HTTP address");
        let claims = StandardClaims {
            r#type: TokenType::Bearer, r#use: TokenUse::Access, exp: i64::MAX, iat: 0, nbf: 0,
            iss: "https://installation.example".into(), aud: crate::MANAGEMENT_APPLICATION_URI.into(),
            client_id: "idp-evaluator".into(), sub: Id::from_u128(4).to_string(), principal_type: PrincipalType::Client,
            resource: None, authorization_details: None, scope: vec![MANAGEMENT_PERMISSION_EVALUATE_SCOPE.into()],
        };
        // Fixture only: Management still validates real token signatures in live acceptance.
        let token = format!("{}.{}.fixture", URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT","kid":"fixture"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize fixture claims")));
        let token_body = serde_json::json!({ "access_token": token, "token_type": "Bearer", "expires_in": 60,
            "iss": claims.iss, "scope": MANAGEMENT_PERMISSION_EVALUATE_SCOPE }).to_string();
        let server = thread::spawn(move || {
            for (status, body) in [(200, token_body), (status, body)] {
                let (mut stream, _) = listener.accept().expect("accept fixture request");
                stream.set_read_timeout(Some(Duration::from_secs(5))).expect("bound fixture read");
                let mut bytes = [0; 8192];
                let length = stream.read(&mut bytes).expect("read fixture request");
                let request = String::from_utf8_lossy(&bytes[..length]);
                if request.starts_with("POST /management/") {
                    assert!(request.starts_with("POST /management/permissions/evaluate "));
                    assert!(request.to_ascii_lowercase().contains("authorization: bearer "));
                    assert!(!request.to_ascii_lowercase().contains("x-actor"));
                } else { assert!(request.starts_with("POST /idp/oauth2/token ")); }
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("write fixture response");
            }
        });
        let client = PermissionClient::new(&format!("http://{address}/management"), &format!("http://{address}/idp"),
            "https://installation.example", "idp-evaluator", "secret").expect("construct bounded client");
        let result = client.evaluate(&request()).await;
        server.join().expect("join HTTP fixture");
        result
    }

    fn decision() -> PermissionEvaluationResponse {
        PermissionEvaluationResponse { request: request(), audit: PermissionAuditIdentity {
            service_subject: Id::from_u128(4), service_client_id: "idp-evaluator".into(), actor: request().subject,
        }, allowed: true }
    }

    #[tokio::test]
    async fn permission_client_binds_decisions_and_fails_closed_on_upstream_errors() {
        let mut decision = decision();
        assert!(response_with(200, serde_json::to_string(&decision).expect("serialize decision")).await.expect("permit"));
        decision.allowed = false;
        assert!(!response_with(200, serde_json::to_string(&decision).expect("serialize decision")).await.expect("deny"));
        for field in ["request", "actor", "service", "client"] {
            let mut decision = super::tests::decision();
            match field {
                "request" => decision.request.request_id = Id::from_u128(9),
                "actor" => decision.audit.actor = PermissionSubject::User { id: Id::from_u128(9) },
                "service" => decision.audit.service_subject = Id::from_u128(9),
                _ => decision.audit.service_client_id = "other-service".into(),
            }
            assert!(response_with(200, serde_json::to_string(&decision).expect("serialize wrong decision")).await.is_err());
        }
        for (status, body) in [(503, "{}".into()), (302, "{}".into()), (200, "{}".into()), (200, "x".repeat(65537))] {
            assert!(response_with(status, body).await.is_err());
        }
        let unavailable = TcpListener::bind("127.0.0.1:0").expect("reserve unavailable address");
        let address = unavailable.local_addr().expect("read address");
        drop(unavailable);
        let client = PermissionClient::new(&format!("http://{address}"), &format!("http://{address}"),
            "https://installation.example", "idp-evaluator", "secret").expect("construct unavailable client");
        assert!(client.evaluate(&request()).await.is_err());
        assert!(PermissionClient::new("http://remote.example", "https://idp.example", "https://idp.example", "client", "secret").is_err());
    }
}
