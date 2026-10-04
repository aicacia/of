use std::marker::PhantomData;

use axum::extract::{FromRef, FromRequestParts};
use http::{HeaderValue, header::AUTHORIZATION, request::Parts};
use idp_model::contract::{ErrorCode, ErrorResponse};
use idp_model::{contract::EntityType, model::Id};
use idp_service::oauth2::{Principal, decode_jwt, verify_jwt};
use model::contract::{PrincipalType, StandardClaims, TokenType, TokenUse};
use serde::de::DeserializeOwned;

use crate::RouterState;

pub const AUTHORIZATION_BEARER_PREFIX: &str = "Bearer ";

pub type StandardAuthorization = Authorization<StandardClaims>;

pub struct Authorization<T>
where
    T: DeserializeOwned + Send,
{
    pub principal: Box<dyn Principal>,
    pub claims: T,
    pub token: String,
    _phantom_data: PhantomData<T>,
}

impl<S> FromRequestParts<S> for Authorization<StandardClaims>
where
    RouterState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(authorization_header_value) = parts.headers.get(AUTHORIZATION) {
            let authorization_string = authorization_from_header(authorization_header_value)?;
            let router_state = RouterState::from_ref(state);
            let authorization = authorize_bearer(&router_state, authorization_string).await?;
            return Ok(Authorization {
                principal: authorization.principal,
                claims: authorization.claims,
                token: authorization.token,
                _phantom_data: PhantomData,
            });
        }
        Err(ErrorResponse::new(ErrorCode::NotAuthorized)
            .with_description("missing authorization header"))
    }
}

pub async fn authorize_bearer(
    router_state: &RouterState,
    authorization_string: &str,
) -> Result<Authorization<StandardClaims>, ErrorResponse> {
    authorize_bearer_with_principal(
        router_state,
        authorization_string,
        Some(PrincipalType::User),
    )
    .await
}

pub(crate) async fn authorize_bearer_any_principal(
    router_state: &RouterState,
    authorization_string: &str,
) -> Result<Authorization<StandardClaims>, ErrorResponse> {
    authorize_bearer_with_principal(router_state, authorization_string, None).await
}

pub(crate) async fn authorize_bearer_client(
    router_state: &RouterState,
    authorization_string: &str,
) -> Result<Authorization<StandardClaims>, ErrorResponse> {
    authorize_bearer_with_principal(
        router_state,
        authorization_string,
        Some(PrincipalType::Client),
    )
    .await
}

async fn authorize_bearer_with_principal(
    router_state: &RouterState,
    authorization_string: &str,
    expected_principal: Option<PrincipalType>,
) -> Result<Authorization<StandardClaims>, ErrorResponse> {
    router_state.oauth2_service.require_security_ready()?;
    let (jwt_header, _) = decode_jwt::<StandardClaims>(authorization_string)?;
    let key_id = jwt_header
        .kid
        .parse::<Id>()
        .map_err(|_| ErrorResponse::new(ErrorCode::NotAuthorized))?;
    let principal = router_state
        .oauth2_service
        .find_principal(key_id)
        .await?
        .ok_or_else(|| {
            ErrorResponse::new(ErrorCode::NotAuthorized)
                .with_description("principal not found for key id")
        })?;
    let jwk = router_state.oauth2_service.find_public_jwk(key_id).await?;
    let (_, claims) = verify_jwt::<StandardClaims>(&jwk, authorization_string)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ErrorResponse::new(ErrorCode::NotAuthorized))?
        .as_secs() as i64;
    let claimed_entity_type = match claims.principal_type {
        PrincipalType::User => EntityType::User,
        PrincipalType::Client => EntityType::Client,
    };
    if claims.r#type != TokenType::Bearer
        || claims.r#use != TokenUse::Access
        || claims.iss != router_state.oauth2_service.metadata().issuer
        || claims.exp <= now
        || claims.nbf > now
        || claims.iat > now
        || principal.get_entity_type() != claimed_entity_type
        || expected_principal.is_some_and(|expected| expected != claims.principal_type)
        || claims.sub != principal.get_entity_id().to_string()
        || claims.aud.is_empty()
    {
        return Err(ErrorResponse::new(ErrorCode::NotAuthorized)
            .with_description("invalid bearer token claims"));
    }

    router_state
        .oauth2_service
        .validate_bearer_client(&claims)
        .await?;

    Ok(Authorization {
        principal,
        claims,
        token: authorization_string.to_owned(),
        _phantom_data: PhantomData,
    })
}

fn authorization_from_header(
    authorization_header_value: &HeaderValue,
) -> Result<&str, ErrorResponse> {
    log::debug!("parsing authorization header");
    match authorization_header_value.to_str() {
        Ok(authorization_string) => {
            if authorization_string.len() < AUTHORIZATION_BEARER_PREFIX.len() {
                log::warn!(
                    "invalid authorization header is too short: length={}",
                    authorization_string.len()
                );
                return Err(ErrorResponse::new(ErrorCode::NotAuthorized)
                    .with_description("authorization header is too short"));
            }
            if !authorization_string.starts_with(AUTHORIZATION_BEARER_PREFIX) {
                log::warn!(
                    "authorization header does not start with 'Bearer ', starts with: {}",
                    authorization_string.chars().take(10).collect::<String>()
                );
                return Err(ErrorResponse::new(ErrorCode::NotAuthorized)
                    .with_description("authorization header does not start with 'Bearer '"));
            }
            log::debug!("authorization header parsed successfully");
            Ok(&authorization_string[AUTHORIZATION_BEARER_PREFIX.len()..])
        }
        Err(e) => {
            log::warn!(
                "invalid authorization header cannot be parsed as string: {}",
                e
            );
            Err(ErrorResponse::new(ErrorCode::NotAuthorized)
                .with_description("invalid authorization header cannot be parsed as string"))
        }
    }
}
