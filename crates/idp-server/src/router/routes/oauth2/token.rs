use axum::{
    Json,
    extract::{Form, State},
    http::HeaderMap,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use idp_model::contract::{ErrorResponse, OAuth2ClientAuth, TokenEndpointAuthMethod, TokenRequest};
use model::contract::TokenResponse;

use crate::router::RouterState;

#[utoipa::path(post, path = "/oauth2/token", request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"), responses((status = 200, description = "Token response", body = TokenResponse)))]
pub(crate) async fn token(
    headers: HeaderMap,
    State(state): State<RouterState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ErrorResponse> {
    let client_auth = parse_client_auth(&headers, &request)?;
    let response = state.oauth2_service.token(request, client_auth).await?;
    Ok(Json(response))
}

fn parse_client_auth(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Option<OAuth2ClientAuth>, ErrorResponse> {
    if !headers.contains_key(axum::http::header::AUTHORIZATION) {
        return Ok(match request {
            TokenRequest::ClientCredentials(request) => Some(OAuth2ClientAuth {
                client_id: request.client_id.clone(),
                client_secret: Some(request.client_secret.clone()),
                method: TokenEndpointAuthMethod::ClientSecretPost,
            }),
            _ => None,
        });
    }
    parse_basic_client_auth(headers)
}

pub(super) fn parse_basic_client_auth(headers: &HeaderMap) -> Result<Option<OAuth2ClientAuth>, ErrorResponse> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| {
        ErrorResponse::new(idp_model::contract::ErrorCode::InvalidClient)
            .with_description("invalid authorization header encoding")
    })?;

    let Some(encoded) = raw.strip_prefix("Basic ") else {
        return Err(
            ErrorResponse::new(idp_model::contract::ErrorCode::InvalidClient)
                .with_description("unsupported token endpoint authorization method"),
        );
    };

    let decoded = STANDARD.decode(encoded).map_err(|_| {
        ErrorResponse::new(idp_model::contract::ErrorCode::InvalidClient)
            .with_description("invalid basic authorization token")
    })?;

    let decoded = String::from_utf8(decoded).map_err(|_| {
        ErrorResponse::new(idp_model::contract::ErrorCode::InvalidClient)
            .with_description("invalid basic authorization token")
    })?;

    let mut parts = decoded.splitn(2, ':');
    let client_id = parts.next().unwrap_or_default().trim();
    let client_secret = parts.next();

    if client_id.is_empty() {
        return Err(
            ErrorResponse::new(idp_model::contract::ErrorCode::InvalidClient)
                .with_description("client_id is required in basic authorization"),
        );
    }

    Ok(Some(OAuth2ClientAuth {
        client_id: client_id.to_string(),
        client_secret: client_secret.map(str::to_string),
        method: TokenEndpointAuthMethod::ClientSecretBasic,
    }))
}
