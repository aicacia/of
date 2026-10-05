use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
};
use idp_model::contract::{
    ErrorCode, ErrorResponse, IDP_TOKEN_VALIDATE_SCOPE, IntrospectionRequest, IntrospectionResponse,
};

use crate::{RouterState, authorize_bearer_any_principal, authorize_bearer_client};

const VALIDATE_TOKEN_SCOPE: &str = IDP_TOKEN_VALIDATE_SCOPE;

#[utoipa::path(
    post,
    path = "/oauth2/introspect",
    request_body = IntrospectionRequest,
    responses(
        (status = 200, description = "Validated access token", body = IntrospectionResponse),
        (status = 401, description = "Invalid caller or inspected token"),
        (status = 403, description = "Caller is not permitted to validate tokens")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn introspect(
    State(state): State<RouterState>,
    headers: HeaderMap,
    Json(request): Json<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, ErrorResponse> {
    let caller_token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(not_authorized)?;
    let caller = authorize_bearer_client(&state, caller_token).await?;

    if caller.claims.aud != state.service_audience {
        return Err(not_authorized());
    }
    if !caller
        .claims
        .scope
        .iter()
        .any(|scope| scope == VALIDATE_TOKEN_SCOPE)
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let client = state
        .oauth2_service
        .get_client(&caller.claims.client_id)
        .await?;

    let inspected = authorize_bearer_any_principal(&state, &request.token).await?;
    if !allows_audience(&client.allowed_audiences, &inspected.claims.aud) {
        return Err(not_authorized());
    }
    let application_id = state
        .oauth2_service
        .application_id_for_client(&inspected.claims.client_id)
        .await?;

    Ok(Json(IntrospectionResponse {
        claims: inspected.claims,
        application_id: application_id.to_string(),
    }))
}

fn allows_audience(allowed_audiences: &[String], audience: &str) -> bool {
    allowed_audiences.iter().any(|allowed| allowed == audience)
}

fn not_authorized() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::NotAuthorized)
}

#[cfg(test)]
mod tests {
    use super::allows_audience;

    #[test]
    fn inspected_token_audience_must_be_registered_for_caller() {
        let allowed = vec!["management-api".to_owned(), "storage-api".to_owned()];

        assert!(allows_audience(&allowed, "storage-api"));
        assert!(!allows_audience(&allowed, "other-api"));
        assert!(!allows_audience(&[], "storage-api"));
    }
}
