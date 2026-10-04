use axum::{extract::{Form, State}, http::HeaderMap};
use idp_model::contract::{ErrorResponse, RevocationRequest};

use crate::router::RouterState;

#[utoipa::path(post, path = "/oauth2/revoke", request_body(content = RevocationRequest, content_type = "application/x-www-form-urlencoded"), responses((status = 200, description = "Revoke token")))]
pub(crate) async fn revoke(
    headers: HeaderMap,
    State(state): State<RouterState>,
    Form(request): Form<RevocationRequest>,
) -> Result<(), ErrorResponse> {
    let client_auth = super::token::parse_basic_client_auth(&headers)?;
    state.oauth2_service.revoke(request, client_auth).await
}
