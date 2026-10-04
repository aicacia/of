use axum::Json;
use idp_model::contract::{
    ErrorCode, ErrorResponse, SetupBootstrapRegistration, SetupBootstrapRequest,
};

use crate::router::middleware::StandardAuthorization;

#[utoipa::path(
    post,
    path = "/setup/bootstrap",
    request_body = SetupBootstrapRequest,
    responses((status = 403, description = "Privileged scoped replica enrollment is unavailable")),
    security(("authorization" = []))
)]
pub(crate) async fn register_bootstrap(
    StandardAuthorization { .. }: StandardAuthorization,
    Json(_request): Json<SetupBootstrapRequest>,
) -> Result<Json<SetupBootstrapRegistration>, ErrorResponse> {
    Err(ErrorResponse::new(ErrorCode::AccessDenied)
        .with_description("privileged scoped IdP replica enrollment is unavailable"))
}
