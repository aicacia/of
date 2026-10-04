use axum::{
    Json,
    extract::{Path, State},
};
use idp_model::contract::{ClientRegistration, ErrorCode, ErrorResponse};

use crate::router::{RouterState, middleware::StandardAuthorization};

#[utoipa::path(
    post,
    path = "/oauth2/register",
    request_body(
        content(
            (ClientRegistration = "application/json"),
            (ClientRegistration = "application/x-www-form-urlencoded")
        )
    ),
    responses((status = 201, description = "Register client", body = ClientRegistration)),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn register(
    State(state): State<RouterState>,
    StandardAuthorization { .. }: StandardAuthorization,
    Json(body): Json<ClientRegistration>,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let _ = (state, body);
    Err(identity_admin_not_authorized())
}

#[utoipa::path(
    get,
    path = "/oauth2/register/{client_id}",
    params(
        ("client_id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 200, description = "Get client", body = ClientRegistration),
        (status = 403, description = "Identity administration requires an authorized RBAC permission")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn get_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    StandardAuthorization { .. }: StandardAuthorization,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let _ = (state, client_id);
    Err(identity_admin_not_authorized())
}

#[utoipa::path(
    delete,
    path = "/oauth2/register/{client_id}",
    params(
        ("client_id" = String, Path, description = "Client ID")
    ),
    responses(
        (status = 204, description = "Delete client"),
        (status = 403, description = "Identity administration requires an authorized RBAC permission")
    ),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn delete_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    StandardAuthorization { .. }: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    let _ = (state, client_id);
    Err(identity_admin_not_authorized())
}

#[utoipa::path(
    put,
    path = "/oauth2/register/{client_id}",
    params(
        ("client_id" = String, Path, description = "Client ID")
    ),
    request_body(
        content(
            (ClientRegistration = "application/json"),
            (ClientRegistration = "application/x-www-form-urlencoded")
        )
    ),
    responses(
        (status = 200, description = "Update client", body = ClientRegistration),
        (status = 403, description = "Identity administration requires an authorized RBAC permission")
    ),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn put_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    StandardAuthorization { .. }: StandardAuthorization,
    Json(body): Json<ClientRegistration>,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let _ = (state, client_id, body);
    Err(identity_admin_not_authorized())
}

fn identity_admin_not_authorized() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::AccessDenied)
        .with_description("identity administration requires an authorized RBAC permission")
}

#[cfg(test)]
mod tests {
    use super::identity_admin_not_authorized;
    use idp_model::contract::ErrorCode;

    #[test]
    fn identity_administration_fails_closed_without_rbac() {
        let error = identity_admin_not_authorized();
        assert_eq!(error.error, ErrorCode::AccessDenied);
    }
}
