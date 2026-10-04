use axum::{
    Json,
    extract::{Path, State},
};
use idp_model::contract::ErrorResponse;
use serde::{Deserialize, Serialize};

use crate::router::{RouterState, middleware::ManagementAuthorization};

use super::roles::require_application_permission;

const USERS_READ_PERMISSION: &str = "users.read";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub(crate) struct UserApplicationRoleResponse {
    #[schema(value_type = String)]
    pub role_id: idp_model::model::Id,
    #[schema(value_type = String)]
    pub application_id: idp_model::model::Id,
    pub role_name: String,
    pub role_description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<idp_model::model::Role> for UserApplicationRoleResponse {
    fn from(value: idp_model::model::Role) -> Self {
        Self {
            role_id: value.id,
            application_id: value.application_id,
            role_name: value.name,
            role_description: value.description,
            created_at: value.created_at.timestamp(),
            updated_at: value.updated_at.timestamp(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/users/{user_id}/roles",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses((status = 200, description = "List user roles within the authorized application", body = [UserApplicationRoleResponse])),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn list_user_roles_across_applications(
    State(state): State<RouterState>,
    Path(user_id): Path<idp_model::model::Id>,
    authorization: ManagementAuthorization,
) -> Result<Json<Vec<UserApplicationRoleResponse>>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        authorization.application_id,
        USERS_READ_PERMISSION,
    )
    .await?;

    let roles = state
        .management_service
        .list_user_roles(authorization.application_id, user_id)
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(roles.into_iter().map(Into::into).collect()))
}
