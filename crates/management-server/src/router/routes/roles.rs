use axum::{
    Json,
    extract::{Path, Query, State},
};
use idp_model::contract::{ErrorCode, ErrorResponse};
use serde::{Deserialize, Serialize};

use crate::router::{ManagementRouterService, RouterState, middleware::ManagementAuthorization};

const ROLES_READ_PERMISSION: &str = "roles.read";
const ROLES_WRITE_PERMISSION: &str = "roles.write";

#[cfg(test)]
#[path = "permission_boundary_tests.rs"]
mod permission_boundary_tests;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub(crate) struct RoleResponse {
    #[schema(value_type = String)]
    pub id: idp_model::model::Id,
    #[schema(value_type = String)]
    pub application_id: idp_model::model::Id,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<idp_model::model::Role> for RoleResponse {
    fn from(role: idp_model::model::Role) -> Self {
        Self {
            id: role.id,
            application_id: role.application_id,
            name: role.name,
            description: role.description,
            created_at: role.created_at.timestamp(),
            updated_at: role.updated_at.timestamp(),
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::IntoParams, utoipa::ToSchema,
)]
pub(crate) struct ListRolesQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub(crate) struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

#[utoipa::path(
    get,
    path = "/applications/{application_id}/roles",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ListRolesQuery
    ),
    responses((status = 200, description = "List roles", body = [RoleResponse])),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn list_roles(
    State(state): State<RouterState>,
    Path(application_id): Path<idp_model::model::Id>,
    Query(query): Query<ListRolesQuery>,
    authorization: ManagementAuthorization,
) -> Result<Json<Vec<RoleResponse>>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_READ_PERMISSION,
    )
    .await?;

    let roles = state
        .management_service
        .list_roles(application_id, query.offset, normalize_limit(query.limit))
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/applications/{application_id}/roles",
    params(
        ("application_id" = String, Path, description = "Application ID")
    ),
    request_body = CreateRoleRequest,
    responses((status = 201, description = "Create role", body = RoleResponse)),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn create_role(
    State(state): State<RouterState>,
    Path(application_id): Path<idp_model::model::Id>,
    authorization: ManagementAuthorization,
    Json(body): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_WRITE_PERMISSION,
    )
    .await?;

    let role = state
        .management_service
        .create_role(application_id, &body.name, body.description.as_deref())
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(role.into()))
}

#[utoipa::path(
    delete,
    path = "/applications/{application_id}/roles/{role_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("role_id" = String, Path, description = "Role ID")
    ),
    responses((status = 204, description = "Delete role")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn delete_role(
    State(state): State<RouterState>,
    Path((application_id, role_id)): Path<(idp_model::model::Id, idp_model::model::Id)>,
    authorization: ManagementAuthorization,
) -> Result<(), ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_WRITE_PERMISSION,
    )
    .await?;

    if state
        .management_service
        .find_role_by_id(application_id, role_id)
        .await
        .map_err(ErrorResponse::from)?
        .is_none()
    {
        return Err(ErrorResponse::new(ErrorCode::NotFound).with_description("Role not found"));
    }

    state
        .management_service
        .delete_role_by_id(application_id, role_id)
        .await
        .map_err(ErrorResponse::from)
}

#[utoipa::path(
    get,
    path = "/applications/{application_id}/users/{user_id}/roles",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("user_id" = String, Path, description = "User ID")
    ),
    responses((status = 200, description = "List user roles", body = [RoleResponse])),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn list_user_roles(
    State(state): State<RouterState>,
    Path((application_id, user_id)): Path<(idp_model::model::Id, idp_model::model::Id)>,
    authorization: ManagementAuthorization,
) -> Result<Json<Vec<RoleResponse>>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_READ_PERMISSION,
    )
    .await?;

    let roles = state
        .management_service
        .list_user_roles(application_id, user_id)
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/applications/{application_id}/users/{user_id}/roles/{role_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("user_id" = String, Path, description = "User ID"),
        ("role_id" = String, Path, description = "Role ID")
    ),
    responses((status = 204, description = "Assign role to user")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn assign_role_to_user(
    State(state): State<RouterState>,
    Path((application_id, user_id, role_id)): Path<(
        idp_model::model::Id,
        idp_model::model::Id,
        idp_model::model::Id,
    )>,
    authorization: ManagementAuthorization,
) -> Result<(), ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_WRITE_PERMISSION,
    )
    .await?;

    if state
        .management_service
        .find_role_by_id(application_id, role_id)
        .await
        .map_err(ErrorResponse::from)?
        .is_none()
    {
        return Err(ErrorResponse::new(ErrorCode::NotFound).with_description("Role not found"));
    }

    state
        .management_service
        .add_role_to_user(application_id, user_id, role_id)
        .await
        .map_err(ErrorResponse::from)
}

#[utoipa::path(
    delete,
    path = "/applications/{application_id}/users/{user_id}/roles/{role_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("user_id" = String, Path, description = "User ID"),
        ("role_id" = String, Path, description = "Role ID")
    ),
    responses((status = 204, description = "Revoke role from user")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn revoke_role_from_user(
    State(state): State<RouterState>,
    Path((application_id, user_id, role_id)): Path<(
        idp_model::model::Id,
        idp_model::model::Id,
        idp_model::model::Id,
    )>,
    authorization: ManagementAuthorization,
) -> Result<(), ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        ROLES_WRITE_PERMISSION,
    )
    .await?;

    state
        .management_service
        .remove_role_from_user(application_id, user_id, role_id)
        .await
        .map_err(ErrorResponse::from)
}

pub(crate) async fn require_application_permission(
    management_service: &ManagementRouterService,
    authorization: &ManagementAuthorization,
    application_id: idp_model::model::Id,
    permission: &str,
) -> Result<(), ErrorResponse> {
    if application_id.is_nil() || authorization.application_id != application_id {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied)
            .with_description("application permission does not authorize another application"));
    }
    let has_permission = management_service
        .has_user_application_permission(authorization.subject, application_id, permission)
        .await
        .map_err(ErrorResponse::from)?;

    if has_permission {
        return Ok(());
    }

    Err(ErrorResponse::new(ErrorCode::AccessDenied)
        .with_description("missing required application permission"))
}

const fn default_limit() -> u32 {
    50
}

fn normalize_limit(limit: u32) -> u32 {
    limit.clamp(1, 100)
}
