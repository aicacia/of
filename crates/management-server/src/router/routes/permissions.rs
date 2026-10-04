use axum::{
    Json,
    extract::{Path, Query, State},
};
use idp_model::contract::{ErrorCode, ErrorResponse};
use serde::{Deserialize, Serialize};

use crate::router::{RouterState, middleware::ManagementAuthorization};

use super::roles::require_application_permission;

const PERMISSIONS_READ_PERMISSION: &str = "permissions.read";
const PERMISSIONS_WRITE_PERMISSION: &str = "permissions.write";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub(crate) struct PermissionResponse {
    #[schema(value_type = String)]
    pub id: idp_model::model::Id,
    #[schema(value_type = String)]
    pub application_id: idp_model::model::Id,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<idp_model::model::Permission> for PermissionResponse {
    fn from(value: idp_model::model::Permission) -> Self {
        Self {
            id: value.id,
            application_id: value.application_id,
            name: value.name,
            description: value.description,
            created_at: value.created_at.timestamp(),
            updated_at: value.updated_at.timestamp(),
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::IntoParams, utoipa::ToSchema,
)]
pub(crate) struct ListPermissionsQuery {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub(crate) struct CreatePermissionRequest {
    pub name: String,
    pub description: Option<String>,
}

#[utoipa::path(
    get,
    path = "/applications/{application_id}/permissions",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ListPermissionsQuery
    ),
    responses((status = 200, description = "List permissions", body = [PermissionResponse])),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn list_permissions(
    State(state): State<RouterState>,
    Path(application_id): Path<idp_model::model::Id>,
    Query(query): Query<ListPermissionsQuery>,
    authorization: ManagementAuthorization,
) -> Result<Json<Vec<PermissionResponse>>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        PERMISSIONS_READ_PERMISSION,
    )
    .await?;

    let permissions = state
        .management_service
        .list_permissions(application_id, query.offset, normalize_limit(query.limit))
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(permissions.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/applications/{application_id}/permissions",
    params(
        ("application_id" = String, Path, description = "Application ID")
    ),
    request_body = CreatePermissionRequest,
    responses((status = 201, description = "Create permission", body = PermissionResponse)),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn create_permission(
    State(state): State<RouterState>,
    Path(application_id): Path<idp_model::model::Id>,
    authorization: ManagementAuthorization,
    Json(body): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        PERMISSIONS_WRITE_PERMISSION,
    )
    .await?;

    let permission = state
        .management_service
        .create_permission(application_id, &body.name, body.description.as_deref())
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(permission.into()))
}

#[utoipa::path(
    delete,
    path = "/applications/{application_id}/permissions/{permission_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("permission_id" = String, Path, description = "Permission ID")
    ),
    responses((status = 204, description = "Delete permission")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn delete_permission(
    State(state): State<RouterState>,
    Path((application_id, permission_id)): Path<(idp_model::model::Id, idp_model::model::Id)>,
    authorization: ManagementAuthorization,
) -> Result<(), ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        PERMISSIONS_WRITE_PERMISSION,
    )
    .await?;

    if state
        .management_service
        .find_permission_by_id(application_id, permission_id)
        .await
        .map_err(ErrorResponse::from)?
        .is_none()
    {
        return Err(
            ErrorResponse::new(ErrorCode::NotFound).with_description("Permission not found")
        );
    }

    state
        .management_service
        .delete_permission_by_id(application_id, permission_id)
        .await
        .map_err(ErrorResponse::from)
}

#[utoipa::path(
    get,
    path = "/applications/{application_id}/roles/{role_id}/permissions",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("role_id" = String, Path, description = "Role ID")
    ),
    responses((status = 200, description = "List role permissions", body = [PermissionResponse])),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn list_role_permissions(
    State(state): State<RouterState>,
    Path((application_id, role_id)): Path<(idp_model::model::Id, idp_model::model::Id)>,
    authorization: ManagementAuthorization,
) -> Result<Json<Vec<PermissionResponse>>, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        PERMISSIONS_READ_PERMISSION,
    )
    .await?;

    let permissions = state
        .management_service
        .list_role_permissions(application_id, role_id)
        .await
        .map_err(ErrorResponse::from)?;

    Ok(Json(permissions.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/applications/{application_id}/roles/{role_id}/permissions/{permission_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("role_id" = String, Path, description = "Role ID"),
        ("permission_id" = String, Path, description = "Permission ID")
    ),
    responses((status = 204, description = "Assign permission to role")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn assign_permission_to_role(
    State(state): State<RouterState>,
    Path((application_id, role_id, permission_id)): Path<(
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
        PERMISSIONS_WRITE_PERMISSION,
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

    if state
        .management_service
        .find_permission_by_id(application_id, permission_id)
        .await
        .map_err(ErrorResponse::from)?
        .is_none()
    {
        return Err(
            ErrorResponse::new(ErrorCode::NotFound).with_description("Permission not found")
        );
    }

    state
        .management_service
        .add_permission_to_role(application_id, role_id, permission_id)
        .await
        .map_err(ErrorResponse::from)
}

#[utoipa::path(
    delete,
    path = "/applications/{application_id}/roles/{role_id}/permissions/{permission_id}",
    params(
        ("application_id" = String, Path, description = "Application ID"),
        ("role_id" = String, Path, description = "Role ID"),
        ("permission_id" = String, Path, description = "Permission ID")
    ),
    responses((status = 204, description = "Revoke permission from role")),
    security(
        ("authorization" = [])
    )
)]
pub(crate) async fn revoke_permission_from_role(
    State(state): State<RouterState>,
    Path((application_id, role_id, permission_id)): Path<(
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
        PERMISSIONS_WRITE_PERMISSION,
    )
    .await?;

    state
        .management_service
        .remove_permission_from_role(application_id, role_id, permission_id)
        .await
        .map_err(ErrorResponse::from)
}

const fn default_limit() -> u32 {
    50
}

fn normalize_limit(limit: u32) -> u32 {
    limit.clamp(1, 100)
}
