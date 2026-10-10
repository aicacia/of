use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use storage_service::{FileSystemId, ScopedFileSystemRuntime};

use super::{ResourceState, StorageNamespace, authorization, authorize_response, namespace};

struct ResidencyUpdateError(StatusCode);

impl From<String> for ResidencyUpdateError {
    fn from(error: String) -> Self {
        log::warn!("Storage Residency owner update failed: {error}");
        Self(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ResidencyMode {
    Full,
    Passthrough,
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceResidency {
    mode: ResidencyMode,
}

async fn require_target(
    runtime: &ScopedFileSystemRuntime<EndpointId>,
    scope: &StorageNamespace,
    id: FileSystemId,
) -> Result<(), StatusCode> {
    if !runtime
        .list_resources(scope)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .iter()
        .any(|resource| resource.id == id)
    {
        return Err(StatusCode::NOT_FOUND);
    }
    runtime
        .require_local_copy(scope, id)
        .map_err(|_| StatusCode::CONFLICT)
}

#[utoipa::path(
    get,
    path = "/storage/filesystems/{filesystem_id}/residency",
    params(("filesystem_id" = String, Path, description = "Filesystem resource ID")),
    responses(
        (status = 200, description = "Current local whole-filesystem mode, not content availability", body = ResourceResidency),
        (status = 401, description = "Invalid Storage User authorization"),
        (status = 403, description = "Token does not permit reads"),
        (status = 404, description = "Filesystem not found in the authorized namespace"),
        (status = 409, description = "Local copy unavailable; cleanup must not be bypassed"),
        (status = 500, description = "Owner Residency read failed"),
        (status = 503, description = "Local Storage or identity service unavailable")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn get_file_system_residency(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ResourceResidency>, StatusCode> {
    let (scope, can_read, _) = namespace(
        authorization(&state, &headers).await?,
        "storage:filesystems",
    )?;
    if !can_read {
        return Err(StatusCode::FORBIDDEN);
    }
    let id = FileSystemId::parse(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    let runtime = state
        .file_systems
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    require_target(runtime, &scope, id).await?;
    let filesystem = runtime
        .open_resource(&scope, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mode = match filesystem
        .residency("")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        file_system::Residency::Full => ResidencyMode::Full,
        file_system::Residency::Passthrough => ResidencyMode::Passthrough,
    };
    authorize_response(&state, &headers, &scope, "storage:filesystems", false).await?;
    require_target(runtime, &scope, id).await?;
    Ok(Json(ResourceResidency { mode }))
}

#[utoipa::path(
    put,
    path = "/storage/filesystems/{filesystem_id}/residency",
    params(("filesystem_id" = String, Path, description = "Filesystem resource ID")),
    request_body = ResourceResidency,
    responses(
        (status = 204, description = "Local whole-filesystem Residency persisted; not content availability or cleanup completion"),
        (status = 401, description = "Invalid Storage User authorization"),
        (status = 403, description = "Token does not permit writes"),
        (status = 404, description = "Filesystem not found in the authorized namespace"),
        (status = 409, description = "Local copy unavailable; cleanup must not be bypassed"),
        (status = 500, description = "Owner Residency update failed; retry/read current mode"),
        (status = 503, description = "Local Storage or identity service unavailable")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn put_file_system_residency(
    State(state): State<ResourceState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ResourceResidency>,
) -> Result<StatusCode, StatusCode> {
    let (scope, _, can_write) = namespace(
        authorization(&state, &headers).await?,
        "storage:filesystems",
    )?;
    if !can_write {
        return Err(StatusCode::FORBIDDEN);
    }
    let id = FileSystemId::parse(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    let runtime = state
        .file_systems
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    require_target(runtime, &scope, id).await?;
    let mode = match request.mode {
        ResidencyMode::Full => file_system::Residency::Full,
        ResidencyMode::Passthrough => file_system::Residency::Passthrough,
    };
    runtime
        .set_resource_residency_checked(&scope, id, mode, || async {
            authorize_response(&state, &headers, &scope, "storage:filesystems", true)
                .await
                .map_err(ResidencyUpdateError)?;
            require_target(runtime, &scope, id)
                .await
                .map_err(ResidencyUpdateError)
        })
        .await
        .map_err(|error| error.0)?;
    Ok(StatusCode::NO_CONTENT)
}
