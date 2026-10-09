use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use idp_model::{
    contract::{
        ErrorCode, ErrorResponse, IdentityAction, IdentityResource, PermissionEvaluationRequest,
        PermissionSubject, PermissionTarget,
    },
    model::Id,
};
use serde::{Deserialize, Serialize};

use crate::router::{RouterState, middleware::ManagementAuthorization};

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceRestriction {
    pub admin_allowed: bool,
}

async fn binding(
    state: &RouterState,
    actor: &ManagementAuthorization,
    device: Id,
    action: IdentityAction,
) -> Result<String, ErrorResponse> {
    let allowed = state
        .management_service
        .evaluate_permission(&PermissionEvaluationRequest {
            request_id: Id::now_v7(),
            subject: PermissionSubject::User { id: actor.subject },
            action,
            target: PermissionTarget::Installation {
                resource: IdentityResource::Device { id: Some(device) },
            },
        })
        .await
        .map_err(ErrorResponse::from)?;
    if !allowed {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let identity = state
        .control_plane
        .get_storage_device_identity(device)
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::AccessDenied))?;
    if !state
        .selection_policies
        .reconcile_owner_prevalidated(device, &identity.owner_subject)
        .await
        .map_err(ErrorResponse::from)?
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    Ok(identity.owner_subject)
}

#[utoipa::path(get, path = "/devices/{device_id}/restriction", params(("device_id" = String, Path)),
    responses((status = 200, description = "Current Device restriction", body = DeviceRestriction)), security(("authorization" = [])))]
pub(crate) async fn get_device_restriction(
    State(state): State<RouterState>,
    Path(device): Path<Id>,
    actor: ManagementAuthorization,
) -> Result<Json<DeviceRestriction>, ErrorResponse> {
    let owner = binding(
        &state,
        &actor,
        device,
        IdentityAction::DeviceRestrictionsRead,
    )
    .await?;
    let policy = state
        .selection_policies
        .get(device, &owner, Id::nil())
        .await
        .map_err(ErrorResponse::from)?
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))?;
    Ok(Json(DeviceRestriction {
        admin_allowed: policy.admin_allowed,
    }))
}

#[utoipa::path(put, path = "/devices/{device_id}/restriction", params(("device_id" = String, Path)), request_body = DeviceRestriction,
    responses((status = 204, description = "Device restriction updated")), security(("authorization" = [])))]
pub(crate) async fn put_device_restriction(
    State(state): State<RouterState>,
    Path(device): Path<Id>,
    actor: ManagementAuthorization,
    Json(request): Json<DeviceRestriction>,
) -> Result<StatusCode, ErrorResponse> {
    let owner = binding(
        &state,
        &actor,
        device,
        IdentityAction::DeviceRestrictionsUpdate,
    )
    .await?;
    if !state
        .selection_policies
        .set_admin_allowed_prevalidated(device, &owner, request.admin_allowed)
        .await
        .map_err(ErrorResponse::from)?
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::DeviceRestriction;

    #[test]
    fn malformed_restriction_is_not_a_policy_update() {
        for body in [
            r#"{}"#,
            r#"{"adminAllowed":"true"}"#,
            r#"{"adminAllowed":true,"ownerSubject":"forged"}"#,
        ] {
            assert!(serde_json::from_str::<DeviceRestriction>(body).is_err());
        }
    }
}
