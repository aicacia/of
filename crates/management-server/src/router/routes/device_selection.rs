use std::string::String;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use idp_model::{
    contract::{ErrorCode, ErrorResponse},
    model::Id,
};
use management_service::replica::SelectionPolicy;
use serde::Deserialize;
use storage_model::ResourceKind;

use crate::router::{RouterState, middleware::ManagementAuthorization};

use super::roles::require_application_permission;

const SELECTION_PERMISSION: &str = "devices.select";

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectionRequest {
    #[schema(value_type = String)]
    application_id: Id,
    kind: SelectionKind,
    #[schema(value_type = String)]
    id: Id,
    storage_access_token: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SelectionKind {
    Database,
    Filesystem,
}

impl SelectionKind {
    fn resource_kind(&self) -> ResourceKind {
        match self {
            Self::Database => ResourceKind::Database,
            Self::Filesystem => ResourceKind::FileSystem,
        }
    }

    fn policy_kind(&self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Filesystem => "filesystem",
        }
    }
}

#[utoipa::path(
    put,
    path = "/devices/{device_id}/selection",
    params(("device_id" = String, Path, description = "Device ID")),
    request_body = SelectionRequest,
    responses((status = 204, description = "Device selection updated")),
    security(("authorization" = []))
)]
pub(crate) async fn put_device_selection(
    State(state): State<RouterState>,
    Path(device_id): Path<Id>,
    authorization: ManagementAuthorization,
    Json(body): Json<SelectionRequest>,
) -> Result<StatusCode, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        body.application_id,
        SELECTION_PERMISSION,
    )
    .await?;
    let owner = authorization.subject.to_string();
    if body.storage_access_token.is_empty()
        || body
            .storage_access_token
            .trim()
            .contains(char::is_whitespace)
    {
        return Err(ErrorResponse::new(ErrorCode::NotAuthorized));
    }

    state
        .control_plane
        .validate_selection_device(
            &body.storage_access_token,
            &owner,
            &state.storage_audience,
            device_id,
        )
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::AccessDenied))?;
    state
        .control_plane
        .validate_storage_resource(
            &body.storage_access_token,
            &owner,
            &state.storage_audience,
            body.application_id,
            body.kind.resource_kind(),
            &body.id.to_string(),
        )
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::AccessDenied))?;

    let previous = state
        .selection_policies
        .get(device_id, &owner, body.application_id)
        .await
        .map_err(ErrorResponse::from)?;
    if previous
        .as_ref()
        .is_some_and(|policy| !policy.admin_allowed)
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    state
        .selection_policies
        .set_prevalidated(SelectionPolicy {
            device_id,
            owner_subject: owner,
            application_id: Some(body.application_id),
            selected_kind: Some(body.kind.policy_kind().to_owned()),
            selected_id: Some(body.id),
            admin_allowed: previous.is_none_or(|policy| policy.admin_allowed),
        })
        .await
        .map_err(ErrorResponse::from)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/devices/{device_id}/selection",
    params(("device_id" = String, Path, description = "Device ID")),
    responses((status = 204, description = "Device selection removed")),
    security(("authorization" = []))
)]
pub(crate) async fn delete_device_selection(
    Path(_device_id): Path<Id>,
    _authorization: ManagementAuthorization,
) -> Result<StatusCode, ErrorResponse> {
    Err(ErrorResponse::new(ErrorCode::AccessDenied)
        .with_description("deselect resources through the application-scoped resource route"))
}

#[utoipa::path(
    delete,
    path = "/devices/{device_id}/selection/{application_id}/{kind}/{resource_id}",
    params(
        ("device_id" = String, Path, description = "Device ID"),
        ("application_id" = String, Path, description = "Application ID"),
        ("kind" = String, Path, description = "Resource kind"),
        ("resource_id" = String, Path, description = "Resource ID")
    ),
    responses((status = 204, description = "Device resource selection removed")),
    security(("authorization" = []))
)]
pub(crate) async fn delete_device_resource_selection(
    State(state): State<RouterState>,
    Path((device_id, application_id, kind, resource_id)): Path<(Id, Id, SelectionKind, Id)>,
    authorization: ManagementAuthorization,
) -> Result<StatusCode, ErrorResponse> {
    require_application_permission(
        state.management_service.as_ref(),
        &authorization,
        application_id,
        SELECTION_PERMISSION,
    )
    .await?;
    let owner = authorization.subject.to_string();
    if !state
        .selection_policies
        .deselect_resource_owned(
            device_id,
            &owner,
            application_id,
            kind.policy_kind(),
            resource_id,
        )
        .await
        .map_err(ErrorResponse::from)?
    {
        return Err(ErrorResponse::new(ErrorCode::NotFound));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::{SelectionKind, SelectionRequest};

    #[test]
    fn selection_request_accepts_only_supported_kinds() {
        let id = "00000000-0000-0000-0000-000000000001";
        for kind in ["database", "filesystem"] {
            let body = format!(
                r#"{{"applicationId":"{id}","kind":"{kind}","id":"{id}","storageAccessToken":"storage-token"}}"#
            );
            let parsed: SelectionRequest = serde_json::from_str(&body).expect("supported kind");
            assert!(matches!(
                parsed.kind,
                SelectionKind::Database | SelectionKind::Filesystem
            ));
        }
        let body = format!(
            r#"{{"applicationId":"{id}","kind":"unknown","id":"{id}","storageAccessToken":"storage-token"}}"#
        );
        assert!(serde_json::from_str::<SelectionRequest>(&body).is_err());
    }

    #[test]
    fn selection_request_requires_storage_access_token_as_data() {
        let id = "00000000-0000-0000-0000-000000000001";
        let without_token = format!(r#"{{"applicationId":"{id}","kind":"database","id":"{id}"}}"#);
        assert!(serde_json::from_str::<SelectionRequest>(&without_token).is_err());
        let with_token = format!(
            r#"{{"applicationId":"{id}","kind":"database","id":"{id}","storageAccessToken":"token"}}"#
        );
        let parsed: SelectionRequest =
            serde_json::from_str(&with_token).expect("token is request data");
        assert_eq!(parsed.storage_access_token, "token");
    }
}
