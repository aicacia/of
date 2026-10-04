use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header::AUTHORIZATION},
};
use idp_model::{
    contract::{
        ApprovedDeviceEndpoints, DeviceEndpointIdentity, DeviceEnrollment, DeviceEnrollmentRequest,
        DeviceInfo, DeviceState, ErrorCode, ErrorResponse, IdentityAction, IdentityResource,
        PairingAcceptance, PermissionTarget, TrustedDevice, UpdateDeviceRequest,
    },
    model::Id,
};
use iroh::EndpointId;
use management_service::{DeviceEnrollmentService, DeviceRepo};
use model::contract::PrincipalType;

use crate::router::{
    PairingAcceptanceController, RouterState,
    middleware::{StandardAuthorization, authorize_bearer_client, require_identity_permission},
};

const DEVICE_LOOKUP_SCOPE: &str = "idp.device.lookup";
const DEVICE_LIST_SCOPE: &str = "idp.device.list";

#[utoipa::path(
    get,
    path = "/devices/endpoints/{endpoint_id}",
    params(("endpoint_id" = String, Path, description = "Iroh endpoint public key")),
    responses(
        (status = 200, description = "Approved endpoint identity", body = DeviceEndpointIdentity),
        (status = 401, description = "Invalid client access token"),
        (status = 403, description = "Client lacks device lookup permission"),
        (status = 404, description = "Endpoint is not an approved device")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn lookup_device_endpoint(
    State(state): State<RouterState>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeviceEndpointIdentity>, ErrorResponse> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotAuthorized))?;
    let caller = authorize_bearer_client(&state, token).await?;
    if !can_lookup_device_endpoint(
        caller.claims.principal_type,
        &caller.claims.aud,
        &caller.claims.scope,
        &state.service_audience,
    ) {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let parsed_endpoint = endpoint_id
        .parse::<EndpointId>()
        .map_err(|_| ErrorResponse::new(ErrorCode::InvalidRequest))?;
    if parsed_endpoint.to_string() != endpoint_id {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest));
    }
    let device = state
        .devices
        .find_approved_by_public_key(&endpoint_id)
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))?;
    Ok(Json(DeviceEndpointIdentity {
        device_id: device.id,
        owner_subject: device.owner_subject,
        endpoint_id,
    }))
}

#[utoipa::path(
    get,
    path = "/devices/endpoints",
    responses(
        (status = 200, description = "Approved endpoint IDs", body = ApprovedDeviceEndpoints),
        (status = 401, description = "Invalid client access token"),
        (status = 403, description = "Client lacks device-list permission")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn list_approved_device_endpoints(
    State(state): State<RouterState>,
    headers: HeaderMap,
) -> Result<Json<ApprovedDeviceEndpoints>, ErrorResponse> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotAuthorized))?;
    let caller = authorize_bearer_client(&state, token).await?;
    if !can_list_device_endpoints(
        caller.claims.principal_type,
        &caller.claims.aud,
        &caller.claims.scope,
        &state.service_audience,
    ) {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let endpoint_ids = state
        .devices
        .list()
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?
        .into_iter()
        .filter(|device| device.state == DeviceState::Approved)
        .map(|device| device.public_key)
        .collect();
    Ok(Json(ApprovedDeviceEndpoints { endpoint_ids }))
}

fn can_list_device_endpoints(
    principal_type: PrincipalType,
    audience: &str,
    scopes: &[String],
    service_audience: &str,
) -> bool {
    principal_type == PrincipalType::Client
        && audience == service_audience
        && scopes.iter().any(|scope| scope == DEVICE_LIST_SCOPE)
}

fn can_lookup_device_endpoint(
    principal_type: PrincipalType,
    audience: &str,
    scopes: &[String],
    service_audience: &str,
) -> bool {
    principal_type == PrincipalType::Client
        && audience == service_audience
        && scopes.iter().any(|scope| scope == DEVICE_LOOKUP_SCOPE)
}

#[cfg(test)]
mod tests {
    use model::contract::PrincipalType;

    use super::{DEVICE_LIST_SCOPE, can_list_device_endpoints, can_lookup_device_endpoint};

    #[test]
    fn device_lookup_requires_client_principal_audience_and_scope() {
        let scopes = vec!["idp.device.lookup".to_owned()];

        assert!(can_lookup_device_endpoint(
            PrincipalType::Client,
            "idp-service",
            &scopes,
            "idp-service"
        ));
        assert!(!can_lookup_device_endpoint(
            PrincipalType::User,
            "idp-service",
            &scopes,
            "idp-service"
        ));
        assert!(!can_lookup_device_endpoint(
            PrincipalType::Client,
            "other-service",
            &scopes,
            "idp-service"
        ));
        assert!(!can_lookup_device_endpoint(
            PrincipalType::Client,
            "idp-service",
            &[],
            "idp-service"
        ));
    }

    #[test]
    fn device_list_requires_its_own_client_scope() {
        let scopes = vec!["idp.device.lookup".to_owned()];
        assert!(!can_list_device_endpoints(
            PrincipalType::Client,
            "idp-service",
            &scopes,
            "idp-service"
        ));
        let scopes = vec![DEVICE_LIST_SCOPE.to_owned()];
        assert!(can_list_device_endpoints(
            PrincipalType::Client,
            "idp-service",
            &scopes,
            "idp-service"
        ));
        assert!(!can_list_device_endpoints(
            PrincipalType::User,
            "idp-service",
            &scopes,
            "idp-service"
        ));
    }
}

#[utoipa::path(
    get,
    path = "/devices/trusted",
    responses((status = 200, description = "Approved devices", body = [TrustedDevice])),
    security(("authorization" = []))
)]
pub(crate) async fn trusted_devices(
    State(state): State<RouterState>,
    StandardAuthorization { claims, .. }: StandardAuthorization,
) -> Result<Json<Vec<TrustedDevice>>, ErrorResponse> {
    if !claims.scope.iter().any(|scope| scope == "storage") {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let devices = state
        .devices
        .list_approved(&claims.sub)
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?;
    Ok(Json(devices))
}

#[utoipa::path(
    post,
    path = "/devices/enrollments",
    request_body = DeviceEnrollmentRequest,
    responses((status = 200, description = "Device enrollment", body = DeviceEnrollment)),
    security(("authorization" = []))
)]
pub(crate) async fn enroll_device(
    State(state): State<RouterState>,
    StandardAuthorization { claims, .. }: StandardAuthorization,
    Json(request): Json<DeviceEnrollmentRequest>,
) -> Result<Json<DeviceEnrollment>, ErrorResponse> {
    DeviceEnrollmentService::new(state.devices)
        .enroll(claims.sub, request)
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/devices/pairing-accepting",
    responses((status = 200, description = "Pairing acceptance state", body = PairingAcceptance)),
    security(("authorization" = []))
)]
pub(crate) async fn pairing_acceptance(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
) -> Result<Json<PairingAcceptance>, ErrorResponse> {
    require_identity_permission(
        &state,
        &actor,
        IdentityAction::DevicePairingRead,
        PermissionTarget::Installation {
            resource: IdentityResource::DevicePairing,
        },
    )
    .await?;
    state
        .pairing_acceptance
        .pairing_accepting()
        .map(|accepting| Json(PairingAcceptance { accepting }))
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))
}

#[utoipa::path(
    put,
    path = "/devices/pairing-accepting",
    request_body = PairingAcceptance,
    responses((status = 200, description = "Pairing acceptance state", body = PairingAcceptance)),
    security(("authorization" = []))
)]
pub(crate) async fn set_pairing_acceptance(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
    Json(PairingAcceptance { accepting }): Json<PairingAcceptance>,
) -> Result<Json<PairingAcceptance>, ErrorResponse> {
    require_identity_permission(
        &state,
        &actor,
        IdentityAction::DevicePairingUpdate,
        PermissionTarget::Installation {
            resource: IdentityResource::DevicePairing,
        },
    )
    .await?;
    state
        .pairing_acceptance
        .set_pairing_accepting(accepting)
        .map(|()| Json(PairingAcceptance { accepting }))
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))
}

#[utoipa::path(
    get,
    path = "/devices",
    responses((status = 200, description = "Devices", body = [DeviceInfo])),
    security(("authorization" = []))
)]
pub(crate) async fn list_devices(
    State(state): State<RouterState>,
    StandardAuthorization { claims, .. }: StandardAuthorization,
) -> Result<Json<Vec<DeviceInfo>>, ErrorResponse> {
    DeviceEnrollmentService::new(state.devices)
        .list(&claims.sub)
        .await
        .map(Json)
}

#[utoipa::path(
    patch,
    path = "/devices/{id}",
    params(("id" = String, Path, description = "Device ID")),
    request_body = UpdateDeviceRequest,
    responses((status = 200, description = "Updated device", body = DeviceInfo)),
    security(("authorization" = []))
)]
pub(crate) async fn update_device(
    State(state): State<RouterState>,
    Path(device_id): Path<Id>,
    StandardAuthorization { claims, .. }: StandardAuthorization,
    Json(request): Json<UpdateDeviceRequest>,
) -> Result<Json<DeviceInfo>, ErrorResponse> {
    DeviceEnrollmentService::new(state.devices)
        .rename(&claims.sub, device_id, request)
        .await
        .map(Json)
}

#[utoipa::path(
    delete,
    path = "/devices/{id}",
    params(("id" = String, Path, description = "Device ID")),
    responses((status = 204, description = "Revoked device")),
    security(("authorization" = []))
)]
pub(crate) async fn revoke_device(
    State(state): State<RouterState>,
    Path(device_id): Path<Id>,
    StandardAuthorization { claims, .. }: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    DeviceEnrollmentService::new(state.devices)
        .revoke(
            &claims.sub,
            device_id,
            &state.device_identity.endpoint_id().to_string(),
        )
        .await
}
