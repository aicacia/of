use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use idp_model::{
    contract::{
        ErrorCode, ErrorResponse, IdentityAction, IdentityResource, IdpSignerRecord, JwkPublic,
        PermissionTarget, ReplicaMembership,
    },
    model::Id,
};
use idp_service::repo::RepoError;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::router::{
    RouterState,
    middleware::{StandardAuthorization, require_identity_permission},
};

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EnrollReplicaSigner {
    #[schema(value_type = String)]
    member_id: Id,
    endpoint_id: String,
    public_jwk: JwkPublic,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RotateReplicaSigner {
    public_jwk: JwkPublic,
}

#[utoipa::path(
    post,
    path = "/replica-signers",
    request_body = EnrollReplicaSigner,
    responses(
        (status = 201, description = "Replica signer approved"),
        (status = 403, description = "Caller is not authorized")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn enroll_replica_signer(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
    Json(body): Json<EnrollReplicaSigner>,
) -> Result<StatusCode, ErrorResponse> {
    if !state.oauth2_service.is_authority() {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    require_identity_permission(
        &state,
        &actor,
        IdentityAction::ReplicaSignersEnroll,
        PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner { member_id: None },
        },
    )
    .await?;

    let key_id = body
        .public_jwk
        .kid
        .parse::<Id>()
        .map_err(|_| ErrorResponse::new(ErrorCode::InvalidRequest))?;
    let issuer = state.oauth2_service.metadata().issuer;
    let approved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))?
        .as_secs() as i64;
    let membership = ReplicaMembership {
        installation_id: issuer.clone(),
        member_id: body.member_id,
        endpoint_id: body.endpoint_id,
        issuer: issuer.clone(),
        approved_at,
        revoked_at: None,
    };
    let signer = IdpSignerRecord {
        member_id: membership.member_id,
        key_id,
        issuer,
        public_jwk: body.public_jwk,
        approved_at: Some(approved_at),
        revoked_at: None,
        expires_at: None,
    };

    let created = state
        .replica_signers
        .enroll(&membership, &signer)
        .await
        .map_err(signer_repo_error)?;
    if !created {
        return Ok(StatusCode::OK);
    }
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    put,
    path = "/replica-signers/{member_id}",
    params(("member_id" = String, Path)),
    request_body = RotateReplicaSigner,
    responses((status = 200, description = "Replica signer rotated")),
    security(("authorization" = []))
)]
pub(crate) async fn rotate_replica_signer(
    State(state): State<RouterState>,
    Path(member_id): Path<Id>,
    actor: StandardAuthorization,
    Json(body): Json<RotateReplicaSigner>,
) -> Result<StatusCode, ErrorResponse> {
    if !state.oauth2_service.is_authority() {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    require_identity_permission(
        &state,
        &actor,
        IdentityAction::ReplicaSignersRotate,
        PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner {
                member_id: Some(member_id),
            },
        },
    )
    .await?;
    let key_id = body
        .public_jwk
        .kid
        .parse::<Id>()
        .map_err(|_| ErrorResponse::new(ErrorCode::InvalidRequest))?;
    let issuer = state.oauth2_service.metadata().issuer;
    let approved_at = unix_time()?;
    let signer = IdpSignerRecord {
        member_id,
        key_id,
        issuer: issuer.clone(),
        public_jwk: body.public_jwk,
        approved_at: Some(approved_at),
        revoked_at: None,
        expires_at: None,
    };
    state
        .replica_signers
        .rotate(member_id, &issuer, &signer)
        .await
        .map_err(signer_repo_error)?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    delete,
    path = "/replica-signers/{member_id}",
    params(("member_id" = String, Path)),
    responses((status = 200, description = "Replica signer revoked")),
    security(("authorization" = []))
)]
pub(crate) async fn revoke_replica_signer(
    State(state): State<RouterState>,
    Path(member_id): Path<Id>,
    actor: StandardAuthorization,
) -> Result<StatusCode, ErrorResponse> {
    if !state.oauth2_service.is_authority() {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    require_identity_permission(
        &state,
        &actor,
        IdentityAction::ReplicaSignersRevoke,
        PermissionTarget::Installation {
            resource: IdentityResource::ReplicaSigner {
                member_id: Some(member_id),
            },
        },
    )
    .await?;
    state
        .replica_signers
        .revoke(
            member_id,
            &state.oauth2_service.metadata().issuer,
            unix_time()?,
        )
        .await
        .map_err(signer_repo_error)?;
    Ok(StatusCode::OK)
}

fn signer_repo_error(error: RepoError) -> ErrorResponse {
    match error {
        RepoError::InvalidInput(_) => ErrorResponse::new(ErrorCode::InvalidRequest),
        error => ErrorResponse::from(error),
    }
}

fn unix_time() -> Result<i64, ErrorResponse> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| ErrorResponse::new(ErrorCode::ServerError))
}
