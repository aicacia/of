use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
};
use idp_model::{
    contract::{
        ErrorCode, ErrorResponse, MANAGEMENT_PERMISSION_EVALUATE_SCOPE, PermissionAuditIdentity,
        PermissionEvaluationRequest, PermissionEvaluationResponse, PermissionSubject,
        PermissionTarget,
    },
    model::Id,
};
use model::contract::{PrincipalType, StandardClaims};

use crate::RouterState;

#[utoipa::path(
    post, path = "/permissions/evaluate",
    request_body = PermissionEvaluationRequest,
    responses(
        (status = 200, description = "Exact permission decision", body = PermissionEvaluationResponse),
        (status = 401, description = "Invalid caller"),
        (status = 403, description = "Caller cannot assert this actor or scope"),
        (status = 503, description = "Identity or policy authority unavailable")
    ),
    security(("authorization" = []))
)]
pub(crate) async fn evaluate_permission(
    State(state): State<RouterState>,
    headers: HeaderMap,
    Json(request): Json<PermissionEvaluationRequest>,
) -> Result<Json<PermissionEvaluationResponse>, ErrorResponse> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ErrorResponse::new(ErrorCode::NotAuthorized))?;
    let (claims, caller_application) = state
        .control_plane
        .validate_actor_token(bearer)
        .await
        .map_err(|error| {
            ErrorResponse::new(if error == "actor token was rejected by IdP" {
                ErrorCode::NotAuthorized
            } else {
                ErrorCode::TemporarilyUnavailable
            })
        })?;
    let audit = bind_actor(
        &claims,
        caller_application,
        state.control_plane.permission_evaluator_client_id(),
        &request,
    )?;

    let PermissionSubject::User { id } = request.subject;
    let allowed = state
        .management_service
        .evaluate_permission(&request)
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::TemporarilyUnavailable))?;
    log::info!(
        "permission decision: request={} caller={} client={} actor={} action={} target={:?} allowed={}",
        request.request_id,
        audit.service_subject,
        audit.service_client_id,
        id,
        request.action.permission(),
        request.target,
        allowed
    );
    Ok(Json(PermissionEvaluationResponse {
        request,
        audit,
        allowed,
    }))
}

fn bind_actor(
    claims: &StandardClaims,
    caller_application: Id,
    evaluator_client_id: Option<&str>,
    request: &PermissionEvaluationRequest,
) -> Result<PermissionAuditIdentity, ErrorResponse> {
    let caller = claims.sub.parse::<Id>().map_err(|_| denied())?;
    let PermissionSubject::User { id } = request.subject;
    if caller.is_nil()
        || id.is_nil()
        || request.request_id.is_nil()
        || claims.aud != management_service::MANAGEMENT_APPLICATION_URI
        || request.policy_namespace().is_none()
    {
        return Err(denied());
    }
    match claims.principal_type {
        PrincipalType::Client => {
            if evaluator_client_id != Some(claims.client_id.as_str())
                || claims.scope.len() != 1
                || claims.scope[0] != MANAGEMENT_PERMISSION_EVALUATE_SCOPE
            {
                return Err(denied());
            }
        }
        PrincipalType::User => {
            if caller != id
                || matches!(request.target,
                PermissionTarget::Application { application_id, .. } if application_id != caller_application)
            {
                return Err(denied());
            }
        }
    }
    Ok(PermissionAuditIdentity {
        service_subject: caller,
        service_client_id: claims.client_id.clone(),
        actor: request.subject.clone(),
    })
}

fn denied() -> ErrorResponse {
    ErrorResponse::new(ErrorCode::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::bind_actor;
    use idp_model::{
        contract::{
            IdentityAction, IdentityResource, MANAGEMENT_PERMISSION_EVALUATE_SCOPE,
            PermissionEvaluationRequest, PermissionSubject, PermissionTarget,
        },
        model::Id,
    };
    use model::contract::{PrincipalType, StandardClaims, TokenType, TokenUse};

    #[test]
    fn actor_binding_requires_the_distinct_idp_relationship_or_the_same_user() {
        let app = Id::now_v7();
        let actor = Id::now_v7();
        let mut request = PermissionEvaluationRequest {
            request_id: Id::now_v7(),
            subject: PermissionSubject::User { id: actor },
            action: IdentityAction::ClientsRead,
            target: PermissionTarget::Application {
                application_id: app,
                resource: IdentityResource::Client {
                    client_id: Some("client".into()),
                },
            },
        };
        let mut claims = StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: i64::MAX,
            iat: 0,
            nbf: 0,
            iss: "issuer".into(),
            aud: management_service::MANAGEMENT_APPLICATION_URI.into(),
            client_id: "idp-evaluator".into(),
            sub: Id::now_v7().to_string(),
            principal_type: PrincipalType::Client,
            resource: None,
            authorization_details: None,
            scope: vec![MANAGEMENT_PERMISSION_EVALUATE_SCOPE.into()],
        };
        assert!(bind_actor(&claims, app, None, &request).is_err());
        assert!(bind_actor(&claims, app, Some("storage-client"), &request).is_err());
        assert!(bind_actor(&claims, app, Some("idp-evaluator"), &request).is_ok());
        claims.principal_type = PrincipalType::User;
        assert!(bind_actor(&claims, app, Some("idp-evaluator"), &request).is_err());
        claims.sub = actor.to_string();
        assert!(bind_actor(&claims, app, None, &request).is_ok());
        assert!(bind_actor(&claims, Id::now_v7(), None, &request).is_err());
        request.target = PermissionTarget::Installation {
            resource: IdentityResource::Client {
                client_id: Some("client".into()),
            },
        };
        assert!(bind_actor(&claims, app, None, &request).is_err());
    }
}
