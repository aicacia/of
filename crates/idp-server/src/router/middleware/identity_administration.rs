use idp_model::{
    contract::{
        ClientRegistration, ErrorCode, ErrorResponse, GrantType, IdentityAction,
        PermissionEvaluationRequest, PermissionSubject, PermissionTarget,
    },
    model::Id,
};
use model::contract::PrincipalType;

use crate::{RouterState, router::middleware::StandardAuthorization};

pub(crate) async fn require_identity_permission(
    state: &RouterState,
    actor: &StandardAuthorization,
    action: IdentityAction,
    target: PermissionTarget,
) -> Result<(), ErrorResponse> {
    if actor.claims.principal_type != PrincipalType::User
        || actor.claims.aud != state.service_audience
        || actor.principal.get_entity_id().to_string() != actor.claims.sub
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    if let PermissionTarget::Application { application_id, .. } = target {
        let actor_application = state
            .oauth2_service
            .application_id_for_client(&actor.claims.client_id)
            .await?;
        if application_id.is_nil() || actor_application != application_id {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied));
        }
    }
    let request = PermissionEvaluationRequest {
        request_id: Id::now_v7(),
        subject: PermissionSubject::User {
            id: actor.principal.get_entity_id(),
        },
        action,
        target,
    };
    let client = state.permission_client.as_ref().ok_or_else(|| {
        ErrorResponse::new(ErrorCode::AccessDenied)
            .with_description("IdP permission service relationship is not configured")
    })?;
    let allowed = client
        .evaluate(&request)
        .await
        .map_err(|_| ErrorResponse::new(ErrorCode::TemporarilyUnavailable))?;
    if !allowed {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    Ok(())
}

pub(crate) fn infrastructure_client(client: &ClientRegistration) -> bool {
    client.allowed_grant_types.is_empty()
        || client
            .allowed_grant_types
            .contains(&GrantType::ClientCredentials)
        || client
            .allowed_scopes
            .iter()
            .any(|scope| scope.starts_with("idp.") || scope.starts_with("management."))
}
