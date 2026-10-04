use axum::{
    Json,
    extract::{Path, State},
};
use idp_model::contract::{
    ClientRegistration, ErrorCode, ErrorResponse, IdentityAction, IdentityResource,
    PermissionTarget,
};

use crate::router::{
    RouterState,
    middleware::{StandardAuthorization, infrastructure_client, require_identity_permission},
};

#[utoipa::path(post, path = "/oauth2/register", request_body = ClientRegistration,
    responses((status = 200, description = "Register client", body = ClientRegistration)),
    security(("authorization" = [])))]
pub(crate) async fn register(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
    Json(body): Json<ClientRegistration>,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let application_id = state
        .oauth2_service
        .application_id_for_uri(&body.application.uri)
        .await?;
    let infrastructure = infrastructure_client(&body);
    let action = if infrastructure {
        IdentityAction::InfrastructureClientsCreate
    } else {
        IdentityAction::ClientsCreate
    };
    let target = client_target(application_id, infrastructure, None);
    require_identity_permission(&state, &actor, action, target).await?;
    if body.client_id.is_some() {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest));
    }
    let client = if infrastructure {
        state
            .oauth2_service
            .register_infrastructure_client(body)
            .await?
    } else {
        state.oauth2_service.register_client(body).await?
    };
    Ok(Json(client))
}

#[utoipa::path(get, path = "/oauth2/register/{client_id}",
    params(("client_id" = String, Path)),
    responses((status = 200, description = "Get client", body = ClientRegistration)),
    security(("authorization" = [])))]
pub(crate) async fn get_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let client = state.oauth2_service.get_client(&client_id).await?;
    let application_id = state
        .oauth2_service
        .application_id_for_client(&client_id)
        .await?;
    let infrastructure = infrastructure_client(&client);
    let action = if infrastructure {
        IdentityAction::InfrastructureClientsRead
    } else {
        IdentityAction::ClientsRead
    };
    require_identity_permission(
        &state,
        &actor,
        action,
        client_target(application_id, infrastructure, Some(client_id)),
    )
    .await?;
    Ok(Json(client))
}

#[utoipa::path(delete, path = "/oauth2/register/{client_id}",
    params(("client_id" = String, Path)), responses((status = 200, description = "Delete client")),
    security(("authorization" = [])))]
pub(crate) async fn delete_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    let client = state.oauth2_service.get_client(&client_id).await?;
    let application_id = state
        .oauth2_service
        .application_id_for_client(&client_id)
        .await?;
    let infrastructure = infrastructure_client(&client);
    let action = if infrastructure {
        IdentityAction::InfrastructureClientsDelete
    } else {
        IdentityAction::ClientsDelete
    };
    require_identity_permission(
        &state,
        &actor,
        action,
        client_target(application_id, infrastructure, Some(client_id.clone())),
    )
    .await?;
    state.oauth2_service.delete_client(&client_id).await
}

#[utoipa::path(put, path = "/oauth2/register/{client_id}",
    params(("client_id" = String, Path)), request_body = ClientRegistration,
    responses((status = 200, description = "Update client", body = ClientRegistration)),
    security(("authorization" = [])))]
pub(crate) async fn put_register(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
    Json(body): Json<ClientRegistration>,
) -> Result<Json<ClientRegistration>, ErrorResponse> {
    let existing = state.oauth2_service.get_client(&client_id).await?;
    let application_id = state
        .oauth2_service
        .application_id_for_client(&client_id)
        .await?;
    if body.application.uri != existing.application.uri
        || body.client_id.as_deref().is_some_and(|id| id != client_id)
    {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    let infrastructure = infrastructure_client(&existing) || infrastructure_client(&body);
    let action = if infrastructure {
        IdentityAction::InfrastructureClientsUpdate
    } else {
        IdentityAction::ClientsUpdate
    };
    require_identity_permission(
        &state,
        &actor,
        action,
        client_target(application_id, infrastructure, Some(client_id.clone())),
    )
    .await?;
    let client = if infrastructure {
        state
            .oauth2_service
            .update_infrastructure_client(&client_id, body)
            .await?
    } else {
        state.oauth2_service.update_client(&client_id, body).await?
    };
    Ok(Json(client))
}

fn client_target(
    application_id: idp_model::model::Id,
    infrastructure: bool,
    client_id: Option<String>,
) -> PermissionTarget {
    let resource = IdentityResource::Client { client_id };
    if infrastructure {
        PermissionTarget::Installation { resource }
    } else {
        PermissionTarget::Application {
            application_id,
            resource,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client_target;
    use idp_model::{
        contract::{IdentityAction, PermissionEvaluationRequest, PermissionSubject},
        model::Id,
    };

    #[test]
    fn infrastructure_clients_never_use_application_permissions() {
        let mut request = PermissionEvaluationRequest {
            request_id: Id::now_v7(),
            subject: PermissionSubject::User { id: Id::now_v7() },
            action: IdentityAction::ClientsCreate,
            target: client_target(Id::now_v7(), true, None),
        };
        assert!(request.policy_namespace().is_none());
        request.action = IdentityAction::InfrastructureClientsCreate;
        assert_eq!(request.policy_namespace(), Some(Id::nil()));
    }
}
