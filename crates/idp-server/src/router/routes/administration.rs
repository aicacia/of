use axum::{
    Json,
    extract::{Path, Query, State},
};
use idp_model::{
    contract::{
        ApplicationRegistration, ErrorCode, ErrorResponse, IdentityAction, IdentityResource,
        PermissionTarget, UserInfo,
    },
    model::{Application, Id, Key, OAuth2UserConsent},
};
use idp_service::oauth2::UpdateUserInfoRequest;
use serde::Deserialize;

use crate::router::{
    RouterState,
    middleware::{StandardAuthorization, require_identity_permission},
};

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct Page {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}
fn default_limit() -> u32 {
    50
}

async fn require(
    state: &RouterState,
    actor: &StandardAuthorization,
    action: IdentityAction,
    resource: IdentityResource,
) -> Result<(), ErrorResponse> {
    require_identity_permission(
        state,
        actor,
        action,
        PermissionTarget::Installation { resource },
    )
    .await
}

#[utoipa::path(get, path = "/applications", params(Page),
    responses((status = 200, description = "Applications")), security(("authorization" = [])))]
pub(crate) async fn list_applications(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
    Query(page): Query<Page>,
) -> Result<Json<Vec<Application>>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ApplicationsRead,
        IdentityResource::Application { id: None },
    )
    .await?;
    Ok(Json(
        state
            .oauth2_service
            .list_applications(page.offset, page.limit.clamp(1, 100))
            .await?,
    ))
}

#[utoipa::path(post, path = "/applications", request_body = ApplicationRegistration,
    responses((status = 200, description = "Created application")), security(("authorization" = [])))]
pub(crate) async fn create_application(
    State(state): State<RouterState>,
    actor: StandardAuthorization,
    Json(body): Json<ApplicationRegistration>,
) -> Result<Json<Application>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ApplicationsCreate,
        IdentityResource::Application { id: None },
    )
    .await?;
    Ok(Json(
        state
            .oauth2_service
            .create_application(
                body.name.unwrap_or_else(|| body.uri.clone()),
                body.uri,
                body.description,
            )
            .await?,
    ))
}

#[utoipa::path(get, path = "/applications/{application_id}", params(("application_id" = String, Path)),
    responses((status = 200, description = "Application")), security(("authorization" = [])))]
pub(crate) async fn get_application(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
) -> Result<Json<Application>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ApplicationsRead,
        IdentityResource::Application { id: Some(id) },
    )
    .await?;
    Ok(Json(state.oauth2_service.get_application(id).await?))
}

#[utoipa::path(put, path = "/applications/{application_id}", params(("application_id" = String, Path)),
    request_body = ApplicationRegistration, responses((status = 200, description = "Updated application")), security(("authorization" = [])))]
pub(crate) async fn update_application(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
    Json(body): Json<ApplicationRegistration>,
) -> Result<Json<Application>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ApplicationsUpdate,
        IdentityResource::Application { id: Some(id) },
    )
    .await?;
    let mut application = state.oauth2_service.get_application(id).await?;
    // URI is the canonical resource/audience identity, not editable profile data.
    if application.uri != body.uri {
        return Err(ErrorResponse::new(ErrorCode::AccessDenied));
    }
    if let Some(name) = body.name {
        application.name = name;
    }
    application.description = body.description;
    Ok(Json(
        state.oauth2_service.update_application(application).await?,
    ))
}

#[utoipa::path(delete, path = "/applications/{application_id}", params(("application_id" = String, Path)),
    responses((status = 200, description = "Deleted application")), security(("authorization" = [])))]
pub(crate) async fn delete_application(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ApplicationsDelete,
        IdentityResource::Application { id: Some(id) },
    )
    .await?;
    state.oauth2_service.delete_application(id).await
}

#[utoipa::path(get, path = "/users/{user_id}", params(("user_id" = String, Path)),
    responses((status = 200, description = "User", body = UserInfo)), security(("authorization" = [])))]
pub(crate) async fn get_user(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
) -> Result<Json<UserInfo>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::UsersRead,
        IdentityResource::User { id },
    )
    .await?;
    Ok(Json(state.oauth2_service.find_user_info(id).await?))
}

#[utoipa::path(put, path = "/users/{user_id}", params(("user_id" = String, Path)),
    request_body = Object, responses((status = 200, description = "Updated user", body = UserInfo)), security(("authorization" = [])))]
pub(crate) async fn update_user(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
    Json(body): Json<UpdateUserInfoRequest>,
) -> Result<Json<UserInfo>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::UsersUpdate,
        IdentityResource::User { id },
    )
    .await?;
    Ok(Json(state.oauth2_service.update_user_info(id, body).await?))
}

#[utoipa::path(delete, path = "/users/{user_id}", params(("user_id" = String, Path)),
    responses((status = 200, description = "Deleted user")), security(("authorization" = [])))]
pub(crate) async fn delete_user(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::UsersDelete,
        IdentityResource::User { id },
    )
    .await?;
    state.oauth2_service.delete_user(id).await
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResetPassword {
    pub password: String,
}

#[utoipa::path(put, path = "/users/{user_id}/password", params(("user_id" = String, Path)),
    request_body = ResetPassword, responses((status = 200, description = "Reset password")), security(("authorization" = [])))]
pub(crate) async fn reset_password(
    State(state): State<RouterState>,
    Path(id): Path<Id>,
    actor: StandardAuthorization,
    Json(body): Json<ResetPassword>,
) -> Result<(), ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::UsersResetPassword,
        IdentityResource::User { id },
    )
    .await?;
    state
        .oauth2_service
        .reset_user_password(id, &body.password)
        .await
}

#[utoipa::path(get, path = "/users/{user_id}/consents", params(("user_id" = String, Path), Page),
    responses((status = 200, description = "Consents")), security(("authorization" = [])))]
pub(crate) async fn list_consents(
    State(state): State<RouterState>,
    Path(user_id): Path<Id>,
    actor: StandardAuthorization,
    Query(page): Query<Page>,
) -> Result<Json<Vec<OAuth2UserConsent>>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ConsentsRead,
        IdentityResource::Consent { user_id, id: None },
    )
    .await?;
    Ok(Json(
        state
            .oauth2_service
            .list_user_consents(user_id, page.offset, page.limit.clamp(1, 100))
            .await?,
    ))
}

#[utoipa::path(delete, path = "/users/{user_id}/consents/{consent_id}",
    params(("user_id" = String, Path), ("consent_id" = String, Path)),
    responses((status = 200, description = "Revoked consent")), security(("authorization" = [])))]
pub(crate) async fn revoke_consent(
    State(state): State<RouterState>,
    Path((user_id, id)): Path<(Id, Id)>,
    actor: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::ConsentsRevoke,
        IdentityResource::Consent {
            user_id,
            id: Some(id),
        },
    )
    .await?;
    state.oauth2_service.revoke_user_consent(user_id, id).await
}

#[utoipa::path(post, path = "/clients/{client_id}/keys/rotate", params(("client_id" = String, Path)),
    responses((status = 200, description = "Rotated client signing key metadata")), security(("authorization" = [])))]
pub(crate) async fn rotate_client_key(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
) -> Result<Json<Key>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::KeysRotate,
        IdentityResource::ClientKeys {
            client_id: client_id.clone(),
        },
    )
    .await?;
    Ok(Json(
        state.oauth2_service.rotate_client_key(&client_id).await?,
    ))
}

#[utoipa::path(delete, path = "/clients/{client_id}/keys", params(("client_id" = String, Path)),
    responses((status = 200, description = "Revoked all client signing keys and local private material")), security(("authorization" = [])))]
pub(crate) async fn revoke_client_keys(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
) -> Result<(), ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::KeysRevoke,
        IdentityResource::ClientKeys {
            client_id: client_id.clone(),
        },
    )
    .await?;
    state.oauth2_service.revoke_client_keys(&client_id).await
}

#[utoipa::path(get, path = "/clients/{client_id}/keys", params(("client_id" = String, Path)),
    responses((status = 200, description = "Client key metadata")), security(("authorization" = [])))]
pub(crate) async fn list_client_keys(
    State(state): State<RouterState>,
    Path(client_id): Path<String>,
    actor: StandardAuthorization,
) -> Result<Json<Vec<Key>>, ErrorResponse> {
    require(
        &state,
        &actor,
        IdentityAction::KeysRead,
        IdentityResource::ClientKeys {
            client_id: client_id.clone(),
        },
    )
    .await?;
    Ok(Json(
        state.oauth2_service.list_client_keys(&client_id).await?,
    ))
}
