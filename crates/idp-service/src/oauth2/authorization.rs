#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use idp_model::contract::{
    AuthorizationRequest, ClientType, CodeChallengeMethod, ErrorCode, ErrorResponse,
    ErrorResponseResult, GrantType, ResponseMode, ResponseType,
};
use idp_model::model::Client;
use model::contract::AuthorizationDetail;

use super::scope::{parse_scopes, validate_scopes};

pub(crate) fn validate_dynamic_client_grants(grant_types: &[GrantType]) -> ErrorResponseResult<()> {
    if grant_types.is_empty() {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("explicit client grant types are required"));
    }
    if grant_types.contains(&GrantType::ClientCredentials) {
        return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
            .with_description("client credentials clients require trusted owner provisioning"));
    }
    Ok(())
}

pub fn validate_authorization_request(
    request: &AuthorizationRequest,
    client: &Client,
    require_pkce: bool,
) -> ErrorResponseResult<()> {
    if request.client_id != client.client_id {
        return Err(ErrorResponse::new(ErrorCode::InvalidClient));
    }

    validate_response_type(request, client)?;
    resolve_redirect_uri(request, client)?;
    validate_pkce(request, client, require_pkce)?;
    validate_response_mode(request)?;

    if let Some(scope) = &request.scope {
        validate_scopes(&parse_scopes(scope), &client.allowed_scopes)?;
    }

    Ok(())
}

pub fn validate_authorization_details(details: &[AuthorizationDetail]) -> ErrorResponseResult<()> {
    let [AuthorizationDetail::Storage(detail)] = details else {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("exactly one storage authorization detail is required"));
    };

    if detail.actions.is_empty()
        || detail
            .actions
            .iter()
            .enumerate()
            .any(|(index, action)| detail.actions[..index].contains(action))
    {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("storage actions must be non-empty and unique"));
    }

    Ok(())
}

pub fn resolve_redirect_uri(
    request: &AuthorizationRequest,
    client: &Client,
) -> ErrorResponseResult<String> {
    match (&request.redirect_uri, client.redirect_uris.as_slice()) {
        (Some(redirect_uri), redirect_uris) if redirect_uris.contains(redirect_uri) => {
            Ok(redirect_uri.clone())
        }
        (Some(_), _) => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("redirect_uri is not registered for this client")),
        (None, [redirect_uri]) => Ok(redirect_uri.clone()),
        (None, _) => Err(
            ErrorResponse::new(ErrorCode::InvalidRequest).with_description(
                "redirect_uri is required when multiple redirect URIs are registered",
            ),
        ),
    }
}

fn validate_response_type(
    request: &AuthorizationRequest,
    client: &Client,
) -> ErrorResponseResult<()> {
    if request.response_type != ResponseType::Code {
        return Err(ErrorResponse::new(ErrorCode::UnsupportedResponseType));
    }

    if client.response_types.is_empty() || client.response_types.contains(&request.response_type) {
        Ok(())
    } else {
        Err(ErrorResponse::new(ErrorCode::InvalidResponseType))
    }
}

fn validate_pkce(
    request: &AuthorizationRequest,
    client: &Client,
    require_pkce: bool,
) -> ErrorResponseResult<()> {
    let pkce_required = require_pkce || client.client_type == ClientType::Public;

    match (&request.code_challenge, &request.code_challenge_method) {
        (Some(_), Some(method)) if *method == CodeChallengeMethod::S256 => Ok(()),
        (Some(_), Some(_)) => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("only S256 code challenge method is supported")),
        (Some(_), None) => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("code_challenge_method is required when code_challenge is present")),
        (None, Some(_)) => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("code_challenge is required when code_challenge_method is present")),
        (None, None) if pkce_required => Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("PKCE is required for this authorization request")),
        (None, None) => Ok(()),
    }
}

fn validate_response_mode(request: &AuthorizationRequest) -> ErrorResponseResult<()> {
    match request.response_mode {
        None | Some(ResponseMode::Query) | Some(ResponseMode::FormPost) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use idp_model::{
        contract::{ClientProfile, GrantType, TokenEndpointAuthMethod},
        model::Id,
    };
    use model::contract::{StorageAuthorizationAction, StorageAuthorizationDetail};

    use super::*;

    #[test]
    fn dynamic_registration_rejects_client_credentials_grant() {
        assert!(validate_dynamic_client_grants(&[GrantType::AuthorizationCode]).is_ok());
        assert!(validate_dynamic_client_grants(&[]).is_err());
        assert_eq!(
            validate_dynamic_client_grants(&[GrantType::ClientCredentials])
                .expect_err("dynamic registration must not create service clients")
                .error,
            ErrorCode::UnauthorizedClient
        );
        assert!(
            validate_dynamic_client_grants(&[
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
            ])
            .is_err()
        );
    }

    fn sample_client() -> Client {
        Client {
            id: Id::nil(),
            application_id: Id::nil(),
            client_id: "client-1".to_string(),
            client_secret_hash: String::new(),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Example".to_string(),
            client_uri: String::new(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_type: ClientType::Public,
            profile: ClientProfile::Web,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            allowed_grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            allowed_scopes: vec!["openid".to_string()],
            allowed_audiences: Vec::new(),
            logo_uri: None,
            contacts: Vec::new(),
            terms_of_service_uri: None,
            policy_uri: None,
            software_statement: None,
            software_id: None,
            software_version: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn validate_storage_authorization_details_accepts_resource_wide_actions() {
        let details = vec![AuthorizationDetail::Storage(StorageAuthorizationDetail {
            actions: vec![StorageAuthorizationAction::Read],
        })];

        assert!(validate_authorization_details(&details).is_ok());
    }

    #[test]
    fn validate_authorization_request_requires_pkce_for_public_clients() {
        let client = sample_client();
        let request = AuthorizationRequest {
            response_type: ResponseType::Code,
            client_id: "client-1".to_string(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            scope: Some("openid".to_string()),
            state: Some("state".to_string()),
            resource: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            prompt: None,
            response_mode: None,
            login_hint: None,
            id_token_hint: None,
            ui_locales: None,
        };

        let error = validate_authorization_request(&request, &client, false).unwrap_err();
        assert_eq!(error.error, ErrorCode::InvalidRequest);
    }
}
