use idp_model::contract::{
    AuthorizationCodeGrantRequest, ErrorCode, ErrorResponse, ErrorResponseResult,
};

#[derive(serde::Serialize)]
pub(super) struct RefreshClaims {
    #[serde(flatten)]
    pub standard_claims: model::contract::StandardClaims,
    pub jti: alloc::string::String,
}

pub fn validate_authorization_code_grant(
    request: &AuthorizationCodeGrantRequest,
    expected_client_id: &str,
    expected_redirect_uri: Option<&str>,
) -> ErrorResponseResult<()> {
    if request.code.is_empty() {
        return Err(
            ErrorResponse::new(ErrorCode::InvalidRequest).with_description("code is required")
        );
    }

    if request.code_verifier.is_empty() {
        return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
            .with_description("code_verifier is required"));
    }

    if let Some(client_id) = &request.client_id
        && client_id != expected_client_id
    {
        return Err(ErrorResponse::new(ErrorCode::InvalidClient));
    }

    if let Some(redirect_uri) = &request.redirect_uri
        && expected_redirect_uri.is_some_and(|expected| expected != redirect_uri)
    {
        return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
            .with_description("redirect_uri does not match the authorization request"));
    }

    Ok(())
}
