#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use idp_model::contract::{
    AuthorizationServerMetadata, CodeChallengeMethod, GrantType, IdpRole, ResponseMode,
    ResponseType, TokenEndpointAuthMethod,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_ISSUER: &str = "https://api.localhost:1355/idp";
pub const DEFAULT_REQUIRE_PKCE: bool = true;
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;
pub const DEFAULT_REFRESH_TOKEN_TTL_SECS: u64 = 2_592_000;
pub const DEFAULT_AUTHORIZATION_CODE_TTL_SECS: u64 = 600;
pub const DEFAULT_DEVICE_CODE_TTL_SECS: i64 = 600;
pub const DEFAULT_DEVICE_POLL_INTERVAL_SECS: i64 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuth2Config {
    /// Local deployment role. Replica enrollment and freshness are separate checks.
    pub role: IdpRole,
    pub issuer: String,
    pub require_pkce: bool,
    pub token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub authorization_code_ttl_secs: u64,
    pub device_code_ttl_secs: i64,
    pub device_poll_interval_secs: i64,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            role: IdpRole::Authority,
            issuer: DEFAULT_ISSUER.to_string(),
            require_pkce: DEFAULT_REQUIRE_PKCE,
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
            authorization_code_ttl_secs: DEFAULT_AUTHORIZATION_CODE_TTL_SECS,
            device_code_ttl_secs: DEFAULT_DEVICE_CODE_TTL_SECS,
            device_poll_interval_secs: DEFAULT_DEVICE_POLL_INTERVAL_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use idp_model::contract::IdpRole;

    use super::OAuth2Config;

    #[test]
    fn idp_role_config_is_explicit_and_rejects_unknown_roles() {
        let config: OAuth2Config =
            serde_json::from_str(r#"{"role":"replica"}"#).expect("read replica config");
        assert_eq!(config.role, IdpRole::Replica);
        assert!(serde_json::from_str::<OAuth2Config>(r#"{"role":"primary"}"#).is_err());
        let config: OAuth2Config =
            serde_json::from_str(r#"{"role":"authority"}"#).expect("read authority config");
        assert_eq!(config.role, IdpRole::Authority);
    }
}

impl OAuth2Config {
    pub fn to_metadata(&self) -> AuthorizationServerMetadata {
        let issuer = self.issuer.trim_end_matches('/');

        AuthorizationServerMetadata {
            issuer: issuer.to_string(),
            authorization_endpoint: Some(format!("{issuer}/oauth2/auth")),
            token_endpoint: Some(format!("{issuer}/oauth2/token")),
            jwks_uri: Some(format!("{issuer}/.well-known/jwks.json")),
            registration_endpoint: Some(format!("{issuer}/oauth2/register")),
            userinfo_endpoint: Some(format!("{issuer}/userinfo")),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "address".to_string(),
                "phone".to_string(),
                "offline_access".to_string(),
                "storage".to_string(),
            ],
            response_types_supported: vec![ResponseType::Code],
            response_modes_supported: vec![ResponseMode::Query, ResponseMode::FormPost],
            grant_types_supported: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
                GrantType::TokenExchange,
            ],
            token_endpoint_auth_methods_supported: vec![
                TokenEndpointAuthMethod::ClientSecretBasic,
                TokenEndpointAuthMethod::ClientSecretPost,
                TokenEndpointAuthMethod::None,
            ],
            token_endpoint_auth_signing_alg_values_supported: Vec::new(),
            service_documentation: None,
            ui_locales_supported: Vec::new(),
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: Some(format!("{issuer}/oauth2/revoke")),
            revocation_endpoint_auth_methods_supported: vec![
                TokenEndpointAuthMethod::ClientSecretBasic,
                TokenEndpointAuthMethod::ClientSecretPost,
                TokenEndpointAuthMethod::None,
            ],
            revocation_endpoint_auth_signing_alg_values_supported: Vec::new(),
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: Vec::new(),
            introspection_endpoint_auth_signing_alg_values_supported: Vec::new(),
            code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
            signed_metadata: None,
            pushed_authorization_request_endpoint: None,
            dpop_signing_alg_values_supported: Vec::new(),
            require_pkce: self.require_pkce,
        }
    }
}
