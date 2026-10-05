#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use model::contract::{
    AccessToken, AuthorizationDetail, IdToken, PrincipalType, RefreshToken, StandardClaims,
    TokenResponse, TokenType, TokenUse,
};
#[cfg(feature = "std")]
use std::sync::Arc;

use chrono::{Duration, Utc};
use idp_model::model::{Application, Client, Id, Key};
use idp_model::{
    contract::{
        ApproveForUserRequest, AuthorizationCodeGrantRequest, AuthorizationCodeResponse,
        AuthorizationRequest, AuthorizationServerMetadata, ClientCredentialsGrantRequest,
        ClientRegistration, ClientType, DeviceAuthorization, DeviceAuthorizationRequest,
        EntityType, ErrorCode, ErrorResponse, ErrorResponseResult, GrantType, IdTokenClaims,
        IdpRole, IsAllowedForUserRequest, IsAllowedForUserResponse, JwkPrivate, JwkPublic,
        JwkPublicParameters, Jwks, JwsAlgorithm, KeyUse, OAuth2ClientAuth, PasswordGrantRequest,
        RefreshTokenGrantRequest, RevocationRequest, SubjectTokenType, TokenEndpointAuthMethod,
        TokenExchangeGrantRequest, TokenPrincipalBinding, TokenRequest, UserInfo,
    },
    model::User,
};

use crate::{
    PasswordConfig,
    oauth2::{ClientPrincipal, Principal, UserPrincipal, decode_jwt, encode_jwt, verify_jwt},
    repo::{
        ApplicationRepo, ClientRepo, KeyRepo, KeyService, OAuth2AuthorizationCodeRepo,
        OAuth2RefreshToken, OAuth2RefreshTokenRepo, OAuth2UserConsentRepo, UserRepo,
    },
    util::{encrypt_password, generate_random_string, verify_password},
};

use super::{
    OAuth2Config, intersect_scopes, jwt::verifing_key_from_jwt, parse_scopes, resolve_redirect_uri,
    validate_authorization_code_grant, validate_authorization_details,
    validate_authorization_request, validate_dynamic_client_grants, validate_scopes,
    verify_code_challenge,
};

#[cfg(all(test, feature = "replica"))]
#[path = "refresh_tests.rs"]
mod refresh_tests;

pub struct OAuth2Service<A, C, AC, RT, U, G, K, P> {
    pub application_repo: A,
    pub client_repo: C,
    pub authorization_code_repo: AC,
    pub refresh_token_repo: RT,
    pub user_repo: U,
    pub oauth2_user_consent_repo: G,
    pub key_service: Arc<KeyService<K, P>>,
    pub oauth_config: OAuth2Config,
    role: IdpRole,
    replica_readiness: super::readiness::ReplicaReadiness,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserInfoRequest {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub sex: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
}

impl<A, C, AC, RT, U, G, K, P> OAuth2Service<A, C, AC, RT, U, G, K, P>
where
    A: ApplicationRepo,
    C: ClientRepo,
    AC: OAuth2AuthorizationCodeRepo,
    RT: OAuth2RefreshTokenRepo,
    U: UserRepo,
    G: OAuth2UserConsentRepo,
    K: KeyRepo,
    P: crate::repo::PrivateKeyRepo,
{
    pub fn new(
        application_repo: A,
        client_repo: C,
        authorization_code_repo: AC,
        refresh_token_repo: RT,
        user_repo: U,
        oauth2_user_consent_repo: G,
        key_service: Arc<KeyService<K, P>>,
        oauth_config: OAuth2Config,
    ) -> Self {
        Self {
            application_repo,
            client_repo,
            authorization_code_repo,
            refresh_token_repo,
            user_repo,
            oauth2_user_consent_repo,
            key_service,
            role: oauth_config.role,
            replica_readiness: super::readiness::ReplicaReadiness::default(),
            oauth_config,
        }
    }

    /// Deny replica security operations until trusted authority synchronization exists.
    pub fn require_security_ready(&self) -> ErrorResponseResult<()> {
        if self.role == IdpRole::Replica && !self.replica_readiness.is_fresh() {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("replica requires fresh approved authority state"));
        }
        Ok(())
    }

    fn require_authority(&self) -> ErrorResponseResult<()> {
        if self.role != IdpRole::Authority {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("operation requires the designated IdP authority"));
        }
        Ok(())
    }

    pub async fn ensure_initial_user(
        &self,
        user_id: Id,
        credential_id: Id,
        name: &str,
        password: &str,
    ) -> ErrorResponseResult<User> {
        self.require_authority()?;
        if user_id == Id::nil() || credential_id == Id::nil() || name.trim().is_empty() {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("stable user and credential IDs and a name are required"));
        }
        if password.trim().is_empty() {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("password is required"));
        }

        if let Some(user) = self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
        {
            if user.name != name {
                return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("initial user ID is already used by different data"));
            }
            let stored = self
                .user_repo
                .find_user_password_by_user_id(user_id)
                .await
                .map_err(ErrorResponse::from)?
                .ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("initial user has no active password credential")
                })?;
            if stored.id != credential_id
                || !verify_password(password, &stored.password_hash).map_err(|error| {
                    ErrorResponse::new(ErrorCode::ServerError).with_description(error.to_string())
                })?
            {
                return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("initial user ID is already used by different credentials"));
            }
            return Ok(user);
        }

        self.user_repo
            .create_user_with_password_and_ids(user_id, credential_id, name, password)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn register_client(
        &self,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        self.require_authority()?;
        validate_dynamic_client_grants(&request.allowed_grant_types)?;
        self.register_owned_client(request).await
    }

    pub async fn register_infrastructure_client(
        &self,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        self.require_authority()?;
        if request.client_type != ClientType::Confidential
            || request.allowed_grant_types != [GrantType::ClientCredentials]
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest));
        }
        self.register_owned_client(request).await
    }

    pub async fn ensure_infrastructure_client(
        &self,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        self.require_authority()?;
        if request.client_type != ClientType::Confidential
            || request.allowed_grant_types != [GrantType::ClientCredentials]
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest));
        }
        let client_id = request
            .client_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("stable infrastructure client ID is required")
            })?
            .to_owned();
        let client_secret = request
            .client_secret
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("infrastructure client secret is required")
            })?
            .to_owned();

        let Some(client) = self
            .client_repo
            .find_client_by_client_id(&client_id)
            .await
            .map_err(ErrorResponse::from)?
        else {
            return self.register_infrastructure_client(request).await;
        };

        let application = self
            .application_repo
            .find_by_id(client.application_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description("infrastructure client application is missing")
            })?;
        let secret_matches =
            verify_password(&client_secret, &client.client_secret_hash).map_err(|error| {
                ErrorResponse::new(ErrorCode::ServerError).with_description(error.to_string())
            })?;
        let application_name = request
            .application
            .name
            .as_deref()
            .unwrap_or(&request.client_name);
        let client_uri = request
            .client_uri
            .as_deref()
            .unwrap_or(&request.application.uri);
        let exact_match = secret_matches
            && application.name == application_name
            && application.uri == request.application.uri
            && application.description == request.application.description
            && client.client_name == request.client_name
            && client.client_uri == client_uri
            && client.client_id_issued_at.map(|time| time.timestamp())
                == request.client_id_issued_at
            && client.client_secret_expires_at.map(|time| time.timestamp())
                == request.client_secret_expires_at
            && client.client_type == request.client_type
            && client.profile == request.profile
            && client.token_endpoint_auth_method == request.token_endpoint_auth_method
            && client.allowed_grant_types == request.allowed_grant_types
            && client.response_types == request.response_types
            && client.allowed_scopes == request.allowed_scopes
            && client.allowed_audiences == request.allowed_audiences
            && client.redirect_uris == request.redirect_uris
            && client.logo_uri == request.logo_uri
            && client.contacts == request.contacts
            && client.terms_of_service_uri == request.terms_of_service_uri
            && client.policy_uri == request.policy_uri
            && client.software_statement == request.software_statement
            && client.software_id == request.software_id
            && client.software_version == request.software_version;
        if !exact_match {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("infrastructure client ID is already used by different data"));
        }

        let mut registration: ClientRegistration = client.into();
        registration.application = request.application;
        registration.client_secret = Some(client_secret);
        Ok(registration)
    }

    async fn register_owned_client(
        &self,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        let client = ClientRegistration {
            client_id: Some(
                request
                    .client_id
                    .unwrap_or_else(generate_random_string::<32>),
            ),
            client_secret: Some(
                request
                    .client_secret
                    .unwrap_or_else(generate_random_string::<32>),
            ),
            ..request
        };

        let issued_secret = if client.client_type == ClientType::Confidential {
            client.client_secret.clone()
        } else {
            None
        };
        let client = self
            .client_repo
            .create_client(client)
            .await
            .map_err(ErrorResponse::from)?;

        let mut registration: ClientRegistration = client.into();
        registration.client_secret = issued_secret;
        Ok(registration)
    }

    pub async fn get_client(&self, client_id: &str) -> ErrorResponseResult<ClientRegistration> {
        let client = self
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;
        Ok(client.into())
    }

    pub async fn list_applications(
        &self,
        offset: u32,
        limit: u32,
    ) -> ErrorResponseResult<Vec<Application>> {
        self.application_repo
            .list_applications(offset, limit.min(100))
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn get_application(&self, id: Id) -> ErrorResponseResult<Application> {
        self.application_repo
            .find_by_id(id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))
    }

    pub async fn create_application(
        &self,
        name: String,
        uri: String,
        description: Option<String>,
    ) -> ErrorResponseResult<Application> {
        self.require_authority()?;
        self.application_repo
            .create_application(name, uri, description)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn update_application(
        &self,
        application: Application,
    ) -> ErrorResponseResult<Application> {
        self.require_authority()?;
        self.application_repo
            .update_application(application)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn delete_application(&self, id: Id) -> ErrorResponseResult<()> {
        self.require_authority()?;
        self.application_repo
            .delete_application_by_id(id)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn application_id_for_uri(&self, uri: &str) -> ErrorResponseResult<Id> {
        self.application_repo
            .find_by_uri(uri)
            .await
            .map_err(ErrorResponse::from)?
            .map(|application| application.id)
            .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))
    }

    /// Checks live client registration for already verified access-token claims.
    pub async fn validate_bearer_client(&self, claims: &StandardClaims) -> ErrorResponseResult<()> {
        self.require_security_ready()?;
        let client = self
            .client_repo
            .find_client_by_client_id(&claims.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::NotAuthorized))?;
        if claims
            .scope
            .iter()
            .any(|scope| !client.allowed_scopes.contains(scope))
            || (claims.principal_type == PrincipalType::Client
                && (claims.sub != client.id.to_string()
                    || !client
                        .allowed_grant_types
                        .contains(&GrantType::ClientCredentials)
                    || !client.allowed_audiences.contains(&claims.aud)))
        {
            return Err(ErrorResponse::new(ErrorCode::NotAuthorized));
        }
        Ok(())
    }

    pub async fn application_id_for_client(&self, client_id: &str) -> ErrorResponseResult<Id> {
        self.client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .map(|client| client.application_id)
            .ok_or_else(|| ErrorResponse::new(ErrorCode::InvalidClient))
    }

    pub async fn list_clients(
        &self,
        offset: u32,
        limit: u32,
    ) -> ErrorResponseResult<Vec<ClientRegistration>> {
        let clients = self
            .client_repo
            .list_clients(offset, limit)
            .await
            .map_err(ErrorResponse::from)?;

        Ok(clients.into_iter().map(Into::into).collect())
    }

    pub async fn update_client(
        &self,
        client_id: &str,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        self.require_authority()?;
        validate_dynamic_client_grants(&request.allowed_grant_types)?;
        self.update_owned_client(client_id, request).await
    }

    pub async fn update_infrastructure_client(
        &self,
        client_id: &str,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        self.require_authority()?;
        if request.client_type != ClientType::Confidential
            || request.allowed_grant_types != [GrantType::ClientCredentials]
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest));
        }
        self.update_owned_client(client_id, request).await
    }

    async fn update_owned_client(
        &self,
        client_id: &str,
        request: ClientRegistration,
    ) -> ErrorResponseResult<ClientRegistration> {
        let existing = self
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;

        let issued_secret = if request.client_type == ClientType::Confidential {
            request.client_secret
        } else {
            None
        };
        let client_secret_hash = if request.client_type == ClientType::Confidential {
            match issued_secret.as_deref() {
                Some(secret) if !secret.trim().is_empty() => {
                    encrypt_password(&PasswordConfig::default(), secret).map_err(|error| {
                        ErrorResponse::new(ErrorCode::ServerError)
                            .with_description(error.to_string())
                    })?
                }
                None if !existing.client_secret_hash.is_empty() => existing.client_secret_hash,
                _ => {
                    return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                        .with_description("a confidential client requires a nonempty secret"));
                }
            }
        } else {
            String::new()
        };
        let now = Utc::now();
        let client = Client {
            id: existing.id,
            application_id: existing.application_id,
            client_id: existing.client_id,
            client_secret_hash,
            client_id_issued_at: existing.client_id_issued_at,
            client_secret_expires_at: request
                .client_secret_expires_at
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                .or(existing.client_secret_expires_at),
            client_name: request.client_name,
            client_uri: request.client_uri.unwrap_or(existing.client_uri),
            redirect_uris: request.redirect_uris,
            client_type: request.client_type,
            profile: request.profile,
            token_endpoint_auth_method: request.token_endpoint_auth_method,
            allowed_grant_types: request.allowed_grant_types,
            response_types: request.response_types,
            allowed_scopes: request.allowed_scopes,
            allowed_audiences: request.allowed_audiences,
            logo_uri: request.logo_uri,
            contacts: request.contacts,
            terms_of_service_uri: request.terms_of_service_uri,
            policy_uri: request.policy_uri,
            software_statement: request.software_statement,
            software_id: request.software_id,
            software_version: request.software_version,
            created_at: existing.created_at,
            updated_at: now,
        };

        let client = self
            .client_repo
            .update_client(client)
            .await
            .map_err(ErrorResponse::from)?;
        let mut registration: ClientRegistration = client.into();
        registration.client_secret = issued_secret;
        Ok(registration)
    }

    pub async fn delete_client(&self, client_id: &str) -> ErrorResponseResult<()> {
        self.require_authority()?;
        self.client_repo
            .delete_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn authorize<PT: Principal + ?Sized>(
        &self,
        request: AuthorizationRequest,
        principal: &PT,
    ) -> ErrorResponseResult<AuthorizationCodeResponse> {
        self.require_authority()?;
        let client = self
            .client_repo
            .find_client_by_client_id(&request.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;

        validate_authorization_request(&request, &client, self.oauth_config.require_pkce)?;
        let redirect_uri = resolve_redirect_uri(&request, &client)?;
        let requested_scopes = request
            .scope
            .as_deref()
            .map(parse_scopes)
            .unwrap_or_default();
        let scopes = intersect_scopes(&requested_scopes, &client.allowed_scopes);
        let normalized_scope = Self::normalize_scopes(&scopes);

        if principal.get_entity_type() != EntityType::User {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("only users can authorize clients"));
        }

        let consent = self
            .oauth2_user_consent_repo
            .find_user_consent(
                principal.get_entity_id(),
                &client.client_id,
                &redirect_uri,
                &normalized_scope,
            )
            .await
            .map_err(ErrorResponse::from)?;

        if consent.is_none() {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("client approval required"));
        }

        let authorization_code = self
            .authorization_code_repo
            .create_authorization_code(
                client.client_id,
                principal.get_key().id,
                redirect_uri,
                scopes,
                request.resource,
                request.code_challenge,
                request.code_challenge_method,
                request.nonce,
                Utc::now()
                    + Duration::seconds(self.oauth_config.authorization_code_ttl_secs as i64),
            )
            .await
            .map_err(ErrorResponse::from)?;

        Ok(AuthorizationCodeResponse::Success {
            code: authorization_code.code,
            state: request.state,
            issuer: Some(self.oauth_config.issuer.clone()),
        })
    }

    pub async fn approve_for_user<PT: Principal + ?Sized>(
        &self,
        request: ApproveForUserRequest,
        principal: &PT,
    ) -> ErrorResponseResult<IsAllowedForUserResponse> {
        self.require_authority()?;
        if principal.get_entity_type() != EntityType::User {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("only users can approve clients"));
        }

        let client = self
            .client_repo
            .find_client_by_client_id(&request.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;

        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("redirect_uri is not allowed for this client"));
        }

        let requested_scopes = parse_scopes(&request.scope);
        validate_scopes(&requested_scopes, &client.allowed_scopes)?;
        let effective_scopes = intersect_scopes(&requested_scopes, &client.allowed_scopes);
        let normalized_scope = Self::normalize_scopes(&effective_scopes);

        self.oauth2_user_consent_repo
            .upsert_user_consent(
                principal.get_entity_id(),
                &client.client_id,
                &request.redirect_uri,
                &normalized_scope,
            )
            .await
            .map_err(ErrorResponse::from)?;

        Ok(IsAllowedForUserResponse { allowed: true })
    }

    pub async fn is_allowed_for_user<PT: Principal + ?Sized>(
        &self,
        request: IsAllowedForUserRequest,
        principal: &PT,
    ) -> ErrorResponseResult<IsAllowedForUserResponse> {
        if principal.get_entity_type() != EntityType::User {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("only users can check client approval"));
        }

        let client = self
            .client_repo
            .find_client_by_client_id(&request.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;

        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Ok(IsAllowedForUserResponse { allowed: false });
        }

        let requested_scopes = parse_scopes(&request.scope);
        validate_scopes(&requested_scopes, &client.allowed_scopes)?;
        let effective_scopes = intersect_scopes(&requested_scopes, &client.allowed_scopes);
        let normalized_scope = Self::normalize_scopes(&effective_scopes);

        let consent = self
            .oauth2_user_consent_repo
            .find_user_consent(
                principal.get_entity_id(),
                &client.client_id,
                &request.redirect_uri,
                &normalized_scope,
            )
            .await
            .map_err(ErrorResponse::from)?;

        Ok(IsAllowedForUserResponse {
            allowed: consent.is_some(),
        })
    }

    pub async fn token(
        &self,
        request: TokenRequest,
        client_auth: Option<OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        self.require_security_ready()?;
        if !matches!(&request, TokenRequest::ClientCredentials(_)) {
            self.require_authority()?;
        }
        match request {
            TokenRequest::Password(request) => self.password(request, client_auth.as_ref()).await,
            TokenRequest::AuthorizationCode(request) => {
                self.authorization_code(request, client_auth.as_ref()).await
            }
            TokenRequest::ClientCredentials(request) => {
                self.client_credentials(request, client_auth.as_ref()).await
            }
            TokenRequest::RefreshToken(request) => {
                self.refresh_token(request, client_auth.as_ref()).await
            }
            TokenRequest::TokenExchange(request) => {
                self.token_exchange(request, client_auth.as_ref()).await
            }
        }
    }

    async fn password(
        &self,
        request: PasswordGrantRequest,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        let client = self
            .client_repo
            .find_client_by_client_id(&request.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient)
                    .with_description(format!("client {} not found", request.client_id))
            })?;
        self.validate_grant_type(&client, GrantType::Password)?;
        self.authenticate_client_for_token_endpoint(&client, client_auth)?;

        let user = self
            .user_repo
            .find_user_by_username_or_email(&request.username)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description(format!("user {} not found", request.username))
            })?;

        let user_password = self
            .user_repo
            .find_user_password_by_user_id(user.id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("user password not found")
            })?;

        let verified_password = verify_password(&request.password, &user_password.password_hash)
            .map_err(|e| {
                ErrorResponse::new(ErrorCode::ServerError).with_description(e.to_string())
            })?;

        if !verified_password {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("invalid username or password"));
        }

        let key = self
            .key_service
            .key_repo()
            .find_by_entity_type_and_id(EntityType::User, user.id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant).with_description("user key not found")
            })?;

        let principal = self.find_principal(key.id).await?.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("principal not found for user")
        })?;

        let requested_scopes = request
            .scope
            .as_deref()
            .map(parse_scopes)
            .unwrap_or_default();
        let scopes = intersect_scopes(&requested_scopes, &client.allowed_scopes);

        self.issue_tokens_for_client(
            &client,
            principal.as_ref(),
            &scopes,
            request.resource.as_deref(),
            None,
            None,
        )
        .await
    }

    async fn authorization_code(
        &self,
        request: AuthorizationCodeGrantRequest,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        let now = Utc::now();
        let authorization_code = self
            .authorization_code_repo
            .find_authorization_code_by_code(&request.code)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("authorization code not found")
            })?;

        if authorization_code.consumed_at.is_some() {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("authorization code already consumed"));
        }

        if authorization_code.expires_at < now {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("authorization code expired"));
        }

        let principal = self
            .find_principal(authorization_code.key_id)
            .await?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("principal not found for authorization code")
            })?;

        let client = self
            .client_repo
            .find_client_by_client_id(&authorization_code.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;
        self.validate_grant_type(&client, GrantType::AuthorizationCode)?;
        self.authenticate_client_for_token_endpoint(&client, client_auth)?;

        validate_authorization_code_grant(
            &request,
            &authorization_code.client_id,
            Some(&authorization_code.redirect_uri),
        )?;

        if let Some(code_challenge) = &authorization_code.code_challenge {
            verify_code_challenge(
                &request.code_verifier,
                code_challenge,
                authorization_code.code_challenge_method.ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidGrant).with_description(
                        "code_challenge_method is required when code_challenge is present",
                    )
                })?,
            )?;
        }

        self.authorization_code_repo
            .consume_authorization_code(authorization_code.id, now)
            .await
            .map_err(ErrorResponse::from)?;

        self.issue_tokens_for_client(
            &client,
            principal.as_ref(),
            &authorization_code.scopes,
            authorization_code.resource.as_deref(),
            None,
            None,
        )
        .await
    }

    async fn client_credentials(
        &self,
        request: ClientCredentialsGrantRequest,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        let auth = client_auth.as_ref().ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client authentication is required")
        })?;

        let client = self
            .client_repo
            .find_client_by_client_id(&auth.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;
        self.validate_grant_type(&client, GrantType::ClientCredentials)?;
        if client.client_type != ClientType::Confidential {
            return Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
                .with_description("client credentials requires a confidential client"));
        }
        if client
            .client_secret_expires_at
            .is_some_and(|expires_at| expires_at.timestamp() > 0 && expires_at <= Utc::now())
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client credentials have expired"));
        }
        self.authenticate_client_for_token_endpoint(&client, Some(auth))?;
        if request.client_id != auth.client_id {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client_id does not match authenticated client"));
        }

        let audience = request.audience.as_deref().ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("an audience is required for client credentials")
        })?;
        if !client
            .allowed_audiences
            .iter()
            .any(|allowed| allowed == audience)
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("client is not authorized for the requested audience"));
        }

        if request
            .resource
            .as_deref()
            .is_some_and(|resource| resource != audience)
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("resource must match the approved audience"));
        }

        let requested_scopes = request
            .scope
            .as_deref()
            .map(parse_scopes)
            .unwrap_or_default();
        if requested_scopes.is_empty() {
            return Err(ErrorResponse::new(ErrorCode::InvalidScope)
                .with_description("at least one scope is required for client credentials"));
        }
        validate_scopes(&requested_scopes, &client.allowed_scopes)?;

        let key = self
            .key_service
            .key_repo()
            .find_active_entity_root_key(EntityType::Client, client.id)
            .await?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient)
                    .with_description("active client signing key not found")
            })?;
        let principal = self.find_principal(key.id).await?.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client principal is inactive")
        })?;
        self.issue_client_credentials_access_token(
            &client,
            principal.as_ref(),
            &requested_scopes,
            audience,
            request.resource.as_deref(),
        )
        .await
    }

    async fn refresh_token(
        &self,
        request: RefreshTokenGrantRequest,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        let now = Utc::now();

        let (unverified_header, _) = decode_jwt::<StandardClaims>(&request.refresh_token.0)?;
        let key_id = Id::parse_str(&unverified_header.kid).map_err(|_| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("invalid refresh token signing key")
        })?;
        let verification_key = self.find_public_jwk(key_id).await.map_err(|_| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token signing key is not available")
        })?;
        let (_, refresh_token) =
            verify_jwt::<StandardClaims>(&verification_key, &request.refresh_token.0).map_err(
                |_| {
                    ErrorResponse::new(ErrorCode::InvalidGrant)
                        .with_description("refresh token signature is invalid")
                },
            )?;

        if refresh_token.r#type != TokenType::Bearer
            || refresh_token.r#use != TokenUse::Refresh
            || refresh_token.iss != self.oauth_config.issuer
            || refresh_token.nbf > now.timestamp()
            || refresh_token.iat > now.timestamp()
            || refresh_token.aud != refresh_token.client_id
            || refresh_token.principal_type != PrincipalType::User
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token claims are invalid"));
        }
        if refresh_token.exp <= now.timestamp() {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token is expired"));
        }
        let client = self
            .client_repo
            .find_client_by_client_id(&refresh_token.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;
        self.validate_grant_type(&client, GrantType::RefreshToken)?;
        self.authenticate_client_for_token_endpoint(&client, client_auth)?;

        let requested_scopes = request
            .scope
            .as_deref()
            .map(parse_scopes)
            .unwrap_or_default();
        let scopes = if requested_scopes.is_empty() {
            refresh_token.scope
        } else {
            let scopes = intersect_scopes(&requested_scopes, &refresh_token.scope);
            if scopes.len() != requested_scopes.len() {
                return Err(ErrorResponse::new(ErrorCode::InvalidScope)
                    .with_description("requested scope must be a subset of refresh token scope"));
            }
            scopes
        };

        let principal = self.find_principal(key_id).await?.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("principal not found for refresh token")
        })?;

        if principal.get_entity_id().to_string() != refresh_token.sub {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("refresh token subject does not match principal"));
        }
        self.issue_tokens_with_refresh(
            &client,
            principal.as_ref(),
            &scopes,
            refresh_token.resource.as_deref(),
            refresh_token.authorization_details.as_deref(),
            None,
            Some(&request.refresh_token.0),
        )
        .await
    }

    async fn token_exchange(
        &self,
        request: TokenExchangeGrantRequest,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<TokenResponse> {
        if request.subject_token_type != SubjectTokenType::AccessToken {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("subject_token_type must be access_token"));
        }

        let (jwt_header, _) = decode_jwt::<StandardClaims>(&request.subject_token)?;
        let key_id = Id::parse_str(&jwt_header.kid).map_err(|_| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("invalid subject token signing key")
        })?;
        let jwk = self.find_public_jwk(key_id).await?;
        let (_, subject_token) = verify_jwt::<StandardClaims>(&jwk, &request.subject_token)?;
        let now = Utc::now().timestamp();
        if subject_token.r#type != TokenType::Bearer
            || subject_token.r#use != TokenUse::Access
            || subject_token.iss != self.oauth_config.issuer
            || subject_token.exp <= now
            || subject_token.nbf > now
            || subject_token.aud.is_empty()
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("invalid subject access token"));
        }

        let key = self
            .key_service
            .key_repo()
            .find_by_id(key_id)
            .await?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("subject token signing key not found")
            })?;

        // TODO: get a derevided key from the key ring store to validate token.

        let client = self
            .client_repo
            .find_client_by_client_id(&subject_token.client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;
        self.validate_grant_type(&client, GrantType::TokenExchange)?;
        self.authenticate_client_for_token_endpoint(&client, client_auth)?;

        let requested_scopes = request
            .scope
            .as_deref()
            .map(parse_scopes)
            .unwrap_or_default();
        let scopes = if requested_scopes.is_empty() {
            subject_token.scope
        } else {
            intersect_scopes(&requested_scopes, &subject_token.scope)
        };

        if let Some(details) = &request.authorization_details {
            validate_authorization_details(details)?;
        }

        let principal = self.find_principal(key.id).await?.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("principal not found for subject_token")
        })?;
        let resource = request
            .resource
            .as_deref()
            .or(subject_token.resource.as_deref());

        self.issue_tokens_for_client(
            &client,
            principal.as_ref(),
            &scopes,
            resource,
            request.authorization_details.as_deref(),
            resource,
        )
        .await
    }

    fn validate_grant_type(
        &self,
        client: &Client,
        grant_type: GrantType,
    ) -> ErrorResponseResult<()> {
        if client.allowed_grant_types.contains(&grant_type) {
            return Ok(());
        }

        Err(ErrorResponse::new(ErrorCode::UnauthorizedClient)
            .with_description("client is not authorized for this grant type"))
    }

    fn normalize_scopes(scopes: &[String]) -> String {
        let mut normalized = scopes.to_vec();
        normalized.sort();
        normalized.dedup();
        normalized.join(" ")
    }

    fn authenticate_client_for_token_endpoint(
        &self,
        client: &Client,
        client_auth: Option<&OAuth2ClientAuth>,
    ) -> ErrorResponseResult<()> {
        match client.client_type {
            ClientType::Confidential => {
                let auth = client_auth.ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("client authentication is required")
                })?;

                if auth.client_id != client.client_id {
                    return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("client_id does not match token subject"));
                }
                if auth.method != client.token_endpoint_auth_method
                    || !matches!(
                        auth.method,
                        TokenEndpointAuthMethod::ClientSecretBasic
                            | TokenEndpointAuthMethod::ClientSecretPost
                    )
                {
                    return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("unsupported client authentication method"));
                }

                let secret = auth.client_secret.as_deref().ok_or_else(|| {
                    ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("client secret is required")
                })?;
                if !verify_password(secret, &client.client_secret_hash).map_err(|_| {
                    ErrorResponse::new(ErrorCode::ServerError)
                        .with_description("stored client secret verifier is invalid")
                })? {
                    return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("invalid client credentials"));
                }

                Ok(())
            }
            ClientType::Public => {
                if let Some(auth) = client_auth
                    && auth.client_id != client.client_id
                {
                    return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                        .with_description("client_id does not match token subject"));
                }

                Ok(())
            }
        }
    }

    pub async fn revoke(
        &self,
        request: RevocationRequest,
        client_auth: Option<OAuth2ClientAuth>,
    ) -> ErrorResponseResult<()> {
        self.require_authority()?;
        if request.token.trim().is_empty() {
            return Err(
                ErrorResponse::new(ErrorCode::InvalidRequest).with_description("token is required")
            );
        }

        let Ok((header, _)) = decode_jwt::<StandardClaims>(&request.token) else {
            return Ok(());
        };
        let Ok(key_id) = Id::parse_str(&header.kid) else {
            return Ok(());
        };
        let Ok(key) = self.find_public_jwk(key_id).await else {
            return Ok(());
        };
        let Ok((_, claims)) = verify_jwt::<StandardClaims>(&key, &request.token) else {
            return Ok(());
        };
        if claims.r#type != TokenType::Bearer
            || claims.r#use != TokenUse::Refresh
            || claims.iss != self.oauth_config.issuer
            || claims.aud != claims.client_id
            || claims.principal_type != PrincipalType::User
        {
            return Ok(());
        }
        let Some(client) = self
            .client_repo
            .find_client_by_client_id(&claims.client_id)
            .await
            .map_err(ErrorResponse::from)?
        else {
            return Ok(());
        };
        self.authenticate_client_for_token_endpoint(&client, client_auth.as_ref())?;
        self.refresh_token_repo
            .revoke_refresh_token(&request.token, client.id, Utc::now().timestamp())
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn list_jwks(&self) -> ErrorResponseResult<Jwks> {
        self.require_security_ready()?;
        let keys = self
            .key_service
            .key_repo()
            .list_active()
            .await
            .map_err(ErrorResponse::from)?;

        let mut jwks = Vec::new();
        for key in keys {
            if let Ok(jwk) = self.find_public_jwk(key.id).await {
                jwks.push(jwk);
            }
        }

        Ok(Jwks { keys: jwks })
    }

    pub async fn rotate_client_key(&self, client_id: &str) -> ErrorResponseResult<Key> {
        self.require_authority()?;
        let client = self
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))?;
        let (key, _) = self
            .key_service
            .rotate_active_entity_root_key(
                EntityType::Client,
                client.id,
                "client signing key".into(),
                None,
            )
            .await
            .map_err(ErrorResponse::from)?;
        Ok(key)
    }

    pub async fn revoke_client_keys(&self, client_id: &str) -> ErrorResponseResult<()> {
        self.require_authority()?;
        let client = self
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| ErrorResponse::new(ErrorCode::NotFound))?;
        self.key_service
            .delete_entity_key_material(EntityType::Client, client.id)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn list_client_keys(&self, client_id: &str) -> ErrorResponseResult<Vec<Key>> {
        let client = self
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::InvalidClient).with_description("client not found")
            })?;

        let key = self
            .key_service
            .key_repo()
            .find_active_entity_root_key(EntityType::Client, client.id)
            .await
            .map_err(ErrorResponse::from)?;

        if let Some(key) = key {
            Ok(vec![key])
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn find_public_jwk(&self, key_id: Id) -> ErrorResponseResult<JwkPublic> {
        self.require_security_ready()?;
        let principal = self.find_principal(key_id).await?.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("active signing principal not found")
        })?;
        let jwk = principal.get_key().public_jwk.clone().ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("public verification material not found")
        })?;
        if jwk.kid != key_id.to_string()
            || jwk.r#use != KeyUse::Signature
            || jwk.alg != JwsAlgorithm::EdDSA
            || !matches!(&jwk.params,
                JwkPublicParameters::Ec { crv, .. } if crv == "secp256k1")
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("public verification material does not match signing key"));
        }
        verifing_key_from_jwt(&jwk)?;
        Ok(jwk)
    }

    pub fn metadata(&self) -> AuthorizationServerMetadata {
        self.oauth_config.to_metadata()
    }

    async fn load_signing_jwk(&self, key: &Key) -> ErrorResponseResult<JwkPrivate> {
        let public_jwk = self.find_public_jwk(key.id).await?;
        if let Some(private_key) = self.key_service.private_key_repo().load(
            &self
                .key_service
                .scoped_namespace(key.entity_type, key.entity_id),
            &key.derivation_path()?,
        )? {
            let signing_jwk = key.to_jwk_private(&private_key)?;
            if JwkPublic::from(signing_jwk.clone()) != public_jwk {
                return Err(ErrorResponse::new(ErrorCode::ServerError).with_description(
                    "local signing key does not match public verification material",
                ));
            }
            return Ok(signing_jwk);
        }
        Err(ErrorResponse::new(ErrorCode::ServerError)
            .with_description("signing key not found in private key repository"))
    }

    pub fn device_authorization(
        &self,
        request: DeviceAuthorizationRequest,
    ) -> ErrorResponseResult<DeviceAuthorization> {
        self.require_authority()?;
        if request.client_id.as_deref().is_some_and(str::is_empty) {
            return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                .with_description("client_id cannot be empty"));
        }

        let issuer = self.oauth_config.issuer.trim_end_matches('/');
        let user_code = generate_random_string::<32>();

        Ok(DeviceAuthorization {
            device_code: Some(generate_random_string::<32>()),
            expires_in: Some(self.oauth_config.device_code_ttl_secs),
            interval: Some(self.oauth_config.device_poll_interval_secs),
            user_code: Some(user_code.clone()),
            verification_uri: Some(format!("{issuer}/oauth2/device/verify")),
            verification_uri_complete: Some(format!(
                "{issuer}/oauth2/device/verify?user_code={user_code}"
            )),
        })
    }

    async fn issue_tokens_for_client(
        &self,
        client: &Client,
        principal: &dyn Principal,
        scopes: &[String],
        resource: Option<&str>,
        authorization_details: Option<&[AuthorizationDetail]>,
        audience: Option<&str>,
    ) -> ErrorResponseResult<TokenResponse> {
        self.issue_tokens_with_refresh(
            client,
            principal,
            scopes,
            resource,
            authorization_details,
            audience,
            None,
        )
        .await
    }

    async fn issue_tokens_with_refresh(
        &self,
        client: &Client,
        principal: &dyn Principal,
        scopes: &[String],
        resource: Option<&str>,
        authorization_details: Option<&[AuthorizationDetail]>,
        audience: Option<&str>,
        previous: Option<&str>,
    ) -> ErrorResponseResult<TokenResponse> {
        self.require_authority()?;
        if principal.get_entity_type() != EntityType::User {
            return Err(ErrorResponse::new(ErrorCode::AccessDenied)
                .with_description("this grant cannot issue user tokens to a client principal"));
        }

        let now = Utc::now();
        let signing_jwk = self.load_signing_jwk(principal.get_key()).await?;
        let scope = if scopes.is_empty() {
            None
        } else {
            Some(scopes.join(" "))
        };

        let access_claims = StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: (now + Duration::seconds(self.oauth_config.token_ttl_secs as i64)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            iss: self.oauth_config.issuer.clone(),
            aud: audience.unwrap_or(&client.client_id).to_string(),
            client_id: client.client_id.clone(),
            sub: principal.get_entity_id().to_string(),
            principal_type: match principal.get_entity_type() {
                EntityType::User => PrincipalType::User,
                EntityType::Client => PrincipalType::Client,
            },
            scope: scopes.to_vec(),
            resource: resource.map(str::to_string),
            authorization_details: authorization_details
                .map(<[model::contract::AuthorizationDetail]>::to_vec),
        };

        let access_token_value = encode_jwt(&signing_jwk, &access_claims)?;

        let user_info = match principal.get_entity_type() {
            EntityType::User => principal
                .get_entity_as_any()
                .downcast_ref::<User>()
                .cloned()
                .map(User::into),
            _ => None,
        };

        let id_token = IdTokenClaims {
            standard_claims: StandardClaims {
                r#use: TokenUse::Id,
                ..access_claims.clone()
            },
            user_info,
        };

        let id_token_value = encode_jwt(&signing_jwk, &id_token)?;

        let refresh_claims = StandardClaims {
            aud: client.client_id.clone(),
            r#use: TokenUse::Refresh,
            exp: (now + Duration::seconds(self.oauth_config.refresh_token_ttl_secs as i64))
                .timestamp(),
            ..access_claims
        };

        let refresh_token_value = encode_jwt(
            &signing_jwk,
            &super::token::RefreshClaims {
                standard_claims: refresh_claims.clone(),
                jti: generate_random_string::<32>(),
            },
        )?;
        self.refresh_token_repo
            .issue_refresh_token(
                OAuth2RefreshToken {
                    token: refresh_token_value.clone(),
                    client_id: client.id,
                    user_id: principal.get_entity_id(),
                    scopes: refresh_claims.scope,
                    resource: refresh_claims.resource,
                    authorization_details: refresh_claims.authorization_details,
                    expires_at: refresh_claims.exp,
                    created_at: now.timestamp(),
                },
                previous,
            )
            .await
            .map_err(|error| {
                if previous.is_some() {
                    ErrorResponse::new(ErrorCode::InvalidGrant).with_description(error.to_string())
                } else {
                    ErrorResponse::from(error)
                }
            })?;

        Ok(TokenResponse {
            id_token: Some(IdToken(id_token_value)),
            access_token: AccessToken(access_token_value),
            token_type: TokenType::Bearer,
            expires_in: Some(self.oauth_config.token_ttl_secs),
            refresh_token_expires_in: Some(self.oauth_config.refresh_token_ttl_secs),
            refresh_token: Some(RefreshToken(refresh_token_value)),
            scope,
            issuer: Some(self.oauth_config.issuer.clone()),
        })
    }

    async fn issue_client_credentials_access_token(
        &self,
        client: &Client,
        principal: &dyn Principal,
        scopes: &[String],
        audience: &str,
        resource: Option<&str>,
    ) -> ErrorResponseResult<TokenResponse> {
        if self.role == IdpRole::Replica {
            return Err(
                ErrorResponse::new(ErrorCode::AccessDenied).with_description(
                    "replica issuance requires approved local signer and fresh authority state",
                ),
            );
        }
        if principal.get_entity_type() != EntityType::Client
            || principal.get_entity_id() != client.id
        {
            return Err(ErrorResponse::new(ErrorCode::InvalidClient)
                .with_description("client signing principal does not match the client"));
        }

        let now = Utc::now();
        let signing_jwk = self.load_signing_jwk(principal.get_key()).await?;
        let claims = StandardClaims {
            r#type: TokenType::Bearer,
            r#use: TokenUse::Access,
            exp: (now + Duration::seconds(self.oauth_config.token_ttl_secs as i64)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            iss: self.oauth_config.issuer.clone(),
            aud: audience.to_string(),
            client_id: client.client_id.clone(),
            sub: client.id.to_string(),
            principal_type: PrincipalType::Client,
            scope: scopes.to_vec(),
            resource: resource.map(str::to_string),
            authorization_details: None,
        };
        let access_token = AccessToken(encode_jwt(&signing_jwk, &claims)?);

        Ok(TokenResponse {
            id_token: None,
            access_token,
            token_type: TokenType::Bearer,
            expires_in: Some(self.oauth_config.token_ttl_secs),
            refresh_token: None,
            refresh_token_expires_in: None,
            scope: Some(scopes.join(" ")),
            issuer: Some(self.oauth_config.issuer.clone()),
        })
    }

    pub async fn find_user_info(&self, user_id: Id) -> ErrorResponseResult<UserInfo> {
        let user = self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::NotFound)
                    .with_description("User not found".to_string())
            })?;

        self.hydrate_user_info(user).await
    }

    pub async fn list_user_info(
        &self,
        offset: u32,
        limit: u32,
    ) -> ErrorResponseResult<Vec<UserInfo>> {
        let users = self
            .user_repo
            .list_users(offset, limit)
            .await
            .map_err(ErrorResponse::from)?;
        let mut user_info_list = Vec::with_capacity(users.len());

        for user in users {
            user_info_list.push(self.hydrate_user_info(user).await?);
        }

        Ok(user_info_list)
    }

    pub async fn update_user_info(
        &self,
        user_id: Id,
        request: UpdateUserInfoRequest,
    ) -> ErrorResponseResult<UserInfo> {
        self.require_authority()?;
        let existing = self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::NotFound)
                    .with_description("User not found".to_string())
            })?;

        let sex = match request.sex.as_deref() {
            Some("male") => Some(idp_model::contract::Sex::Male),
            Some("female") => Some(idp_model::contract::Sex::Female),
            Some(value) => {
                return Err(ErrorResponse::new(ErrorCode::InvalidRequest)
                    .with_description(format!("unsupported sex value: {value}")));
            }
            None => existing.sex,
        };

        let birthdate = match request.birthdate.as_deref() {
            Some(value) => Some(
                chrono::DateTime::parse_from_rfc3339(value)
                    .map_err(|_| {
                        ErrorResponse::new(ErrorCode::InvalidRequest)
                            .with_description("birthdate must be RFC3339".to_string())
                    })?
                    .with_timezone(&Utc),
            ),
            None => existing.birthdate,
        };

        let user = User {
            id: existing.id,
            name: request.name.unwrap_or(existing.name),
            given_name: request.given_name.or(existing.given_name),
            family_name: request.family_name.or(existing.family_name),
            middle_name: request.middle_name.or(existing.middle_name),
            nickname: request.nickname.or(existing.nickname),
            profile: request.profile.or(existing.profile),
            picture: request.picture.or(existing.picture),
            website: request.website.or(existing.website),
            sex,
            birthdate,
            zoneinfo: request.zoneinfo.or(existing.zoneinfo),
            locale: request.locale.or(existing.locale),
            created_at: existing.created_at,
            updated_at: Utc::now(),
        };

        let user = self
            .user_repo
            .update_user(user)
            .await
            .map_err(ErrorResponse::from)?;

        if let Some(email) = request.email {
            self.user_repo
                .upsert_primary_user_email(user.id, &email, request.email_verified.unwrap_or(false))
                .await
                .map_err(ErrorResponse::from)?;
        }

        if let Some(phone_number) = request.phone_number {
            self.user_repo
                .upsert_primary_user_phone_number(
                    user.id,
                    &phone_number,
                    request.phone_number_verified.unwrap_or(false),
                )
                .await
                .map_err(ErrorResponse::from)?;
        }

        self.hydrate_user_info(user).await
    }

    pub async fn reset_user_password(
        &self,
        user_id: Id,
        password: &str,
    ) -> ErrorResponseResult<()> {
        self.require_authority()?;
        if self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .is_none()
        {
            return Err(ErrorResponse::new(ErrorCode::NotFound)
                .with_description("User not found".to_string()));
        }

        self.user_repo
            .replace_user_password(user_id, password)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn delete_user(&self, user_id: Id) -> ErrorResponseResult<()> {
        self.require_authority()?;
        if self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .is_none()
        {
            return Err(ErrorResponse::new(ErrorCode::NotFound)
                .with_description("User not found".to_string()));
        }

        self.user_repo
            .delete_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn list_user_consents(
        &self,
        user_id: Id,
        offset: u32,
        limit: u32,
    ) -> ErrorResponseResult<Vec<idp_model::model::OAuth2UserConsent>> {
        if self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .is_none()
        {
            return Err(ErrorResponse::new(ErrorCode::NotFound)
                .with_description("User not found".to_string()));
        }

        self.oauth2_user_consent_repo
            .list_user_consents(user_id, offset, limit)
            .await
            .map_err(ErrorResponse::from)
    }

    pub async fn revoke_user_consent(
        &self,
        user_id: Id,
        consent_id: Id,
    ) -> ErrorResponseResult<()> {
        self.require_authority()?;
        if self
            .user_repo
            .find_user_by_id(user_id)
            .await
            .map_err(ErrorResponse::from)?
            .is_none()
        {
            return Err(ErrorResponse::new(ErrorCode::NotFound)
                .with_description("User not found".to_string()));
        }

        let consent = self
            .oauth2_user_consent_repo
            .find_user_consent_by_id(consent_id)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::NotFound)
                    .with_description("User consent not found".to_string())
            })?;

        if consent.user_id != user_id {
            return Err(ErrorResponse::new(ErrorCode::NotFound)
                .with_description("User consent not found".to_string()));
        }

        self.oauth2_user_consent_repo
            .delete_user_consent_by_id(consent_id)
            .await
            .map_err(ErrorResponse::from)
    }

    async fn hydrate_user_info(&self, user: User) -> ErrorResponseResult<UserInfo> {
        let user_id = user.id;
        let mut user_info: UserInfo = From::from(user);

        let emails = self
            .user_repo
            .find_user_emails_by_user_id(user_id)
            .await
            .map_err(ErrorResponse::from)?;
        if let Some(primary_email) = emails.into_iter().find(|e| e.primary) {
            user_info.email = Some(primary_email.email);
            user_info.email_verified = Some(primary_email.verified);
        }

        let phone_numbers = self
            .user_repo
            .find_user_phone_numbers_by_user_id(user_id)
            .await
            .map_err(ErrorResponse::from)?;
        if let Some(primary_phone_number) = phone_numbers.into_iter().find(|e| e.primary) {
            user_info.phone_number = Some(primary_phone_number.phone_number);
            user_info.phone_number_verified = Some(primary_phone_number.verified);
        }

        Ok(user_info)
    }

    pub async fn find_principal(
        &self,
        key_id: Id,
    ) -> ErrorResponseResult<Option<Box<dyn Principal>>> {
        self.require_security_ready()?;
        let key = if let Some(key) = self.key_service.key_repo().find_by_id(key_id).await? {
            key
        } else {
            return Ok(None);
        };

        if self.ensure_key_is_active_entity_root(&key).await.is_err() {
            return Ok(None);
        }

        let principal = match key.entity_type {
            EntityType::User => {
                let user = if let Some(user) = self.user_repo.find_user_by_id(key.entity_id).await?
                {
                    user
                } else {
                    return Ok(None);
                };

                Box::new(UserPrincipal { user, key }) as Box<dyn Principal>
            }
            EntityType::Client => {
                let client = if let Some(client) =
                    self.client_repo.find_client_by_id(key.entity_id).await?
                {
                    client
                } else {
                    return Ok(None);
                };

                Box::new(ClientPrincipal { client, key }) as Box<dyn Principal>
            }
        };

        Ok(Some(principal))
    }

    async fn ensure_key_is_active_entity_root(&self, key: &Key) -> ErrorResponseResult<()> {
        let active_root = self
            .key_service
            .key_repo()
            .find_active_entity_root_key(key.entity_type, key.entity_id)
            .await
            .map_err(ErrorResponse::from)?;

        let active_root = active_root.ok_or_else(|| {
            ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("active entity root key not found")
        })?;

        let binding = TokenPrincipalBinding {
            entity_type: key.entity_type,
            entity_id: key.entity_id,
            key_id: key.id,
        };
        if !binding.matches_active_root(&active_root, Utc::now().timestamp()) {
            return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                .with_description("key is not the active entity root"));
        }

        Ok(())
    }
}
