use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use db::Database;
use idp_model::{
    contract::{
        ClientCredentialsGrantRequest, ClientRegistration, ErrorResponse, OAuth2ClientAuth,
        TokenRequest,
    },
    model::Id,
};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{ApplicationRepo, ClientRepo, KeyService, PrivateKeyKeyringRepo, PrivateKeyRepo},
};

use crate::AppConfig;

fn to_io_error(error: ErrorResponse) -> io::Error {
    io::Error::other(
        error
            .error_description
            .unwrap_or_else(|| format!("IdP provisioning failed: {:?}", error.error)),
    )
}

type NativeOAuth2Service<P> = OAuth2Service<
    DbApplicationRepo,
    DbClientRepo<P>,
    DbOAuth2AuthorizationCodeRepo,
    DbOAuth2RefreshTokenRepo,
    DbUserRepo,
    DbOAuth2UserConsentRepo,
    DbKeyRepo,
    P,
>;

pub struct OwnerProvisioner<P: PrivateKeyRepo + Send + Sync = PrivateKeyKeyringRepo> {
    pub(crate) oauth2: NativeOAuth2Service<P>,
    pub(crate) engine: Arc<Database>,
    pub(crate) key_namespace: String,
    pub(crate) data_dir: PathBuf,
}

impl OwnerProvisioner {
    pub fn from_database(config: &AppConfig, engine: Arc<Database>) -> io::Result<Self> {
        Ok(Self::with_database(
            config,
            engine,
            PrivateKeyKeyringRepo::new(&config.oauth2.issuer).map_err(io::Error::other)?,
        ))
    }

    pub async fn open(config: &AppConfig) -> io::Result<Self> {
        Self::open_with_private_keys(
            config,
            PrivateKeyKeyringRepo::new(&config.oauth2.issuer).map_err(io::Error::other)?,
        )
        .await
    }
}

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    pub async fn open_with_private_keys(config: &AppConfig, private_keys: P) -> io::Result<Self> {
        let data_dir = Path::new(&config.data_dir);
        fs::create_dir_all(data_dir)?;
        let engine = Arc::new(Database::open(data_dir.join("idp.redb")).map_err(io::Error::other)?);
        idp_model::replica::up(&engine)
            .await
            .map_err(io::Error::other)?;
        Ok(Self::with_database(config, engine, private_keys))
    }

    fn with_database(config: &AppConfig, engine: Arc<Database>, private_keys: P) -> Self {
        let keys = Arc::new(KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            private_keys,
            config.key_namespace.clone(),
        ));
        let oauth2 = OAuth2Service::new(
            DbApplicationRepo::new(Arc::clone(&engine)),
            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&keys)),
            DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
            DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
            DbUserRepo::new(Arc::clone(&engine), config.password.clone()),
            DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
            keys,
            config.oauth2.clone(),
        );
        Self {
            oauth2,
            engine,
            key_namespace: config.key_namespace.clone(),
            data_dir: PathBuf::from(&config.data_dir),
        }
    }

    pub async fn ensure_initial_user(
        &self,
        user_id: Id,
        credential_id: Id,
        name: &str,
        password: &str,
    ) -> io::Result<Id> {
        self.oauth2
            .ensure_initial_user(user_id, credential_id, name, password)
            .await
            .map_err(to_io_error)?;
        Ok(user_id)
    }

    /// Verifies an existing active relationship without provisioning or repairing local state.
    pub async fn verify_infrastructure_client(
        &self,
        mut expected: ClientRegistration,
    ) -> io::Result<()> {
        let id = expected.client_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "existing Client ID is required",
            )
        })?;
        let client = self
            .oauth2
            .client_repo
            .find_client_by_client_id(id)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing Client is missing or inactive",
                )
            })?;
        let secret = expected
            .client_secret
            .take()
            .filter(|secret| !secret.trim().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "current Client secret is required",
                )
            })?;

        let application = self
            .oauth2
            .application_repo
            .find_by_id(client.application_id)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing Client Application is missing",
                )
            })?;
        if expected.application.name.is_none() {
            expected.application.name = Some(expected.client_name.clone());
        }
        if expected.client_uri.is_none() {
            expected.client_uri = Some(expected.application.uri.clone());
        }
        let mut current: ClientRegistration = client.into();
        current.application = idp_model::contract::ApplicationRegistration {
            name: Some(application.name),
            uri: application.uri,
            description: application.description,
        };
        if current != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "current Client relationship conflicts with retained intent",
            ));
        }
        let id = expected.client_id.expect("validated existing Client ID");
        self.oauth2
            .token(
                TokenRequest::ClientCredentials(ClientCredentialsGrantRequest {
                    client_id: id.clone(),
                    client_secret: secret.clone(),
                    scope: Some(expected.allowed_scopes.join(" ")),
                    audience: expected.allowed_audiences.first().cloned(),
                    resource: None,
                }),
                Some(OAuth2ClientAuth {
                    client_id: id,
                    client_secret: Some(secret),
                    method: expected.token_endpoint_auth_method,
                }),
            )
            .await
            .map_err(to_io_error)?;
        Ok(())
    }

    pub async fn ensure_infrastructure_client(
        &self,
        request: ClientRegistration,
    ) -> io::Result<ClientRegistration> {
        self.oauth2
            .ensure_infrastructure_client(request)
            .await
            .map_err(to_io_error)
    }
}
