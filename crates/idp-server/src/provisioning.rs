use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use db::Database;
use idp_model::{
    contract::{ClientRegistration, ErrorResponse},
    model::Id,
};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{KeyService, PrivateKeyKeyringRepo, PrivateKeyRepo},
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
