use std::{fs, io, path::Path, sync::Arc};

use db::open_native_engine;
use idp_model::{
    contract::{ClientRegistration, ErrorResponse, IdpRole},
    model::Id,
};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{KeyService, PrivateKeyKeyringRepo},
};
use ofdb_sql::{AutomergeRowCodec, RedbKernel};

use crate::AppConfig;

fn to_io_error(error: ErrorResponse) -> io::Error {
    io::Error::other(
        error
            .error_description
            .unwrap_or_else(|| format!("IdP provisioning failed: {:?}", error.error)),
    )
}

type NativeOAuth2Service = OAuth2Service<
    DbApplicationRepo<RedbKernel, AutomergeRowCodec>,
    DbClientRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2AuthorizationCodeRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2RefreshTokenRepo<RedbKernel, AutomergeRowCodec>,
    DbUserRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2UserConsentRepo<RedbKernel, AutomergeRowCodec>,
    DbKeyRepo<RedbKernel, AutomergeRowCodec>,
    PrivateKeyKeyringRepo,
>;

pub struct OwnerProvisioner {
    oauth2: NativeOAuth2Service,
}

impl OwnerProvisioner {
    pub async fn open(config: &AppConfig) -> io::Result<Self> {
        if config.oauth2.role != IdpRole::Authority {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "initial provisioning requires the designated IdP authority",
            ));
        }
        let data_dir = Path::new(&config.data_dir);
        fs::create_dir_all(data_dir)?;
        let engine =
            Arc::new(open_native_engine(data_dir.join("idp.redb")).map_err(io::Error::other)?);
        idp_model::replica::up(&engine)
            .await
            .map_err(io::Error::other)?;
        let keys = Arc::new(KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            PrivateKeyKeyringRepo::new(&config.oauth2.issuer).map_err(io::Error::other)?,
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
        Ok(Self { oauth2 })
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

#[cfg(test)]
mod tests {
    use idp_model::{contract::IdpRole, model::Id};

    use crate::{AppConfig, OwnerProvisioner};

    #[tokio::test]
    async fn replica_cannot_open_owner_provisioner_or_create_state() {
        let data_dir = std::env::temp_dir().join(format!("idp-replica-{}", Id::now_v7()));
        let mut config = AppConfig::default();
        config.data_dir = data_dir.to_string_lossy().into_owned();
        config.oauth2.role = IdpRole::Replica;

        let error = match OwnerProvisioner::open(&config).await {
            Ok(_) => panic!("replica must not open owner provisioning"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!data_dir.exists());
    }
}
