use std::{fs, io, path::Path, sync::Arc};

use db::open_native_engine;
use idp_model::{
    contract::IdentityAction,
    model::{Id, Role},
};
use management_service::{
    ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, up},
};

use crate::AppConfig;

pub async fn provision_initial_administrator(
    config: &AppConfig,
    user_id: Id,
    role_id: Id,
    permissions: &[(Id, IdentityAction)],
) -> io::Result<Role> {
    let data_dir = Path::new(&config.data_dir);
    fs::create_dir_all(data_dir)?;
    let engine =
        Arc::new(open_native_engine(data_dir.join("management.redb")).map_err(io::Error::other)?);
    up(&engine).await.map_err(io::Error::other)?;
    let service = ManagementService::new(
        DbPermissionRepo::new(Arc::clone(&engine)),
        DbRoleRepo::new(engine),
    );
    service
        .provision_initial_administrator(user_id, role_id, permissions)
        .await
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use idp_model::{contract::IdentityAction, model::Id};

    use crate::{AppConfig, provision_initial_administrator};

    #[tokio::test]
    async fn owner_provisioning_is_retry_safe_in_its_own_data_root() {
        let root = std::env::temp_dir().join(format!("management-owner-{}", Id::now_v7()));
        let mut config = AppConfig::default();
        config.data_dir = root.to_string_lossy().into_owned();
        let user_id = Id::now_v7();
        let role_id = Id::now_v7();
        let permissions = [
            (Id::now_v7(), IdentityAction::DevicePairingRead),
            (Id::now_v7(), IdentityAction::DevicePairingUpdate),
        ];

        let first = provision_initial_administrator(&config, user_id, role_id, &permissions)
            .await
            .expect("provision initial administrator");
        let retry = provision_initial_administrator(&config, user_id, role_id, &permissions)
            .await
            .expect("retry initial administrator provisioning");

        assert_eq!(first.id, role_id);
        assert_eq!(retry.id, first.id);
        assert!(root.join("management.redb").is_file());
        fs::remove_dir_all(root).expect("remove temporary Management data");
    }
}
