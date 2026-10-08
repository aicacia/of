use std::sync::Arc;

use axum::Router;
use db::Database;
use idp_model::{contract::DeviceEndpointIdentity, model::Id};
use management_service::{
    HostedControlPlane, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo, up},
};
use model::contract::SelectedResource;

use crate::{RouterState, router::openapi_router};

pub async fn replication_policy(
    engine: Arc<Database>,
    device: &DeviceEndpointIdentity,
) -> Result<(bool, Vec<SelectedResource>), String> {
    if device.device_id.is_nil()
        || !device
            .owner_subject
            .parse::<Id>()
            .is_ok_and(|owner| !owner.is_nil())
    {
        return Err("invalid local Device owner binding".into());
    }
    let policies = DbSelectionPolicyRepo::new(engine);
    let policy = policies
        .get(device.device_id, &device.owner_subject, Id::nil())
        .await
        .map_err(|error| error.to_string())?
        .ok_or("missing locally trusted Device policy")?;
    let selected = policies
        .selected_resources_for_device(device.device_id)
        .await
        .map_err(|error| error.to_string())?;
    if selected
        .iter()
        .any(|resource| resource.owner_subject != device.owner_subject)
    {
        return Err("selected resource owner mismatch".into());
    }
    Ok((
        policy.admin_allowed,
        selected
            .into_iter()
            .map(|resource| SelectedResource {
                owner_subject: resource.owner_subject,
                application_id: resource.application_id.to_string(),
                kind: resource.kind,
                resource_id: resource.resource_id.to_string(),
            })
            .collect(),
    ))
}

pub async fn build_router(
    engine: Arc<Database>,
    api_base_uri: &str,
    prefix: &str,
    storage_audience: &str,
    control_plane: Arc<HostedControlPlane>,
) -> Result<Router, db::QueryError> {
    up(&engine).await?;

    let management_service = Arc::new(ManagementService::new(
        DbPermissionRepo::new(Arc::clone(&engine)),
        DbRoleRepo::new(Arc::clone(&engine)),
    ));
    let router_state = RouterState::new(
        api_base_uri,
        management_service,
        Arc::new(DbSelectionPolicyRepo::new(engine)),
        control_plane,
        storage_audience,
    );

    Ok(openapi_router(router_state, prefix).into())
}

#[cfg(test)]
mod tests {
    use super::replication_policy;
    use db::Database;
    use idp_model::{contract::DeviceEndpointIdentity, model::Id};
    use management_service::replica::{DbSelectionPolicyRepo, SelectionPolicy, up};
    use std::{fs, sync::Arc};

    #[tokio::test]
    async fn native_owner_policy_requires_binding_and_rechecks_persisted_restrictions() {
        let root = std::env::temp_dir().join(format!("local-owner-policy-{}", Id::now_v7()));
        fs::create_dir_all(&root).expect("owner policy fixture");
        let path = root.join("management.redb");
        let device = DeviceEndpointIdentity {
            device_id: Id::now_v7(),
            owner_subject: Id::now_v7().to_string(),
            endpoint_id: "authenticated-by-idp".into(),
        };
        {
            let engine = Arc::new(Database::open(&path).expect("native Management owner"));
            up(&engine).await.expect("owner schema");
            assert!(
                replication_policy(Arc::clone(&engine), &device)
                    .await
                    .is_err(),
                "missing policy cannot fall back to remote approval"
            );
            let policies = DbSelectionPolicyRepo::new(Arc::clone(&engine));
            policies
                .set_prevalidated(SelectionPolicy {
                    device_id: device.device_id,
                    owner_subject: device.owner_subject.clone(),
                    application_id: None,
                    selected_kind: None,
                    selected_id: None,
                    admin_allowed: true,
                })
                .await
                .expect("persist empty selection");
            let (allowed, resources) = replication_policy(Arc::clone(&engine), &device)
                .await
                .expect("approved local policy");
            assert!(allowed);
            assert!(resources.is_empty());
            let forged = DeviceEndpointIdentity {
                owner_subject: Id::now_v7().to_string(),
                ..device.clone()
            };
            assert!(
                replication_policy(Arc::clone(&engine), &forged)
                    .await
                    .is_err()
            );
            policies
                .set_admin_allowed_prevalidated(device.device_id, &device.owner_subject, false)
                .await
                .expect("learn restriction");
            let (allowed, resources) = replication_policy(Arc::clone(&engine), &device)
                .await
                .expect("current restriction");
            assert!(!allowed);
            assert!(resources.is_empty());
        }
        let engine = Arc::new(Database::open(&path).expect("reopen owner offline"));
        let (allowed, resources) = replication_policy(Arc::clone(&engine), &device)
            .await
            .expect("persisted restriction");
        assert!(!allowed);
        assert!(resources.is_empty());
        drop(engine);
        fs::remove_dir_all(root).expect("remove owner policy fixture");
    }
}
