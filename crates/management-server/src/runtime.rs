use std::sync::Arc;

use axum::Router;
use db::NativeEngine;
use management_service::{
    HostedControlPlane, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo, up},
};

use crate::{RouterState, router::openapi_router};

pub async fn build_router(
    engine: Arc<NativeEngine>,
    api_base_uri: &str,
    prefix: &str,
    storage_audience: &str,
    control_plane: Arc<HostedControlPlane>,
) -> Result<Router, db::EngineError> {
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
