use std::sync::Arc;

use management_service::{
    HostedControlPlane, ManagementService,
    replica::{DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo},
};

type DbPermission = DbPermissionRepo;
type DbRole = DbRoleRepo;
type DbSelectionPolicy = DbSelectionPolicyRepo;

pub(crate) type ManagementRouterService = ManagementService<DbPermission, DbRole>;

#[derive(Clone)]
pub struct RouterState {
    pub(crate) api_base_uri: String,
    pub(crate) management_service: Arc<ManagementRouterService>,

    pub(crate) selection_policies: Arc<DbSelectionPolicy>,

    pub(crate) control_plane: Arc<HostedControlPlane>,
    pub(crate) storage_audience: String,
}

impl RouterState {
    pub fn new(
        api_base_uri: impl Into<String>,
        management_service: Arc<ManagementRouterService>,

        selection_policies: Arc<DbSelectionPolicy>,
        control_plane: Arc<HostedControlPlane>,
        storage_audience: impl Into<String>,
    ) -> Self {
        Self {
            api_base_uri: api_base_uri.into(),
            management_service,

            selection_policies,

            control_plane,
            storage_audience: storage_audience.into(),
        }
    }
}
