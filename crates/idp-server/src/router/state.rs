use std::sync::Arc;

use idp_model::contract::{DeviceSelfRevocationRequest, device_self_revocation_payload};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::PrivateKeyKeyringRepo,
};
use iroh::{Endpoint, EndpointId, SecretKey};
use management_service::{HostedControlPlane, replica::DbDeviceRepo};
use ofdb_sql::{AutomergeRowCodec, RedbKernel};

use super::PairingAcceptanceControllerSlot;
use crate::bootstrap::BootstrapRegistry;

pub(super) type NativeOAuth2Service = OAuth2Service<
    DbApplicationRepo<RedbKernel, AutomergeRowCodec>,
    DbClientRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2AuthorizationCodeRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2RefreshTokenRepo<RedbKernel, AutomergeRowCodec>,
    DbUserRepo<RedbKernel, AutomergeRowCodec>,
    DbOAuth2UserConsentRepo<RedbKernel, AutomergeRowCodec>,
    DbKeyRepo<RedbKernel, AutomergeRowCodec>,
    PrivateKeyKeyringRepo,
>;

pub type NativeDeviceRepo = DbDeviceRepo<RedbKernel, AutomergeRowCodec>;

#[derive(Clone)]
pub struct DeviceIdentity {
    endpoint: Endpoint,
    secret_key: SecretKey,
}

impl DeviceIdentity {
    #[must_use]
    pub fn new(endpoint: Endpoint, secret_key: SecretKey) -> Self {
        Self {
            endpoint,
            secret_key,
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    pub fn endpoint_address(&self) -> Result<String, String> {
        serde_json::to_string(&self.endpoint.addr()).map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn self_revocation_request(&self) -> DeviceSelfRevocationRequest {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let public_key = self.endpoint_id().to_string();
        let payload = device_self_revocation_payload(&public_key);
        DeviceSelfRevocationRequest {
            public_key,
            signature: URL_SAFE_NO_PAD.encode(self.secret_key.sign(payload.as_bytes()).to_bytes()),
        }
    }
}

#[derive(Clone)]
pub struct RouterState {
    pub ui_base_uri: String,
    pub api_base_uri: String,
    pub service_audience: String,
    pub engine: Arc<db::NativeEngine>,
    pub oauth2_service: Arc<NativeOAuth2Service>,
    pub devices: Arc<NativeDeviceRepo>,
    pub device_identity: Arc<DeviceIdentity>,
    pub pairing_acceptance: Arc<PairingAcceptanceControllerSlot>,
    pub hosted_control_plane: Option<Arc<HostedControlPlane>>,
    pub bootstrap_grants: Arc<BootstrapRegistry>,
}

impl RouterState {
    pub fn new(
        ui_base_uri: impl Into<String>,
        api_base_uri: impl Into<String>,
        engine: Arc<db::NativeEngine>,
        oauth2_service: Arc<NativeOAuth2Service>,
        devices: Arc<NativeDeviceRepo>,
        device_identity: Arc<DeviceIdentity>,
    ) -> Self {
        let api_base_uri = api_base_uri.into();
        Self {
            ui_base_uri: ui_base_uri.into(),
            service_audience: api_base_uri.clone(),
            api_base_uri,
            engine,
            oauth2_service,
            devices,
            device_identity,
            pairing_acceptance: Arc::new(PairingAcceptanceControllerSlot::new()),
            hosted_control_plane: None,
            bootstrap_grants: Arc::new(BootstrapRegistry::default()),
        }
    }

    pub fn with_service_audience(mut self, audience: impl Into<String>) -> Self {
        self.service_audience = audience.into();
        self
    }

    pub fn with_hosted_control_plane(mut self, control_plane: Arc<HostedControlPlane>) -> Self {
        self.hosted_control_plane = Some(control_plane);
        self
    }
}
