use std::{io, sync::Arc, time::Duration};

use axum::Router;
use db::Database;
use idp_model::contract::DeviceEndpointIdentity;
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbReplicaSignerRepo, DbUserRepo,
    },
    repo::{KeyService, PrivateKeyKeyringRepo, UserRepo},
};
use iroh::EndpointId;
use iroh::protocol::{ProtocolHandler, Router as IrohRouter};
use iroh_chain::Server;
use management_service::{DeviceRepo, HostedControlPlane, LocalPermissions, replica::DbDeviceRepo};

use crate::{
    AppConfig, BootstrapProtocolHandler, DeviceIdentity, RouterState,
    TimedPairingAcceptanceController, bootstrap::BOOTSTRAP_ALPN, router::openapi_router,
};

pub struct IdpRuntime {
    router: Router,
    bootstrap_protocol: BootstrapProtocolHandler,
    signers: DbReplicaSignerRepo,
    issuer: String,
    devices: Arc<DbDeviceRepo>,
    users: DbUserRepo,
    join_state: RouterState,
}

impl IdpRuntime {
    pub async fn approve_node_join(
        &self,
        offer: &iroh_chain::PairingOffer,
        bearer: &str,
    ) -> io::Result<crate::NodeJoinApproval> {
        self.join_state.approve_node_join(offer, bearer).await
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn bootstrap_protocol(&self) -> BootstrapProtocolHandler {
        self.bootstrap_protocol.clone()
    }

    pub fn protocol_router<D>(&self, server: &Server, data_protocol: D) -> IrohRouter
    where
        D: ProtocolHandler,
    {
        server.router_with_protocol(data_protocol, BOOTSTRAP_ALPN, self.bootstrap_protocol())
    }

    pub async fn approved_device_owner(
        &self,
        endpoint: EndpointId,
    ) -> io::Result<DeviceEndpointIdentity> {
        if !self.approved_peer_ids().await?.contains(&endpoint) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "endpoint is not a trusted Node",
            ));
        }
        let device = self
            .devices
            .find_approved_by_public_key(&endpoint.to_string())
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Device is not uniquely approved",
                )
            })?;
        let owner = device.owner_subject.parse().map_err(io::Error::other)?;
        if self
            .users
            .find_user_by_id(owner)
            .await
            .map_err(io::Error::other)?
            .is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Device owner is not locally active",
            ));
        }
        Ok(DeviceEndpointIdentity {
            device_id: device.id,
            owner_subject: device.owner_subject,
            endpoint_id: endpoint.to_string(),
        })
    }

    pub async fn approved_peer_ids(&self) -> io::Result<Vec<EndpointId>> {
        self.signers
            .trusted_signers(
                &self.issuer,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_secs()
                    .try_into()
                    .map_err(io::Error::other)?,
            )
            .await
            .map_err(io::Error::other)?
            .into_iter()
            .map(|(member, _)| {
                member
                    .endpoint_id
                    .parse::<EndpointId>()
                    .map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()
    }
}

pub async fn build_runtime(
    config: &AppConfig,
    engine: Arc<Database>,
    device_identity: Arc<DeviceIdentity>,
    server: Server,
    local_permissions: Option<LocalPermissions>,
) -> io::Result<IdpRuntime> {
    if device_identity.endpoint_id() != server.endpoint().id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device identity does not match the injected Iroh server",
        ));
    }

    if config
        .oauth2
        .local_signer
        .as_ref()
        .is_some_and(|binding| binding.endpoint_id != device_identity.endpoint_id().to_string())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local signer endpoint does not match the injected Node endpoint",
        ));
    }

    idp_model::replica::up(&engine)
        .await
        .map_err(io::Error::other)?;

    let key_service = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        PrivateKeyKeyringRepo::new(&config.oauth2.issuer).map_err(io::Error::other)?,
        config.key_namespace.clone(),
    ));
    if let Some(binding) = config.oauth2.local_signer.as_ref() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs()
            .try_into()
            .map_err(io::Error::other)?;
        key_service
            .load_node_signer(binding, &config.oauth2.issuer, now)
            .await
            .map_err(io::Error::other)?;
    }
    let devices = Arc::new(DbDeviceRepo::new(Arc::clone(&engine)));
    let oauth2_service = Arc::new(OAuth2Service::new(
        DbApplicationRepo::new(Arc::clone(&engine)),
        DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service)),
        DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
        DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
        DbUserRepo::new(Arc::clone(&engine), config.password.clone()),
        DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
        key_service,
        config.oauth2.clone(),
    ));

    let control_plane = config
        .control_plane_uri
        .as_deref()
        .map(HostedControlPlane::new)
        .transpose()
        .map_err(io::Error::other)?
        .map(Arc::new);
    let service_audience = config
        .service_audience
        .as_deref()
        .unwrap_or(&config.api_public_uri);
    if service_audience.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service_audience must not be empty",
        ));
    }

    let router_state = RouterState::new(
        &config.ui_public_uri,
        &config.api_public_uri,
        Arc::clone(&engine),
        Arc::clone(&oauth2_service),
        Arc::clone(&devices),
        device_identity,
    )
    .with_service_audience(service_audience);
    let router_state = match control_plane {
        Some(control_plane) => router_state.with_hosted_control_plane(control_plane),
        None => router_state,
    };

    let local_permissions = match local_permissions {
        Some(local) => Some(local),
        None => match config.management_data_dir.as_deref() {
            Some(directory) => {
                if std::path::Path::new(directory) == std::path::Path::new(&config.data_dir) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "IdP and Management data directories must be separate",
                    ));
                }
                let engine = Arc::new(
                    db::Database::open(std::path::Path::new(directory).join("management.redb"))
                        .map_err(io::Error::other)?,
                );
                management_service::replica::up(&engine)
                    .await
                    .map_err(io::Error::other)?;
                Some(LocalPermissions::new(engine))
            }
            None => None,
        },
    };
    let router_state = match local_permissions {
        Some(local) => router_state.with_local_permissions(local),
        None => router_state,
    };

    router_state
        .pairing_acceptance
        .bind(Arc::new(TimedPairingAcceptanceController::new(
            server,
            Duration::from_secs(config.pairing.accepting_timeout_seconds),
        )))
        .map_err(io::Error::other)?;

    let bootstrap_protocol = BootstrapProtocolHandler;
    let router = openapi_router(router_state.clone(), config.server.prefix())
        .split_for_parts()
        .0;

    Ok(IdpRuntime {
        router,
        bootstrap_protocol,
        signers: DbReplicaSignerRepo::new(Arc::clone(&engine)),
        issuer: config.oauth2.issuer.clone(),
        devices,
        users: DbUserRepo::new(engine, config.password.clone()),
        join_state: router_state,
    })
}
