use std::{io, sync::Arc, time::Duration};

use axum::Router;
use db::NativeEngine;
use idp_model::contract::DeviceState;
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{KeyService, PrivateKeyKeyringRepo},
};
use iroh::EndpointId;
use iroh::protocol::{ProtocolHandler, Router as IrohRouter};
use iroh_chain::Server;
use management_service::{DeviceRepo, HostedControlPlane, PermissionClient, replica::DbDeviceRepo};

use crate::{
    AppConfig, BootstrapProtocolHandler, DeviceIdentity, RouterState,
    TimedPairingAcceptanceController,
    bootstrap::BOOTSTRAP_ALPN,
    router::{NativeDeviceRepo, openapi_router},
};

pub struct IdpRuntime {
    router: Router,
    bootstrap_protocol: BootstrapProtocolHandler,
    devices: Arc<NativeDeviceRepo>,
}

impl IdpRuntime {
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

    pub async fn approved_peer_ids(&self) -> io::Result<Vec<EndpointId>> {
        Ok(self
            .devices
            .list()
            .await
            .map_err(io::Error::other)?
            .into_iter()
            .filter(|device| device.state == DeviceState::Approved)
            .filter_map(|device| device.public_key.parse::<EndpointId>().ok())
            .collect())
    }
}

pub async fn build_runtime(
    config: &AppConfig,
    engine: Arc<NativeEngine>,
    device_identity: Arc<DeviceIdentity>,
    server: Server,
    permission_client: Option<PermissionClient>,
) -> io::Result<IdpRuntime> {
    if device_identity.endpoint_id() != server.endpoint().id() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device identity does not match the injected Iroh server",
        ));
    }

    idp_model::replica::up(&engine)
        .await
        .map_err(io::Error::other)?;

    let key_service = Arc::new(KeyService::new(
        DbKeyRepo::new(Arc::clone(&engine)),
        PrivateKeyKeyringRepo::new(&config.oauth2.issuer),
        config.key_namespace.clone(),
    ));
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

    let router_state = if let Some(client) = permission_client {
        router_state.with_permission_client(client)
    } else {
        match (
            config.management_api_base.as_deref(),
            config.permission_idp_api_base.as_deref(),
            config.management_oauth_client_id.as_deref(),
        ) {
            (None, None, None) => router_state,
            (Some(management), Some(idp), Some(client_id)) => {
                let secret =
                    std::env::var("LIDP_MANAGEMENT_OAUTH_CLIENT_SECRET").map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "LIDP_MANAGEMENT_OAUTH_CLIENT_SECRET is required",
                        )
                    })?;
                router_state.with_permission_client(
                    PermissionClient::new(
                        management,
                        idp,
                        &config.oauth2.issuer,
                        client_id,
                        &secret,
                    )
                    .map_err(io::Error::other)?,
                )
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "management_api_base, permission_idp_api_base and management_oauth_client_id must be configured together",
                ));
            }
        }
    };

    router_state
        .pairing_acceptance
        .bind(Arc::new(TimedPairingAcceptanceController::new(
            server,
            Duration::from_secs(config.pairing.accepting_timeout_seconds),
        )))
        .map_err(io::Error::other)?;

    let bootstrap_protocol = BootstrapProtocolHandler;
    let router = openapi_router(router_state, config.server.prefix())
        .split_for_parts()
        .0
        .into();

    Ok(IdpRuntime {
        router,
        bootstrap_protocol,
        devices,
    })
}
