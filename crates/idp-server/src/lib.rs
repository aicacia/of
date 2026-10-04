#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;

mod bootstrap;

mod device_identity;
mod router;
mod runtime;
#[cfg(feature = "cli")]
mod unavailable_data_protocol;

pub use bootstrap::{BOOTSTRAP_ALPN, BootstrapProtocolHandler, BootstrapRegistry};
#[cfg(feature = "cli")]
pub use cli::run;
pub use config::{AppConfig, PairingConfig};

pub use device_identity::{
    delete as delete_device_identity, identity_from_server as device_identity_from_server,
    open as open_device_identity, open_with_allowlist as open_device_identity_with_allowlist,
};
pub use router::{
    DeviceIdentity, PairingAcceptanceController, PairingAcceptanceControllerSlot, RouterState,
    TimedPairingAcceptanceController, authorize_bearer, openapi_router,
};
pub(crate) use router::{authorize_bearer_any_principal, authorize_bearer_client};
pub use runtime::{IdpRuntime, build_runtime};
