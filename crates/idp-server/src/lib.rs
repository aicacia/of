#![forbid(unsafe_code)]
#![cfg_attr(test, recursion_limit = "256")]

#[cfg(feature = "cli")]
mod cli;
mod config;

mod bootstrap;

mod device_identity;
mod node_join;
#[cfg(test)]
mod node_join_tests;
mod node_provisioning;
#[cfg(test)]
mod node_provisioning_tests;
mod provisioning;
mod router;
mod runtime;
mod security_sync;
#[cfg(feature = "cli")]
mod unavailable_data_protocol;

pub use bootstrap::{BOOTSTRAP_ALPN, BootstrapProtocolHandler};
#[cfg(feature = "cli")]
pub use cli::run;
pub use config::{AppConfig, PairingConfig};

pub use device_identity::{
    delete as delete_device_identity, identity_from_server as device_identity_from_server,
    open as open_device_identity, open_with_allowlist as open_device_identity_with_allowlist,
};
pub use node_join::{NodeJoinApproval, NodeJoinRequest};
pub use provisioning::OwnerProvisioner;
pub use router::{
    DeviceIdentity, PairingAcceptanceController, PairingAcceptanceControllerSlot, RouterState,
    TimedPairingAcceptanceController, authorize_bearer, openapi_router,
};
pub(crate) use router::{authorize_bearer_any_principal, authorize_bearer_client};
pub use runtime::{IdpRuntime, build_runtime};
pub use security_sync::validate_public_security_record;
