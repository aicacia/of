#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;
mod endpoint;
mod local_provisioning;
#[cfg(all(test, unix))]
mod local_provisioning_tests;
#[cfg(test)]
mod native_api_tests;
#[cfg(test)]
mod node_bootstrap_owner_tests;
#[cfg(test)]
mod node_join_bootstrap_tests;
#[cfg(test)]
mod permission_http_tests;
mod protocol;
mod router;
mod runtime;
#[cfg(test)]
mod security_history_tests;
mod security_sync;
#[cfg(test)]
mod security_sync_tests;

#[cfg(feature = "cli")]
pub use cli::run;
pub use config::{ServiceClientCredentials, UnifiedConfig};
pub use endpoint::UnifiedEndpoint;
pub use local_provisioning::LocalProvisioner;
pub use protocol::compose_protocol_router;
pub use router::compose_router;
pub use runtime::UnifiedRuntime;
pub use security_sync::{SecurityContext, SecurityProtocol};
