#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;
mod endpoint;
#[cfg(test)]
mod permission_http_tests;
mod protocol;
mod router;
mod runtime;
mod security_sync;
#[cfg(test)]
mod security_sync_tests;

#[cfg(feature = "cli")]
pub use cli::run;
pub use config::{ServiceClientCredentials, UnifiedConfig};
pub use endpoint::UnifiedEndpoint;
pub use protocol::compose_protocol_router;
pub use router::compose_router;
pub use runtime::UnifiedRuntime;
pub use security_sync::{SecurityContext, SecurityProtocol};
