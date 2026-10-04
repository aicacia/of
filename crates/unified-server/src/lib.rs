#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;
mod endpoint;
mod protocol;
mod router;
mod runtime;

#[cfg(feature = "cli")]
pub use cli::run;
pub use config::{ServiceClientCredentials, UnifiedConfig};
pub use endpoint::UnifiedEndpoint;
pub use protocol::compose_protocol_router;
pub use router::compose_router;
pub use runtime::UnifiedRuntime;
