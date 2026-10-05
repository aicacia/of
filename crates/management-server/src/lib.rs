#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;
mod provisioning;
mod router;
mod runtime;

#[cfg(feature = "cli")]
pub use cli::run;
pub use config::AppConfig;
pub use management_service::MANAGEMENT_APPLICATION_URI;
pub use provisioning::provision_initial_administrator;
pub use router::{RouterState, openapi_router};
pub use runtime::build_router;
