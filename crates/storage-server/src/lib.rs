#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
mod cli;
mod config;
#[cfg(feature = "network")]
mod data_protocol;
#[cfg(feature = "network")]
mod database_protocol;
mod idp_client;
mod management_client;
#[cfg(feature = "network")]
mod network;
#[cfg(feature = "network")]
mod replication_runtime;
mod router;
#[cfg(feature = "network")]
mod runtime;
#[cfg(feature = "network")]
mod storage_protocol;
#[cfg(feature = "network")]
mod sync_stage;
#[cfg(feature = "network")]
mod sync_timeout;

#[cfg(feature = "cli")]
pub use cli::run;
pub use config::AppConfig;
pub use idp_client::{IdpClient, IdpIntrospectionError};
pub use management_client::ManagementClient;
#[cfg(feature = "network")]
pub use network::StoragePeerNetwork;
#[cfg(feature = "network")]
pub use replication_runtime::StorageReplicationRuntime;
pub use router::{
    RouterState, StorageSocketAccess, StorageSocketAuthorizationError, StorageSocketAuthorizer,
    openapi_router, resource_router, storage_router,
};
pub use router::{
    StorageAuthorization, StorageAuthorizationError, authorize_storage_token,
    scoped_file_system_socket_router,
};
#[cfg(feature = "network")]
pub use runtime::{StorageRuntime, build_runtime};
