use iroh::protocol::Router;
use iroh_chain::Server;
use storage_server::StorageRuntime;

use crate::SecurityProtocol;

pub fn compose_protocol_router(
    server: &Server,
    storage: &StorageRuntime,
    security: &SecurityProtocol,
) -> Option<Router> {
    storage.data_handler().map(|data_protocol| {
        server.router_with_protocol(
            security.attach(data_protocol),
            idp_server::BOOTSTRAP_ALPN,
            security.node_bootstrap_handler(),
        )
    })
}
