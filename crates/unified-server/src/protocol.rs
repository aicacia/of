use idp_server::IdpRuntime;
use iroh::protocol::Router;
use iroh_chain::Server;
use storage_server::StorageRuntime;

pub fn compose_protocol_router(
    server: &Server,
    idp: &IdpRuntime,
    storage: &StorageRuntime,
) -> Option<Router> {
    storage
        .data_handler()
        .map(|data_protocol| idp.protocol_router(server, data_protocol))
}
