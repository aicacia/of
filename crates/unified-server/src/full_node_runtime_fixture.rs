use iroh_chain::Server;

use super::UnifiedRuntime;

impl UnifiedRuntime {
    pub(crate) fn full_node_test_server(&self) -> &Server {
        self.endpoint.server()
    }
}
