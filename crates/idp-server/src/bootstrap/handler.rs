use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};

pub const BOOTSTRAP_ALPN: &[u8] = b"idp-bootstrap/1";

#[derive(Clone, Debug, Default)]
pub struct BootstrapProtocolHandler;

impl ProtocolHandler for BootstrapProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        connection.close(
            1u32.into(),
            b"privileged scoped IdP enrollment is unavailable",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets, protocol::Router};

    use super::{BOOTSTRAP_ALPN, BootstrapProtocolHandler};

    #[tokio::test]
    async fn bootstrap_denies_admitted_peer_without_privileged_enrollment() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let lookup = MemoryLookup::new();
            let authority = Endpoint::builder(presets::Minimal)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .expect("bind authority endpoint");
            let replica = Endpoint::builder(presets::Minimal)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .expect("bind replica endpoint");
            lookup.add_endpoint_info(authority.addr());
            lookup.add_endpoint_info(replica.addr());
            let address = authority.addr();
            let router = Router::builder(authority)
                .accept(BOOTSTRAP_ALPN, BootstrapProtocolHandler)
                .spawn();
            // A real transport connection is not permission to copy identity state.
            let connection = replica
                .connect(address, BOOTSTRAP_ALPN)
                .await
                .expect("complete Iroh handshake with the registered bootstrap handler");
            {
                let reason = connection.closed().await;
                assert!(
                    matches!(
                        reason,
                        iroh::endpoint::ConnectionError::ApplicationClosed(_)
                    ),
                    "{reason:?}"
                );
            }
            replica.close().await;
            router.shutdown().await.expect("shut down authority router");
        })
        .await
        .expect("bootstrap denial must not wait for a grant or sync frame");
    }
}
