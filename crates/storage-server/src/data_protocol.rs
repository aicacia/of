use std::time::Duration;

use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::{database_protocol::DatabaseProtocolHandler, storage_protocol::StorageProtocolHandler};
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};

pub(crate) const DATABASE_STREAM_KIND: u8 = 1;
pub(crate) const FILESYSTEM_STREAM_KIND: u8 = file_system::FILESYSTEM_STREAM_KIND;
const STREAM_MARKER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct DataProtocolHandler {
    database: DatabaseProtocolHandler,
    file_system: StorageProtocolHandler,
    cancellation_token: CancellationToken,
}

impl DataProtocolHandler {
    pub(crate) fn new(
        database: DatabaseProtocolHandler,
        file_system: StorageProtocolHandler,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            database,
            file_system,
            cancellation_token,
        }
    }
}

impl ProtocolHandler for DataProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = select! {
                () = self.cancellation_token.cancelled() => return Ok(()),
                result = connection.accept_bi() => result?,
            };
            select! {
                () = self.cancellation_token.cancelled() => return Ok(()),
                () = async {
                    let mut kind = [0; 1];
                    match tokio::time::timeout(STREAM_MARKER_TIMEOUT, recv.read_exact(&mut kind)).await {
                        Ok(Ok(())) => match kind[0] {
                            DATABASE_STREAM_KIND => self.database.accept_stream(connection.clone(), send, recv).await,
                            FILESYSTEM_STREAM_KIND => self.file_system.accept_stream(connection.clone(), send, recv).await,
                            _ => log::debug!("rejected data stream with an unknown protocol kind"),
                        },
                        Ok(Err(error)) => log::debug!("rejected data stream without a protocol kind: {error}"),
                        Err(_) => log::debug!("rejected data stream with a timed-out protocol marker"),
                    }
                } => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use iroh::{Endpoint, address_lookup::MemoryLookup, endpoint::presets};
    use iroh_chain::{DATA_ALPN, EndpointIdStore, Server};
    use storage_service::{DatabaseRuntime, ScopedFileSystemRuntime};

    use super::*;
    use crate::{
        ManagementClient, database_protocol::DatabaseProtocolHandler,
        storage_protocol::StorageProtocolHandler,
    };

    #[tokio::test]
    async fn shutdown_cancels_inbound_stream_waiting_for_marker() {
        let lookup = MemoryLookup::new();
        let storage_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind Storage endpoint");
        let peer_endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![DATA_ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind peer endpoint");
        lookup.add_endpoint_info(storage_endpoint.addr());
        let server = Server::new(storage_endpoint, EndpointIdStore::default());
        let (peer_connection, accepted_connection) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    peer_endpoint.connect(server.endpoint().id(), DATA_ALPN),
                    async {
                        server
                            .endpoint()
                            .accept()
                            .await
                            .expect("incoming connection")
                            .accept()
                            .expect("start incoming connection")
                            .await
                    }
                )
            })
            .await
            .expect("connection setup completes");
        let peer_connection = peer_connection.expect("peer connects");
        let accepted_connection = accepted_connection.expect("Storage accepts peer");
        let cancellation_token = CancellationToken::new();
        let management = ManagementClient::new(
            "http://127.0.0.1:1/management",
            "http://127.0.0.1:1/idp",
            "storage-client",
            "test-secret",
            "https://idp.example",
            "management-api",
        )
        .expect("build test Management client");
        let root = std::env::temp_dir().join(format!(
            "storage-active-shutdown-{}",
            idp_model::model::Id::now_v7()
        ));
        let databases = Arc::new(DatabaseRuntime::new(root.join("databases")).expect("open DB"));
        let file_systems = Arc::new(
            ScopedFileSystemRuntime::<iroh::EndpointId>::new(
                root.join("filesystems"),
                server.endpoint().id(),
            )
            .expect("open filesystems"),
        );
        let database = DatabaseProtocolHandler::new(
            server.clone(),
            management.clone(),
            databases,
            root.join("sync-staging"),
            cancellation_token.clone(),
        );
        let file_system = StorageProtocolHandler::new(
            server.clone(),
            management,
            file_systems,
            cancellation_token.clone(),
        );
        let handler = DataProtocolHandler::new(database, file_system, cancellation_token.clone());
        let task = tokio::spawn(async move { handler.accept(accepted_connection).await });
        let (_send, mut peer_receive) = peer_connection
            .open_bi()
            .await
            .expect("open stream handled by Storage");
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancellation_token.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("handler stops on shutdown")
            .expect("handler task joins")
            .expect("handler returns cleanly");
        let mut frame_prefix = [0; 4];
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                peer_receive.read_exact(&mut frame_prefix)
            )
            .await
            .expect("peer stream closes on shutdown")
            .is_err()
        );
        server.endpoint().close().await;
        peer_endpoint.close().await;
        let _ = std::fs::remove_dir_all(root);
    }
}

impl core::fmt::Debug for DataProtocolHandler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DataProtocolHandler")
            .finish_non_exhaustive()
    }
}
