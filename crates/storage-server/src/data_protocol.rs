use std::{future::Future, io, pin::Pin, sync::Arc};

use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use tokio::{select, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{database_protocol::DatabaseProtocolHandler, storage_protocol::StorageProtocolHandler};

pub(crate) const DATABASE_STREAM_KIND: u8 = 1;
pub(crate) const FILESYSTEM_STREAM_KIND: u8 = crate::filesystem_transport::FILESYSTEM_STREAM_KIND;

type AdditionalStreamHandler = Arc<
    dyn Fn(
            u8,
            Connection,
            SendStream,
            RecvStream,
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct DataProtocolHandler {
    database: DatabaseProtocolHandler,
    file_system: StorageProtocolHandler,
    cancellation_token: CancellationToken,
    additional_stream: Option<AdditionalStreamHandler>,
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
            additional_stream: None,
        }
    }

    pub fn with_additional_stream<F, U>(mut self, handler: F) -> Self
    where
        F: Fn(u8, Connection, SendStream, RecvStream) -> U + Send + Sync + 'static,
        U: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.additional_stream = Some(Arc::new(move |kind, connection, send, recv| {
            Box::pin(handler(kind, connection, send, recv))
        }));
        self
    }
}

impl ProtocolHandler for DataProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let mut streams = JoinSet::new();
        loop {
            let (send, mut recv) = select! {
                () = self.cancellation_token.cancelled() => {
                    streams.shutdown().await;
                    return Ok(());
                },
                result = streams.join_next(), if !streams.is_empty() => {
                    if let Some(Err(error)) = result {
                        log::debug!("data stream task failed: {error}");
                    }
                    continue;
                },
                result = connection.accept_bi() => match result {
                    Ok(stream) => stream,
                    Err(error) => {
                        streams.shutdown().await;
                        return Err(error.into());
                    }
                },
            };
            let handler = self.clone();
            let connection = connection.clone();
            streams.spawn(async move {
                select! {
                    () = handler.cancellation_token.cancelled() => {},
                    () = async {
                    let mut kind = [0; 1];
                    match recv.read_exact(&mut kind).await {
                        Ok(()) => match kind[0] {
                            DATABASE_STREAM_KIND => handler.database.accept_stream(connection.clone(), send, recv).await,
                            FILESYSTEM_STREAM_KIND => handler.file_system.accept_stream(connection.clone(), send, recv).await,
                            kind => {
                                if let Some(handler) = &handler.additional_stream {
                                    if let Err(error) = handler(kind, connection.clone(), send, recv).await {
                                        log::debug!("rejected additional data stream: {error}");
                                    }
                                } else {
                                    log::debug!("rejected data stream with an unknown protocol kind");
                                }
                            },
                        },
                        Err(error) => log::debug!("rejected data stream without a protocol kind: {error}"),
                    }
                    } => {}
                }
            });
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
    async fn stalled_handshake_does_not_block_other_streams_and_shutdown_cleans_tasks() {
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
        let handler = DataProtocolHandler::new(database, file_system, cancellation_token.clone())
            .with_additional_stream(|kind, _, mut send, _| async move {
                assert_eq!(kind, 9);
                send.write_all(b"ready")
                    .await
                    .map_err(std::io::Error::other)?;
                send.finish().map_err(std::io::Error::other)?;
                Ok(())
            });
        let task = tokio::spawn(async move { handler.accept(accepted_connection).await });
        let (mut stalled_send, mut peer_receive) = peer_connection
            .open_bi()
            .await
            .expect("open stream handled by Storage");
        stalled_send
            .write_all(&[DATABASE_STREAM_KIND])
            .await
            .expect("send database marker without handshake");
        let (mut independent_send, mut independent_receive) = peer_connection
            .open_bi()
            .await
            .expect("independent stream on same connection");
        independent_send
            .write_all(&[9])
            .await
            .expect("send independent marker");
        let mut reply = [0; 5];
        tokio::time::timeout(
            Duration::from_secs(5),
            independent_receive.read_exact(&mut reply),
        )
        .await
        .expect("stalled database handshake cannot block independent stream")
        .expect("read independent response");
        assert_eq!(&reply, b"ready");
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
