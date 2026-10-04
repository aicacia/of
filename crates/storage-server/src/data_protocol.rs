use std::time::Duration;

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
}

impl DataProtocolHandler {
    pub(crate) fn new(
        database: DatabaseProtocolHandler,
        file_system: StorageProtocolHandler,
    ) -> Self {
        Self {
            database,
            file_system,
        }
    }
}

impl ProtocolHandler for DataProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (send, mut recv) = connection.accept_bi().await?;
            let mut kind = [0; 1];
            match tokio::time::timeout(STREAM_MARKER_TIMEOUT, recv.read_exact(&mut kind)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::debug!("rejected data stream without a protocol kind: {error}");
                    continue;
                }
                Err(_) => {
                    log::debug!("rejected data stream with a timed-out protocol marker");
                    continue;
                }
            }
            match kind[0] {
                DATABASE_STREAM_KIND => {
                    self.database
                        .accept_stream(connection.clone(), send, recv)
                        .await;
                }
                FILESYSTEM_STREAM_KIND => {
                    self.file_system
                        .accept_stream(connection.clone(), send, recv)
                        .await;
                }
                _ => log::debug!("rejected data stream with an unknown protocol kind"),
            }
        }
    }
}

impl core::fmt::Debug for DataProtocolHandler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DataProtocolHandler")
            .finish_non_exhaustive()
    }
}
