use std::{io, sync::Arc, time::Duration};

use iroh::EndpointId;
use iroh_chain::Server;
use storage_service::{DatabaseRuntime, ScopedFileSystemRuntime};
use tokio::{select, task::JoinHandle, time::interval};
use tokio_util::sync::CancellationToken;

use crate::{
    ManagementClient, data_protocol::DataProtocolHandler,
    database_protocol::DatabaseProtocolHandler, storage_protocol::StorageProtocolHandler,
};

pub struct StorageReplicationRuntime {
    data_handler: DataProtocolHandler,
    database: DatabaseProtocolHandler,
    file_system: StorageProtocolHandler,
    sync_task: Option<JoinHandle<()>>,
}

impl StorageReplicationRuntime {
    pub fn start(
        server: Server,
        management: ManagementClient,
        databases: Arc<DatabaseRuntime>,
        file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
    ) -> Self {
        let database = DatabaseProtocolHandler::new(server.clone(), management.clone(), databases);
        let file_system = StorageProtocolHandler::new(server.clone(), management, file_systems);
        let data_handler = DataProtocolHandler::new(database.clone(), file_system.clone());
        Self {
            data_handler,
            sync_task: None,
            database,
            file_system,
        }
    }

    pub fn data_handler(&self) -> impl iroh::protocol::ProtocolHandler + Clone {
        self.data_handler.clone()
    }

    pub fn start_sync(&mut self, cancellation_token: CancellationToken) {
        if self.sync_task.is_some() {
            return;
        }
        let database = self.database.clone();
        let file_system = self.file_system.clone();
        self.sync_task = Some(tokio::spawn(async move {
            let mut sync_interval = interval(Duration::from_secs(10));
            loop {
                select! {
                    () = cancellation_token.cancelled() => return,
                    _ = sync_interval.tick() => {
                        database.synchronize_selected_peers().await;
                        file_system.synchronize_selected_peers().await;
                    }
                }
            }
        }));
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(sync_task) = self.sync_task.take() {
            sync_task.abort();
            match sync_task.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        Ok(())
    }
}
