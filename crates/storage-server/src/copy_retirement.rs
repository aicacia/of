use std::{io, sync::Arc};

use iroh::EndpointId;
use storage_service::{DatabaseRuntime, ScopedFileSystemRuntime};

#[derive(Clone)]
pub struct StorageCopyRetirement {
    pub(crate) databases: Arc<DatabaseRuntime>,
    pub(crate) file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
}

impl StorageCopyRetirement {
    pub fn new(
        databases: Arc<DatabaseRuntime>,
        file_systems: Arc<ScopedFileSystemRuntime<EndpointId>>,
    ) -> Self {
        Self {
            databases,
            file_systems,
        }
    }

    /// Host calls only after durable cleanup completion and current IdP ownership validation.
    pub fn activate_owner(&self, owner: &str) -> io::Result<()> {
        self.databases.activate_owner(owner)?;
        self.file_systems
            .activate_owner(owner)
            .map_err(io::Error::other)
    }

    pub async fn remove_owner_copies(&self, owner: &str) -> io::Result<()> {
        let databases = self.databases.remove_owner_copies(owner).await;
        let file_systems = self
            .file_systems
            .remove_owner_copies(owner)
            .await
            .map_err(io::Error::other);
        databases.and(file_systems)
    }
}
