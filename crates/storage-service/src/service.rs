use std::{fmt, sync::Arc};

use file_system::{Entry, FileKind, FileSystem};
use serde::{Serialize, de::DeserializeOwned};
use storage_model::{
    StorageEntry, StorageErrorCode, StorageNamespace, StorageRequest, StorageResponse,
    StorageSession,
};

use crate::{ScopedFileSystem, ScopedFileSystemRuntime};

pub struct StorageService<PeerId>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + 'static,
{
    file_system: Arc<FileSystem<PeerId>>,
}

impl<PeerId> Clone for StorageService<PeerId>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + 'static,
{
    fn clone(&self) -> Self {
        Self {
            file_system: Arc::clone(&self.file_system),
        }
    }
}

impl<PeerId> StorageService<PeerId>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(file_system: Arc<FileSystem<PeerId>>) -> Self {
        Self { file_system }
    }

    pub async fn execute(
        &self,
        request: StorageRequest,
    ) -> Result<StorageResponse, StorageServiceError> {
        execute(&self.file_system, request).await
    }

    pub async fn stream(
        &self,
        path: &str,
        chunk_size: usize,
    ) -> Result<file_system::ReadStream, StorageServiceError> {
        self.file_system
            .stream(path, chunk_size)
            .await
            .map_err(StorageServiceError::FileSystem)
    }
}

impl<PeerId> StorageSession for StorageService<PeerId>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn execute_session(&self, request: StorageRequest) -> StorageResponse {
        self.execute(request)
            .await
            .unwrap_or_else(StorageServiceError::response)
    }
}

pub struct ScopedStorageService<PeerId, S>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + 'static,
{
    scope: S,
    resource_id: file_system::FileSystemId,
    generation: u64,
    content_reader: Arc<std::sync::Mutex<Option<crate::scoped_file_system::ContentReader>>>,
    local_copies: Arc<crate::local_copy::LocalCopyPolicy>,
    file_system: Arc<ScopedFileSystem<PeerId>>,
}

impl<PeerId, S> ScopedStorageService<PeerId, S>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
    S: StorageNamespace + Send + Sync + 'static,
{
    pub async fn open_resource(
        runtime: &ScopedFileSystemRuntime<PeerId>,
        scope: S,
        resource_id: file_system::FileSystemId,
    ) -> Result<Self, StorageServiceError> {
        let generation = runtime
            .local_copies
            .generation(&scope, resource_id.as_uuid())
            .map_err(|error| StorageServiceError::Scope(error.to_string()))?;
        let file_system = runtime
            .open_resource(&scope, resource_id)
            .await
            .map_err(StorageServiceError::Scope)?;
        runtime
            .local_copies
            .require_generation(&scope, resource_id.as_uuid(), generation)
            .map_err(|error| StorageServiceError::Scope(error.to_string()))?;
        Ok(Self {
            scope,
            resource_id,
            generation,
            content_reader: Arc::clone(&runtime.content_reader),
            local_copies: Arc::clone(&runtime.local_copies),
            file_system,
        })
    }

    fn require_local_copy(&self) -> Result<(), StorageServiceError> {
        self.local_copies
            .require_generation(&self.scope, self.resource_id.as_uuid(), self.generation)
            .map_err(|error| StorageServiceError::Scope(error.to_string()))
    }

    pub async fn execute(
        &self,
        request: StorageRequest,
    ) -> Result<StorageResponse, StorageServiceError> {
        self.require_local_copy()?;
        if let StorageRequest::Read { path } = &request
            && self
                .file_system
                .residency(path)
                .map_err(StorageServiceError::FileSystem)?
                == file_system::Residency::Passthrough
        {
            let reader = self
                .content_reader
                .lock()
                .map_err(|_| StorageServiceError::Scope("content reader lock poisoned".into()))?
                .clone()
                .ok_or(StorageServiceError::FileSystem(
                    file_system::Error::ContentUnavailable,
                ))?;
            let content = reader(
                self.scope.user_sub().to_owned(),
                self.scope.application_id(),
                self.resource_id,
                path.clone(),
            )
            .await
            .map_err(StorageServiceError::Scope)?;
            self.require_local_copy()?;
            return Ok(StorageResponse::Read { content });
        }
        execute(&self.file_system, request).await
    }

    pub async fn stream(
        &self,
        path: &str,
        chunk_size: usize,
    ) -> Result<file_system::ReadStream, StorageServiceError> {
        self.require_local_copy()?;
        if self
            .file_system
            .residency(path)
            .map_err(StorageServiceError::FileSystem)?
            == file_system::Residency::Passthrough
        {
            return Err(StorageServiceError::FileSystem(
                file_system::Error::ContentUnavailable,
            ));
        }
        self.file_system
            .stream(path, chunk_size)
            .await
            .map_err(StorageServiceError::FileSystem)
    }
}

impl<PeerId, S> StorageSession for ScopedStorageService<PeerId, S>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
    S: StorageNamespace + Send + Sync + 'static,
{
    async fn execute_session(&self, request: StorageRequest) -> StorageResponse {
        self.execute(request)
            .await
            .unwrap_or_else(StorageServiceError::response)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::StorageService;
    use std::sync::Arc;
    use storage_model::StorageRequest;

    #[tokio::test]
    async fn passthrough_service_cannot_delete_or_rename_metadata() {
        let root = std::env::temp_dir().join(format!(
            "passthrough-service-{}",
            idp_model::model::Id::now_v7()
        ));
        let filesystem = Arc::new(file_system::FileSystem::open(&root, 1_u8).expect("filesystem"));
        filesystem
            .set_residency("", file_system::Residency::Full)
            .await
            .expect("Full");
        filesystem
            .write("original.txt", b"retain metadata")
            .await
            .expect("source");
        filesystem
            .set_residency("", file_system::Residency::Passthrough)
            .await
            .expect("Passthrough");
        let service = StorageService::new(Arc::clone(&filesystem));
        assert!(
            service
                .execute(StorageRequest::Delete {
                    path: "original.txt".into()
                })
                .await
                .is_err()
        );
        assert!(
            service
                .execute(StorageRequest::Rename {
                    from: "original.txt".into(),
                    to: "renamed.txt".into()
                })
                .await
                .is_err()
        );
        assert!(filesystem.entry("original.txt").await.is_ok());
        assert!(filesystem.entry("renamed.txt").await.is_err());
        drop(service);
        drop(filesystem);
        std::fs::remove_dir_all(root).expect("remove fixture");
    }
}

async fn execute<PeerId>(
    file_system: &FileSystem<PeerId>,
    request: StorageRequest,
) -> Result<StorageResponse, StorageServiceError>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    match &request {
        StorageRequest::Write { path, .. }
        | StorageRequest::Append { path, .. }
        | StorageRequest::Delete { path }
        | StorageRequest::CreateDir { path } => require_full(file_system, path)?,
        StorageRequest::Rename { from, to } => {
            require_full(file_system, from)?;
            require_full(file_system, to)?;
        }
        _ => {}
    }
    match request {
        StorageRequest::Read { path } => Ok(StorageResponse::Read {
            content: file_system
                .read(&path)
                .await
                .map_err(StorageServiceError::FileSystem)?,
        }),
        StorageRequest::Write { path, content } => Ok(StorageResponse::Written {
            entry: storage_entry(
                file_system,
                file_system
                    .write(&path, &content)
                    .await
                    .map_err(StorageServiceError::FileSystem)?,
            )
            .await?,
        }),
        StorageRequest::Append { path, content } => {
            file_system
                .append(&path, &content)
                .await
                .map_err(StorageServiceError::FileSystem)?;
            Ok(StorageResponse::Appended {
                entry: storage_entry(
                    file_system,
                    file_system
                        .entry(&path)
                        .await
                        .map_err(StorageServiceError::FileSystem)?,
                )
                .await?,
            })
        }
        StorageRequest::Delete { path } => {
            file_system
                .delete(&path)
                .await
                .map_err(StorageServiceError::FileSystem)?;
            Ok(StorageResponse::Deleted)
        }
        StorageRequest::CreateDir { path } => Ok(StorageResponse::DirectoryCreated {
            entry: storage_entry(
                file_system,
                file_system
                    .create_dir(&path)
                    .await
                    .map_err(StorageServiceError::FileSystem)?,
            )
            .await?,
        }),
        StorageRequest::Rename { from, to } => {
            file_system
                .rename(&from, &to)
                .await
                .map_err(StorageServiceError::FileSystem)?;
            Ok(StorageResponse::Renamed)
        }
        StorageRequest::Entry { path } => Ok(StorageResponse::Entry {
            entry: storage_entry(
                file_system,
                file_system
                    .entry(&path)
                    .await
                    .map_err(StorageServiceError::FileSystem)?,
            )
            .await?,
        }),
        StorageRequest::List { path } => {
            let mut entries = Vec::new();
            for entry in file_system
                .list(&path)
                .await
                .map_err(StorageServiceError::FileSystem)?
            {
                entries.push(storage_entry(file_system, entry).await?);
            }
            Ok(StorageResponse::Listed { entries })
        }
    }
}

fn require_full<PeerId>(
    filesystem: &FileSystem<PeerId>,
    path: &str,
) -> Result<(), StorageServiceError>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    if filesystem
        .residency(path)
        .map_err(StorageServiceError::FileSystem)?
        != file_system::Residency::Full
    {
        return Err(StorageServiceError::FileSystem(
            file_system::Error::PassthroughWrite,
        ));
    }
    Ok(())
}

async fn storage_entry<PeerId>(
    file_system: &FileSystem<PeerId>,
    entry: Entry<PeerId>,
) -> Result<StorageEntry, StorageServiceError>
where
    PeerId: Clone + fmt::Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let size = if entry.meta.kind == FileKind::File {
        file_system
            .read(&entry.path)
            .await
            .map_err(StorageServiceError::FileSystem)?
            .len() as u64
    } else {
        0
    };
    Ok(StorageEntry {
        name: entry.path,
        hash: entry.meta.revision.to_string(),
        size,
        local: entry.meta.local,
    })
}

#[derive(Debug)]
pub enum StorageServiceError {
    FileSystem(file_system::Error),
    Scope(String),
}

impl StorageServiceError {
    fn response(self) -> StorageResponse {
        StorageResponse::Error {
            code: StorageErrorCode::OperationFailed,
        }
    }
}

impl fmt::Display for StorageServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem(error) => error.fmt(formatter),
            Self::Scope(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for StorageServiceError {}

#[cfg(test)]
mod tests {
    use std::{env, fs, sync::Arc};

    use file_system::{FileSystem, Residency};
    use storage_model::{StorageRequest, StorageResponse};

    use super::StorageService;

    #[tokio::test]
    async fn dispatches_scoped_file_system_operations() {
        let root = env::temp_dir().join(format!("storage-service-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let file_system = Arc::new(FileSystem::open(&root, 1_u8).unwrap());
        file_system
            .set_residency("", Residency::Full)
            .await
            .unwrap();
        let service = StorageService::new(Arc::clone(&file_system));

        assert!(matches!(
            service
                .execute(StorageRequest::Write {
                    path: "notes/today.txt".into(),
                    content: b"hello".to_vec()
                })
                .await,
            Ok(StorageResponse::Written { .. })
        ));
        assert_eq!(
            service
                .execute(StorageRequest::Read {
                    path: "notes/today.txt".into()
                })
                .await
                .unwrap(),
            StorageResponse::Read {
                content: b"hello".to_vec()
            }
        );
        assert!(matches!(
            service
                .execute(StorageRequest::Append {
                    path: "notes/today.txt".into(),
                    content: b"!".to_vec()
                })
                .await,
            Ok(StorageResponse::Appended { .. })
        ));
        assert_eq!(
            service
                .execute(StorageRequest::Read {
                    path: "notes/today.txt".into()
                })
                .await
                .expect("read appended file"),
            StorageResponse::Read {
                content: b"hello!".to_vec()
            }
        );
        assert!(matches!(
            service
                .execute(StorageRequest::CreateDir {
                    path: "notes/sub".into()
                })
                .await,
            Ok(StorageResponse::DirectoryCreated { .. })
        ));
        assert!(matches!(
            service
                .execute(StorageRequest::Entry {
                    path: "notes/sub".into()
                })
                .await,
            Ok(StorageResponse::Entry { entry }) if entry.size == 0
        ));
        assert!(matches!(
            service
                .execute(StorageRequest::Rename {
                    from: "notes/today.txt".into(),
                    to: "notes/renamed.txt".into()
                })
                .await,
            Ok(StorageResponse::Renamed)
        ));
        assert!(matches!(
            service
                .execute(StorageRequest::List {
                    path: "notes".into()
                })
                .await,
            Ok(StorageResponse::Listed { entries }) if entries.len() == 2
        ));
        assert!(service.stream("notes/renamed.txt", 1).await.is_ok());
        assert!(matches!(
            service
                .execute(StorageRequest::Delete {
                    path: "notes/renamed.txt".into()
                })
                .await,
            Ok(StorageResponse::Deleted)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn passthrough_rejects_writes() {
        let root = env::temp_dir().join(format!(
            "storage-service-passthrough-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let service = StorageService::new(Arc::new(FileSystem::open(&root, 1_u8).unwrap()));
        assert!(
            service
                .execute(StorageRequest::Write {
                    path: "note.txt".into(),
                    content: Vec::new()
                })
                .await
                .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }
}
