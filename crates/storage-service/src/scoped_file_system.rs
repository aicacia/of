use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};

use file_system::{
    CatalogEntry, FileSystem, FileSystemCatalog, FileSystemId, FileSystemResource, Residency,
};

use serde::{Serialize, de::DeserializeOwned};
use storage_model::StorageNamespace;
use storage_model::{ResourceCatalog, ResourceIdentity, ResourceKind};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StorageNamespaceId {
    user_sub: String,
    application_id: idp_model::model::Id,
}

impl StorageNamespace for StorageNamespaceId {
    fn user_sub(&self) -> &str {
        &self.user_sub
    }
    fn application_id(&self) -> idp_model::model::Id {
        self.application_id
    }
}

pub(crate) type ContentReader = Arc<
    dyn Fn(
            String,
            idp_model::model::Id,
            FileSystemId,
            String,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
        + Send
        + Sync,
>;

pub type ScopedFileSystem<PeerId> = FileSystem<PeerId>;
type ScopedResources<PeerId> =
    BTreeMap<(StorageNamespaceId, FileSystemId), Arc<ScopedFileSystem<PeerId>>>;

pub struct ScopedFileSystemRuntime<PeerId>
where
    PeerId: Clone + Debug + Ord + Serialize + DeserializeOwned + 'static,
{
    root: PathBuf,
    local_peer: PeerId,
    pub(crate) local_copies: Arc<crate::local_copy::LocalCopyPolicy>,
    pub(crate) content_reader: Arc<StdMutex<Option<ContentReader>>>,

    catalogs: StdMutex<BTreeMap<StorageNamespaceId, Arc<FileSystemCatalog>>>,
    resources: Mutex<ScopedResources<PeerId>>,
    copy_catalogs:
        StdMutex<BTreeMap<(StorageNamespaceId, FileSystemId, u64), Arc<FileSystemCatalog>>>,
}

impl<PeerId> ScopedFileSystemRuntime<PeerId>
where
    PeerId: Clone + Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(root: PathBuf, local_peer: PeerId) -> io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            local_copies: Arc::new(crate::local_copy::LocalCopyPolicy::new(
                root.join("filesystem-local-copies.json"),
            )),
            root,
            local_peer,
            content_reader: Arc::new(StdMutex::new(None)),

            catalogs: StdMutex::new(BTreeMap::new()),
            resources: Mutex::new(BTreeMap::new()),
            copy_catalogs: StdMutex::new(BTreeMap::new()),
        })
    }

    pub fn set_content_reader<F, U>(&self, reader: F) -> Result<(), String>
    where
        F: Fn(String, idp_model::model::Id, FileSystemId, String) -> U + Send + Sync + 'static,
        U: Future<Output = Result<Vec<u8>, String>> + Send + 'static,
    {
        *self
            .content_reader
            .lock()
            .map_err(|_| "content reader lock poisoned".to_owned())? =
            Some(Arc::new(move |owner, app, id, path| {
                Box::pin(reader(owner, app, id, path))
            }));
        Ok(())
    }

    pub async fn create_resource<S: StorageNamespace>(
        &self,
        scope: &S,
        name: Option<String>,
    ) -> Result<FileSystemResource, String> {
        let id = storage_namespace_id(scope)?;
        let _resources = self.resources.lock().await;
        self.local_copies
            .require_owner(scope.user_sub())
            .map_err(|error| error.to_string())?;
        self.catalog(&id)?
            .create(name)
            .map_err(|error| error.to_string())
    }

    pub async fn list_resources<S: StorageNamespace>(
        &self,
        scope: &S,
    ) -> Result<Vec<FileSystemResource>, String> {
        let id = storage_namespace_id(scope)?;
        self.catalog(&id)?.list().map_err(|error| error.to_string())
    }

    pub async fn delete_resource<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<bool, String> {
        let id = storage_namespace_id(scope)?;
        let mut resources = self.resources.lock().await;
        match self.catalog(&id)?.delete(resource_id) {
            Ok(()) => {
                resources.remove(&(id, resource_id));
                Ok(true)
            }
            Err(file_system::Error::NotFound) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }

    pub async fn apply_deletion_tombstone<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<(), String> {
        let id = storage_namespace_id(scope)?;
        self.catalog(&id)?
            .apply_tombstone(resource_id)
            .map_err(|error| error.to_string())?;
        self.resources.lock().await.remove(&(id, resource_id));
        Ok(())
    }

    pub async fn is_tombstoned<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<bool, String> {
        let id = storage_namespace_id(scope)?;
        Ok(self
            .catalog(&id)?
            .snapshot()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|entry| entry.resource.id == resource_id && entry.deleted))
    }

    pub fn require_local_copy<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<(), String> {
        storage_namespace_id(scope)?;
        self.local_copies
            .require_available(scope, resource_id.as_uuid())
            .map_err(|error| error.to_string())
    }

    pub async fn remove_local_copy<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<(), String> {
        let namespace = storage_namespace_id(scope)?;
        if !self
            .catalog(&namespace)?
            .snapshot()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|entry| entry.resource.id == resource_id)
        {
            return Err("unknown local filesystem resource".into());
        }
        self.local_copies
            .retire(scope, resource_id.as_uuid())
            .map_err(|error| error.to_string())?;
        if !self
            .local_copies
            .pending()
            .map_err(|error| error.to_string())?
            .contains(&(
                namespace.user_sub.clone(),
                namespace.application_id,
                resource_id.as_uuid(),
            ))
        {
            return Ok(());
        }
        let mut resources = self.resources.lock().await;
        if !self
            .local_copies
            .pending()
            .map_err(|error| error.to_string())?
            .contains(&(
                namespace.user_sub.clone(),
                namespace.application_id,
                resource_id.as_uuid(),
            ))
        {
            return Ok(());
        }
        self.copy_catalog(&namespace, resource_id)?
            .remove_managed_copy(resource_id)
            .await
            .map_err(|error| error.to_string())?;
        resources.remove(&(namespace, resource_id));
        self.local_copies
            .complete(scope, resource_id.as_uuid())
            .map_err(|error| error.to_string())
    }

    pub fn activate_owner(&self, owner: &str) -> Result<(), String> {
        self.local_copies
            .set_owner_retired(owner, false)
            .map_err(|error| error.to_string())
    }

    pub async fn remove_owner_copies(&self, owner: &str) -> Result<(), String> {
        storage_namespace_id(&crate::local_copy::CopyScope(
            owner.to_owned(),
            idp_model::model::Id::now_v7(),
        ))?;
        let catalogs = {
            let _resources = self.resources.lock().await;
            self.local_copies
                .set_owner_retired(owner, true)
                .map_err(|error| error.to_string())?;
            self.catalogs_on_disk()?
        };
        let mut result = Ok(());
        for (namespace, catalog) in catalogs {
            if namespace.user_sub != owner {
                continue;
            }
            for entry in catalog.snapshot().map_err(|error| error.to_string())? {
                let removal = self.remove_local_copy(&namespace, entry.resource.id).await;
                result = result.and(removal);
            }
        }
        result
    }

    pub async fn register_selected_resource<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<(), String> {
        let _resources = self.resources.lock().await;
        self.require_local_copy(scope, resource_id)?;
        let id = storage_namespace_id(scope)?;
        let catalog = self.catalog(&id)?;
        if let Some(entry) = catalog
            .snapshot()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|entry| entry.resource.id == resource_id)
        {
            return if entry.deleted {
                Err("selected filesystem has a local deletion tombstone".into())
            } else {
                catalog
                    .mark_projected_selected(resource_id)
                    .map_err(|error| error.to_string())?;
                Ok(())
            };
        }
        catalog
            .import_snapshot(&[CatalogEntry {
                resource: FileSystemResource {
                    id: resource_id,
                    name: None,
                },
                deleted: false,
            }])
            .map_err(|error| error.to_string())?;
        catalog
            .mark_projected(resource_id)
            .map_err(|error| error.to_string())
    }

    pub async fn remove_unselected_projected_resources(
        &self,
        selected: &[(String, idp_model::model::Id, FileSystemId)],
    ) -> Result<(), String> {
        let tracked = selected
            .iter()
            .map(|(owner, application_id, resource_id)| {
                (owner.clone(), *application_id, resource_id.as_uuid())
            })
            .collect::<Vec<_>>();
        match self.local_copies.reconcile_selected(&tracked) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return Err(error.to_string()),
        };
        let selected = selected
            .iter()
            .map(|(owner, application_id, resource_id)| {
                (
                    StorageNamespaceId {
                        user_sub: owner.clone(),
                        application_id: *application_id,
                    },
                    *resource_id,
                )
            })
            .collect::<BTreeSet<_>>();
        let catalogs = self.catalogs_on_disk()?;

        for (namespace, catalog) in catalogs {
            for resource_id in catalog
                .projected_selected()
                .map_err(|error| error.to_string())?
            {
                if selected.contains(&(namespace.clone(), resource_id)) {
                    continue;
                }
                self.local_copies
                    .retire(&namespace, resource_id.as_uuid())
                    .map_err(|error| error.to_string())?;
            }
        }
        for (owner, app, id) in self
            .local_copies
            .pending()
            .map_err(|error| error.to_string())?
        {
            self.remove_local_copy(
                &crate::local_copy::CopyScope(owner, app),
                FileSystemId::parse(&id.to_string()).map_err(|error| error.to_string())?,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn set_resource_residency<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
        residency: Residency,
    ) -> Result<(), String> {
        let filesystem = self.open_resource(scope, resource_id).await?;
        self.local_copies
            .set_passthrough(
                scope,
                resource_id.as_uuid(),
                residency == Residency::Passthrough,
            )
            .map_err(|error| error.to_string())?;
        filesystem
            .set_residency("", residency)
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn open_resource<S: StorageNamespace>(
        &self,
        scope: &S,
        resource_id: FileSystemId,
    ) -> Result<Arc<ScopedFileSystem<PeerId>>, String> {
        self.require_local_copy(scope, resource_id)?;
        let id = storage_namespace_id(scope)?;
        let mut resources = self.resources.lock().await;
        self.require_local_copy(scope, resource_id)?;
        if let Some(file_system) = resources.get(&(id.clone(), resource_id)) {
            return Ok(Arc::clone(file_system));
        }
        let file_system = Arc::new(
            self.copy_catalog(&id, resource_id)?
                .open_filesystem(resource_id, self.local_peer.clone())
                .map_err(|error| error.to_string())?,
        );
        let residency = if self
            .local_copies
            .passthrough(scope, resource_id.as_uuid())
            .map_err(|error| error.to_string())?
        {
            Residency::Passthrough
        } else {
            Residency::Full
        };
        file_system
            .set_residency("", residency)
            .await
            .map_err(|error| error.to_string())?;
        resources.insert((id, resource_id), Arc::clone(&file_system));
        Ok(file_system)
    }

    fn copy_catalog(
        &self,
        namespace: &StorageNamespaceId,
        resource_id: FileSystemId,
    ) -> Result<Arc<FileSystemCatalog>, String> {
        let generation = self
            .local_copies
            .generation(namespace, resource_id.as_uuid())
            .map_err(|error| error.to_string())?;
        if generation == 0 {
            return self.catalog(namespace);
        }
        let mut catalogs = self
            .copy_catalogs
            .lock()
            .map_err(|_| "copy catalog lock poisoned".to_owned())?;
        let key = (namespace.clone(), resource_id, generation);
        let entry = self
            .catalog(namespace)?
            .snapshot()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|entry| entry.resource.id == resource_id)
            .ok_or_else(|| "unknown filesystem identity".to_owned())?;
        if let Some(catalog) = catalogs.get(&key) {
            catalog
                .import_snapshot(&[entry])
                .map_err(|error| error.to_string())?;
            return Ok(Arc::clone(catalog));
        }
        let root = namespace_root(&self.root, namespace)
            .join("copies")
            .join(resource_id.as_uuid().to_string())
            .join(generation.to_string());
        let catalog = Arc::new(FileSystemCatalog::open(root).map_err(|error| error.to_string())?);
        catalog
            .import_snapshot(&[entry])
            .map_err(|error| error.to_string())?;
        catalogs.insert(key, Arc::clone(&catalog));
        Ok(catalog)
    }

    fn catalogs_on_disk(
        &self,
    ) -> Result<Vec<(StorageNamespaceId, Arc<FileSystemCatalog>)>, String> {
        let root = self.root.join("filesystems");
        let subjects = match fs::read_dir(root) {
            Ok(subjects) => subjects,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
        };
        let mut catalogs = Vec::new();
        for subject in subjects {
            let subject = subject.map_err(|error| error.to_string())?;
            if !subject
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                continue;
            }
            let Some(user_sub) = subject.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            for application in fs::read_dir(subject.path()).map_err(|error| error.to_string())? {
                let application = application.map_err(|error| error.to_string())?;
                if !application
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_dir()
                {
                    continue;
                }
                let Ok(application_id) = application.file_name().to_string_lossy().parse() else {
                    continue;
                };
                let namespace = StorageNamespaceId {
                    user_sub: user_sub.clone(),
                    application_id,
                };
                if application.path().join("filesystem-catalog.redb").is_file() {
                    catalogs.push((namespace.clone(), self.catalog(&namespace)?));
                }
            }
        }
        Ok(catalogs)
    }

    fn catalog(&self, id: &StorageNamespaceId) -> Result<Arc<FileSystemCatalog>, String> {
        let mut catalogs = self
            .catalogs
            .lock()
            .expect("filesystem catalog lock poisoned");
        if let Some(catalog) = catalogs.get(id) {
            return Ok(Arc::clone(catalog));
        }
        let catalog = Arc::new(
            FileSystemCatalog::open(namespace_root(&self.root, id))
                .map_err(|error| error.to_string())?,
        );
        catalogs.insert(id.clone(), Arc::clone(&catalog));
        Ok(catalog)
    }
}

impl<PeerId> ResourceCatalog for ScopedFileSystemRuntime<PeerId>
where
    PeerId: Clone + Debug + Ord + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    fn contains(
        &self,
        namespace: &dyn StorageNamespace,
        resource: &ResourceIdentity,
    ) -> Result<bool, String> {
        if resource.kind != ResourceKind::FileSystem {
            return Ok(false);
        }
        let Ok(resource_id) = FileSystemId::parse(&resource.id) else {
            return Ok(false);
        };
        let id = storage_namespace_id(&NamespaceRef(namespace))?;
        self.catalog(&id)?
            .list()
            .map(|resources| resources.iter().any(|entry| entry.id == resource_id))
            .map_err(|error| error.to_string())
    }
}

struct NamespaceRef<'a>(&'a dyn StorageNamespace);

impl StorageNamespace for NamespaceRef<'_> {
    fn user_sub(&self) -> &str {
        self.0.user_sub()
    }

    fn application_id(&self) -> idp_model::model::Id {
        self.0.application_id()
    }
}

fn namespace_root(root: &std::path::Path, id: &StorageNamespaceId) -> PathBuf {
    root.join("filesystems")
        .join(&id.user_sub)
        .join(id.application_id.to_string())
}

fn storage_namespace_id(scope: &impl StorageNamespace) -> Result<StorageNamespaceId, String> {
    let user_sub = scope.user_sub();
    if user_sub.is_empty()
        || matches!(user_sub, "." | "..")
        || !user_sub
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid user subject".to_owned());
    }
    if scope.application_id().is_nil() {
        return Err("invalid application id".to_owned());
    }
    Ok(StorageNamespaceId {
        user_sub: user_sub.to_owned(),
        application_id: scope.application_id(),
    })
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use storage_model::{ResourceCatalog, ResourceIdentity, ResourceKind, StorageNamespace};

    use super::{ScopedFileSystemRuntime, storage_namespace_id};

    struct Namespace {
        user_sub: &'static str,
        application_id: idp_model::model::Id,
    }

    impl StorageNamespace for Namespace {
        fn user_sub(&self) -> &str {
            self.user_sub
        }

        fn application_id(&self) -> idp_model::model::Id {
            self.application_id
        }
    }

    #[test]
    fn rejects_path_traversal_subjects() {
        for user_sub in [".", ".."] {
            let namespace = Namespace {
                user_sub,
                application_id: idp_model::model::Id::now_v7(),
            };
            assert!(storage_namespace_id(&namespace).is_err());
        }
    }

    #[tokio::test]
    async fn registers_selected_resource_without_overriding_a_tombstone() {
        let root = env::temp_dir().join(format!(
            "selected-filesystem-runtime-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let namespace = Namespace {
            user_sub: "user",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime opens");
        let selected_id = file_system::FileSystemId::new();
        runtime
            .register_selected_resource(&namespace, selected_id)
            .await
            .expect("selected resource is registered");
        assert!(
            runtime
                .contains(
                    &namespace,
                    &ResourceIdentity {
                        kind: ResourceKind::FileSystem,
                        id: selected_id.as_uuid().to_string(),
                    },
                )
                .expect("selected resource is in the namespace catalog")
        );
        runtime
            .open_resource(&namespace, selected_id)
            .await
            .expect("selected filesystem opens");
        runtime
            .delete_resource(&namespace, selected_id)
            .await
            .expect("selected filesystem tombstones");
        assert!(
            runtime
                .register_selected_resource(&namespace, selected_id)
                .await
                .is_err(),
            "a selected-resource projection cannot revive a local tombstone"
        );
        drop(runtime);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn imported_deletion_tombstone_survives_runtime_restart() {
        let root = env::temp_dir().join(format!(
            "filesystem-tombstone-runtime-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let namespace = Namespace {
            user_sub: "user",
            application_id: idp_model::model::Id::now_v7(),
        };
        let resource_id = file_system::FileSystemId::new();
        {
            let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime opens");
            runtime
                .register_selected_resource(&namespace, resource_id)
                .await
                .expect("resource projection registers");
            runtime
                .apply_deletion_tombstone(&namespace, resource_id)
                .await
                .expect("remote deletion tombstone applies");
        }
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime reopens");
        assert!(
            runtime
                .list_resources(&namespace)
                .await
                .expect("catalog lists resources")
                .iter()
                .all(|resource| resource.id != resource_id),
            "deleted filesystem stays absent after restart"
        );
        assert!(
            runtime
                .register_selected_resource(&namespace, resource_id)
                .await
                .is_err(),
            "selection cannot revive a replicated tombstone"
        );
        drop(runtime);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn retirement_reselection_preserves_id_but_revokes_old_scoped_session() {
        let root =
            env::temp_dir().join(format!("fs-generation-{}", idp_model::model::Id::now_v7()));
        let scope = Namespace {
            user_sub: "owner",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime");
        let resource = runtime
            .create_resource(&scope, Some("stable".into()))
            .await
            .expect("create");
        let old = runtime
            .open_resource(&scope, resource.id)
            .await
            .expect("old owner");
        old.write("old.txt", b"old copy").await.expect("Full write");
        let session = crate::ScopedStorageService::open_resource(
            &runtime,
            Namespace {
                user_sub: "owner",
                application_id: scope.application_id,
            },
            resource.id,
        )
        .await
        .expect("retained scoped session");
        runtime
            .remove_unselected_projected_resources(&[(
                "owner".into(),
                scope.application_id,
                resource.id,
            )])
            .await
            .expect("observe selection");
        runtime
            .remove_unselected_projected_resources(&[])
            .await
            .expect("public owner cleanup succeeds with live handles");
        assert!(old.write("denied.txt", b"no").await.is_err());
        assert!(runtime.open_resource(&scope, resource.id).await.is_err());
        runtime
            .remove_unselected_projected_resources(&[(
                "owner".into(),
                scope.application_id,
                resource.id,
            )])
            .await
            .expect("later trusted reselection");
        let fresh = runtime
            .open_resource(&scope, resource.id)
            .await
            .expect("fresh generation");
        fresh
            .write("new.txt", b"new copy")
            .await
            .expect("fresh owner writes");
        assert!(
            session
                .execute(storage_model::StorageRequest::Write {
                    path: "resurrect.txt".into(),
                    content: b"no".to_vec()
                })
                .await
                .is_err(),
            "old scoped session cannot follow new generation"
        );
        assert_eq!(
            runtime
                .list_resources(&scope)
                .await
                .expect("stable catalog"),
            vec![resource.clone()]
        );
        drop(fresh);
        drop(old);
        drop(session);
        drop(runtime);
        let reopened = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("restart");
        let fresh = reopened
            .open_resource(&scope, resource.id)
            .await
            .expect("durable generation");
        assert_eq!(
            fresh.read("new.txt").await.expect("fresh content"),
            b"new copy"
        );
        assert!(fresh.read("old.txt").await.is_err());
        drop(fresh);
        drop(reopened);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[tokio::test]
    async fn cached_generation_rejects_reopen_after_local_deletion() {
        cached_generation_rejects_reopen_after_tombstone(false).await;
    }

    #[tokio::test]
    async fn cached_generation_rejects_reopen_after_learned_tombstone() {
        cached_generation_rejects_reopen_after_tombstone(true).await;
    }

    async fn cached_generation_rejects_reopen_after_tombstone(learned: bool) {
        let root = env::temp_dir().join(format!(
            "fs-generation-tombstone-{}",
            idp_model::model::Id::now_v7()
        ));
        let scope = Namespace {
            user_sub: "owner",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime opens");
        let resource = runtime
            .create_resource(&scope, Some("stable".into()))
            .await
            .expect("resource creates");
        runtime
            .open_resource(&scope, resource.id)
            .await
            .expect("original generation opens");
        let selected = [("owner".into(), scope.application_id, resource.id)];
        runtime
            .remove_unselected_projected_resources(&selected)
            .await
            .expect("selection observed");
        runtime
            .remove_unselected_projected_resources(&[])
            .await
            .expect("original generation retires");
        runtime
            .remove_unselected_projected_resources(&selected)
            .await
            .expect("later trusted reselection");
        let session = crate::ScopedStorageService::open_resource(
            &runtime,
            Namespace {
                user_sub: "owner",
                application_id: scope.application_id,
            },
            resource.id,
        )
        .await
        .expect("fresh scoped generation opens");
        session
            .execute(storage_model::StorageRequest::Write {
                path: "new.txt".into(),
                content: b"new copy".to_vec(),
            })
            .await
            .expect("fresh scoped generation writes");
        assert_eq!(
            runtime.list_resources(&scope).await.expect("live catalog"),
            vec![resource.clone()]
        );
        if learned {
            runtime
                .apply_deletion_tombstone(&scope, resource.id)
                .await
                .expect("learned Tombstone applies");
        } else {
            assert!(
                runtime
                    .delete_resource(&scope, resource.id)
                    .await
                    .expect("local deletion applies")
            );
        }
        assert!(
            crate::ScopedStorageService::open_resource(
                &runtime,
                Namespace {
                    user_sub: "owner",
                    application_id: scope.application_id,
                },
                resource.id,
            )
            .await
            .is_err(),
            "authoritative Tombstone denies a cached-generation scoped reopen"
        );
        assert!(runtime.open_resource(&scope, resource.id).await.is_err());
        assert!(
            runtime
                .list_resources(&scope)
                .await
                .expect("deleted catalog lists")
                .is_empty()
        );
        assert!(
            runtime
                .is_tombstoned(&scope, resource.id)
                .await
                .expect("logical ID retains its Tombstone")
        );
        assert!(
            runtime
                .register_selected_resource(&scope, resource.id)
                .await
                .is_err(),
            "selection cannot revive the logical ID"
        );
        runtime
            .remove_local_copy(&scope, resource.id)
            .await
            .expect("tombstoned generation still permits managed-copy cleanup");
        drop(session);
        drop(runtime);
        let restarted = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime restarts");
        assert!(
            restarted
                .is_tombstoned(&scope, resource.id)
                .await
                .expect("Tombstone survives restart")
        );
        assert!(restarted.open_resource(&scope, resource.id).await.is_err());
        drop(restarted);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[tokio::test]
    async fn passthrough_domain_read_requires_peer_even_when_old_content_is_cached() {
        let root = env::temp_dir().join(format!(
            "cached-passthrough-{}",
            idp_model::model::Id::now_v7()
        ));
        let scope = Namespace {
            user_sub: "owner",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime");
        let resource = runtime
            .create_resource(&scope, None)
            .await
            .expect("catalog");
        let owner = runtime
            .open_resource(&scope, resource.id)
            .await
            .expect("owner");
        owner
            .write("cached.txt", b"must not fall back")
            .await
            .expect("Full content");
        runtime
            .set_resource_residency(&scope, resource.id, file_system::Residency::Passthrough)
            .await
            .expect("local choice");
        let session = crate::ScopedStorageService::open_resource(&runtime, scope, resource.id)
            .await
            .expect("scoped session");
        assert!(
            session
                .execute(storage_model::StorageRequest::Read {
                    path: "cached.txt".into()
                })
                .await
                .is_err(),
            "Passthrough requires a reachable authorized Full peer, not local cached bytes"
        );
        drop(session);
        drop(owner);
        drop(runtime);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[tokio::test]
    async fn passthrough_resource_stays_read_only_after_offline_restart() {
        let root = env::temp_dir().join(format!(
            "passthrough-resource-{}",
            idp_model::model::Id::now_v7()
        ));
        let scope = Namespace {
            user_sub: "owner",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime");
        let resource = runtime
            .create_resource(&scope, None)
            .await
            .expect("resource");
        let filesystem = runtime
            .open_resource(&scope, resource.id)
            .await
            .expect("Full copy");
        filesystem
            .write("local.txt", b"local")
            .await
            .expect("Full writes");
        runtime
            .set_resource_residency(&scope, resource.id, file_system::Residency::Passthrough)
            .await
            .expect("local residency choice");
        assert!(filesystem.write("denied.txt", b"no").await.is_err());
        drop(filesystem);
        drop(runtime);
        let reopened = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("offline reopen");
        let filesystem = reopened
            .open_resource(&scope, resource.id)
            .await
            .expect("Passthrough copy");
        assert_eq!(
            filesystem.residency("").expect("persisted residency"),
            file_system::Residency::Passthrough
        );
        assert!(filesystem.write("denied.txt", b"no").await.is_err());
        assert!(
            filesystem.read("local.txt").await.is_err(),
            "no reachable Full peer; do not pretend cached content is available"
        );
        drop(filesystem);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[tokio::test]
    async fn deselection_retires_projected_and_created_copies_without_tombstones() {
        let root = env::temp_dir().join(format!(
            "deselected-filesystem-runtime-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let namespace = Namespace {
            user_sub: "user",
            application_id: idp_model::model::Id::now_v7(),
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime opens");
        let projected_id = file_system::FileSystemId::new();
        runtime
            .register_selected_resource(&namespace, projected_id)
            .await
            .expect("selected resource is registered");
        let projected = runtime
            .open_resource(&namespace, projected_id)
            .await
            .expect("projected filesystem opens");
        projected
            .write("cached.txt", b"local copy")
            .await
            .expect("write projected content");
        let projected_root = root
            .join("filesystems")
            .join(namespace.user_sub)
            .join(namespace.application_id.to_string())
            .join("filesystems")
            .join(projected_id.as_uuid().to_string());
        assert!(projected_root.exists());
        let session = crate::ScopedStorageService::open_resource(
            &runtime,
            Namespace {
                user_sub: namespace.user_sub,
                application_id: namespace.application_id,
            },
            projected_id,
        )
        .await
        .expect("open domain session before deselection");

        runtime
            .remove_unselected_projected_resources(&[])
            .await
            .expect("public owner drains and retires active handles");
        assert!(
            session
                .execute(storage_model::StorageRequest::Write {
                    path: "denied.txt".into(),
                    content: b"deny".to_vec()
                })
                .await
                .is_err(),
            "issued domain session must not continue after retirement"
        );
        assert!(!projected_root.exists(), "public owner removed content");
        drop(projected);

        runtime
            .remove_unselected_projected_resources(&[])
            .await
            .expect("completed cleanup is idempotent");
        assert!(!projected_root.exists());
        assert_eq!(
            runtime
                .list_resources(&namespace)
                .await
                .expect("projection identity remains in catalog")
                .len(),
            1
        );
        assert!(
            runtime
                .open_resource(&namespace, projected_id)
                .await
                .is_err()
        );
        runtime
            .register_selected_resource(&namespace, projected_id)
            .await
            .expect_err("reselection cannot bypass pending cleanup");

        let local = runtime
            .create_resource(&namespace, Some("local".into()))
            .await
            .expect("create local resource");
        let local_fs = runtime
            .open_resource(&namespace, local.id)
            .await
            .expect("local resource opens");
        local_fs
            .write("local.txt", b"keep")
            .await
            .expect("write owner content");
        let local_root = root
            .join("filesystems")
            .join(namespace.user_sub)
            .join(namespace.application_id.to_string())
            .join("filesystems")
            .join(local.id.as_uuid().to_string());
        runtime
            .remove_unselected_projected_resources(&[])
            .await
            .expect("unrelated never-selected copy survives");
        assert!(local_root.exists());

        runtime
            .remove_local_copy(&namespace, local.id)
            .await
            .expect("locally created copy is retired through owner");
        assert!(runtime.open_resource(&namespace, local.id).await.is_err());
        drop(local_fs);
        drop(session);
        drop(runtime);
        let reopened = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("offline restart");
        assert!(
            reopened
                .open_resource(&namespace, projected_id)
                .await
                .is_err()
        );
        assert!(reopened.open_resource(&namespace, local.id).await.is_err());
        drop(reopened);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn manages_multiple_resources_per_namespace_and_blocks_deleted_opens() {
        let root = env::temp_dir().join(format!("storage-resource-runtime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let application_id = idp_model::model::Id::now_v7();
        let namespace = Namespace {
            user_sub: "user",
            application_id,
        };
        let runtime = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime opens");
        let first = runtime
            .create_resource(&namespace, Some("same".into()))
            .await
            .expect("first resource is created");
        let second = runtime
            .create_resource(&namespace, Some("same".into()))
            .await
            .expect("second resource is created");
        assert_ne!(first.id, second.id);
        let identity = ResourceIdentity {
            kind: ResourceKind::FileSystem,
            id: first.id.as_uuid().to_string(),
        };
        assert!(
            runtime
                .contains(&namespace, &identity)
                .expect("catalog lookup works")
        );

        assert!(
            !runtime
                .contains(
                    &namespace,
                    &ResourceIdentity {
                        kind: ResourceKind::Database,
                        id: identity.id.clone(),
                    },
                )
                .expect("cross-kind lookup works")
        );
        assert_eq!(
            runtime
                .list_resources(&namespace)
                .await
                .expect("resources list"),
            vec![first.clone(), second]
        );

        let first_fs = runtime
            .open_resource(&namespace, first.id)
            .await
            .expect("first filesystem opens");
        let other_namespace = Namespace {
            user_sub: "other",
            application_id,
        };
        assert!(
            !runtime
                .contains(&other_namespace, &identity)
                .expect("foreign lookup works")
        );
        assert!(
            runtime
                .open_resource(&other_namespace, first.id)
                .await
                .is_err()
        );
        assert!(
            runtime
                .delete_resource(&namespace, first.id)
                .await
                .expect("resource deletes")
        );
        assert!(runtime.open_resource(&namespace, first.id).await.is_err());
        assert!(first_fs.list("").await.is_ok());
        drop(first_fs);
        drop(runtime);

        let reopened = ScopedFileSystemRuntime::new(root.clone(), 1_u8).expect("runtime reopens");
        assert_eq!(
            reopened
                .list_resources(&namespace)
                .await
                .expect("catalog reopens")
                .len(),
            1
        );
        let _ = fs::remove_dir_all(root);
    }
}
