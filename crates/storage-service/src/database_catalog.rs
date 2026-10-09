use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use storage_model::{ResourceCatalog, ResourceIdentity, ResourceKind, StorageNamespace};

pub type DatabaseId = idp_model::model::Id;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, utoipa::ToSchema)]
pub struct DatabaseResource {
    #[schema(value_type = String)]
    pub id: DatabaseId,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CatalogRecord {
    resource: DatabaseResource,
    deleted: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct Catalog {
    records: BTreeMap<DatabaseId, CatalogRecord>,
}

pub struct DatabaseCatalog {
    root: PathBuf,
    lock: Mutex<()>,
}

impl DatabaseCatalog {
    pub fn new(root: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            lock: Mutex::new(()),
        })
    }

    pub(crate) fn owner_resources(
        &self,
        owner: &str,
    ) -> io::Result<Vec<(idp_model::model::Id, DatabaseId)>> {
        catalog_path(
            &self.root,
            &crate::local_copy::CopyScope(owner.to_owned(), DatabaseId::now_v7()),
        )?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let applications = match fs::read_dir(self.root.join("databases").join(owner)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut resources = Vec::new();
        for application in applications {
            let application = application?;
            if !application.file_type()?.is_dir() {
                continue;
            }
            let app = application
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid catalog Application")
                })?;
            let catalog = read_catalog(&catalog_path(
                &self.root,
                &crate::local_copy::CopyScope(owner.to_owned(), app),
            )?)?;
            resources.extend(catalog.records.into_keys().map(|id| (app, id)));
        }
        Ok(resources)
    }

    pub fn create<S: StorageNamespace>(
        &self,
        scope: &S,
        name: Option<String>,
    ) -> io::Result<DatabaseResource> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let path = catalog_path(&self.root, scope)?;
        let mut catalog = read_catalog(&path)?;
        let resource = DatabaseResource {
            id: DatabaseId::now_v7(),
            name,
        };
        catalog.records.insert(
            resource.id,
            CatalogRecord {
                resource: resource.clone(),
                deleted: false,
            },
        );
        write_catalog(&path, &catalog)?;
        Ok(resource)
    }

    pub fn list<S: StorageNamespace>(&self, scope: &S) -> io::Result<Vec<DatabaseResource>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let catalog = read_catalog(&catalog_path(&self.root, scope)?)?;
        Ok(catalog
            .records
            .into_values()
            .filter(|record| !record.deleted)
            .map(|record| record.resource)
            .collect())
    }

    pub fn register_selected<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<bool> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let path = catalog_path(&self.root, scope)?;
        let mut catalog = read_catalog(&path)?;
        if let Some(record) = catalog.records.get(&id) {
            return Ok(!record.deleted);
        }
        let resource = DatabaseResource { id, name: None };
        catalog.records.insert(
            id,
            CatalogRecord {
                resource,
                deleted: false,
            },
        );
        write_catalog(&path, &catalog)?;
        Ok(true)
    }

    pub fn get<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<Option<DatabaseResource>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let catalog = read_catalog(&catalog_path(&self.root, scope)?)?;
        Ok(catalog
            .records
            .get(&id)
            .filter(|record| !record.deleted)
            .map(|record| record.resource.clone()))
    }

    pub fn delete<S: StorageNamespace>(&self, scope: &S, id: DatabaseId) -> io::Result<bool> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let path = catalog_path(&self.root, scope)?;
        let mut catalog = read_catalog(&path)?;
        let Some(record) = catalog
            .records
            .get_mut(&id)
            .filter(|record| !record.deleted)
        else {
            return Ok(false);
        };
        record.deleted = true;
        write_catalog(&path, &catalog)?;
        Ok(true)
    }

    pub fn apply_tombstone<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let path = catalog_path(&self.root, scope)?;
        let mut catalog = read_catalog(&path)?;
        if catalog
            .records
            .get(&id)
            .is_some_and(|record| record.deleted)
        {
            return Ok(());
        }
        let record = catalog.records.entry(id).or_insert_with(|| CatalogRecord {
            resource: DatabaseResource { id, name: None },
            deleted: true,
        });
        record.deleted = true;
        write_catalog(&path, &catalog)?;
        Ok(())
    }

    pub fn is_tombstoned<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<bool> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("database catalog lock poisoned"))?;
        let catalog = read_catalog(&catalog_path(&self.root, scope)?)?;
        Ok(catalog
            .records
            .get(&id)
            .is_some_and(|record| record.deleted))
    }
}

impl ResourceCatalog for DatabaseCatalog {
    fn contains(
        &self,
        namespace: &dyn StorageNamespace,
        resource: &ResourceIdentity,
    ) -> Result<bool, String> {
        if resource.kind != ResourceKind::Database {
            return Ok(false);
        }
        let Ok(id) = resource.id.parse::<DatabaseId>() else {
            return Ok(false);
        };
        self.get(&NamespaceRef(namespace), id)
            .map(|entry| entry.is_some())
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

fn catalog_path(root: &Path, scope: &impl StorageNamespace) -> io::Result<PathBuf> {
    let subject = scope.user_sub();
    if subject.is_empty()
        || matches!(subject, "." | "..")
        || !subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || scope.application_id().is_nil()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid storage namespace",
        ));
    }
    Ok(root
        .join("databases")
        .join(subject)
        .join(scope.application_id().to_string())
        .join("catalog.json"))
}

fn read_catalog(path: &Path) -> io::Result<Catalog> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Catalog::default()),
        Err(error) => Err(error),
    }
}

fn write_catalog(path: &Path, catalog: &Catalog) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("catalog path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temp_path = path.with_extension(format!("{}.tmp", DatabaseId::now_v7()));
    let bytes = serde_json::to_vec(catalog)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = File::create(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temp_path, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use storage_model::{ResourceCatalog, ResourceIdentity, ResourceKind, StorageNamespace};

    use super::DatabaseCatalog;

    #[derive(Clone, Copy)]
    struct Scope {
        subject: &'static str,
        application: idp_model::model::Id,
    }

    impl StorageNamespace for Scope {
        fn user_sub(&self) -> &str {
            self.subject
        }

        fn application_id(&self) -> idp_model::model::Id {
            self.application
        }
    }

    #[test]
    fn resources_are_isolated_persistent_and_tombstoned() {
        let root = std::env::temp_dir().join(format!(
            "database-catalog-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "subject-a",
            application: idp_model::model::Id::now_v7(),
        };
        let other_subject = Scope {
            subject: "subject-b",
            ..scope
        };
        let other_application = Scope {
            application: idp_model::model::Id::now_v7(),
            ..scope
        };
        let catalog = DatabaseCatalog::new(root.clone()).expect("catalog root is created");
        let first = catalog
            .create(&scope, Some("same name".into()))
            .expect("first resource is created");
        let second = catalog
            .create(&scope, Some("same name".into()))
            .expect("second resource is created");
        assert_ne!(first.id, second.id);
        let first_identity = ResourceIdentity {
            kind: ResourceKind::Database,
            id: first.id.to_string(),
        };
        assert!(
            catalog
                .contains(&scope, &first_identity)
                .expect("catalog lookup works")
        );
        assert!(
            !catalog
                .contains(&other_subject, &first_identity)
                .expect("foreign lookup works")
        );
        assert!(
            !catalog
                .contains(
                    &scope,
                    &ResourceIdentity {
                        kind: ResourceKind::FileSystem,
                        id: first.id.to_string(),
                    },
                )
                .expect("cross-kind lookup works")
        );
        assert!(
            catalog
                .list(&other_subject)
                .expect("other subject lists")
                .is_empty()
        );
        assert!(
            catalog
                .list(&other_application)
                .expect("other application lists")
                .is_empty()
        );
        drop(catalog);

        let catalog = DatabaseCatalog::new(root.clone()).expect("catalog reopens");
        assert_eq!(
            catalog
                .list(&scope)
                .expect("resources list after restart")
                .len(),
            2
        );
        assert!(
            catalog
                .delete(&scope, first.id)
                .expect("resource tombstones")
        );
        assert!(
            catalog
                .get(&scope, first.id)
                .expect("lookup succeeds")
                .is_none()
        );
        assert!(
            !catalog
                .delete(&scope, first.id)
                .expect("repeat delete succeeds")
        );
        assert_eq!(
            catalog.list(&scope).expect("live list succeeds"),
            vec![second]
        );
        drop(catalog);
        fs::remove_dir_all(root).expect("test catalog is removed");
    }

    #[test]
    fn imported_tombstone_blocks_late_resource_provisioning_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "database-catalog-imported-tombstone-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "subject-a",
            application: idp_model::model::Id::now_v7(),
        };
        let id = idp_model::model::Id::now_v7();
        let catalog = DatabaseCatalog::new(root.clone()).expect("catalog root is created");
        catalog
            .apply_tombstone(&scope, id)
            .expect("unknown resource tombstone imports");
        assert!(
            !catalog
                .register_selected(&scope, id)
                .expect("late selected-resource projection is rejected")
        );
        drop(catalog);

        let catalog = DatabaseCatalog::new(root.clone()).expect("catalog reopens");
        assert!(
            catalog
                .is_tombstoned(&scope, id)
                .expect("imported tombstone survives restart")
        );
        assert!(
            !catalog
                .register_selected(&scope, id)
                .expect("reselection cannot revive imported tombstone")
        );
        drop(catalog);
        fs::remove_dir_all(root).expect("test catalog is removed");
    }

    #[test]
    fn rejects_invalid_namespace_paths() {
        let root =
            std::env::temp_dir().join(format!("database-catalog-invalid-{}", std::process::id()));
        let catalog = DatabaseCatalog::new(root.clone()).expect("catalog root is created");
        let scope = Scope {
            subject: "../other",
            application: idp_model::model::Id::now_v7(),
        };
        assert!(catalog.list(&scope).is_err());
        fs::remove_dir_all(root).expect("test catalog is removed");
    }
}
