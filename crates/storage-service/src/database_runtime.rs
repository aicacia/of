use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ofdb_kv::Database as KvDatabase;
use ofdb_sql::Database;
use storage_model::StorageNamespace;

use crate::{DatabaseCatalog, DatabaseId, DatabaseResource};

type DatabaseKey = (String, idp_model::model::Id, DatabaseId);
type KvStores = BTreeMap<DatabaseKey, Arc<KvDatabase>>;

pub struct DatabaseRuntime {
    root: PathBuf,
    catalog: DatabaseCatalog,
    local_copies: crate::local_copy::LocalCopyPolicy,
    open: Mutex<BTreeMap<(String, idp_model::model::Id, DatabaseId), Arc<Database>>>,
    kv_open: Mutex<KvStores>,
    cleanup: tokio::sync::Mutex<()>,
}

impl DatabaseRuntime {
    pub fn new(root: PathBuf) -> io::Result<Self> {
        Ok(Self {
            catalog: DatabaseCatalog::new(root.clone())?,
            local_copies: crate::local_copy::LocalCopyPolicy::new(
                root.join("database-local-copies.json"),
            ),
            root,
            open: Mutex::new(BTreeMap::new()),
            kv_open: Mutex::new(BTreeMap::new()),
            cleanup: tokio::sync::Mutex::new(()),
        })
    }

    pub fn create<S: StorageNamespace>(
        &self,
        scope: &S,
        name: Option<String>,
    ) -> io::Result<(DatabaseResource, Arc<Database>)> {
        let mut open = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
        self.local_copies.require_owner(scope.user_sub())?;
        let resource = self.catalog.create(scope, name)?;
        let path = self.copy_path(scope, resource.id)?;
        match Database::open(&path) {
            Ok(database) => {
                let database = Arc::new(database);
                open.insert(database_key(scope, resource.id), Arc::clone(&database));
                Ok((resource, database))
            }
            Err(error) => {
                self.catalog.delete(scope, resource.id)?;
                Err(io::Error::other(error.to_string()))
            }
        }
    }

    pub fn list<S: StorageNamespace>(&self, scope: &S) -> io::Result<Vec<DatabaseResource>> {
        self.catalog.list(scope)
    }

    pub fn get<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<Option<DatabaseResource>> {
        self.catalog.get(scope, id)
    }

    pub fn delete<S: StorageNamespace>(&self, scope: &S, id: DatabaseId) -> io::Result<bool> {
        let mut open = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
        let deleted = self.catalog.delete(scope, id)?;
        if deleted {
            self.evict(scope, id, &mut open)?;
        }
        Ok(deleted)
    }

    pub fn apply_tombstone<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<()> {
        let mut open = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
        self.catalog.apply_tombstone(scope, id)?;
        self.evict(scope, id, &mut open)
    }

    pub fn is_tombstoned<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<bool> {
        self.catalog.is_tombstoned(scope, id)
    }

    fn evict<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
        open: &mut BTreeMap<DatabaseKey, Arc<Database>>,
    ) -> io::Result<()> {
        let key = database_key(scope, id);
        open.remove(&key);
        self.kv_open
            .lock()
            .map_err(|_| io::Error::other("database KV runtime lock poisoned"))?
            .remove(&key);
        Ok(())
    }

    /// Requires the current trusted local Device selection, not handshake claims.
    pub async fn reconcile_selected_copies(
        &self,
        selected: &[(String, idp_model::model::Id, DatabaseId)],
    ) -> io::Result<()> {
        match self.local_copies.reconcile_selected(selected) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return Err(error),
        }
        for (owner, app, id) in self.local_copies.pending()? {
            self.remove_local_copy(&crate::local_copy::CopyScope(owner, app), id)
                .await?;
        }
        Ok(())
    }

    pub fn require_local_copy<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<()> {
        database_path(&self.root, scope, id)?;
        self.local_copies.require_available(scope, id)
    }

    pub async fn remove_local_copy<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<()> {
        let _cleanup = self.cleanup.lock().await;
        database_path(&self.root, scope, id)?;
        if self.catalog.get(scope, id)?.is_none() && !self.catalog.is_tombstoned(scope, id)? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown local database resource",
            ));
        }
        self.local_copies.retire(scope, id)?;
        if !self
            .local_copies
            .pending()?
            .contains(&database_key(scope, id))
        {
            return Ok(());
        }
        let key = database_key(scope, id);
        let path = self.copy_path(scope, id)?;
        let database = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?
            .get(&key)
            .cloned();
        if let Some(database) = database {
            database.retire_and_remove().await?;
        } else if retirement_marker(&path).exists() {
            Database::remove_retired(&path)?;
        } else if path.exists() {
            Database::open(&path)
                .map_err(|error| io::Error::other(error.to_string()))?
                .retire_and_remove()
                .await?;
        }
        let mut kv_path = path;
        kv_path.set_extension("kv.redb");
        let kv = self
            .kv_open
            .lock()
            .map_err(|_| io::Error::other("database KV runtime lock poisoned"))?
            .get(&key)
            .cloned();
        if let Some(kv) = kv {
            kv.retire_and_remove().await?;
        } else if retirement_marker(&kv_path).exists() {
            KvDatabase::remove_retired(&kv_path)?;
        } else if kv_path.exists() {
            KvDatabase::open_with_table(&kv_path, "kv")
                .map_err(|error| io::Error::other(error.to_string()))?
                .retire_and_remove()
                .await?;
        }
        {
            let mut open = self
                .open
                .lock()
                .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
            self.evict(scope, id, &mut open)?;
        }
        self.local_copies.complete(scope, id)
    }

    pub fn activate_owner(&self, owner: &str) -> io::Result<()> {
        self.local_copies.set_owner_retired(owner, false)
    }

    pub async fn remove_owner_copies(&self, owner: &str) -> io::Result<()> {
        let resources = {
            let _open = self
                .open
                .lock()
                .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
            let _kv = self
                .kv_open
                .lock()
                .map_err(|_| io::Error::other("database KV runtime lock poisoned"))?;
            self.local_copies.set_owner_retired(owner, true)?;
            self.catalog.owner_resources(owner)?
        };
        let mut result = Ok(());
        for (app, id) in resources {
            let removal = self
                .remove_local_copy(&crate::local_copy::CopyScope(owner.to_owned(), app), id)
                .await;
            result = result.and(removal);
        }
        result
    }

    fn copy_path(&self, scope: &impl StorageNamespace, id: DatabaseId) -> io::Result<PathBuf> {
        let path = database_path(&self.root, scope, id)?;
        let generation = self.local_copies.generation(scope, id)?;
        if generation == 0 {
            return Ok(path);
        }
        Ok(path
            .parent()
            .expect("database path has namespace parent")
            .join(format!("{id}.copies"))
            .join(generation.to_string())
            .join(format!("{id}.redb")))
    }

    pub fn open_selected<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<Option<Arc<Database>>> {
        self.require_local_copy(scope, id)?;
        let mut open = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
        self.require_local_copy(scope, id)?;
        if !self.catalog.register_selected(scope, id)? {
            return Ok(None);
        }
        let key = database_key(scope, id);
        if let Some(database) = open.get(&key) {
            return Ok(Some(Arc::clone(database)));
        }
        let path = self.copy_path(scope, id)?;
        std::fs::create_dir_all(path.parent().expect("copy path has parent"))?;
        let database = Arc::new(
            Database::open(path)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        );
        open.insert(key, Arc::clone(&database));
        Ok(Some(database))
    }

    pub fn open_kv_selected<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<Option<Arc<KvDatabase>>> {
        self.require_local_copy(scope, id)?;
        let mut open = self
            .kv_open
            .lock()
            .map_err(|_| io::Error::other("database KV runtime lock poisoned"))?;
        self.require_local_copy(scope, id)?;
        if !self.catalog.register_selected(scope, id)? {
            return Ok(None);
        }
        let key = database_key(scope, id);
        if let Some(store) = open.get(&key) {
            return Ok(Some(Arc::clone(store)));
        }
        let mut path = self.copy_path(scope, id)?;
        std::fs::create_dir_all(path.parent().expect("copy path has parent"))?;
        path.set_extension("kv.redb");
        let store = Arc::new(
            KvDatabase::open_with_table(path, "kv")
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        );
        open.insert(key, Arc::clone(&store));
        Ok(Some(store))
    }

    pub fn open<S: StorageNamespace>(
        &self,
        scope: &S,
        id: DatabaseId,
    ) -> io::Result<Option<Arc<Database>>> {
        self.require_local_copy(scope, id)?;
        let mut open = self
            .open
            .lock()
            .map_err(|_| io::Error::other("database runtime lock poisoned"))?;
        self.require_local_copy(scope, id)?;
        if self.catalog.get(scope, id)?.is_none() {
            return Ok(None);
        }
        let key = database_key(scope, id);
        if let Some(database) = open.get(&key) {
            return Ok(Some(Arc::clone(database)));
        }
        let path = self.copy_path(scope, id)?;
        std::fs::create_dir_all(path.parent().expect("copy path has parent"))?;
        let database = Arc::new(
            Database::open(path)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        );
        open.insert(key, Arc::clone(&database));
        Ok(Some(database))
    }
}

fn retirement_marker(path: &std::path::Path) -> PathBuf {
    let mut marker = path.as_os_str().to_owned();
    marker.push(".ofdb-retired");
    PathBuf::from(marker)
}

fn database_key(
    scope: &impl StorageNamespace,
    id: DatabaseId,
) -> (String, idp_model::model::Id, DatabaseId) {
    (scope.user_sub().to_owned(), scope.application_id(), id)
}

fn database_path(
    root: &std::path::Path,
    scope: &impl StorageNamespace,
    id: DatabaseId,
) -> io::Result<PathBuf> {
    if scope.user_sub().is_empty()
        || matches!(scope.user_sub(), "." | "..")
        || !scope
            .user_sub()
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
        .join(scope.user_sub())
        .join(scope.application_id().to_string())
        .join(format!("{id}.redb")))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ofdb_sql::SqlTranslator;
    use storage_model::StorageNamespace;

    use super::DatabaseRuntime;

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

    #[tokio::test]
    async fn local_copy_retirement_removes_both_phases_and_reselection_uses_fresh_generation() {
        let root = std::env::temp_dir().join(format!(
            "database-retirement-{}",
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "owner",
            application: idp_model::model::Id::now_v7(),
        };
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime");
        let (retired, handle) = runtime.create(&scope, None).expect("managed local copy");
        let (unrelated, other_handle) = runtime.create(&scope, None).expect("unrelated copy");
        let kv = runtime
            .open_kv_selected(&scope, retired.id)
            .expect("KV copy")
            .expect("KV owner");
        kv.client()
            .set("old", ofdb_kv::Value::Integer(1), None)
            .await
            .expect("KV source");
        runtime
            .reconcile_selected_copies(&[(scope.subject.to_owned(), scope.application, retired.id)])
            .await
            .expect("observe trusted selection without a peer");
        runtime
            .reconcile_selected_copies(&[])
            .await
            .expect("learned deselection retires managed copy");
        runtime
            .remove_local_copy(&scope, retired.id)
            .await
            .expect("public owners complete both phases");
        assert!(
            handle
                .client()
                .translate_and_execute("CREATE TABLE denied (id UUID PRIMARY KEY)", &SqlTranslator)
                .await
                .is_err(),
            "old owner handle is revoked"
        );
        assert!(
            kv.client().get("old").await.is_err(),
            "issued KV client revoked"
        );
        let old_path = super::database_path(&root, &scope, retired.id).expect("old path");
        assert!(!old_path.exists());
        assert!(!old_path.with_extension("kv.redb").exists());
        assert!(runtime.open(&scope, retired.id).is_err());
        assert!(runtime.open_selected(&scope, retired.id).is_err());
        assert!(runtime.open_kv_selected(&scope, retired.id).is_err());
        assert!(
            runtime
                .open(&scope, unrelated.id)
                .expect("unrelated survives")
                .is_some()
        );
        assert!(
            !runtime
                .is_tombstoned(&scope, retired.id)
                .expect("not global deletion")
        );
        drop(handle);
        drop(other_handle);
        drop(runtime);
        let reopened = DatabaseRuntime::new(root.clone()).expect("offline restart");
        assert!(reopened.open(&scope, retired.id).is_err());
        reopened
            .remove_local_copy(&scope, retired.id)
            .await
            .expect("completed retry is idempotent");
        reopened
            .reconcile_selected_copies(&[(scope.subject.to_owned(), scope.application, retired.id)])
            .await
            .expect("causally later trusted selection");
        let fresh = reopened
            .open_selected(&scope, retired.id)
            .expect("fresh copy generation")
            .expect("stable resource ID");
        fresh
            .client()
            .translate_and_execute("CREATE TABLE fresh (id UUID PRIMARY KEY)", &SqlTranslator)
            .await
            .expect("fresh generation works");
        drop(fresh);
        assert!(
            reopened
                .open(&scope, unrelated.id)
                .expect("unrelated restart")
                .is_some()
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[tokio::test]
    async fn transfer_cleanup_covers_created_copies_but_preserves_other_owner() {
        let root =
            std::env::temp_dir().join(format!("owner-cleanup-{}", idp_model::model::Id::now_v7()));
        let scope = Scope {
            subject: "old",
            application: idp_model::model::Id::now_v7(),
        };
        let other = Scope {
            subject: "other",
            application: scope.application,
        };
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime");
        let (old, old_handle) = runtime
            .create(&scope, None)
            .expect("created unselected old-owner copy");
        let (unrelated, other_handle) = runtime.create(&other, None).expect("other owner copy");
        runtime
            .remove_owner_copies("old")
            .await
            .expect("all covered old-owner copies retired");
        assert!(runtime.open(&scope, old.id).is_err());
        assert!(
            old_handle
                .client()
                .translate_and_execute("CREATE TABLE denied (id UUID PRIMARY KEY)", &SqlTranslator)
                .await
                .is_err()
        );
        assert!(
            runtime
                .open(&other, unrelated.id)
                .expect("other owner survives")
                .is_some()
        );
        assert_eq!(runtime.list(&scope).expect("catalog preserved"), vec![old]);
        assert!(
            runtime.create(&scope, None).is_err(),
            "learned old-owner fence denies new catalog admission"
        );
        let restarted = DatabaseRuntime::new(root.clone()).expect("offline restart");
        assert!(
            restarted.create(&scope, None).is_err(),
            "owner fence survives restart"
        );
        drop(restarted);
        drop(old_handle);
        drop(other_handle);
        drop(runtime);
        fs::remove_dir_all(root).expect("cleanup fixture");
    }

    #[tokio::test]
    async fn sql_phase_survives_kv_owner_failure_and_restart_retry() {
        let root =
            std::env::temp_dir().join(format!("phase-retry-{}", idp_model::model::Id::now_v7()));
        let scope = Scope {
            subject: "owner",
            application: idp_model::model::Id::now_v7(),
        };
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime");
        let (resource, sql) = runtime.create(&scope, None).expect("SQL copy");
        let sql_path =
            super::database_path(&root, &scope, resource.id).expect("dedicated SQL path");
        let kv_path = sql_path.with_extension("kv.redb");
        let foreign_kv = ofdb_kv::Database::open_with_table(&kv_path, "kv")
            .expect("separately issued native owner");
        runtime
            .reconcile_selected_copies(&[("owner".into(), scope.application, resource.id)])
            .await
            .expect("observe");
        runtime
            .reconcile_selected_copies(&[])
            .await
            .expect_err("KV live native owner prevents completion");
        assert!(
            !sql_path.exists(),
            "successful SQL phase is not rolled back"
        );
        assert!(kv_path.exists(), "failed KV phase is not falsely removed");
        assert!(runtime.open(&scope, resource.id).is_err());
        assert!(
            sql.client()
                .translate_and_execute("CREATE TABLE denied (id UUID PRIMARY KEY)", &SqlTranslator)
                .await
                .is_err()
        );
        runtime
            .reconcile_selected_copies(&[("owner".into(), scope.application, resource.id)])
            .await
            .expect_err("reselection while KV cleanup is pending");
        runtime
            .reconcile_selected_copies(&[])
            .await
            .expect_err("newer deselection wins pending reselection");
        drop(sql);
        drop(runtime);
        drop(foreign_kv);
        let reopened = DatabaseRuntime::new(root.clone()).expect("restart with pending intent");
        assert!(reopened.open(&scope, resource.id).is_err());
        reopened
            .reconcile_selected_copies(&[])
            .await
            .expect("owner-only retry completes remaining phase");
        assert!(!kv_path.exists());
        assert!(
            reopened.open(&scope, resource.id).is_err(),
            "pending reselection cancelled by newer deselection cannot reactivate"
        );
        reopened
            .reconcile_selected_copies(&[("owner".into(), scope.application, resource.id)])
            .await
            .expect("later selection after retry");
        let fresh = reopened
            .open_kv_selected(&scope, resource.id)
            .expect("fresh KV generation")
            .expect("KV");
        fresh
            .client()
            .set("new", ofdb_kv::Value::Integer(2), None)
            .await
            .expect("new generation usable");
        drop(fresh);
        drop(reopened);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn selected_resource_provisions_matching_id_without_reviving_tombstones() {
        let root = std::env::temp_dir().join(format!(
            "database-runtime-selected-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "owner",
            application: idp_model::model::Id::now_v7(),
        };
        let id = idp_model::model::Id::now_v7();
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime opens");
        assert!(
            runtime
                .open(&scope, id)
                .expect("unprovisioned resource lookup succeeds")
                .is_none()
        );
        let database = runtime
            .open_selected(&scope, id)
            .expect("selected resource opens")
            .expect("selected resource is provisioned");
        assert_eq!(
            runtime
                .list(&scope)
                .expect("catalog lists selected resource")[0]
                .id,
            id
        );
        assert!(runtime.delete(&scope, id).expect("resource tombstones"));
        assert!(
            runtime
                .open_selected(&scope, id)
                .expect("tombstoned resource lookup succeeds")
                .is_none()
        );
        drop(database);
        drop(runtime);
        fs::remove_dir_all(root).expect("test databases are removed");
    }

    #[tokio::test]
    async fn kv_sidecar_persists_across_runtime_reopen_and_deleted_resources_stay_tombstoned() {
        let root = std::env::temp_dir().join(format!(
            "database-runtime-kv-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "owner",
            application: idp_model::model::Id::now_v7(),
        };
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime opens");
        let (resource, _database) = runtime
            .create(&scope, Some("with-kv".into()))
            .expect("database creates");
        let kv_store = runtime
            .open_kv_selected(&scope, resource.id)
            .expect("KV sidecar opens")
            .expect("created resource remains available");
        let mut transaction = kv_store
            .client()
            .transaction()
            .await
            .expect("KV transaction opens");
        transaction
            .set("key", ofdb_kv::Value::Blob(vec![1, 2, 3]), None)
            .await
            .expect("KV value writes");
        transaction.commit().await.expect("KV value commits");
        drop(kv_store);
        drop(runtime);

        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime reopens");
        let kv_store = runtime
            .open_kv_selected(&scope, resource.id)
            .expect("persisted KV sidecar opens")
            .expect("resource remains selected");
        let mut transaction = kv_store
            .client()
            .transaction()
            .await
            .expect("reopened KV transaction opens");
        assert_eq!(
            transaction.get("key").await.expect("KV value reads"),
            Some(ofdb_kv::Value::Blob(vec![1, 2, 3]))
        );
        transaction
            .rollback()
            .await
            .expect("read transaction rolls back");
        assert!(
            runtime
                .delete(&scope, resource.id)
                .expect("resource tombstones")
        );
        drop(kv_store);
        drop(runtime);

        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime reopens after deletion");
        assert!(
            runtime
                .open_kv_selected(&scope, resource.id)
                .expect("tombstoned KV lookup succeeds")
                .is_none()
        );
        drop(runtime);
        fs::remove_dir_all(root).expect("test databases are removed");
    }

    #[tokio::test]
    async fn resources_open_independent_durable_engines() {
        let root = std::env::temp_dir().join(format!(
            "database-runtime-{}-{}",
            std::process::id(),
            idp_model::model::Id::now_v7()
        ));
        let scope = Scope {
            subject: "owner",
            application: idp_model::model::Id::now_v7(),
        };
        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime opens");
        let (first, first_db) = runtime
            .create(&scope, Some("db".into()))
            .expect("first database creates");
        let (second, second_db) = runtime
            .create(&scope, Some("db".into()))
            .expect("second database creates");
        assert_ne!(first.id, second.id);
        first_db
            .client()
            .translate_and_execute(
                "CREATE TABLE first_table (id UUID PRIMARY KEY)",
                &SqlTranslator,
            )
            .await
            .expect("first schema persists");
        second_db
            .client()
            .translate_and_execute(
                "CREATE TABLE second_table (id UUID PRIMARY KEY)",
                &SqlTranslator,
            )
            .await
            .expect("second schema persists independently");
        drop(runtime);
        drop(first_db);
        drop(second_db);

        let runtime = DatabaseRuntime::new(root.clone()).expect("runtime reopens");
        let other_subject = Scope {
            subject: "other",
            ..scope
        };
        assert!(
            runtime
                .open(&other_subject, first.id)
                .expect("foreign namespace lookup succeeds")
                .is_none()
        );
        let other_application = Scope {
            application: idp_model::model::Id::now_v7(),
            ..scope
        };
        assert!(
            runtime
                .open(&other_application, first.id)
                .expect("foreign Application lookup succeeds")
                .is_none()
        );
        let first_db = runtime
            .open(&scope, first.id)
            .expect("first database opens")
            .expect("first catalog record exists");
        let second_db = runtime
            .open(&scope, second.id)
            .expect("second database opens")
            .expect("second catalog record exists");
        assert!(
            first_db
                .client()
                .execute_sql("SELECT id FROM first_table", None)
                .await
                .expect("first table survives restart")[0]
                .rows
                .is_empty()
        );
        assert!(
            second_db
                .client()
                .execute_sql("SELECT id FROM first_table", None)
                .await
                .is_err()
        );
        assert!(
            second_db
                .client()
                .execute_sql("SELECT id FROM second_table", None)
                .await
                .expect("second table survives restart")[0]
                .rows
                .is_empty()
        );
        assert!(
            runtime
                .delete(&scope, first.id)
                .expect("first database deletes")
        );
        assert!(
            runtime
                .open(&scope, first.id)
                .expect("deleted database lookup succeeds")
                .is_none()
        );
        assert!(
            first_db
                .client()
                .execute_sql("SELECT id FROM first_table", None)
                .await
                .expect("an already-issued handle remains usable")[0]
                .rows
                .is_empty()
        );

        drop(runtime);
        drop(first_db);
        drop(second_db);
        fs::remove_dir_all(root).expect("test databases are removed");
    }
}
