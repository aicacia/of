use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
};

use idp_model::model::Id;
use serde::{Deserialize, Serialize};
use storage_model::StorageNamespace;

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CopyPolicy {
    pending: BTreeSet<(String, Id, Id)>,
    selected: BTreeSet<(String, Id, Id)>,
    passthrough: BTreeSet<(String, Id, Id)>,
}

pub(crate) struct LocalCopyPolicy {
    path: PathBuf,
    lock: Mutex<()>,
}

impl LocalCopyPolicy {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub(crate) fn require_available(
        &self,
        scope: &impl StorageNamespace,
        resource: Id,
    ) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        if self.read()?.pending.contains(&key(scope, resource)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local copy cleanup is incomplete",
            ));
        }
        Ok(())
    }

    pub(crate) fn reconcile_selected(&self, selected: &[(String, Id, Id)]) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        let selected = selected.iter().cloned().collect::<BTreeSet<_>>();
        let retired = policy
            .selected
            .difference(&selected)
            .cloned()
            .collect::<Vec<_>>();
        if policy.selected != selected || !retired.is_empty() {
            policy.pending.extend(retired);
            policy.selected = selected;
            self.write(&policy)?;
        }
        if policy.pending.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "whole-resource cleanup remains pending owner removal/handle APIs",
            ))
        }
    }

    pub(crate) fn retire(&self, scope: &impl StorageNamespace, resource: Id) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        if policy.pending.insert(key(scope, resource)) {
            self.write(&policy)?;
        }
        Ok(())
    }

    pub(crate) fn passthrough(
        &self,
        scope: &impl StorageNamespace,
        resource: Id,
    ) -> io::Result<bool> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        Ok(self.read()?.passthrough.contains(&key(scope, resource)))
    }

    pub(crate) fn set_passthrough(
        &self,
        scope: &impl StorageNamespace,
        resource: Id,
        passthrough: bool,
    ) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        if passthrough {
            policy.passthrough.insert(key(scope, resource));
        } else {
            policy.passthrough.remove(&key(scope, resource));
        }
        self.write(&policy)
    }

    fn write(&self, policy: &CopyPolicy) -> io::Result<()> {
        let bytes = serde_json::to_vec(policy).map_err(io::Error::other)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn read(&self) -> io::Result<CopyPolicy> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CopyPolicy::default()),
            Err(error) => Err(error),
        }
    }
}

fn key(scope: &impl StorageNamespace, resource: Id) -> (String, Id, Id) {
    (
        scope.user_sub().to_owned(),
        scope.application_id(),
        resource,
    )
}
