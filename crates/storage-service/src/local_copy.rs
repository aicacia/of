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
    #[serde(default)]
    retired_owners: BTreeSet<String>,
    pending: BTreeSet<(String, Id, Id)>,
    selected: BTreeSet<(String, Id, Id)>,
    passthrough: BTreeSet<(String, Id, Id)>,
    #[serde(default)]
    removed: BTreeSet<(String, Id, Id)>,
    #[serde(default)]
    generations: Vec<(String, Id, Id, u64)>,
    #[serde(default)]
    reselected: BTreeSet<(String, Id, Id)>,
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
        let policy = self.read()?;
        if policy.retired_owners.contains(scope.user_sub())
            || policy.pending.contains(&key(scope, resource))
            || policy.removed.contains(&key(scope, resource))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local copy cleanup is incomplete",
            ));
        }
        Ok(())
    }

    pub(crate) fn require_owner(&self, owner: &str) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        if self.read()?.retired_owners.contains(owner) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retired local Device owner",
            ));
        }
        Ok(())
    }

    pub(crate) fn set_owner_retired(&self, owner: &str, retired: bool) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        let changed = if retired {
            policy.retired_owners.insert(owner.to_owned())
        } else {
            policy.retired_owners.remove(owner)
        };
        if changed {
            self.write(&policy)?;
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
            policy.reselected.retain(|key| selected.contains(key));
            for added in selected.difference(&policy.selected) {
                if policy.pending.contains(added) {
                    policy.reselected.insert(added.clone());
                } else {
                    policy.removed.remove(added);
                }
            }
            policy.pending.extend(
                retired
                    .into_iter()
                    .filter(|key| !policy.removed.contains(key)),
            );
            policy.selected = selected;
            self.write(&policy)?;
        }
        if policy.pending.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "whole-resource cleanup remains pending",
            ))
        }
    }

    pub(crate) fn retire(&self, scope: &impl StorageNamespace, resource: Id) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        if !policy.removed.contains(&key(scope, resource))
            && policy.pending.insert(key(scope, resource))
        {
            self.write(&policy)?;
        }
        Ok(())
    }

    pub(crate) fn pending(&self) -> io::Result<Vec<(String, Id, Id)>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        Ok(self.read()?.pending.into_iter().collect())
    }

    pub(crate) fn generation(
        &self,
        scope: &impl StorageNamespace,
        resource: Id,
    ) -> io::Result<u64> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        Ok(self
            .read()?
            .generations
            .iter()
            .find(|(owner, app, id, _)| {
                (owner.as_str(), *app, *id) == (scope.user_sub(), scope.application_id(), resource)
            })
            .map_or(0, |entry| entry.3))
    }

    pub(crate) fn require_generation(
        &self,
        scope: &impl StorageNamespace,
        resource: Id,
        generation: u64,
    ) -> io::Result<()> {
        self.require_available(scope, resource)?;
        if self.generation(scope, resource)? != generation {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "retired local copy generation",
            ));
        }
        Ok(())
    }

    pub(crate) fn complete(&self, scope: &impl StorageNamespace, resource: Id) -> io::Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("local copy policy lock poisoned"))?;
        let mut policy = self.read()?;
        let key = key(scope, resource);
        if policy.pending.remove(&key) {
            if let Some(entry) = policy.generations.iter_mut().find(|(owner, app, id, _)| {
                (owner.as_str(), *app, *id) == (scope.user_sub(), scope.application_id(), resource)
            }) {
                entry.3 = entry
                    .3
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("copy generation exhausted"))?;
            } else {
                policy.generations.push((key.0.clone(), key.1, key.2, 1));
            }
            if !policy.reselected.remove(&key) {
                policy.removed.insert(key);
            }
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

pub(crate) struct CopyScope(pub String, pub Id);

impl StorageNamespace for CopyScope {
    fn user_sub(&self) -> &str {
        &self.0
    }
    fn application_id(&self) -> Id {
        self.1
    }
}

fn key(scope: &impl StorageNamespace, resource: Id) -> (String, Id, Id) {
    (
        scope.user_sub().to_owned(),
        scope.application_id(),
        resource,
    )
}
