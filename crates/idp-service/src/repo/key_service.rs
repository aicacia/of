use alloc::{format, string::String};

use chrono::{DateTime, Utc};
use idp_model::{
    contract::EntityType,
    model::{Id, Key},
};
use key::{DerivationPath, DerivedKey};

#[cfg(feature = "std")]
use crate::repo::PrivateKeyKeyringRepo;
#[cfg(not(feature = "std"))]
type DefaultPrivateKeyRepo = ();
use crate::repo::{KeyRepo, PrivateKeyRepo, RepoResult};

#[cfg(feature = "std")]
pub struct KeyService<R, P = PrivateKeyKeyringRepo> {
    key_repo: R,
    private_key_repo: P,
    namespace: String,
}

#[cfg(not(feature = "std"))]
pub struct KeyService<R, P = DefaultPrivateKeyRepo> {
    key_repo: R,
    private_key_repo: P,
    namespace: String,
}

impl<R, P> KeyService<R, P>
where
    R: KeyRepo,
    P: PrivateKeyRepo,
{
    pub fn new(key_repo: R, private_key_repo: P, namespace: impl Into<String>) -> Self {
        Self {
            key_repo,
            private_key_repo,
            namespace: namespace.into(),
        }
    }

    pub fn key_repo(&self) -> &R {
        &self.key_repo
    }

    pub fn private_key_repo(&self) -> &P {
        &self.private_key_repo
    }

    pub async fn create_key(
        &self,
        parent_id: Option<Id>,
        entity_type: EntityType,
        entity_id: Id,
        hardened: bool,
        name: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> RepoResult<(Key, DerivedKey)> {
        let key = self
            .key_repo
            .create_key(
                parent_id,
                entity_type,
                entity_id,
                hardened,
                name,
                expires_at,
            )
            .await?;

        let scoped_namespace = self.scoped_namespace(entity_type, entity_id);

        let private_key = self
            .private_key_repo
            .ensure_derivation_path(&scoped_namespace, key.derivation_path()?)?;

        let public_jwk = key.to_jwk_public(&private_key)?;
        let key = self.key_repo.set_public_jwk(key.id, public_jwk).await?;

        Ok((key, private_key))
    }

    pub async fn delete_entity_key_material(
        &self,
        entity_type: EntityType,
        entity_id: Id,
    ) -> RepoResult<()> {
        let namespace = self.scoped_namespace(entity_type, entity_id);
        for key in self
            .key_repo
            .list_by_entity_type_and_id(entity_type, entity_id)
            .await?
        {
            let derivation_path = key.derivation_path()?;
            if self
                .private_key_repo
                .load(&namespace, &derivation_path)?
                .is_some()
            {
                self.private_key_repo.delete(&namespace, &derivation_path)?;
            }
        }

        let root_path = DerivationPath::default();
        if self
            .private_key_repo
            .load(&namespace, &root_path)?
            .is_some()
        {
            self.private_key_repo.delete(&namespace, &root_path)?;
        }
        self.key_repo
            .delete_by_entity_type_and_id(entity_type, entity_id)
            .await
    }

    pub fn scoped_namespace(&self, entity_type: EntityType, entity_id: Id) -> String {
        format!("{}:{entity_type}:{entity_id}", self.namespace)
    }

    pub fn ensure_entity_master_key(
        &self,
        entity_type: EntityType,
        entity_id: Id,
        passphrase: &str,
    ) -> RepoResult<DerivedKey> {
        let scoped_namespace = self.scoped_namespace(entity_type, entity_id);
        self.private_key_repo
            .ensure_master_key_with_passphrase(&scoped_namespace, passphrase)
    }

    pub async fn rotate_active_entity_root_key(
        &self,
        entity_type: EntityType,
        entity_id: Id,
        name: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> RepoResult<(Key, DerivedKey)> {
        self.create_key(None, entity_type, entity_id, true, name, expires_at)
            .await
    }
}
