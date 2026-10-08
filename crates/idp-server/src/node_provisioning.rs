use std::io;

use db::{SqlTranslator, Value};
use idp_model::{
    contract::{EntityType, IdpSignerRecord, JwkPublic, ReplicaMembership},
    model::Id,
};
use idp_service::{oauth2::NodeSignerBinding, replica::DbReplicaSignerRepo, repo::PrivateKeyRepo};
use iroh::EndpointId;

use crate::OwnerProvisioner;

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    pub fn prepare_node_signer(&self, binding: &NodeSignerBinding) -> io::Result<JwkPublic> {
        validate_binding(binding)?;
        self.oauth2
            .key_service
            .prepare_node_signer(binding)
            .map_err(io::Error::other)
    }

    pub async fn verify_node_signer(&self, binding: &NodeSignerBinding) -> io::Result<JwkPublic> {
        validate_binding(binding)?;
        self.oauth2
            .key_service
            .load_node_signer(binding, &self.oauth2.oauth_config.issuer, now()?)
            .await
            .map(JwkPublic::from)
            .map_err(io::Error::other)
    }

    pub async fn delete_local_secrets(
        &self,
        member_id: Id,
        key_id: Id,
        owner: Id,
        clients: &[Id],
    ) -> io::Result<()> {
        if member_id.is_nil() || key_id.is_nil() || owner.is_nil() || clients.iter().any(Id::is_nil)
        {
            return Err(invalid(
                "local secret deletion requires persisted non-nil IDs",
            ));
        }
        let keys = &self.oauth2.key_service;
        for client in clients {
            keys.delete_entity_key_material(EntityType::Client, *client)
                .await
                .map_err(io::Error::other)?;
        }
        keys.delete_entity_key_material(EntityType::User, owner)
            .await
            .map_err(io::Error::other)?;
        let namespace = format!("{}:node:{}:{}", self.key_namespace, member_id, key_id);
        let path = key::DerivationPath::default();
        if keys
            .private_key_repo()
            .load(&namespace, &path)
            .map_err(io::Error::other)?
            .is_some()
        {
            keys.private_key_repo()
                .delete(&namespace, &path)
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Restricted owner-local fresh setup; never exposed as an unauthenticated HTTP mutation.
    pub async fn ensure_initial_node(
        &self,
        binding: &NodeSignerBinding,
        owner: Id,
        name: &str,
    ) -> io::Result<()> {
        validate_binding(binding)?;
        if owner.is_nil() || name.trim().is_empty() {
            return Err(invalid("initial Node owner and name are required"));
        }
        let rows = self
            .engine
            .client()
            .translate_and_execute("SELECT id FROM users", &SqlTranslator)
            .await
            .map_err(io::Error::other)?;
        if rows[0].rows.len() != 1 || rows[0].rows[0].values != [Value::Uuid(owner)] {
            return Err(invalid("fresh setup requires the exact initial local User"));
        }
        let enrolled = self
            .engine
            .client()
            .translate_and_execute("SELECT member_id FROM idp_replica_members", &SqlTranslator)
            .await
            .map_err(io::Error::other)?;
        let public = if enrolled[0].rows.is_empty() {
            self.prepare_node_signer(binding)?
        } else {
            self.verify_node_signer(binding).await?
        };
        let devices = self
            .engine
            .client()
            .translate_and_execute(
                "SELECT id, owner_subject, name, public_key, state, revoked_at FROM devices",
                &SqlTranslator,
            )
            .await
            .map_err(io::Error::other)?;
        if devices[0].rows.is_empty() {
            self.engine.client().translate_and_execute(&format!("INSERT INTO devices (id, owner_subject, name, public_key, address, state, approved_at, revoked_at, created_at, updated_at) VALUES (CAST('{}' AS UUID), {}, {}, {}, '', 1, 1, NULL, 1, 1)", binding.member_id, text(&owner.to_string()), text(name), text(&binding.endpoint_id)), &SqlTranslator).await.map_err(io::Error::other)?;
        } else if devices[0].rows.len() != 1
            || devices[0].rows[0].values
                != [
                    Value::Uuid(binding.member_id),
                    Value::Text(owner.to_string()),
                    Value::Text(name.into()),
                    Value::Text(binding.endpoint_id.clone()),
                    Value::Integer(1),
                    Value::Null,
                ]
        {
            return Err(invalid(
                "initial Node Device conflicts with persisted setup",
            ));
        }
        let issuer = self.oauth2.oauth_config.issuer.clone();
        DbReplicaSignerRepo::new(self.engine.clone())
            .enroll(
                &ReplicaMembership {
                    installation_id: issuer.clone(),
                    member_id: binding.member_id,
                    endpoint_id: binding.endpoint_id.clone(),
                    issuer: issuer.clone(),
                    approved_at: 1,
                    revoked_at: None,
                },
                &IdpSignerRecord {
                    member_id: binding.member_id,
                    key_id: binding.key_id,
                    issuer,
                    public_jwk: public,
                    approved_at: Some(1),
                    revoked_at: None,
                    expires_at: None,
                },
            )
            .await
            .map_err(io::Error::other)?;
        self.verify_node_signer(binding).await?;
        Ok(())
    }
}

fn validate_binding(binding: &NodeSignerBinding) -> io::Result<()> {
    let endpoint = binding
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(io::Error::other)?;
    if binding.member_id.is_nil()
        || binding.key_id.is_nil()
        || endpoint.to_string() != binding.endpoint_id
    {
        return Err(invalid("invalid Node signer binding"));
    }
    Ok(())
}

fn text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn now() -> io::Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .try_into()
        .map_err(io::Error::other)
}
