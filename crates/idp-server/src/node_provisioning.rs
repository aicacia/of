use std::{
    fs,
    io::{self, Write},
};

use db::{SqlTranslator, Value};
use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, EntityType,
        GrantType, IdpSignerRecord, JwkPublic, ReplicaMembership, TokenEndpointAuthMethod,
    },
    model::Id,
};
use idp_service::{
    oauth2::NodeSignerBinding,
    replica::DbReplicaSignerRepo,
    repo::{ClientRepo, KeyRepo, PrivateKeyRepo},
};
use iroh::EndpointId;
use serde_json::{Value as JsonValue, json};

use crate::OwnerProvisioner;

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    pub async fn ensure_initial_user_signing_key(&self, user: Id) -> io::Result<()> {
        if user.is_nil() {
            return Err(invalid("initial User identity is required"));
        }
        self.oauth2
            .find_user_info(user)
            .await
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        self.ensure_local_entity_key(EntityType::User, user, "Local User", None)
            .await
    }

    pub async fn ensure_client_signing_key(&self, client_id: &str) -> io::Result<()> {
        let client = self
            .oauth2
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("local setup client row is missing"))?;
        self.retain_client_entity(client_id, client.id)?;
        self.ensure_local_entity_key(
            EntityType::Client,
            client.id,
            &client.client_name,
            Some(client_id),
        )
        .await
    }

    async fn ensure_local_entity_key(
        &self,
        entity: EntityType,
        id: Id,
        name: &str,
        client_id: Option<&str>,
    ) -> io::Result<()> {
        let keys = &self.oauth2.key_service;
        let key = match keys
            .key_repo()
            .find_by_entity_type_and_id(entity, id)
            .await
            .map_err(io::Error::other)?
        {
            Some(key) => key,
            None => keys
                .key_repo()
                .create_key(None, entity, id, true, name.into(), None)
                .await
                .map_err(io::Error::other)?,
        };
        let namespace = keys.scoped_namespace(entity, id);
        let path = key.derivation_path().map_err(io::Error::other)?;
        if let Some(client_id) = client_id {
            let mut reference = self.read_client_reference(client_id)?;
            let mut paths: Vec<String> = serde_json::from_value(reference["paths"].clone())?;
            let value = path.to_string();
            if !paths.contains(&value) {
                paths.push(value);
            }
            reference["paths"] = json!(paths);
            self.write_client_reference(client_id, &reference)?;
        }
        let private = if key.public_jwk.is_some() {
            keys.private_key_repo().load(&namespace, &path).map_err(io::Error::other)?
                .ok_or_else(|| invalid("published local key has lost private material; explicit recovery required, no key was recreated"))?
        } else {
            keys.private_key_repo()
                .ensure_master_key(&namespace)
                .map_err(io::Error::other)?;
            keys.private_key_repo()
                .ensure_derivation_path(&namespace, path.clone())
                .map_err(io::Error::other)?
        };
        let retained = keys
            .private_key_repo()
            .load(&namespace, &path)
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                invalid("local private key readback missing; setup remains incomplete")
            })?;
        if retained.to_xprv_string() != private.to_xprv_string() {
            return Err(invalid(
                "local private key readback changed; setup remains incomplete",
            ));
        }
        let public = key.to_jwk_public(&private).map_err(io::Error::other)?;
        if let Some(existing) = &key.public_jwk {
            if existing != &public {
                return Err(invalid(
                    "local public/private key conflict; no key was changed",
                ));
            }
        } else {
            keys.key_repo()
                .set_public_jwk(key.id, public)
                .await
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    pub async fn ensure_desktop_client(&self, client_id: Id) -> io::Result<ClientRegistration> {
        if client_id.is_nil() {
            return Err(invalid("stable desktop client ID is required"));
        }
        let client_id = client_id.to_string();
        self.begin_client_provisioning(&client_id).await?;
        let request = ClientRegistration {
            application: ApplicationRegistration {
                name: Some("Local Desktop".into()),
                uri: "local.aicacia.com".into(),
                description: None,
            },
            client_id: Some(client_id.clone()),
            client_secret: None,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Local Desktop".into(),
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            terms_of_service_uri: None,
            policy_uri: None,
            client_type: ClientType::Public,
            profile: ClientProfile::Native,
            redirect_uris: Vec::new(),
            allowed_grant_types: vec![
                GrantType::Password,
                GrantType::RefreshToken,
                GrantType::TokenExchange,
            ],
            response_types: Vec::new(),
            allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
            allowed_audiences: Vec::new(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            software_statement: None,
            software_id: None,
            software_version: None,
        };
        let registration = match self.oauth2.get_client(&client_id).await {
            Ok(existing) => {
                if existing.application.uri != request.application.uri
                    || existing.client_name != request.client_name
                    || existing.client_type != request.client_type
                    || existing.profile != request.profile
                    || existing.token_endpoint_auth_method != request.token_endpoint_auth_method
                    || existing.allowed_grant_types != request.allowed_grant_types
                    || existing.allowed_scopes != request.allowed_scopes
                    || existing.allowed_audiences != request.allowed_audiences
                    || existing.redirect_uris != request.redirect_uris
                    || !existing.response_types.is_empty()
                    || existing.client_secret.is_some()
                {
                    return Err(invalid(
                        "existing desktop client conflicts with restricted setup; no client was changed",
                    ));
                }
                Ok(existing)
            }
            Err(error) if error.error == idp_model::contract::ErrorCode::InvalidClient => self
                .oauth2
                .register_client(request)
                .await
                .map_err(|error| io::Error::other(format!("{error:?}"))),
            Err(error) => Err(io::Error::other(format!("{error:?}"))),
        }?;
        self.ensure_client_signing_key(&client_id).await?;
        Ok(registration)
    }

    pub async fn prepare_setup_client_slots(&self, clients: &[Id]) -> io::Result<()> {
        for id in clients {
            if id.is_nil() {
                return Err(invalid("non-nil setup Client slot required"));
            }
            let external = id.to_string();
            let path = self.client_reference_path(&external)?;
            if !path.try_exists()? {
                if self.current_client_entity(&external).await?.is_some() {
                    return Err(invalid(
                        "existing Client requires verified key-reference recovery, not a never-started slot",
                    ));
                }
                self.write_client_reference(
                    &external,
                    &self.new_client_reference(&external, "never-started"),
                )?;
            } else {
                self.read_client_reference(&external)?;
            }
        }
        Ok(())
    }

    async fn current_client_entity(&self, external: &str) -> io::Result<Option<Id>> {
        let results = self
            .engine
            .client()
            .translate_and_execute(
                &format!(
                    "SELECT id FROM clients WHERE client_id = {}",
                    text(external)
                ),
                &SqlTranslator,
            )
            .await
            .map_err(io::Error::other)?;
        let rows = &results[0].rows;
        if rows.len() > 1 {
            return Err(invalid("ambiguous Client key reference"));
        }
        if let Some(row) = rows.first() {
            let [Value::Uuid(id)] = row.values.as_slice() else {
                return Err(invalid("invalid internal Client identity"));
            };
            if !self
                .engine
                .client()
                .row_conflicts("clients", &db::Row::new(vec![Value::Uuid(*id)]))
                .await
                .map_err(io::Error::other)?
                .is_empty()
            {
                return Err(invalid("conflicted Client key reference"));
            }
            Ok(Some(*id))
        } else {
            Ok(None)
        }
    }

    pub async fn begin_client_provisioning(&self, external: &str) -> io::Result<()> {
        let path = self.client_reference_path(external)?;
        let mut reference = if path.try_exists()? {
            self.read_client_reference(external)?
        } else {
            self.new_client_reference(external, "pending")
        };
        if reference["state"] == "resolved" {
            let current = self.current_client_entity(external).await?.ok_or_else(|| invalid("retained setup Client was deleted; explicit reset required before reprovisioning"))?;
            if reference["entity_id"] != json!(current) {
                return Err(invalid(
                    "Client identity changed; no private keys were created",
                ));
            }
        } else {
            reference["state"] = json!("pending");
        }
        self.write_client_reference(external, &reference)
    }

    fn client_reference_path(&self, external: &str) -> io::Result<std::path::PathBuf> {
        let id: Id = external.parse().map_err(io::Error::other)?;
        if id.is_nil() || id.to_string() != external {
            return Err(invalid("canonical stable setup Client ID required"));
        }
        Ok(self
            .data_dir
            .join("local-client-key-references")
            .join(format!("{external}.json")))
    }

    fn new_client_reference(&self, external: &str, state: &str) -> JsonValue {
        json!({"version":1,"issuer":self.oauth2.oauth_config.issuer,"key_namespace":self.key_namespace,"client_id":external,"state":state,"entity_id":null,"paths":[]})
    }

    fn read_client_reference(&self, external: &str) -> io::Result<JsonValue> {
        let path = self.client_reference_path(external)?;
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(invalid("Client key reference is not a regular file"));
        }
        let record: JsonValue = serde_json::from_slice(&fs::read(path)?)?;
        if record.as_object().map(|fields| fields.len()) != Some(7)
            || record["version"] != 1
            || record["issuer"] != self.oauth2.oauth_config.issuer
            || record["key_namespace"] != self.key_namespace
            || record["client_id"] != external
            || !matches!(
                record["state"].as_str(),
                Some("never-started" | "pending" | "resolved")
            )
        {
            return Err(invalid(
                "invalid or conflicting local Client key references; reset remains incomplete",
            ));
        }
        let paths: Vec<String> = serde_json::from_value(record["paths"].clone())?;
        for path in paths {
            let _: key::DerivationPath = path.parse().map_err(io::Error::other)?;
        }
        if record["state"] == "resolved" {
            let id: Id = serde_json::from_value(record["entity_id"].clone())?;
            if id.is_nil() {
                return Err(invalid("nil retained internal Client identity"));
            }
        } else if !record["entity_id"].is_null() {
            return Err(invalid(
                "unresolved Client contains an unverified internal identity",
            ));
        }
        Ok(record)
    }

    fn write_client_reference(&self, external: &str, record: &JsonValue) -> io::Result<()> {
        let path = self.client_reference_path(external)?;
        let directory = path.parent().expect("reference directory");
        fs::create_dir_all(directory)?;
        if !fs::symlink_metadata(directory)?.file_type().is_dir() {
            return Err(invalid("Client reference directory must be local"));
        }
        fs::File::open(&self.data_dir)?.sync_all()?;
        if path.try_exists()? {
            self.read_client_reference(external)?;
        }
        let temporary = directory.join(format!(".{}.tmp", Id::now_v7()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(record)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        fs::File::open(directory)?.sync_all()?;
        if self.read_client_reference(external)? != *record {
            return Err(invalid("Client key reference readback changed"));
        }
        Ok(())
    }

    fn retain_client_entity(&self, external: &str, entity: Id) -> io::Result<()> {
        let mut record = self.read_client_reference(external)?;
        if record["state"] == "never-started"
            || (record["state"] == "resolved" && record["entity_id"] != json!(entity))
        {
            return Err(invalid(
                "internal Client reference conflicts with provisioning intent",
            ));
        }
        record["state"] = json!("resolved");
        record["entity_id"] = json!(entity);
        self.write_client_reference(external, &record)
    }

    pub fn prepare_node_signer(&self, binding: &NodeSignerBinding) -> io::Result<JwkPublic> {
        validate_binding(binding)?;
        let keys = &self.oauth2.key_service;
        let namespace = format!(
            "{}:node:{}:{}",
            self.key_namespace, binding.member_id, binding.key_id
        );
        let private = keys
            .private_key_repo()
            .ensure_master_key(&namespace)
            .map_err(io::Error::other)?;
        let retained = keys
            .private_key_repo()
            .load(&namespace, &key::DerivationPath::default())
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::other(
                    "secure-store private signer readback is missing; setup remains incomplete",
                )
            })?;
        if private.to_xprv_string() != retained.to_xprv_string() {
            return Err(io::Error::other(
                "secure-store private signer readback changed; setup remains incomplete",
            ));
        }
        keys.prepare_node_signer(binding).map_err(io::Error::other)
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
        let mut entities = Vec::with_capacity(clients.len() + 1);
        for client_id in clients {
            let external = client_id.to_string();
            let mut reference = self.read_client_reference(&external)?;
            let current = self.current_client_entity(&external).await?;
            if reference["state"] == "never-started" {
                if current.is_some() {
                    return Err(invalid(
                        "unexpected Client without local provisioning intent; reset references preserved",
                    ));
                }
                continue;
            }
            if reference["state"] == "pending" {
                let entity = current.ok_or_else(|| invalid("pending Client has lost internal key references; explicit verified recovery required"))?;
                self.retain_client_entity(&external, entity)?;
                reference = self.read_client_reference(&external)?;
            }
            let entity: Id = serde_json::from_value(reference["entity_id"].clone())?;
            if current.is_some_and(|id| id != entity) {
                return Err(invalid(
                    "current Client conflicts with retained internal key reference",
                ));
            }
            entities.push((EntityType::Client, entity, Some(reference)));
        }
        entities.push((EntityType::User, owner, None));
        for (entity_type, entity_id, reference) in entities {
            let namespace = keys.scoped_namespace(entity_type, entity_id);
            if let Some(reference) = reference {
                let paths: Vec<String> = serde_json::from_value(reference["paths"].clone())?;
                for path in paths {
                    delete_verified(
                        keys.private_key_repo(),
                        &namespace,
                        &path.parse().map_err(io::Error::other)?,
                    )?;
                }
            }
            for key in keys
                .key_repo()
                .list_by_entity_type_and_id(entity_type, entity_id)
                .await
                .map_err(io::Error::other)?
            {
                delete_verified(
                    keys.private_key_repo(),
                    &namespace,
                    &key.derivation_path().map_err(io::Error::other)?,
                )?;
            }
            delete_verified(
                keys.private_key_repo(),
                &namespace,
                &key::DerivationPath::default(),
            )?;
            keys.key_repo()
                .delete_by_entity_type_and_id(entity_type, entity_id)
                .await
                .map_err(io::Error::other)?;
        }
        let namespace = format!("{}:node:{}:{}", self.key_namespace, member_id, key_id);
        let path = key::DerivationPath::default();
        delete_verified(keys.private_key_repo(), &namespace, &path)
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

fn delete_verified<P: PrivateKeyRepo>(
    repo: &P,
    namespace: &str,
    path: &key::DerivationPath,
) -> io::Result<()> {
    if repo
        .load(namespace, path)
        .map_err(io::Error::other)?
        .is_some()
    {
        repo.delete(namespace, path).map_err(io::Error::other)?;
        if repo
            .load(namespace, path)
            .map_err(io::Error::other)?
            .is_some()
        {
            return Err(io::Error::other(
                "secure-store deletion was not durable; retry local reset",
            ));
        }
    }
    Ok(())
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
