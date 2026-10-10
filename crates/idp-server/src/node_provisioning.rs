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
    repo::{ClientRepo, KeyRepo, KeyService, PrivateKeyRepo, RepoError},
};
use iroh::EndpointId;
use serde_json::{Value as JsonValue, json};

use crate::OwnerProvisioner;

impl<P: PrivateKeyRepo + Send + Sync> OwnerProvisioner<P> {
    /// Nonblocking, cross-handle/process exclusion on stable owner-controlled ancestry.
    /// The lock inode must remain in place until exclusive owner-data removal.
    fn setup_operation(&self) -> io::Result<fs::File> {
        let path = self.data_dir.join("setup-secret-operation.lock");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(invalid("setup operation lock must be a regular local file"));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "another setup secret operation owns this directory; retry after it finishes",
            ),
            fs::TryLockError::Error(error) => error,
        })?;
        Ok(file)
    }

    pub async fn ensure_initial_user_signing_key(&self, user: Id) -> io::Result<()> {
        let _operation = self.setup_operation()?;
        if user.is_nil() {
            return Err(invalid("initial User identity is required"));
        }
        self.oauth2
            .find_user_info(user)
            .await
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let slot = format!("user:{user}");
        let inventory = self.ready_inventory()?;
        if inventory["owner"] != json!(user) {
            return Err(invalid("initial User conflicts with secret inventory"));
        }
        let mut reference = self.read_client_reference(&slot)?;
        if reference["state"] == "never-started" {
            reference["state"] = json!("pending");
            self.write_client_reference(&slot, &reference)?;
        } else if reference["state"] == "pending" {
            return Err(invalid(
                "unknown initial User history requires explicit recovery",
            ));
        }
        self.ensure_local_entity_key(EntityType::User, user, "Local User", &slot)
            .await
    }

    pub async fn ensure_client_signing_key(&self, client_id: &str) -> io::Result<()> {
        let _operation = self.setup_operation()?;
        self.ensure_client_signing_key_locked(client_id).await
    }

    async fn ensure_client_signing_key_locked(&self, client_id: &str) -> io::Result<()> {
        let client = self
            .oauth2
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("local setup client row is missing"))?;
        self.ready_inventory()?;
        let reference = self.read_client_reference(client_id)?;
        if reference["state"] != "resolved" || reference["entity_id"] != json!(client.id) {
            return Err(invalid("Client lacks owner-captured secret inventory"));
        }
        self.ensure_local_entity_key(
            EntityType::Client,
            client.id,
            &client.client_name,
            client_id,
        )
        .await
    }

    async fn ensure_local_entity_key(
        &self,
        entity: EntityType,
        id: Id,
        name: &str,
        slot: &str,
    ) -> io::Result<()> {
        let keys = &self.oauth2.key_service;
        let key = match keys
            .key_repo()
            .find_by_entity_type_and_id(entity, id)
            .await
            .map_err(io::Error::other)?
        {
            Some(key) => key,
            None => {
                if self.read_client_reference(slot)?["state"] != "pending" {
                    return Err(invalid(
                        "retained key metadata was lost; no replacement key was created",
                    ));
                }
                let (key, _) = keys
                    .create_initial_key_with_capture(entity, id, name.into(), |key, paths| {
                        self.capture_initial_key(slot, key.entity_id, paths)
                            .map_err(|error| RepoError::InvalidInput(error.to_string()))
                    })
                    .await
                    .map_err(io::Error::other)?;
                key
            }
        };
        let namespace = keys.scoped_namespace(entity, id);
        let path = key.derivation_path().map_err(io::Error::other)?;
        let reference = self.read_client_reference(slot)?;
        if reference["entity_id"] != json!(id) {
            return Err(invalid("entity conflicts with captured inventory"));
        }
        let paths: Vec<String> = serde_json::from_value(reference["paths"].clone())?;
        for required in KeyService::<idp_service::replica::DbKeyRepo, P>::private_paths(&key)
            .map_err(io::Error::other)?
        {
            if !paths.contains(&required.to_string()) {
                return Err(invalid("key is outside captured initial inventory"));
            }
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
        let _operation = self.setup_operation()?;
        if client_id.is_nil() {
            return Err(invalid("stable desktop client ID is required"));
        }
        let client_id = client_id.to_string();
        self.begin_client_provisioning_locked(&client_id).await?;
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
            Err(error) if error.error == idp_model::contract::ErrorCode::InvalidClient => {
                self.create_setup_client(request).await?;
                self.oauth2
                    .get_client(&client_id)
                    .await
                    .map_err(|error| io::Error::other(format!("{error:?}")))
            }
            Err(error) => Err(io::Error::other(format!("{error:?}"))),
        }?;
        self.ensure_client_signing_key_locked(&client_id).await?;
        Ok(registration)
    }

    /// Caller must prove exact fresh setup intent, never an attempted/historical setup.
    /// Publishes only the preparation boundary; no private material is produced.
    pub async fn prepare_fresh_setup_secret_inventory(
        &self,
        owner: Id,
        clients: &[Id],
    ) -> io::Result<()> {
        let _operation = self.setup_operation()?;
        if owner.is_nil() || clients.iter().any(Id::is_nil) || clients.contains(&owner) {
            return Err(invalid("non-nil distinct setup identities required"));
        }
        let mut unique = clients.to_vec();
        unique.sort();
        unique.dedup();
        if unique.len() != clients.len() {
            return Err(invalid("duplicate Client slots"));
        }
        if self
            .data_dir
            .join("setup-secret-inventory.json")
            .try_exists()?
            || self
                .data_dir
                .join("local-client-key-references")
                .try_exists()?
        {
            return Err(invalid("existing inventory cannot be declared fresh"));
        }
        for client in clients {
            if self
                .current_client_entity(&client.to_string())
                .await?
                .is_some()
            {
                return Err(invalid("existing Client is not fresh"));
            }
        }
        if !self
            .oauth2
            .key_service
            .key_repo()
            .list_by_entity_type_and_id(EntityType::User, owner)
            .await
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(invalid("existing User key material is not fresh"));
        }
        self.write_inventory(&json!({"version":1,"issuer":self.oauth2.oauth_config.issuer,"key_namespace":self.key_namespace,"owner":owner,"clients":clients,"phase":"preparing"}))
    }

    fn read_inventory(&self) -> io::Result<JsonValue> {
        let path = self.data_dir.join("setup-secret-inventory.json");
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(invalid("inventory must be regular"));
        }
        let record: JsonValue = serde_json::from_slice(&fs::read(path)?)?;
        let owner: Id = serde_json::from_value(record["owner"].clone())?;
        let clients: Vec<Id> = serde_json::from_value(record["clients"].clone())?;
        let mut unique = clients.clone();
        unique.sort();
        unique.dedup();
        if record.as_object().map(|fields| fields.len()) != Some(6)
            || record["version"] != 1
            || record["issuer"] != self.oauth2.oauth_config.issuer
            || record["key_namespace"] != self.key_namespace
            || owner.is_nil()
            || clients.iter().any(Id::is_nil)
            || clients.contains(&owner)
            || unique.len() != clients.len()
            || !matches!(
                record["phase"].as_str(),
                Some("preparing" | "ready" | "resetting")
            )
        {
            return Err(invalid(
                "unknown or conflicting secret inventory; explicit recovery required",
            ));
        }
        Ok(record)
    }

    fn write_inventory(&self, record: &JsonValue) -> io::Result<()> {
        write_durable_json(&self.data_dir.join("setup-secret-inventory.json"), record)?;
        if self.read_inventory()? != *record {
            return Err(invalid("inventory readback changed"));
        }
        Ok(())
    }

    fn ready_inventory(&self) -> io::Result<JsonValue> {
        let record = self.read_inventory()?;
        if record["phase"] != "ready" {
            return Err(invalid(
                "initial secret production requires a ready inventory; preparation or reset is pending",
            ));
        }
        Ok(record)
    }

    pub async fn prepare_setup_client_slots(&self, clients: &[Id]) -> io::Result<()> {
        let _operation = self.setup_operation()?;
        if self.read_inventory()?["phase"] == "resetting" {
            return Err(invalid(
                "reset secret cleanup has begun; ordinary preparation is barred",
            ));
        }
        self.prepare_setup_client_slots_locked(clients).await
    }

    async fn prepare_setup_client_slots_locked(&self, clients: &[Id]) -> io::Result<()> {
        let mut inventory = self.read_inventory()?;
        if inventory["clients"] != json!(clients) {
            return Err(invalid("setup Client slots conflict with inventory"));
        }
        let owner: Id = serde_json::from_value(inventory["owner"].clone())?;
        let mut slots: Vec<String> = clients.iter().map(ToString::to_string).collect();
        slots.push(format!("user:{owner}"));
        for slot in slots {
            let path = self.client_reference_path(&slot)?;
            if !path.try_exists()? {
                if inventory["phase"] != "preparing" {
                    return Err(invalid("lost slot after preparation is unknown history"));
                }
                if !slot.starts_with("user:") && self.current_client_entity(&slot).await?.is_some()
                {
                    return Err(invalid("unexpected Client during verified preparation"));
                }
                self.write_client_reference(
                    &slot,
                    &self.new_client_reference(&slot, "never-started"),
                )?;
            }
            let reference = self.read_client_reference(&slot)?;
            if inventory["phase"] == "preparing" && reference["state"] != "never-started" {
                return Err(invalid("secret attempt contradicts preparation boundary"));
            }
        }
        if inventory["phase"] == "preparing" {
            inventory["phase"] = json!("ready");
            self.write_inventory(&inventory)?;
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
        let _operation = self.setup_operation()?;
        self.begin_client_provisioning_locked(external).await
    }

    async fn begin_client_provisioning_locked(&self, external: &str) -> io::Result<()> {
        let inventory = self.ready_inventory()?;
        if !inventory["clients"]
            .as_array()
            .expect("validated clients")
            .contains(&json!(external))
        {
            return Err(invalid("Client outside setup inventory"));
        }
        let mut reference = self.read_client_reference(external)?;
        match reference["state"].as_str() {
            Some("resolved") => {
                let current = self.current_client_entity(external).await?.ok_or_else(|| {
                    invalid("retained setup Client was deleted; explicit reset required")
                })?;
                if reference["entity_id"] != json!(current) {
                    return Err(invalid("Client identity changed"));
                }
                Ok(())
            }
            Some("never-started") => {
                if self.current_client_entity(external).await?.is_some() {
                    return Err(invalid("unexpected existing Client"));
                }
                reference["state"] = json!("pending");
                self.write_client_reference(external, &reference)
            }
            _ => Err(invalid(
                "pending unknown Client history requires explicit recovery",
            )),
        }
    }

    async fn create_setup_client(&self, request: ClientRegistration) -> io::Result<()> {
        let external = request
            .client_id
            .as_deref()
            .ok_or_else(|| invalid("stable Client ID required"))?
            .to_owned();
        self.oauth2
            .client_repo
            .create_client_with_capture(request, |key, paths| {
                self.capture_initial_key(&external, key.entity_id, paths)
                    .map_err(|error| RepoError::InvalidInput(error.to_string()))
            })
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }

    pub async fn ensure_setup_infrastructure_client(
        &self,
        request: ClientRegistration,
    ) -> io::Result<ClientRegistration> {
        let _operation = self.setup_operation()?;
        if request.client_type != ClientType::Confidential
            || request.allowed_grant_types != [GrantType::ClientCredentials]
            || request
                .client_secret
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid(
                "restricted confidential infrastructure Client required",
            ));
        }
        let external = request
            .client_id
            .as_deref()
            .ok_or_else(|| invalid("stable Client ID required"))?
            .to_owned();
        self.begin_client_provisioning_locked(&external).await?;
        if self.current_client_entity(&external).await?.is_none() {
            self.create_setup_client(request.clone()).await?;
        }
        let registration = self
            .oauth2
            .ensure_infrastructure_client(request)
            .await
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        self.ensure_client_signing_key_locked(&external).await?;
        Ok(registration)
    }

    fn client_reference_path(&self, external: &str) -> io::Result<std::path::PathBuf> {
        let identity = external.strip_prefix("user:").unwrap_or(external);
        let id: Id = identity.parse().map_err(io::Error::other)?;
        if id.is_nil() || id.to_string() != identity {
            return Err(invalid("canonical stable setup Client ID required"));
        }
        Ok(self
            .data_dir
            .join("local-client-key-references")
            .join(format!("{}.json", external.replace(':', "-"))))
    }

    fn new_client_reference(&self, external: &str, state: &str) -> JsonValue {
        json!({"version":2,"issuer":self.oauth2.oauth_config.issuer,"key_namespace":self.key_namespace,"slot":external,"state":state,"entity_id":null,"paths":[]})
    }

    fn read_client_reference(&self, external: &str) -> io::Result<JsonValue> {
        let path = self.client_reference_path(external)?;
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(invalid("Client key reference is not a regular file"));
        }
        let record: JsonValue = serde_json::from_slice(&fs::read(path)?)?;
        if record.as_object().map(|fields| fields.len()) != Some(7)
            || record["version"] != 2
            || record["issuer"] != self.oauth2.oauth_config.issuer
            || record["key_namespace"] != self.key_namespace
            || record["slot"] != external
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
        let parsed: Vec<key::DerivationPath> = paths
            .iter()
            .map(|path| path.parse().map_err(io::Error::other))
            .collect::<io::Result<_>>()?;
        if record["state"] == "resolved" {
            if parsed.len() < 2
                || parsed.last() != Some(&key::DerivationPath::default())
                || parsed
                    .windows(2)
                    .any(|pair| pair[0].parent().as_ref() != Some(&pair[1]))
                || parsed
                    .iter()
                    .zip(&paths)
                    .any(|(path, text)| path.to_string() != *text)
            {
                return Err(invalid("incomplete initial private path ancestry"));
            }
            let id: Id = serde_json::from_value(record["entity_id"].clone())?;
            if id.is_nil() || record["paths"].as_array().is_none_or(Vec::is_empty) {
                return Err(invalid("incomplete retained initial inventory"));
            }
        } else if !record["entity_id"].is_null() || !paths.is_empty() {
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
        write_durable_json(&path, record)?;
        if self.read_client_reference(external)? != *record {
            return Err(invalid("Client key reference readback changed"));
        }
        Ok(())
    }

    fn capture_initial_key(
        &self,
        slot: &str,
        entity: Id,
        paths: &[key::DerivationPath],
    ) -> io::Result<()> {
        self.ready_inventory()?;
        let mut record = self.read_client_reference(slot)?;
        if record["state"] != "pending" || entity.is_nil() || paths.is_empty() {
            return Err(invalid(
                "initial secret capture conflicts with pending intent",
            ));
        }
        record["state"] = json!("resolved");
        record["entity_id"] = json!(entity);
        record["paths"] = json!(paths.iter().map(ToString::to_string).collect::<Vec<_>>());
        self.write_client_reference(slot, &record)
    }

    pub fn prepare_node_signer(&self, binding: &NodeSignerBinding) -> io::Result<JwkPublic> {
        let _operation = self.setup_operation()?;
        self.prepare_node_signer_locked(binding)
    }

    fn prepare_node_signer_locked(&self, binding: &NodeSignerBinding) -> io::Result<JwkPublic> {
        self.ready_inventory()?;
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
        let _operation = self.setup_operation()?;
        if member_id.is_nil() || key_id.is_nil() || owner.is_nil() || clients.iter().any(Id::is_nil)
        {
            return Err(invalid(
                "local secret deletion requires persisted non-nil IDs",
            ));
        }
        let inventory = self.read_inventory()?;
        if inventory["owner"] != json!(owner) || inventory["clients"] != json!(clients) {
            return Err(invalid("reset identities conflict with secret inventory"));
        }
        self.prepare_setup_client_slots_locked(clients).await?;
        let keys = &self.oauth2.key_service;
        let mut entities = Vec::with_capacity(clients.len() + 1);
        let mut slots: Vec<(String, EntityType)> = clients
            .iter()
            .map(|id| (id.to_string(), EntityType::Client))
            .collect();
        slots.push((format!("user:{owner}"), EntityType::User));
        for (slot, entity_type) in slots {
            let reference = self.read_client_reference(&slot)?;
            let current = if entity_type == EntityType::Client {
                self.current_client_entity(&slot).await?
            } else {
                None
            };
            if reference["state"] == "never-started" {
                if current.is_some()
                    || (entity_type == EntityType::User
                        && !keys
                            .key_repo()
                            .list_by_entity_type_and_id(entity_type, owner)
                            .await
                            .map_err(io::Error::other)?
                            .is_empty())
                {
                    return Err(invalid(
                        "unexpected entity contradicts never-started inventory",
                    ));
                }
                continue;
            }
            if reference["state"] != "resolved" {
                return Err(invalid(
                    "pending initial secret inventory is unknown; reset remains incomplete",
                ));
            }
            let entity: Id = serde_json::from_value(reference["entity_id"].clone())?;
            if current.is_some_and(|id| id != entity)
                || (entity_type == EntityType::User && entity != owner)
            {
                return Err(invalid("entity conflicts with captured inventory"));
            }
            entities.push((entity_type, entity, reference));
        }
        let mut inventory = self.read_inventory()?;
        inventory["phase"] = json!("resetting");
        self.write_inventory(&inventory)?;
        for (entity_type, entity_id, reference) in entities {
            let namespace = keys.scoped_namespace(entity_type, entity_id);
            let paths: Vec<String> = serde_json::from_value(reference["paths"].clone())?;
            for path in paths {
                delete_verified(
                    keys.private_key_repo(),
                    &namespace,
                    &path.parse().map_err(io::Error::other)?,
                )?;
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
        let _operation = self.setup_operation()?;
        self.ready_inventory()?;
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
            self.prepare_node_signer_locked(binding)?
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

fn write_durable_json(path: &std::path::Path, record: &JsonValue) -> io::Result<()> {
    let directory = path.parent().expect("inventory directory");
    fs::create_dir_all(directory)?;
    if !fs::symlink_metadata(directory)?.file_type().is_dir() {
        return Err(invalid("inventory directory must be local"));
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
    fs::rename(&temporary, path)?;
    for ancestor in fs::canonicalize(directory)?.ancestors() {
        fs::File::open(ancestor)?.sync_all()?;
    }
    Ok(())
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
