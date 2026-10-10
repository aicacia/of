use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        IDP_DEVICE_LIST_SCOPE, IDP_DEVICE_LOOKUP_SCOPE, IDP_TOKEN_VALIDATE_SCOPE, IdentityAction,
        JwkPublic, MANAGEMENT_PERMISSION_EVALUATE_SCOPE, TokenEndpointAuthMethod,
    },
    model::Id,
};
use idp_server::OwnerProvisioner;
use idp_service::{encrypt_password, oauth2::NodeSignerBinding};
use model::contract::{MANAGEMENT_REPLICATION_ADMIT_SCOPE, MANAGEMENT_REPLICATION_READ_SCOPE};
use serde::{Deserialize, Serialize};

use crate::{ServiceClientCredentials, UnifiedConfig, UnifiedEndpoint, UnifiedRuntime};

const INITIAL_ACTIONS: [IdentityAction; 24] = [
    IdentityAction::InfrastructureClientsRead,
    IdentityAction::InfrastructureClientsCreate,
    IdentityAction::InfrastructureClientsUpdate,
    IdentityAction::InfrastructureClientsDelete,
    IdentityAction::ApplicationsRead,
    IdentityAction::ApplicationsCreate,
    IdentityAction::ApplicationsUpdate,
    IdentityAction::ApplicationsDelete,
    IdentityAction::UsersRead,
    IdentityAction::UsersUpdate,
    IdentityAction::UsersDelete,
    IdentityAction::UsersResetPassword,
    IdentityAction::ConsentsRead,
    IdentityAction::ConsentsRevoke,
    IdentityAction::KeysRead,
    IdentityAction::KeysRotate,
    IdentityAction::KeysRevoke,
    IdentityAction::DevicePairingRead,
    IdentityAction::DevicePairingUpdate,
    IdentityAction::ReplicaSignersEnroll,
    IdentityAction::ReplicaSignersRotate,
    IdentityAction::ReplicaSignersRevoke,
    IdentityAction::IdpSecuritySync,
    IdentityAction::ManagementSecuritySync,
];

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Intent {
    issuer: String,
    key_namespace: String,
    roots: [PathBuf; 4],
    password_policy: serde_json::Value,
    clients: Vec<ClientRegistration>,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    intent: Intent,
    installation: Id,
    user: Id,
    credential: Id,
    member: Id,
    key: Id,
    role: Id,
    permissions: Vec<Id>,
    administrator: String,
    node: String,
    password_verifier: String,
    secret_verifiers: Vec<String>,
    endpoint_attempted: bool,
    endpoint: Option<String>,
    inventory_attempted: bool,
    node_attempted: bool,
    public_signer: Option<JwkPublic>,
    management_attempted: bool,
    management_complete: bool,
    storage_attempted: bool,
    storage_initialized: bool,
    complete: bool,
}

/// Restricted operator-local setup. Keep this guard alive until the runtime is shut down.
/// Paths require stable operator-controlled ancestry; this is not a hostile-path race defense.
/// Only Unix owner-only files are supported by this local command.
pub struct LocalProvisioner {
    config: UnifiedConfig,
    directory: PathBuf,
    _operation: File,
}

impl LocalProvisioner {
    /// CLI existing-only startup decision; a present local journal is authoritative.
    pub async fn open_runtime(config: UnifiedConfig) -> io::Result<(UnifiedRuntime, Option<Self>)> {
        match fs::symlink_metadata(config.local_provisioning_directory()) {
            Ok(_) => {
                let local = Self::open(config)?;
                let runtime = local.build_runtime().await?;
                Ok((runtime, Some(local)))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                crate::runtime::validate_config(&config)?;
                let binding = config.idp.oauth2.local_signer.as_ref().ok_or_else(|| {
                    invalid("existing host requires an explicit retained Node signer binding")
                })?;
                for root in [
                    Path::new(&config.idp.data_dir),
                    Path::new(&config.management.data_dir),
                    Path::new(&config.storage.data_dir),
                    &config.endpoint_data_dir,
                ] {
                    reject_symlinks(root)?;
                    if !fs::symlink_metadata(root)?.is_dir() {
                        return Err(invalid("existing host requires retained context roots"));
                    }
                }
                require_file(&Path::new(&config.idp.data_dir).join("idp.redb"), false)?;
                require_file(
                    &Path::new(&config.management.data_dir).join("management.redb"),
                    false,
                )?;
                require_file(&config.endpoint_data_dir.join("endpoint.key"), true)?;
                require_storage(&config)?;
                if UnifiedEndpoint::persisted_endpoint_id(&config.endpoint_data_dir)?.to_string()
                    != binding.endpoint_id
                {
                    return Err(invalid(
                        "existing endpoint conflicts with retained Node signer binding",
                    ));
                }
                let owner = OwnerProvisioner::open(&config.idp).await?;
                owner.verify_node_signer(binding).await?;
                drop(owner);
                let runtime = UnifiedRuntime::build(config).await?;
                match runtime.node_public_ready().await {
                    Ok(true) => Ok((runtime, None)),
                    result => {
                        runtime.shutdown().await?;
                        result?;
                        Err(invalid("existing host is not currently locally ready"))
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Publishes a new exact intent, without creating endpoint or owner private material.
    /// All four context/endpoint roots and the adjacent provisioning directory must be absent.
    pub fn create(
        config: UnifiedConfig,
        administrator: &str,
        node: &str,
        password_file: &Path,
    ) -> io::Result<Self> {
        let config = normalized_config(config)?;
        let password = read_password(password_file)?;
        if administrator.trim().is_empty()
            || node.trim().is_empty()
            || config.idp.oauth2.local_signer.is_some()
        {
            return Err(invalid(
                "fresh setup requires names and no preconfigured Node signer",
            ));
        }
        let intent = intent(&config)?;
        for root in &intent.roots {
            require_absent(root)?;
        }
        let directory = config.local_provisioning_directory();
        require_absent(&directory)?;
        let journal = Journal {
            version: 1,
            intent,
            installation: Id::now_v7(),
            user: Id::now_v7(),
            credential: Id::now_v7(),
            member: Id::now_v7(),
            key: Id::now_v7(),
            role: Id::now_v7(),
            permissions: INITIAL_ACTIONS.iter().map(|_| Id::now_v7()).collect(),
            administrator: administrator.to_owned(),
            node: node.to_owned(),
            password_verifier: encrypt_password(&config.idp.password, &password)
                .map_err(io::Error::other)?,
            secret_verifiers: credentials(&config)?
                .iter()
                .map(|client| {
                    encrypt_password(&config.idp.password, &client.client_secret)
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<_>>()?,
            endpoint_attempted: false,
            endpoint: None,
            inventory_attempted: false,
            node_attempted: false,
            public_signer: None,
            management_attempted: false,
            management_complete: false,
            storage_attempted: false,
            storage_initialized: false,
            complete: false,
        };
        create_private_directory(
            directory.parent().expect("absolute provisioning parent"),
            true,
        )?;
        create_private_directory(&directory, false)?;
        let operation = lock(&directory, true)?;
        let host = Self {
            config,
            directory,
            _operation: operation,
        };
        host.write(&journal)?;
        Ok(host)
    }

    /// Existing-only opening. Missing/invalid intent is never fresh authorization.
    pub fn open(config: UnifiedConfig) -> io::Result<Self> {
        let config = normalized_config(config)?;
        let directory = config.local_provisioning_directory();
        require_directory(&directory)?;
        let operation = lock(&directory, false)?;
        let host = Self {
            config,
            directory,
            _operation: operation,
        };
        host.read()?;
        Ok(host)
    }

    /// Continues only the retained exact local intent, using protected password input.
    pub async fn provision(&mut self, password_file: &Path) -> io::Result<()> {
        let password = read_password(password_file)?;
        let mut journal = self.read()?;
        verify(&password, &journal.password_verifier)?;
        if journal.complete {
            let runtime = self.build_runtime().await?;
            return runtime.shutdown().await;
        }
        if journal.management_attempted {
            require_directory(Path::new(&self.config.management.data_dir))?;
            require_file(
                &Path::new(&self.config.management.data_dir).join("management.redb"),
                false,
            )?;
            if !journal.management_complete {
                return Err(invalid(
                    "unacknowledged Management initialization requires explicit recovery",
                ));
            }
        }
        if journal.storage_attempted {
            if !journal.storage_initialized {
                return Err(invalid(
                    "unacknowledged Storage initialization requires explicit recovery",
                ));
            }
            require_storage(&self.config)?;
        }
        let endpoint = if journal.endpoint_attempted {
            UnifiedEndpoint::open(&self.config.endpoint_data_dir, &self.config.idp).await?
        } else {
            for root in &journal.intent.roots {
                require_absent(root)?;
            }
            journal.endpoint_attempted = true;
            self.write(&journal)?;
            UnifiedEndpoint::open_fresh(&self.config.endpoint_data_dir, &self.config.idp).await?
        };
        let endpoint_id = endpoint.endpoint_id().to_string();
        endpoint.close().await;
        if journal
            .endpoint
            .as_ref()
            .is_some_and(|retained| retained != &endpoint_id)
        {
            return Err(invalid(
                "endpoint identity changed; exact recovery required",
            ));
        }
        journal.endpoint = Some(endpoint_id);
        self.write(&journal)?;
        let fresh_inventory = !journal.inventory_attempted;
        if fresh_inventory {
            require_absent(Path::new(&self.config.idp.data_dir))?;
            journal.inventory_attempted = true;
            self.write(&journal)?;
            create_private_directory(Path::new(&self.config.idp.data_dir), false)?;
        } else {
            require_file(
                &Path::new(&self.config.idp.data_dir).join("idp.redb"),
                false,
            )?;
        }
        let owner = OwnerProvisioner::open(&self.config.idp).await?;
        let clients = client_ids(&journal)?;
        if fresh_inventory {
            owner
                .prepare_fresh_setup_secret_inventory(journal.user, &clients)
                .await?;
        }
        owner.prepare_setup_client_slots(&clients).await?;
        owner
            .ensure_initial_user(
                journal.user,
                journal.credential,
                &journal.administrator,
                &password,
            )
            .await?;
        owner.ensure_initial_user_signing_key(journal.user).await?;
        let binding = binding(&journal)?;
        let public = if journal.node_attempted {
            owner.verify_prepared_node_signer(&binding)?
        } else {
            journal.node_attempted = true;
            self.write(&journal)?;
            owner.prepare_node_signer(&binding)?
        };
        if journal
            .public_signer
            .as_ref()
            .is_some_and(|retained| retained != &public)
        {
            return Err(invalid(
                "prepared Node signer changed; exact recovery required",
            ));
        }
        journal.public_signer = Some(public);
        self.write(&journal)?;
        owner
            .ensure_initial_node(&binding, journal.user, &journal.node)
            .await?;
        if Some(owner.verify_node_signer(&binding).await?) != journal.public_signer {
            return Err(invalid(
                "approved Node signer differs from retained preparation",
            ));
        }
        for (mut request, credential) in journal
            .intent
            .clients
            .iter()
            .cloned()
            .zip(credentials(&self.config)?)
        {
            request.client_secret = Some(credential.client_secret.clone());
            owner.ensure_setup_infrastructure_client(request).await?;
        }
        drop(owner);
        if !journal.management_attempted {
            require_absent(Path::new(&self.config.management.data_dir))?;
            journal.management_attempted = true;
            self.write(&journal)?;
            create_private_directory(Path::new(&self.config.management.data_dir), false)?;
            let permissions = journal
                .permissions
                .iter()
                .copied()
                .zip(INITIAL_ACTIONS)
                .collect::<Vec<_>>();
            management_server::provision_initial_administrator(
                &self.config.management,
                journal.user,
                journal.role,
                &permissions,
            )
            .await?;
            management_server::provision_initial_device(
                &self.config.management,
                journal.member,
                journal.user,
            )
            .await?;
            journal.management_complete = true;
            self.write(&journal)?;
        }
        let listener = tokio::net::TcpListener::bind(self.config.listen_addr).await?;
        let api_base = format!("http://{}", listener.local_addr()?);
        if !journal.storage_attempted {
            require_absent(Path::new(&self.config.storage.data_dir))?;
            journal.storage_attempted = true;
            self.write(&journal)?;
            create_private_directory(Path::new(&self.config.storage.data_dir), false)?;
        }
        let mut config = self.config.clone();
        config.idp.oauth2.local_signer = Some(binding);
        let runtime = UnifiedRuntime::build_on_listener(config, listener, api_base).await?;
        journal.storage_initialized = true;
        if let Err(error) = self.write(&journal) {
            runtime.shutdown().await?;
            return Err(error);
        }
        let ready = runtime.node_public_ready().await;
        runtime.shutdown().await?;
        if !ready? {
            return Err(invalid(
                "local contexts are not currently ready; setup remains incomplete",
            ));
        }
        journal.complete = true;
        self.write(&journal)
    }

    /// Requires explicit completion and current local evidence; never provisions at startup.
    pub async fn build_runtime(&self) -> io::Result<UnifiedRuntime> {
        let journal = self.read()?;
        if !journal.complete {
            return Err(invalid(
                "local provisioning is incomplete; run the explicit provision command",
            ));
        }
        for root in &journal.intent.roots {
            require_directory(root)?;
        }
        require_file(
            &Path::new(&self.config.idp.data_dir).join("idp.redb"),
            false,
        )?;
        require_file(
            &Path::new(&self.config.management.data_dir).join("management.redb"),
            false,
        )?;
        require_file(&self.config.endpoint_data_dir.join("endpoint.key"), true)?;
        require_storage(&self.config)?;
        let owner = OwnerProvisioner::open(&self.config.idp).await?;
        let binding = binding(&journal)?;
        if Some(owner.verify_prepared_node_signer(&binding)?) != journal.public_signer
            || Some(owner.verify_node_signer(&binding).await?) != journal.public_signer
        {
            return Err(invalid(
                "current Node signing capability does not match completed intent",
            ));
        }
        owner
            .prepare_setup_client_slots(&client_ids(&journal)?)
            .await?;
        for (mut request, credential) in journal
            .intent
            .clients
            .iter()
            .cloned()
            .zip(credentials(&self.config)?)
        {
            request.client_secret = Some(credential.client_secret.clone());
            owner.ensure_setup_infrastructure_client(request).await?;
        }
        drop(owner);
        let mut config = self.config.clone();
        config.idp.oauth2.local_signer = Some(binding);
        let runtime = UnifiedRuntime::build(config).await?;
        if journal.endpoint.as_deref() != Some(&runtime.endpoint_id().to_string()) {
            runtime.shutdown().await?;
            return Err(invalid(
                "endpoint identity changed; exact recovery required",
            ));
        }
        match runtime.node_public_ready().await {
            Ok(true) => Ok(runtime),
            result => {
                runtime.shutdown().await?;
                result?;
                Err(invalid("completed intent is not current local readiness"))
            }
        }
    }

    fn read(&self) -> io::Result<Journal> {
        let bytes = read_private(&self.directory.join("intent.json"))?;
        let journal: Journal = serde_json::from_slice(&bytes)?;
        let retained: serde_json::Value = serde_json::from_slice(&bytes)?;
        if serde_json::to_value(&journal)? != retained
            || journal.version != 1
            || journal.intent != intent(&self.config)?
            || journal.administrator.trim().is_empty()
            || journal.node.trim().is_empty()
            || journal.permissions.len() != INITIAL_ACTIONS.len()
            || journal.secret_verifiers.len() != journal.intent.clients.len()
            || journal.endpoint.is_some() && !journal.endpoint_attempted
            || journal.inventory_attempted && journal.endpoint.is_none()
            || journal.node_attempted && !journal.inventory_attempted
            || journal.public_signer.is_some() && !journal.node_attempted
            || journal.management_attempted && journal.public_signer.is_none()
            || journal.management_complete && !journal.management_attempted
            || journal.storage_attempted && !journal.management_complete
            || journal.storage_initialized && !journal.storage_attempted
            || journal.complete && !journal.storage_initialized
        {
            return Err(invalid(
                "invalid or conflicting local intent; exact recovery required",
            ));
        }
        let mut identities = vec![
            journal.installation,
            journal.user,
            journal.credential,
            journal.member,
            journal.key,
            journal.role,
        ];
        identities.extend(&journal.permissions);
        identities.extend(client_ids(&journal)?);
        let count = identities.len();
        identities.sort();
        identities.dedup();
        if identities.len() != count || identities.iter().any(Id::is_nil) {
            return Err(invalid(
                "local intent identities must be distinct and non-nil",
            ));
        }
        for (credential, verifier) in credentials(&self.config)?
            .iter()
            .zip(&journal.secret_verifiers)
        {
            verify(&credential.client_secret, verifier)?;
        }
        if let Some(configured) = &self.config.idp.oauth2.local_signer
            && !same_binding(configured, &binding(&journal)?)
        {
            return Err(invalid(
                "configured Node signer conflicts with local intent",
            ));
        }
        Ok(journal)
    }

    fn write(&self, journal: &Journal) -> io::Result<()> {
        let path = self.directory.join("intent.json");
        let temporary = self.directory.join(format!(".{}.tmp", Id::now_v7()));
        let mut file = private_options(true).open(&temporary)?;
        file.write_all(&serde_json::to_vec(journal)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        sync_ancestry(&self.directory)?;
        if self.read()? != *journal {
            return Err(invalid("durable local intent readback changed"));
        }
        Ok(())
    }
}

fn intent(config: &UnifiedConfig) -> io::Result<Intent> {
    crate::runtime::validate_config(config)?;
    if !config.listen_addr.ip().is_loopback() {
        return Err(invalid("local host must use a loopback listener"));
    }
    let clients = credentials(config)?;
    let mut secrets: Vec<&str> = Vec::new();
    for credential in &clients {
        canonical_id(&credential.client_id)?;
        if credential.client_secret.trim().is_empty()
            || secrets.contains(&credential.client_secret.as_str())
        {
            return Err(invalid(
                "each service relationship requires a distinct nonempty secret",
            ));
        }
        secrets.push(credential.client_secret.as_str());
    }
    let roots = [
        PathBuf::from(&config.idp.data_dir),
        PathBuf::from(&config.management.data_dir),
        PathBuf::from(&config.storage.data_dir),
        config.endpoint_data_dir.clone(),
    ];
    let directory = config.local_provisioning_directory();
    let all = roots
        .iter()
        .chain(std::iter::once(&directory))
        .collect::<Vec<_>>();
    for (index, root) in all.iter().enumerate() {
        reject_symlinks(root)?;
        if all[..index]
            .iter()
            .any(|other| root.starts_with(other) || other.starts_with(root))
        {
            return Err(invalid(
                "context, endpoint and provisioning roots must not overlap",
            ));
        }
    }
    let mut requests = [
        registration(
            clients[0],
            "Management",
            &config.management.api_public_uri,
            "Management service to IdP",
            &[IDP_TOKEN_VALIDATE_SCOPE, IDP_DEVICE_LOOKUP_SCOPE],
        ),
        registration(
            clients[1],
            "Storage",
            &config.storage.api_public_uri,
            "Storage service to IdP",
            &[
                IDP_TOKEN_VALIDATE_SCOPE,
                IDP_DEVICE_LOOKUP_SCOPE,
                IDP_DEVICE_LIST_SCOPE,
            ],
        ),
        registration(
            clients[2],
            "Storage",
            &config.storage.api_public_uri,
            "Storage service to Management",
            &[
                MANAGEMENT_REPLICATION_READ_SCOPE,
                MANAGEMENT_REPLICATION_ADMIT_SCOPE,
            ],
        ),
        registration(
            clients[3],
            "IdP",
            &config.idp.api_public_uri,
            "IdP service to Management",
            &[MANAGEMENT_PERMISSION_EVALUATE_SCOPE],
        ),
    ];
    // IdP's introspection contract uses the Client audience allowlist for inspected tokens too.
    allow_inspection(
        &mut requests[0],
        &[
            management_service::MANAGEMENT_APPLICATION_URI,
            &config.management.storage_audience,
        ],
    );
    allow_inspection(
        &mut requests[1],
        &["storage:databases", "storage:filesystems"],
    );
    if config.idp.oauth2.issuer.trim().is_empty() || config.idp.key_namespace.trim().is_empty() {
        return Err(invalid("Canonical Issuer and key namespace are required"));
    }
    Ok(Intent {
        issuer: config.idp.oauth2.issuer.clone(),
        key_namespace: config.idp.key_namespace.clone(),
        roots,
        password_policy: serde_json::to_value(&config.idp.password)?,
        clients: requests.into(),
    })
}

fn credentials(config: &UnifiedConfig) -> io::Result<[&ServiceClientCredentials; 4]> {
    Ok([
        &config.management_idp_client,
        &config.storage_idp_client,
        &config.storage_management_client,
        config.idp_management_client.as_ref().ok_or_else(|| {
            invalid("local provisioning requires the explicit IdP to Management relationship")
        })?,
    ])
}

fn registration(
    credential: &ServiceClientCredentials,
    application: &str,
    uri: &str,
    name: &str,
    scopes: &[&str],
) -> ClientRegistration {
    ClientRegistration {
        application: ApplicationRegistration {
            name: Some(application.into()),
            uri: uri.into(),
            description: Some(format!("{application} service identity")),
        },
        client_id: Some(credential.client_id.clone()),
        client_secret: None,
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: name.into(),
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        terms_of_service_uri: None,
        policy_uri: None,
        client_type: ClientType::Confidential,
        profile: ClientProfile::Web,
        redirect_uris: Vec::new(),
        allowed_grant_types: vec![GrantType::ClientCredentials],
        response_types: Vec::new(),
        allowed_scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
        allowed_audiences: vec![credential.audience.clone()],
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        software_statement: None,
        software_id: None,
        software_version: None,
    }
}

fn allow_inspection(request: &mut ClientRegistration, audiences: &[&str]) {
    for audience in audiences {
        if !request
            .allowed_audiences
            .iter()
            .any(|allowed| allowed == audience)
        {
            request.allowed_audiences.push((*audience).to_owned());
        }
    }
}

fn client_ids(journal: &Journal) -> io::Result<Vec<Id>> {
    journal
        .intent
        .clients
        .iter()
        .map(|request| {
            canonical_id(
                request
                    .client_id
                    .as_deref()
                    .ok_or_else(|| invalid("missing retained Client ID"))?,
            )
        })
        .collect()
}

fn canonical_id(value: &str) -> io::Result<Id> {
    let id: Id = value
        .parse()
        .map_err(|_| invalid("canonical UUID service Client ID required"))?;
    if id.is_nil() || id.to_string() != value {
        return Err(invalid("canonical non-nil UUID service Client ID required"));
    }
    Ok(id)
}

fn binding(journal: &Journal) -> io::Result<NodeSignerBinding> {
    let endpoint = journal
        .endpoint
        .clone()
        .ok_or_else(|| invalid("retained endpoint identity is required"))?;
    endpoint
        .parse::<iroh::EndpointId>()
        .map_err(|_| invalid("invalid retained endpoint identity"))?;
    Ok(NodeSignerBinding {
        member_id: journal.member,
        key_id: journal.key,
        endpoint_id: endpoint,
    })
}

fn same_binding(left: &NodeSignerBinding, right: &NodeSignerBinding) -> bool {
    left.member_id == right.member_id
        && left.key_id == right.key_id
        && left.endpoint_id == right.endpoint_id
}

fn normalized_config(mut config: UnifiedConfig) -> io::Result<UnifiedConfig> {
    config.endpoint_data_dir = absolute(&config.endpoint_data_dir)?;
    config.idp.data_dir = absolute(Path::new(&config.idp.data_dir))?
        .to_string_lossy()
        .into_owned();
    config.management.data_dir = absolute(Path::new(&config.management.data_dir))?
        .to_string_lossy()
        .into_owned();
    config.storage.data_dir = absolute(Path::new(&config.storage.data_dir))?
        .to_string_lossy()
        .into_owned();
    intent(&config)?;
    Ok(config)
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("empty paths and parent components are not allowed"));
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(path
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect())
}

fn reject_symlinks(path: &Path) -> io::Result<()> {
    for ancestor in absolute(path)?.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid("symlink ancestry is not allowed"));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn require_absent(path: &Path) -> io::Result<()> {
    reject_symlinks(path)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(invalid(
            "fresh setup requires absent roots; existing state requires exact continuation or recovery",
        )),
    }
}

fn require_directory(path: &Path) -> io::Result<()> {
    reject_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(invalid("managed root must be a regular directory"));
    }
    private_permissions(&metadata)
}

fn require_file(path: &Path, private: bool) -> io::Result<File> {
    reject_symlinks(path)?;
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("input or retained state must be a regular file"));
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("input or retained state must be a regular file"));
    }
    if private {
        private_permissions(&metadata)?;
    }
    Ok(file)
}

fn private_permissions(metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 == 0 {
            return Ok(());
        }
        Err(invalid(
            "operator files/directories must deny group and other access",
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local provisioning requires Unix owner-only permissions; no Windows ACL qualification",
        ))
    }
}

fn create_private_directory(path: &Path, recursive: bool) -> io::Result<()> {
    reject_symlinks(path)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.recursive(recursive).create(path)?;
    sync_ancestry(path)
}

fn require_storage(config: &UnifiedConfig) -> io::Result<()> {
    let root = Path::new(&config.storage.data_dir);
    require_directory(root)?;
    for name in ["databases", "filesystems"] {
        let path = root.join(name);
        reject_symlinks(&path)?;
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err(invalid(
                "acknowledged Storage runtime roots require exact recovery",
            ));
        }
    }
    Ok(())
}

fn private_options(create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn lock(directory: &Path, fresh: bool) -> io::Result<File> {
    require_directory(directory)?;
    let path = directory.join("operation.lock");
    if !fresh {
        require_file(&path, true)?;
    }
    let file = private_options(fresh).open(path)?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "another local provisioning/runtime operation owns this host",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    file.sync_all()?;
    sync_ancestry(directory)?;
    Ok(file)
}

fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = require_file(path, true)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_password(path: &Path) -> io::Result<String> {
    let mut password = String::from_utf8(read_private(path)?)
        .map_err(|_| invalid("password input must be UTF-8"))?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.trim().is_empty() || password.contains(['\r', '\n']) {
        return Err(invalid("password input must contain one nonempty line"));
    }
    Ok(password)
}

fn verify(secret: &str, verifier: &str) -> io::Result<()> {
    if !argon2::verify_encoded(verifier, secret.as_bytes())
        .map_err(|_| invalid("invalid retained secret verifier"))?
    {
        return Err(invalid(
            "input credential differs from retained local intent",
        ));
    }
    Ok(())
}

fn sync_ancestry(directory: &Path) -> io::Result<()> {
    for ancestor in directory.ancestors() {
        File::open(ancestor)?.sync_all()?;
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
