use std::{
    fs,
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    sync::{Mutex as StdMutex, OnceLock},
};

use axum::Router;
use idp_model::{
    contract::{
        ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
        IDP_DEVICE_LIST_SCOPE, IDP_DEVICE_LOOKUP_SCOPE, IDP_TOKEN_VALIDATE_SCOPE, IdentityAction,
        MANAGEMENT_PERMISSION_EVALUATE_SCOPE, TokenEndpointAuthMethod,
    },
    model::Id,
};
use idp_server::{AppConfig as IdpAppConfig, OwnerProvisioner};
use idp_service::oauth2::NodeSignerBinding;
use management_server::{AppConfig as ManagementAppConfig, MANAGEMENT_APPLICATION_URI};
use model::contract::{MANAGEMENT_REPLICATION_ADMIT_SCOPE, MANAGEMENT_REPLICATION_READ_SCOPE};
use serde_json::{Value, json};
use storage_server::AppConfig as StorageAppConfig;
use tauri::{AppHandle, Manager, Wry, async_runtime::Mutex};
use tokio::net::TcpListener;
use unified_server::{ServiceClientCredentials, UnifiedConfig, UnifiedEndpoint, UnifiedRuntime};

use crate::localhost_server::{
    LocalhostServer, localhost_server_base_url, reserve_localhost_listener,
    start_unified_localhost_server, verify_unified_localhost_server,
};
use crate::{local_api, service_secrets, service_secrets::ServiceRelationship, setup};

#[path = "setup_peer_revocation.rs"]
mod peer_revocation;
#[path = "setup_reset.rs"]
mod reset;

static SETUP_IDS_LOCK: StdMutex<()> = StdMutex::new(());
static SETUP_OPERATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SETUP_CANCELLATION: OnceLock<tokio::sync::watch::Sender<()>> = OnceLock::new();

fn setup_cancellation() -> &'static tokio::sync::watch::Sender<()> {
    SETUP_CANCELLATION.get_or_init(|| tokio::sync::watch::channel(()).0)
}

#[tauri::command]
pub fn cancel_installation_setup() {
    setup_cancellation().send_replace(());
}

const SETUP_READY_FILE: &str = "setup-ready";
const DEVICE_READY_FILE: &str = "device-setup-ready";

const INITIAL_ADMIN_ACTIONS: [IdentityAction; 24] = [
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

#[derive(Debug)]
struct SetupIds {
    installation_id: Id,
    administrator_id: Id,
    credential_id: Id,
    member_id: Id,
    signer_key_id: Id,
    role_id: Id,
    permission_ids: Vec<Id>,
    management_to_idp_client_id: Id,
    storage_to_idp_client_id: Id,
    storage_to_management_client_id: Id,
    idp_to_management_client_id: Id,
}

#[derive(Clone, Default)]
pub struct LocalhostServerState {
    pub base_url: String,
    pub ready: bool,
}

pub fn init_setup_router() -> Router {
    Router::new()
        .nest("/lidp", setup::router())
        .merge(local_api::router())
}

pub fn reject_legacy_state(app_data_dir: &Path, app_config_dir: &Path) -> io::Result<()> {
    for path in [
        app_data_dir.join("lidp.redb"),
        app_config_dir.join("lidp.redb"),
    ] {
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy shared IdP state is not supported at {}; reset it explicitly before setup",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn provision_initial_administrator(
    app_handle: AppHandle<Wry>,
    name: String,
    password: String,
) -> Result<String, String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    if name.trim().is_empty() || password.trim().is_empty() {
        return Err("administrator name and password are required".to_owned());
    }
    let app_data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;
    reject_legacy_state(&app_data_dir, &config_dir).map_err(|error| error.to_string())?;
    let base_url = localhost_server_base_url_for(&app_handle).await;
    if base_url.is_empty() {
        return Err("local HTTPS listener is not ready".to_owned());
    }
    if setup_ready(&app_data_dir).map_err(|error| error.to_string())? {
        return Err("Installation setup is already complete; use authenticated administration or explicit reset".into());
    }
    if fs::symlink_metadata(app_data_dir.join(reset::JOURNAL)).is_ok() {
        return Err("local reset is pending; retry reset before creating an Installation".into());
    }
    require_setup_runtime_stopped(&app_handle).await?;
    let ids = load_or_create_setup_ids(&app_data_dir).map_err(|error| error.to_string())?;
    persist_setup_intent(
        &app_data_dir,
        &json!({"purpose": "create", "issuer": format!("{base_url}/idp")}),
    )
    .map_err(|error| error.to_string())?;

    let mut idp_config = IdpAppConfig::default();
    idp_config.data_dir = app_data_dir
        .join("services/idp")
        .to_string_lossy()
        .into_owned();
    idp_config.oauth2.issuer = format!("{base_url}/idp");
    idp_config.api_public_uri = format!("{base_url}/idp");
    idp_config.ui_public_uri = base_url.clone();
    let (endpoint, fresh) = open_setup_endpoint(&app_data_dir, &idp_config)
        .await
        .map_err(|error| error.to_string())?;
    endpoint.close().await;
    let idp = OwnerProvisioner::open(&idp_config)
        .await
        .map_err(|error| error.to_string())?;
    prepare_setup_inventory(&idp, &ids, fresh)
        .await
        .map_err(|error| error.to_string())?;
    let administrator_id = idp
        .ensure_initial_user(ids.administrator_id, ids.credential_id, &name, &password)
        .await
        .map_err(|error| error.to_string())?;

    idp.ensure_initial_user_signing_key(administrator_id)
        .await
        .map_err(|error| error.to_string())?;

    let idp_service_audience = idp_config
        .service_audience
        .as_deref()
        .unwrap_or(&idp_config.api_public_uri)
        .to_owned();
    let storage_audience = format!("{base_url}/storage");
    let mut management_config = ManagementAppConfig::default();
    management_config.data_dir = app_data_dir
        .join("services/management")
        .to_string_lossy()
        .into_owned();
    management_config.storage_audience = storage_audience.clone();
    let permissions = INITIAL_ADMIN_ACTIONS
        .iter()
        .copied()
        .zip(ids.permission_ids.iter().copied())
        .map(|(action, permission_id)| (permission_id, action))
        .collect::<Vec<_>>();
    management_server::provision_initial_administrator(
        &management_config,
        administrator_id,
        ids.role_id,
        &permissions,
    )
    .await
    .map_err(|error| error.to_string())?;

    management_server::provision_initial_device(
        &management_config,
        ids.member_id,
        administrator_id,
    )
    .await
    .map_err(|error| error.to_string())?;
    idp.ensure_initial_node(
        &node_binding(&app_data_dir, &ids).map_err(|error| error.to_string())?,
        administrator_id,
        "Local Node",
    )
    .await
    .map_err(|error| error.to_string())?;
    provision_service_clients(
        &app_data_dir,
        &idp,
        &ids,
        &base_url,
        &idp_service_audience,
        &storage_audience,
    )
    .await
    .map_err(|error| error.to_string())?;
    drop(idp);
    close(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    let (listener, base_url) = reserve_unified_localhost_server(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    if let Err(error) = start_composed_unified_runtime(&app_handle, listener, base_url, true).await
    {
        let restore = restore_setup_listener(&app_handle).await;
        return match restore {
            Ok(()) => Err(error.to_string()),
            Err(restore_error) => Err(format!(
                "unified runtime startup failed ({error}); setup status listener restore failed ({restore_error})"
            )),
        };
    }

    Ok(administrator_id.to_string())
}

#[tauri::command]
pub fn get_setup_intent(app_handle: AppHandle<Wry>) -> Result<Option<Value>, String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    match fs::symlink_metadata(data_dir.join("node-setup.json")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
        Ok(_) => read_setup_intent(&data_dir)
            .map(Some)
            .map_err(|error| error.to_string()),
    }
}

#[tauri::command]
pub async fn join_installation(
    app_handle: AppHandle<Wry>,
    issuer: String,
    peer: String,
    name: String,
) -> Result<(), String> {
    let mut cancellation = setup_cancellation().subscribe();
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;
    reject_legacy_state(&data_dir, &config_dir).map_err(|error| error.to_string())?;
    if fs::symlink_metadata(data_dir.join(reset::JOURNAL)).is_ok() {
        return Err("local reset is pending; retry reset before joining".into());
    }
    if setup_ready(&data_dir).map_err(|error| error.to_string())? {
        return Err(
            "Installation setup is already complete; reset explicitly before joining".into(),
        );
    }
    let intent = json!({"purpose": "join", "issuer": issuer, "peer": peer, "name": name});
    validate_setup_intent(&intent).map_err(|error| error.to_string())?;
    let base_url = localhost_server_base_url_for(&app_handle).await;
    if base_url.is_empty() {
        return Err("local HTTPS setup listener is unavailable".into());
    }
    require_setup_runtime_stopped(&app_handle).await?;
    let ids = load_or_create_setup_ids(&data_dir).map_err(|error| error.to_string())?;
    persist_setup_intent(&data_dir, &intent).map_err(|error| error.to_string())?;
    let mut config = IdpAppConfig {
        data_dir: data_dir.join("services/idp").to_string_lossy().into_owned(),
        ..IdpAppConfig::default()
    };
    config.oauth2.issuer = issuer;
    config.api_public_uri = format!("{base_url}/idp");
    config.ui_public_uri = base_url.clone();
    let (endpoint, fresh) = open_setup_endpoint(&data_dir, &config)
        .await
        .map_err(|error| error.to_string())?;
    let result = tokio::select! {
        biased;
        _ = cancellation.changed() => Err(io::Error::new(io::ErrorKind::Interrupted, "join cancelled; retained setup can be retried or reset locally")),
        result = async {
        let binding = node_binding(&data_dir, &ids)?;
        let (protocol, owner) = unified_server::SecurityProtocol::open_node_bootstrap(
            &endpoint,
            &config,
            &data_dir.join("services/management"),
            binding,
        )
        .await?;
        prepare_setup_inventory(&owner, &ids, fresh).await?;
        protocol
            .join_from_trusted_peer(&owner, &name, &peer)
            .await?;
        provision_service_clients(
            &data_dir,
            &owner,
            &ids,
            &base_url,
            &format!("{base_url}/idp"),
            &format!("{base_url}/storage"),
        )
        .await
    } => result,
    };
    endpoint.close().await;
    result.map_err(|error| error.to_string())?;
    close(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    let (listener, base_url) = reserve_unified_localhost_server(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    if let Err(error) = start_composed_unified_runtime(&app_handle, listener, base_url, true).await
    {
        let restore = restore_setup_listener(&app_handle).await;
        return Err(match restore {
            Ok(()) => error.to_string(),
            Err(restore) => {
                format!("local runtime failed ({error}); setup listener restore failed ({restore})")
            }
        });
    }
    Ok(())
}

fn validate_setup_intent(value: &Value) -> io::Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| io::Error::other("Node setup intent must be an object"))?;
    let purpose = value["purpose"].as_str().unwrap_or_default();
    let expected = match purpose {
        "create" => &["purpose", "issuer"][..],
        "join" => &["purpose", "issuer", "peer", "name"][..],
        _ => {
            return Err(io::Error::other(
                "unsupported Node setup purpose; explicit reset required",
            ));
        }
    };
    if object.len() != expected.len()
        || expected.iter().any(|field| {
            value[*field]
                .as_str()
                .is_none_or(|text| text.trim().is_empty())
        })
    {
        return Err(io::Error::other(
            "invalid Node setup intent; explicit reset required",
        ));
    }
    if purpose == "join" {
        idp_server::NodeJoinRequest::validate_trusted_peer(
            value["peer"].as_str().expect("validated peer field"),
        )?;
        if value["name"].as_str().expect("validated name field").len() > 256 {
            return Err(io::Error::other("local Node name exceeds 256 bytes"));
        }
    }
    let issuer = reqwest::Url::parse(value["issuer"].as_str().expect("validated issuer field"))
        .map_err(io::Error::other)?;
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.fragment().is_some()
        || issuer.query().is_some()
    {
        return Err(io::Error::other(
            "canonical Installation issuer must be an HTTPS URL without credentials, query or fragment",
        ));
    }
    Ok(())
}

fn read_setup_intent(directory: &Path) -> io::Result<Value> {
    let path = directory.join("node-setup.json");
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(io::Error::other("Node setup intent must be a regular file"));
    }
    let value = serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)?;
    validate_setup_intent(&value)?;
    Ok(value)
}

fn persist_setup_intent(directory: &Path, value: &Value) -> io::Result<()> {
    validate_setup_intent(value)?;
    let path = directory.join("node-setup.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if read_setup_intent(directory)? != *value {
                return Err(io::Error::other(
                    "Node setup purpose or identity changed; explicit reset required",
                ));
            }
            fs::File::open(directory)?.sync_all()?;
            return reset::retain(directory);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    reset::prepare_provisioning(directory, value)?;
    let temporary = directory.join(format!(".node-setup-{}.tmp", Id::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &path) {
            Ok(()) => (),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    && read_setup_intent(directory)? == *value => {}
            Err(error) => return Err(error),
        }
        fs::File::open(directory)?.sync_all()
    })();
    let cleanup = fs::remove_file(temporary);
    result.and(cleanup)?;
    reset::retain(directory)
}

pub async fn restore_setup_listener(app_handle: &AppHandle<Wry>) -> io::Result<()> {
    let startup = async {
        let (listener, base_url) = reserve_unified_localhost_server(app_handle)
            .await
            .map_err(io::Error::other)?;
        init_unified_localhost_server(app_handle, init_setup_router(), listener, base_url.clone())
            .await
            .map_err(io::Error::other)?;
        crate::localhost_server::verify_localhost_server(&base_url).await
    }
    .await;
    finish_managed_startup(startup, close(app_handle)).await
}

async fn require_setup_runtime_stopped(app_handle: &AppHandle<Wry>) -> Result<(), String> {
    if let Some(runtime) = app_handle.try_state::<Mutex<Option<UnifiedRuntime>>>()
        && runtime.lock().await.is_some()
    {
        return Err(
            "local runtime is still active; use runtime retry or explicit reset before setup"
                .into(),
        );
    }
    Ok(())
}

async fn open_setup_endpoint(
    data: &Path,
    config: &IdpAppConfig,
) -> io::Result<(UnifiedEndpoint, bool)> {
    let fresh = reset::start_provisioning(data)?;
    let directory = data.join("services/unified-endpoint");
    let endpoint = if fresh {
        fs::create_dir_all(data.join("services"))?;
        let endpoint = UnifiedEndpoint::open_fresh(&directory, config).await?;
        if let Err(error) = reset::retain_endpoint(data, &endpoint.endpoint_id().to_string()) {
            endpoint.close().await;
            return Err(error);
        }
        endpoint
    } else {
        let expected = reset::retained_endpoint(data)?;
        if UnifiedEndpoint::persisted_endpoint_id(&directory)?.to_string() != expected {
            return Err(io::Error::other(
                "endpoint identity conflicts with original setup attempt",
            ));
        }
        let endpoint = UnifiedEndpoint::open(&directory, config).await?;
        if endpoint.endpoint_id().to_string() != expected {
            endpoint.close().await;
            return Err(io::Error::other(
                "endpoint identity conflicts with original setup attempt",
            ));
        }
        endpoint
    };
    Ok((endpoint, fresh))
}

async fn prepare_setup_inventory(
    owner: &OwnerProvisioner,
    ids: &SetupIds,
    fresh: bool,
) -> io::Result<()> {
    let clients = setup_client_ids(ids);
    if fresh {
        owner
            .prepare_fresh_setup_secret_inventory(ids.administrator_id, &clients)
            .await?;
    }
    owner.prepare_setup_client_slots(&clients).await
}

fn setup_client_ids(ids: &SetupIds) -> [Id; 5] {
    [
        ids.installation_id,
        ids.management_to_idp_client_id,
        ids.storage_to_idp_client_id,
        ids.storage_to_management_client_id,
        ids.idp_to_management_client_id,
    ]
}

async fn provision_service_clients(
    data: &Path,
    idp: &OwnerProvisioner,
    ids: &SetupIds,
    base_url: &str,
    idp_audience: &str,
    storage_audience: &str,
) -> io::Result<()> {
    idp.ensure_desktop_client(ids.installation_id).await?;
    for (relationship, client_id) in [
        (
            ServiceRelationship::ManagementToIdp,
            ids.management_to_idp_client_id,
        ),
        (
            ServiceRelationship::StorageToIdp,
            ids.storage_to_idp_client_id,
        ),
        (
            ServiceRelationship::StorageToManagement,
            ids.storage_to_management_client_id,
        ),
        (
            ServiceRelationship::IdpToManagement,
            ids.idp_to_management_client_id,
        ),
    ] {
        provision_service_client(
            data,
            idp,
            ids,
            relationship,
            client_id,
            base_url,
            idp_audience,
            storage_audience,
        )
        .await?;
    }
    Ok(())
}

async fn provision_service_client(
    data: &Path,
    idp: &OwnerProvisioner,
    ids: &SetupIds,
    relationship: ServiceRelationship,
    client_id: Id,
    base_url: &str,
    idp_audience: &str,
    storage_audience: &str,
) -> io::Result<()> {
    let never_produced =
        reset::start_relationship_provisioning(data, ids.installation_id, relationship, client_id)?;
    let client_secret = service_secrets::ensure_secret(
        ids.installation_id,
        relationship,
        client_id,
        never_produced,
    )
    .map_err(|error| {
        io::Error::other(format!(
            "could not persist {} credential: {error}",
            relationship.key_name()
        ))
    })?;
    idp.ensure_setup_infrastructure_client(service_client_registration(
        client_id,
        client_secret,
        relationship,
        base_url,
        idp_audience,
        storage_audience,
    ))
    .await?;
    Ok(())
}

fn unified_runtime_config(
    app_data_dir: &Path,
    listen_addr: SocketAddr,
    base_url: &str,
    ids: &SetupIds,
) -> io::Result<UnifiedConfig> {
    let idp_api = format!("{base_url}/idp");
    let management_api = format!("{base_url}/management");
    let storage_api = format!("{base_url}/storage");
    let mut idp = IdpAppConfig::default();
    idp.data_dir = app_data_dir
        .join("services/idp")
        .to_string_lossy()
        .into_owned();
    idp.oauth2.issuer = read_setup_intent(app_data_dir)?["issuer"]
        .as_str()
        .expect("validated canonical issuer")
        .to_owned();
    idp.oauth2.local_signer = Some(node_binding(app_data_dir, ids)?);
    idp.api_public_uri = idp_api.clone();
    idp.service_audience = Some(idp_api.clone());
    idp.ui_public_uri = base_url.to_owned();

    let mut management = ManagementAppConfig::default();
    management.data_dir = app_data_dir
        .join("services/management")
        .to_string_lossy()
        .into_owned();
    management.api_public_uri = management_api;
    management.idp_api_base = idp_api.clone();
    management.storage_api_base = storage_api.clone();
    management.expected_issuer = idp.oauth2.issuer.clone();
    management.storage_audience = storage_api.clone();
    management.idp_permission_evaluator_client_id =
        Some(ids.idp_to_management_client_id.to_string());

    let mut storage = StorageAppConfig::default();
    storage.data_dir = app_data_dir
        .join("services/storage")
        .to_string_lossy()
        .into_owned();
    storage.api_public_uri = storage_api.clone();

    let management_idp_client = load_service_credentials(
        ids,
        ServiceRelationship::ManagementToIdp,
        ids.management_to_idp_client_id,
        &idp_api,
    )?;
    let storage_idp_client = load_service_credentials(
        ids,
        ServiceRelationship::StorageToIdp,
        ids.storage_to_idp_client_id,
        &idp_api,
    )?;
    let storage_management_client = load_service_credentials(
        ids,
        ServiceRelationship::StorageToManagement,
        ids.storage_to_management_client_id,
        &storage_api,
    )?;
    let idp_management_client = load_service_credentials(
        ids,
        ServiceRelationship::IdpToManagement,
        ids.idp_to_management_client_id,
        MANAGEMENT_APPLICATION_URI,
    )?;

    Ok(UnifiedConfig {
        listen_addr,
        endpoint_data_dir: app_data_dir.join("services/unified-endpoint"),
        idp,
        management,
        storage,
        management_idp_client,
        storage_idp_client,
        storage_management_client,
        idp_management_client: Some(idp_management_client),
    })
}

fn node_binding(app_data_dir: &Path, ids: &SetupIds) -> io::Result<NodeSignerBinding> {
    let endpoint_id =
        UnifiedEndpoint::persisted_endpoint_id(&app_data_dir.join("services/unified-endpoint"))?
            .to_string();
    if endpoint_id != reset::retained_endpoint(app_data_dir)? {
        return Err(io::Error::other(
            "endpoint identity conflicts with original setup attempt",
        ));
    }
    Ok(NodeSignerBinding {
        member_id: ids.member_id,
        key_id: ids.signer_key_id,
        endpoint_id,
    })
}

fn load_service_credentials(
    ids: &SetupIds,
    relationship: ServiceRelationship,
    client_id: Id,
    audience: &str,
) -> io::Result<ServiceClientCredentials> {
    Ok(ServiceClientCredentials {
        client_id: client_id.to_string(),
        client_secret: service_secrets::load_secret(ids.installation_id, relationship, client_id)?,
        audience: audience.to_owned(),
    })
}

fn service_client_registration(
    client_id: Id,
    client_secret: String,
    relationship: ServiceRelationship,
    base_url: &str,
    idp_audience: &str,
    storage_audience: &str,
) -> ClientRegistration {
    let (application_name, path, client_name, audiences, scopes): (_, _, _, Vec<&str>, &[&str]) =
        match relationship {
            ServiceRelationship::ManagementToIdp => (
                "Management",
                "management",
                "Management service to IdP",
                vec![idp_audience, MANAGEMENT_APPLICATION_URI, storage_audience],
                &[IDP_TOKEN_VALIDATE_SCOPE, IDP_DEVICE_LOOKUP_SCOPE],
            ),
            ServiceRelationship::StorageToIdp => (
                "Storage",
                "storage",
                "Storage service to IdP",
                vec![idp_audience, "storage:databases", "storage:filesystems"],
                &[
                    IDP_TOKEN_VALIDATE_SCOPE,
                    IDP_DEVICE_LOOKUP_SCOPE,
                    IDP_DEVICE_LIST_SCOPE,
                ],
            ),
            ServiceRelationship::StorageToManagement => (
                "Storage",
                "storage",
                "Storage service to Management",
                vec![storage_audience],
                &[
                    MANAGEMENT_REPLICATION_READ_SCOPE,
                    MANAGEMENT_REPLICATION_ADMIT_SCOPE,
                ],
            ),
            ServiceRelationship::IdpToManagement => (
                "IdP",
                "idp",
                "IdP service to Management",
                vec![MANAGEMENT_APPLICATION_URI],
                &[MANAGEMENT_PERMISSION_EVALUATE_SCOPE],
            ),
        };
    ClientRegistration {
        application: ApplicationRegistration {
            name: Some(application_name.to_owned()),
            uri: format!("{base_url}/{path}"),
            description: Some(format!("{application_name} service identity")),
        },
        client_id: Some(client_id.to_string()),
        client_secret: Some(client_secret),
        client_id_issued_at: None,
        client_secret_expires_at: None,
        client_name: client_name.to_owned(),
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
        allowed_scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        allowed_audiences: audiences.into_iter().map(str::to_owned).collect(),
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        software_statement: None,
        software_id: None,
        software_version: None,
    }
}

pub fn setup_ready(app_data_dir: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(app_data_dir.join(reset::JOURNAL)) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    match fs::symlink_metadata(app_data_dir.join(SETUP_READY_FILE)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let ids = read_setup_ids(&app_data_dir.join("setup-ids.json"))?;
    crate::setup_completion::read(
        app_data_dir,
        SETUP_READY_FILE,
        &ids.installation_id.to_string(),
    )
}

pub async fn start_persisted_unified_runtime(
    app_handle: &AppHandle<Wry>,
    listener: TcpListener,
    base_url: String,
) -> io::Result<()> {
    start_composed_unified_runtime(app_handle, listener, base_url, false).await
}

async fn start_composed_unified_runtime(
    app_handle: &AppHandle<Wry>,
    listener: TcpListener,
    base_url: String,
    persist_ready: bool,
) -> io::Result<()> {
    let app_data_dir = app_handle.path().app_data_dir().map_err(io::Error::other)?;
    let ids = read_setup_ids(&app_data_dir.join("setup-ids.json"))?;
    crate::setup_completion::read(
        &app_data_dir,
        SETUP_READY_FILE,
        &ids.installation_id.to_string(),
    )?;
    let config = unified_runtime_config(&app_data_dir, listener.local_addr()?, &base_url, &ids)?;
    let mut runtime = UnifiedRuntime::build_on_listener(config, listener, base_url.clone()).await?;
    let startup = async {
        if !current_public_ready(&runtime, &app_data_dir).await? {
            return Err(io::Error::other(
                "current local trust, both public contexts and independent signer are required before starting a Node",
            ));
        }
        let router = runtime.router();
        let listener = runtime.take_listener()?;
        let server = start_unified_localhost_server(router, listener, &app_data_dir)
            .map_err(io::Error::other)?;
        set_localhost_server(app_handle, server).await;
        set_localhost_server_state(app_handle, base_url.clone(), true).await;
        verify_unified_localhost_server(&base_url).await?;
        runtime.start_background_tasks().await?;
        if persist_ready {
            crate::setup_completion::write(
                &app_data_dir,
                SETUP_READY_FILE,
                &ids.installation_id.to_string(),
            )?;
        }
        Ok(())
    }
    .await;
    let runtime = finish_runtime_startup(runtime, startup, close(app_handle)).await?;
    store_unified_runtime(app_handle, runtime).await;
    Ok(())
}

pub(crate) async fn finish_managed_startup<E>(
    startup: Result<(), E>,
    close_owners: impl core::future::Future<Output = io::Result<()>>,
) -> Result<(), E> {
    if startup.is_err()
        && let Err(cleanup_error) = close_owners.await
    {
        log::error!("desktop managed cleanup after startup failure: {cleanup_error}");
    }
    startup
}

async fn finish_runtime_startup(
    runtime: UnifiedRuntime,
    startup: io::Result<()>,
    close_listener: impl core::future::Future<Output = io::Result<()>>,
) -> io::Result<UnifiedRuntime> {
    if let Err(error) = startup {
        if let Err(cleanup_error) = close_listener.await {
            log::error!("desktop listener cleanup after startup failure: {cleanup_error}");
        }
        if let Err(cleanup_error) = runtime.shutdown().await {
            log::error!("desktop runtime cleanup after startup failure: {cleanup_error}");
        }
        return Err(error);
    }
    Ok(runtime)
}

#[cfg(all(test, unix))]
#[path = "desktop_lifecycle_tests.rs"]
mod desktop_lifecycle_tests;

async fn set_localhost_server(app_handle: &AppHandle<Wry>, server: LocalhostServer) {
    if let Some(state) = app_handle.try_state::<Mutex<Option<LocalhostServer>>>() {
        *state.lock().await = Some(server);
    } else {
        app_handle.manage(Mutex::new(Some(server)));
    }
}

async fn store_unified_runtime(app_handle: &AppHandle<Wry>, runtime: UnifiedRuntime) {
    if let Some(state) = app_handle.try_state::<Mutex<Option<UnifiedRuntime>>>() {
        *state.lock().await = Some(runtime);
    } else {
        app_handle.manage(Mutex::new(Some(runtime)));
    }
}

fn load_or_create_setup_ids(app_data_dir: &Path) -> io::Result<SetupIds> {
    let _guard = SETUP_IDS_LOCK
        .lock()
        .map_err(|_| io::Error::other("setup ID lock is poisoned"))?;
    let manifest_path = app_data_dir.join("setup-ids.json");
    match fs::symlink_metadata(&manifest_path) {
        Ok(_) => return read_setup_ids(&manifest_path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    for name in [
        "services",
        "node-setup.json",
        "setup-provisioning.json",
        "setup-reference-backup.json",
        reset::JOURNAL,
        "vaults",
        "storage-residency.json",
        SETUP_READY_FILE,
        DEVICE_READY_FILE,
    ] {
        let path = app_data_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "owner state exists without the setup manifest at {}; explicit reset is required",
                        path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }

    fs::create_dir_all(app_data_dir)?;
    let ids = SetupIds {
        installation_id: Id::now_v7(),
        administrator_id: Id::now_v7(),
        credential_id: Id::now_v7(),
        member_id: Id::now_v7(),
        signer_key_id: Id::now_v7(),
        role_id: Id::now_v7(),
        permission_ids: INITIAL_ADMIN_ACTIONS.iter().map(|_| Id::now_v7()).collect(),
        management_to_idp_client_id: Id::now_v7(),
        storage_to_idp_client_id: Id::now_v7(),
        storage_to_management_client_id: Id::now_v7(),
        idp_to_management_client_id: Id::now_v7(),
    };
    let value = json!({
        "version": 2,
        "intent_disposition": "unclaimed",
        "installation_id": ids.installation_id.to_string(),
        "administrator_id": ids.administrator_id.to_string(),
        "credential_id": ids.credential_id.to_string(),
        "member_id": ids.member_id.to_string(),
        "signer_key_id": ids.signer_key_id.to_string(),
        "role_id": ids.role_id.to_string(),
        "permission_ids": ids.permission_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "service_client_ids": {
            "management_to_idp": ids.management_to_idp_client_id.to_string(),
            "storage_to_idp": ids.storage_to_idp_client_id.to_string(),
            "storage_to_management": ids.storage_to_management_client_id.to_string(),
            "idp_to_management": ids.idp_to_management_client_id.to_string(),
        },
    });
    let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
    let temporary_path = app_data_dir.join(format!(".setup-ids-{}.tmp", ids.installation_id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::hard_link(&temporary_path, &manifest_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::File::open(app_data_dir)?.sync_all()?;
    fs::remove_file(&temporary_path)?;
    fs::File::open(app_data_dir)?.sync_all()?;
    Ok(ids)
}

fn read_setup_ids(path: &Path) -> io::Result<SetupIds> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup manifest must be a regular file; explicit recovery/reset required",
        ));
    }
    let value: Value = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("setup manifest is corrupt ({error}); explicit reset is required"),
        )
    })?;
    parse_setup_ids(&value)
}

fn parse_setup_ids(value: &Value) -> io::Result<SetupIds> {
    if value.get("version").and_then(Value::as_u64) != Some(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported setup manifest version; explicit reset is required",
        ));
    }
    let permission_ids = value
        .get("permission_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "setup permissions are missing"))?
        .iter()
        .map(|value| parse_setup_id(value, "permission ID"))
        .collect::<io::Result<Vec<_>>>()?;
    if permission_ids.len() != INITIAL_ADMIN_ACTIONS.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup manifest has the wrong permission count; explicit reset is required",
        ));
    }
    Ok(SetupIds {
        installation_id: parse_setup_id(
            value.get("installation_id").unwrap_or(&Value::Null),
            "installation ID",
        )?,
        administrator_id: parse_setup_id(
            value.get("administrator_id").unwrap_or(&Value::Null),
            "administrator ID",
        )?,
        credential_id: parse_setup_id(
            value.get("credential_id").unwrap_or(&Value::Null),
            "credential ID",
        )?,
        member_id: parse_setup_id(value.get("member_id").unwrap_or(&Value::Null), "member ID")?,
        signer_key_id: parse_setup_id(
            value.get("signer_key_id").unwrap_or(&Value::Null),
            "signer key ID",
        )?,
        role_id: parse_setup_id(value.get("role_id").unwrap_or(&Value::Null), "role ID")?,
        permission_ids,
        management_to_idp_client_id: parse_setup_id(
            value
                .get("service_client_ids")
                .and_then(|ids| ids.get("management_to_idp"))
                .unwrap_or(&Value::Null),
            "Management-to-IdP client ID",
        )?,
        storage_to_idp_client_id: parse_setup_id(
            value
                .get("service_client_ids")
                .and_then(|ids| ids.get("storage_to_idp"))
                .unwrap_or(&Value::Null),
            "Storage-to-IdP client ID",
        )?,
        storage_to_management_client_id: parse_setup_id(
            value
                .get("service_client_ids")
                .and_then(|ids| ids.get("storage_to_management"))
                .unwrap_or(&Value::Null),
            "Storage-to-Management client ID",
        )?,
        idp_to_management_client_id: parse_setup_id(
            value
                .get("service_client_ids")
                .and_then(|ids| ids.get("idp_to_management"))
                .unwrap_or(&Value::Null),
            "IdP-to-Management client ID",
        )?,
    })
}

fn parse_setup_id(value: &Value, label: &str) -> io::Result<Id> {
    value
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{label} is invalid")))?
        .parse()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} is invalid: {error}"),
            )
        })
}

#[tauri::command]
pub async fn get_localhost_server_base_url(app_handle: AppHandle<Wry>) -> String {
    localhost_server_base_url_for(&app_handle).await
}

async fn current_public_ready(runtime: &UnifiedRuntime, data_dir: &Path) -> io::Result<bool> {
    if read_setup_intent(data_dir)?["purpose"] == "join" {
        runtime.node_join_public_ready().await
    } else {
        runtime.node_public_ready().await
    }
}

#[tauri::command]
pub async fn node_join_accepting(
    app_handle: AppHandle<Wry>,
    bearer: String,
    accepting: Option<bool>,
) -> Result<bool, String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let state = app_handle
        .try_state::<Mutex<Option<UnifiedRuntime>>>()
        .ok_or("local runtime is unavailable")?;
    let guard = state.lock().await;
    guard
        .as_ref()
        .ok_or("local runtime is unavailable")?
        .node_join_accepting(&bearer, accepting)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn pending_node_joins(
    app_handle: AppHandle<Wry>,
    bearer: String,
) -> Result<serde_json::Value, String> {
    let state = app_handle
        .try_state::<Mutex<Option<UnifiedRuntime>>>()
        .ok_or("local runtime is unavailable")?;
    let guard = state.lock().await;
    guard
        .as_ref()
        .ok_or("local runtime is unavailable")?
        .pending_node_joins(&bearer)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn approve_pending_node_join(
    app_handle: AppHandle<Wry>,
    bearer: String,
    offer_id: String,
) -> Result<(), String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let state = app_handle
        .try_state::<Mutex<Option<UnifiedRuntime>>>()
        .ok_or("local runtime is unavailable")?;
    let guard = state.lock().await;
    guard
        .as_ref()
        .ok_or("local runtime is unavailable")?
        .approve_pending_node_join(
            &bearer,
            offer_id.parse::<Id>().map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn reject_pending_node_join(
    app_handle: AppHandle<Wry>,
    bearer: String,
    offer_id: String,
) -> Result<(), String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let state = app_handle
        .try_state::<Mutex<Option<UnifiedRuntime>>>()
        .ok_or("local runtime is unavailable")?;
    let guard = state.lock().await;
    guard
        .as_ref()
        .ok_or("local runtime is unavailable")?
        .reject_pending_node_join(
            &bearer,
            offer_id.parse::<Id>().map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn get_setup_stage(app_handle: AppHandle<Wry>) -> Result<String, String> {
    let app_data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let contexts_ready = match app_handle.try_state::<Mutex<Option<UnifiedRuntime>>>() {
        Some(runtime) => match runtime.lock().await.as_ref() {
            Some(runtime) => current_public_ready(runtime, &app_data_dir)
                .await
                .map_err(|error| error.to_string())?,
            None => false,
        },
        None => false,
    } && !localhost_server_base_url_for(&app_handle).await.is_empty();
    local_setup_stage(&app_data_dir, contexts_ready).map_err(|error| error.to_string())
}

fn local_setup_stage(data_dir: &Path, contexts_ready: bool) -> io::Result<String> {
    if !setup_ready(data_dir)? {
        return Ok("installation".into());
    }
    if !contexts_ready {
        return Ok("unavailable".into());
    }
    let ids = read_setup_ids(&data_dir.join("setup-ids.json"))?;
    crate::setup_completion::read(
        data_dir,
        DEVICE_READY_FILE,
        &ids.installation_id.to_string(),
    )
    .map(|complete| if complete { "ready" } else { "device" }.to_owned())
}

#[tauri::command]
pub async fn retry_local_runtime(app_handle: AppHandle<Wry>) -> Result<(), String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    if !setup_ready(&data_dir).map_err(|error| error.to_string())? {
        return Err("Installation setup is incomplete or reset is pending".into());
    }
    close(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    let result = async {
        let (listener, base_url) = reserve_unified_localhost_server(&app_handle)
            .await
            .map_err(io::Error::other)?;
        start_persisted_unified_runtime(&app_handle, listener, base_url).await
    }
    .await;
    if let Err(error) = result {
        return Err(match restore_setup_listener(&app_handle).await {
            Ok(()) => {
                format!("local services remain unavailable; persisted setup retained: {error}")
            }
            Err(restore) => format!(
                "local services unavailable ({error}); setup listener restore failed ({restore})"
            ),
        });
    }
    Ok(())
}

#[tauri::command]
pub async fn complete_device_setup(app_handle: AppHandle<Wry>) -> Result<(), String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    if !setup_ready(&data_dir).map_err(|error| error.to_string())? {
        return Err("Installation setup is incomplete".into());
    }
    let ids =
        read_setup_ids(&data_dir.join("setup-ids.json")).map_err(|error| error.to_string())?;
    let base_url = localhost_server_base_url_for(&app_handle).await;
    let Some(runtime) = app_handle.try_state::<Mutex<Option<UnifiedRuntime>>>() else {
        return Err("all three local contexts must be running before Device completion".into());
    };
    let ready = match runtime.lock().await.as_ref() {
        Some(runtime) => current_public_ready(runtime, &data_dir)
            .await
            .map_err(|error| error.to_string())?,
        None => false,
    };
    if !ready || base_url.is_empty() {
        return Err(
            "local services or current Node trust are unavailable; Device setup remains incomplete"
                .into(),
        );
    }
    verify_unified_localhost_server(&base_url)
        .await
        .map_err(|error| error.to_string())?;
    crate::setup_completion::write(
        &data_dir,
        DEVICE_READY_FILE,
        &ids.installation_id.to_string(),
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn get_desktop_client_id(app_handle: AppHandle<Wry>) -> Result<String, String> {
    let data = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    read_setup_ids(&data.join("setup-ids.json"))
        .map(|ids| ids.installation_id.to_string())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn recover_reset_references(app_handle: AppHandle<Wry>) -> Result<(), String> {
    cancel_installation_setup();
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let config = app_handle
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;
    reset::recover(&data, &config).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn pending_reset_revocations(app_handle: AppHandle<Wry>) -> Result<Value, String> {
    let data = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let mut targets = reset::revocations(&data).map_err(|error| error.to_string())?;
    if let Ok(references) = reset::recovery_references(&data) {
        let ids = parse_setup_ids(&references["ids"]).map_err(|error| error.to_string())?;
        let member = ids.member_id.to_string();
        if !targets.iter().any(|target| target["member_id"] == member) {
            targets.push(json!({"version":1,"issuer":references["issuer"],"member_id":member,"status":"pending"}));
        }
    }
    Ok(Value::Array(targets))
}

#[tauri::command]
pub async fn revoke_reset_on_peer(
    app_handle: AppHandle<Wry>,
    peer_api: String,
    bearer: String,
    member_id: Id,
) -> Result<(), String> {
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let local_api = format!("{}/idp", localhost_server_base_url_for(&app_handle).await);
    let client = peer_revocation::client_builder()
        .build()
        .map_err(|error| error.to_string())?;
    peer_revocation::revoke(&data, &local_api, &peer_api, &bearer, member_id, &client).await
}

#[tauri::command]
pub async fn reset_device(app_handle: AppHandle<Wry>) -> Result<(), String> {
    cancel_installation_setup();
    let _operation = SETUP_OPERATION_LOCK.lock().await;
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;

    reset::begin(&data_dir, &config_dir).map_err(|error| error.to_string())?;
    let result = async {
        close(&app_handle).await?;
        let data = &data_dir;
        reset::run(&data_dir, &config_dir, |references| {
            delete_setup_secrets(data, references)
        })
        .await
    }
    .await;
    if let Err(error) = result {
        return Err(match restore_setup_listener(&app_handle).await {
            Ok(()) => format!("local reset remains pending; retry reset: {error}"),
            Err(restore) => format!(
                "local reset remains pending ({error}); setup listener restore failed ({restore})"
            ),
        });
    }
    app_handle.exit(0);
    Ok(())
}

async fn delete_setup_secrets(data: &Path, references: reset::ResetSecrets) -> io::Result<()> {
    let ids = references.ids;
    let mut config = IdpAppConfig {
        data_dir: data.join("services/idp").to_string_lossy().into_owned(),
        ..IdpAppConfig::default()
    };
    config.oauth2.issuer = references.issuer;
    let owner = OwnerProvisioner::open(&config).await?;

    owner
        .delete_local_secrets(
            ids.member_id,
            ids.signer_key_id,
            ids.administrator_id,
            &setup_client_ids(&ids),
        )
        .await?;
    for (relationship, client_id) in [
        (
            ServiceRelationship::ManagementToIdp,
            ids.management_to_idp_client_id,
        ),
        (
            ServiceRelationship::StorageToIdp,
            ids.storage_to_idp_client_id,
        ),
        (
            ServiceRelationship::StorageToManagement,
            ids.storage_to_management_client_id,
        ),
        (
            ServiceRelationship::IdpToManagement,
            ids.idp_to_management_client_id,
        ),
    ] {
        service_secrets::delete_secret(ids.installation_id, relationship, client_id)?;
    }
    Ok(())
}

pub async fn localhost_server_base_url_for(app_handle: &AppHandle<Wry>) -> String {
    if let Some(state) = app_handle.try_state::<Mutex<LocalhostServerState>>() {
        let state = state.lock().await;
        if state.ready {
            state.base_url.clone()
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

pub async fn set_localhost_server_state(
    app_handle: &AppHandle<Wry>,
    base_url: String,
    ready: bool,
) {
    if let Some(state) = app_handle.try_state::<Mutex<LocalhostServerState>>() {
        *state.lock().await = LocalhostServerState { base_url, ready };
    } else {
        app_handle.manage(Mutex::new(LocalhostServerState { base_url, ready }));
    }
}

pub async fn init_unified_localhost_server(
    app_handle: &AppHandle<Wry>,
    router: Router,
    listener: TcpListener,
    base_url: String,
) -> tauri::Result<String> {
    let data_dir = app_handle.path().app_data_dir()?;
    let server = start_unified_localhost_server(router, listener, &data_dir)
        .map_err(|error| tauri::Error::Io(io::Error::other(error)))?;
    set_localhost_server(app_handle, server).await;

    set_localhost_server_state(app_handle, base_url.clone(), true).await;
    Ok(base_url)
}

pub async fn reserve_unified_localhost_server(
    app_handle: &AppHandle<Wry>,
) -> tauri::Result<(TcpListener, String)> {
    let app_data_dir = app_handle.path().app_data_dir()?;
    let (listener, port) = reserve_localhost_listener(&app_data_dir)
        .await
        .map_err(|error| tauri::Error::Io(io::Error::other(error)))?;
    Ok((listener, localhost_server_base_url(port)))
}

pub async fn close(app_handle: &AppHandle<Wry>) -> io::Result<()> {
    set_localhost_server_state(app_handle, String::new(), false).await;
    let mut shutdown_error = None;
    if let Some(server) = app_handle.try_state::<Mutex<Option<LocalhostServer>>>() {
        if let Some(server) = server.lock().await.take()
            && let Err(error) = server.close().await
        {
            shutdown_error = Some(error);
        }
    }
    if let Some(runtime) = app_handle.try_state::<Mutex<Option<UnifiedRuntime>>>() {
        if let Some(runtime) = runtime.lock().await.take()
            && let Err(error) = runtime.shutdown().await
        {
            shutdown_error.get_or_insert(error);
        }
    }

    match shutdown_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "setup_peer_revocation_tests.rs"]
mod peer_revocation_tests;

#[cfg(test)]
#[path = "service_relationship_tests.rs"]
mod service_relationship_tests;

#[cfg(test)]
mod tests {
    use std::fs;

    use idp_model::model::Id;

    use super::{SETUP_READY_FILE, load_or_create_setup_ids, reject_legacy_state, setup_ready};

    #[tokio::test]
    async fn owner_cutover_endpoint_attempt_is_one_shot_and_retry_never_replaces_identity() {
        let root = std::env::temp_dir().join(format!("owner-cutover-endpoint-{}", Id::now_v7()));
        let ids = load_or_create_setup_ids(&root).expect("original identities");
        super::persist_setup_intent(
            &root,
            &serde_json::json!({"purpose":"create", "issuer":"https://cutover.test/idp"}),
        )
        .expect("positive fresh intent");
        let config = super::IdpAppConfig {
            data_dir: root.join("services/idp").to_string_lossy().into_owned(),
            ..super::IdpAppConfig::default()
        };
        let (endpoint, fresh) = super::open_setup_endpoint(&root, &config)
            .await
            .expect("fresh native startup");
        assert!(fresh);
        let identity = endpoint.endpoint_id();
        endpoint.close().await;
        let owner = super::OwnerProvisioner::open(&config)
            .await
            .expect("native owner");
        owner
            .prepare_fresh_setup_secret_inventory(
                ids.administrator_id,
                &super::setup_client_ids(&ids),
            )
            .await
            .expect("fresh inventory before private work");
        owner
            .prepare_setup_client_slots(&super::setup_client_ids(&ids))
            .await
            .expect("exact slots");
        drop(owner);
        let (endpoint, fresh) = super::open_setup_endpoint(&root, &config)
            .await
            .expect("native reopen");
        assert!(!fresh);
        assert_eq!(endpoint.endpoint_id(), identity);
        endpoint.close().await;
        let path = root.join("services/unified-endpoint/endpoint.key");
        let original = fs::read(&path).expect("canonical identity");
        fs::remove_file(&path).expect("lose identity after known attempt");
        assert!(super::open_setup_endpoint(&root, &config).await.is_err());
        assert!(
            !path.exists(),
            "retry must not mint replacement private state"
        );
        fs::write(&path, &original).expect("restore original identity");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure original identity");
        }
        let (endpoint, fresh) = super::open_setup_endpoint(&root, &config)
            .await
            .expect("exact restored retry");
        assert!(!fresh);
        assert_eq!(endpoint.endpoint_id(), identity);
        endpoint.close().await;
        let other = super::UnifiedEndpoint::open_fresh(&root.join("different-endpoint"), &config)
            .await
            .expect("independent identity fixture");
        other.close().await;
        let replacement = fs::read(root.join("different-endpoint/endpoint.key"))
            .expect("different canonical identity");
        fs::write(&path, &replacement).expect("simulate canonical identity replacement");
        assert!(super::open_setup_endpoint(&root, &config).await.is_err());
        assert!(super::node_binding(&root, &ids).is_err());
        assert_eq!(
            fs::read(&path).expect("no mutation on refusal"),
            replacement
        );
        fs::write(&path, &original).expect("restore exact original fixture");
        fs::remove_dir_all(root).expect("owned no-private-write fixture cleanup");
    }

    #[tokio::test]
    async fn owner_cutover_unknown_attempts_and_lost_inventory_fail_closed() {
        for case in [
            "before-endpoint",
            "before-inventory",
            "lost-inventory",
            "lost-stage",
            "unknown-ids",
        ] {
            let root = std::env::temp_dir().join(format!("owner-cutover-{case}-{}", Id::now_v7()));
            let ids = load_or_create_setup_ids(&root).expect("original identities");
            let intent =
                serde_json::json!({"purpose":"create", "issuer":"https://cutover.test/idp"});
            super::persist_setup_intent(&root, &intent).expect("positive original intent");
            let config = super::IdpAppConfig {
                data_dir: root.join("services/idp").to_string_lossy().into_owned(),
                ..super::IdpAppConfig::default()
            };
            if case == "before-endpoint" {
                assert!(super::reset::start_provisioning(&root).expect("consume attempt"));
                assert!(super::open_setup_endpoint(&root, &config).await.is_err());
                assert!(!root.join("services").exists());
            } else if case == "unknown-ids" {
                fs::remove_file(root.join("setup-ids.json")).expect("lose identities");
                assert!(load_or_create_setup_ids(&root).is_err());
                assert!(!root.join("setup-ids.json").exists());
            } else {
                let (endpoint, fresh) = super::open_setup_endpoint(&root, &config)
                    .await
                    .expect("original endpoint");
                assert!(fresh);
                endpoint.close().await;
                let key = fs::read(root.join("services/unified-endpoint/endpoint.key"))
                    .expect("original key");
                let owner = super::OwnerProvisioner::open(&config)
                    .await
                    .expect("native owner without private work");
                if case != "before-inventory" {
                    super::prepare_setup_inventory(&owner, &ids, fresh)
                        .await
                        .expect("original inventory");
                }
                drop(owner);
                if case == "lost-inventory" {
                    fs::remove_file(root.join("services/idp/setup-secret-inventory.json"))
                        .expect("lose inventory");
                }
                if case == "lost-stage" {
                    fs::remove_file(root.join("setup-provisioning.json"))
                        .expect("lose attempt evidence");
                    assert!(super::open_setup_endpoint(&root, &config).await.is_err());
                } else {
                    let (endpoint, fresh) = super::open_setup_endpoint(&root, &config)
                        .await
                        .expect("existing endpoint only");
                    assert!(!fresh);
                    endpoint.close().await;
                    let owner = super::OwnerProvisioner::open(&config)
                        .await
                        .expect("native owner reopen");
                    assert!(
                        super::prepare_setup_inventory(&owner, &ids, fresh)
                            .await
                            .is_err()
                    );
                    assert!(
                        !root
                            .join("services/idp/setup-secret-inventory.json")
                            .exists()
                    );
                    drop(owner);
                }
                assert_eq!(
                    fs::read(root.join("services/unified-endpoint/endpoint.key"))
                        .expect("unchanged key"),
                    key
                );
            }
            assert!(root.join("node-setup.json").is_file());
            fs::remove_dir_all(root).expect("owned fixture with no private owner writes");
        }
    }

    #[tokio::test]
    #[ignore = "writes isolated initial owner and relationship credentials to the real OS provider"]
    async fn owner_cutover_native_startup_retry_and_reset() {
        let _operation = super::SETUP_OPERATION_LOCK.lock().await;
        let root = std::env::temp_dir().join(format!("owner-cutover-native-{}", Id::now_v7()));
        let data = root.join("data");
        let config_dir = root.join("config");
        let ids = load_or_create_setup_ids(&data).expect("original setup identities");
        let listener = super::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("native listener");
        let address = listener.local_addr().expect("listener address");
        let base = format!("http://{address}");
        let issuer = format!("https://{}.test/idp", ids.installation_id);
        super::persist_setup_intent(
            &data,
            &serde_json::json!({"purpose":"create", "issuer":issuer}),
        )
        .expect("positive fresh intent");
        let mut config = super::IdpAppConfig {
            data_dir: data.join("services/idp").to_string_lossy().into_owned(),
            ..super::IdpAppConfig::default()
        };
        config.oauth2.issuer = issuer;
        config.api_public_uri = format!("{base}/idp");
        let (endpoint, fresh) = super::open_setup_endpoint(&data, &config)
            .await
            .expect("fresh native endpoint");
        let endpoint_id = endpoint.endpoint_id();
        endpoint.close().await;
        let owner = super::OwnerProvisioner::open(&config)
            .await
            .expect("native IdP owner and OS private provider");
        super::prepare_setup_inventory(&owner, &ids, fresh)
            .await
            .expect("inventory before private work");
        owner
            .ensure_initial_user(
                ids.administrator_id,
                ids.credential_id,
                "cutover-admin",
                "isolated-cutover-password",
            )
            .await
            .expect("initial User");
        owner
            .ensure_initial_user_signing_key(ids.administrator_id)
            .await
            .expect("captured initial User key");
        let management = super::ManagementAppConfig {
            data_dir: data
                .join("services/management")
                .to_string_lossy()
                .into_owned(),
            ..super::ManagementAppConfig::default()
        };
        let permissions = super::INITIAL_ADMIN_ACTIONS
            .iter()
            .copied()
            .zip(ids.permission_ids.iter().copied())
            .map(|(action, id)| (id, action))
            .collect::<Vec<_>>();
        management_server::provision_initial_administrator(
            &management,
            ids.administrator_id,
            ids.role_id,
            &permissions,
        )
        .await
        .expect("native Management administrator");
        management_server::provision_initial_device(
            &management,
            ids.member_id,
            ids.administrator_id,
        )
        .await
        .expect("native Device");
        let binding = super::node_binding(&data, &ids).expect("retained endpoint binding");
        owner
            .ensure_initial_node(&binding, ids.administrator_id, "Cutover Node")
            .await
            .expect("initial Node signer");
        let signer = owner
            .verify_node_signer(&binding)
            .await
            .expect("independent signer");
        super::provision_service_clients(
            &data,
            &owner,
            &ids,
            &base,
            &format!("{base}/idp"),
            &format!("{base}/storage"),
        )
        .await
        .expect("captured five initial Clients and exact relationship credentials");
        let relationship = super::service_secrets::load_secret(
            ids.installation_id,
            super::ServiceRelationship::ManagementToIdp,
            ids.management_to_idp_client_id,
        )
        .expect("retained relationship secret");
        drop(owner);
        let (endpoint, fresh) = super::open_setup_endpoint(&data, &config)
            .await
            .expect("ordinary native retry");
        assert!(!fresh);
        assert_eq!(endpoint.endpoint_id(), endpoint_id);
        endpoint.close().await;
        let owner = super::OwnerProvisioner::open(&config)
            .await
            .expect("owner reopen");
        super::prepare_setup_inventory(&owner, &ids, fresh)
            .await
            .expect("continuation uses only exact slots");
        owner
            .ensure_initial_user_signing_key(ids.administrator_id)
            .await
            .expect("same User key");
        super::provision_service_clients(
            &data,
            &owner,
            &ids,
            &base,
            &format!("{base}/idp"),
            &format!("{base}/storage"),
        )
        .await
        .expect("exact service retry without a second pending begin");
        assert_eq!(
            owner
                .verify_node_signer(&binding)
                .await
                .expect("same native signer"),
            signer
        );
        assert_eq!(
            super::service_secrets::load_secret(
                ids.installation_id,
                super::ServiceRelationship::ManagementToIdp,
                ids.management_to_idp_client_id
            )
            .expect("same relationship"),
            relationship
        );
        super::service_secrets::delete_secret(
            ids.installation_id,
            super::ServiceRelationship::ManagementToIdp,
            ids.management_to_idp_client_id,
        )
        .expect("simulate loss after resolved Client provisioning");
        let missing_retry = super::provision_service_clients(
            &data,
            &owner,
            &ids,
            &base,
            &format!("{base}/idp"),
            &format!("{base}/storage"),
        )
        .await;
        let replacement = super::service_secrets::load_secret(
            ids.installation_id,
            super::ServiceRelationship::ManagementToIdp,
            ids.management_to_idp_client_id,
        );
        idp_service::repo::RawKeyringRepo::new("local.unified-service-credentials")
            .expect("isolated fixture provider")
            .store(
                &ids.installation_id.to_string(),
                &ids.management_to_idp_client_id.to_string(),
                "management-to-idp",
                relationship.as_bytes(),
            )
            .expect("restore exact original fixture credential, not a replacement");
        let error = missing_retry.expect_err("historical missing relationship refuses app retry");
        assert!(error.to_string().contains("replacement is not authorized"));
        assert!(
            replacement.is_err(),
            "app retry must not write a replacement"
        );
        super::provision_service_clients(
            &data,
            &owner,
            &ids,
            &base,
            &format!("{base}/idp"),
            &format!("{base}/storage"),
        )
        .await
        .expect("restored original credential permits exact retry");
        drop(owner);
        let runtime_config = super::unified_runtime_config(&data, address, &base, &ids)
            .expect("real desktop host configuration");
        let runtime =
            super::UnifiedRuntime::build_on_listener(runtime_config, listener, base.clone())
                .await
                .expect("real existing-only native host startup");
        assert!(
            super::current_public_ready(&runtime, &data)
                .await
                .expect("current public readiness, not markers")
        );
        runtime.shutdown().await.expect("native host shutdown");
        let listener = super::TcpListener::bind(address)
            .await
            .expect("same native listener after shutdown");
        let runtime_config = super::unified_runtime_config(&data, address, &base, &ids)
            .expect("persisted host configuration");
        let runtime = super::UnifiedRuntime::build_on_listener(runtime_config, listener, base)
            .await
            .expect("offline native host reopen");
        assert!(
            super::current_public_ready(&runtime, &data)
                .await
                .expect("offline public readiness")
        );
        runtime.shutdown().await.expect("reopened host shutdown");
        super::reset::begin(&data, &config_dir).expect("explicit reset");
        assert!(
            super::open_setup_endpoint(&data, &config).await.is_err(),
            "pending reset bars owner commands"
        );
        let owner_config = &config;
        super::reset::run(&data, &config_dir, |references| async move {
            let owner = super::OwnerProvisioner::open(owner_config).await?;
            owner
                .delete_local_secrets(
                    references.ids.member_id,
                    references.ids.signer_key_id,
                    references.ids.administrator_id,
                    &super::setup_client_ids(&references.ids),
                )
                .await?;
            Err(std::io::Error::other(
                "interrupted before relationship deletion",
            ))
        })
        .await
        .expect_err("partial real secret cleanup must retain all owner references");
        assert!(data.join(super::reset::JOURNAL).is_file());
        assert!(
            data.join("services/idp/setup-secret-inventory.json")
                .is_file()
        );
        let owner = super::OwnerProvisioner::open(&config)
            .await
            .expect("native reopen after private deletion");
        assert!(owner.verify_node_signer(&binding).await.is_err());
        assert!(
            owner
                .ensure_initial_node(&binding, ids.administrator_id, "Cutover Node")
                .await
                .is_err(),
            "approved missing signer must not be replaced"
        );
        assert!(
            owner
                .ensure_initial_user_signing_key(ids.administrator_id)
                .await
                .is_err(),
            "published missing User key must not be replaced"
        );
        assert!(
            owner
                .ensure_desktop_client(ids.installation_id)
                .await
                .is_err(),
            "published missing Client key must not be replaced"
        );
        assert_eq!(
            super::service_secrets::load_secret(
                ids.installation_id,
                super::ServiceRelationship::ManagementToIdp,
                ids.management_to_idp_client_id
            )
            .expect("relationship credential retained for cleanup retry"),
            relationship
        );
        drop(owner);
        super::reset::run(&data, &config_dir, |references| {
            super::delete_setup_secrets(&data, references)
        })
        .await
        .expect("real native and relationship deletion/readback retry before owner removal");
        assert!(!data.join("services").exists());
        assert!(!data.join("setup-ids.json").exists());
        assert!(
            super::service_secrets::load_secret(
                ids.installation_id,
                super::ServiceRelationship::ManagementToIdp,
                ids.management_to_idp_client_id
            )
            .is_err()
        );
        fs::remove_dir_all(root).expect("owned native fixture cleanup after secret cleanup");
    }

    #[tokio::test]
    #[ignore = "writes isolated pending join signer credentials to the real OS provider"]
    async fn owner_cutover_native_join_preparation_retry_and_reset() {
        let _operation = super::SETUP_OPERATION_LOCK.lock().await;
        let root = std::env::temp_dir().join(format!("owner-cutover-join-{}", Id::now_v7()));
        let data = root.join("data");
        let config_dir = root.join("config");
        let ids = load_or_create_setup_ids(&data).expect("original join identities");
        let peer = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let issuer = format!("https://{}.test/idp", ids.installation_id);
        super::persist_setup_intent(&data, &serde_json::json!({"purpose":"join", "issuer":issuer, "peer":peer, "name":"Cutover join"})).expect("positive fresh join intent");
        let mut config = super::IdpAppConfig {
            data_dir: data.join("services/idp").to_string_lossy().into_owned(),
            ..super::IdpAppConfig::default()
        };
        config.oauth2.issuer = issuer;
        let (endpoint, fresh) = super::open_setup_endpoint(&data, &config)
            .await
            .expect("fresh joining endpoint");
        let binding = super::node_binding(&data, &ids).expect("original retained binding");
        let (protocol, owner) = unified_server::SecurityProtocol::open_node_bootstrap(
            &endpoint,
            &config,
            &data.join("services/management"),
            binding.clone(),
        )
        .await
        .expect("actual native join bootstrap");
        super::prepare_setup_inventory(&owner, &ids, fresh)
            .await
            .expect("complete inventory before join signer");
        let request = owner
            .prepare_node_join(
                &binding,
                "Cutover join",
                peer.parse().expect("explicit trusted peer"),
            )
            .expect("retained join request and private signer");
        assert!(!setup_ready(&data).expect("join preparation is not completion"));
        assert!(
            owner.verify_node_signer(&binding).await.is_err(),
            "private preparation is not public approval"
        );
        drop(protocol);
        drop(owner);
        endpoint.close().await;
        let (endpoint, fresh) = super::open_setup_endpoint(&data, &config)
            .await
            .expect("existing joining endpoint");
        assert!(!fresh);
        let (protocol, owner) = unified_server::SecurityProtocol::open_node_bootstrap(
            &endpoint,
            &config,
            &data.join("services/management"),
            binding.clone(),
        )
        .await
        .expect("native bootstrap reopen");
        super::prepare_setup_inventory(&owner, &ids, fresh)
            .await
            .expect("exact continuation slots only");
        let retried = owner
            .prepare_node_join(
                &binding,
                "Cutover join",
                peer.parse().expect("same trusted peer"),
            )
            .expect("exact pending join retry");
        assert_eq!(
            serde_json::to_value(retried).expect("retried public request"),
            serde_json::to_value(request).expect("original public request")
        );
        drop(protocol);
        drop(owner);
        endpoint.close().await;
        super::reset::begin(&data, &config_dir).expect("explicit pending join reset");
        super::reset::run(&data, &config_dir, |references| {
            super::delete_setup_secrets(&data, references)
        })
        .await
        .expect("real pending join signer cleanup before native owner removal");
        assert!(!data.join("services").exists());
        fs::remove_dir_all(root).expect("owned join fixture cleanup after secret deletion");
    }

    #[test]
    fn setup_intent_pins_canonical_issuer_and_join_identity_across_retry() {
        let root = std::env::temp_dir().join(format!("setup-intent-{}", Id::now_v7()));
        fs::create_dir_all(&root).expect("intent fixture");
        load_or_create_setup_ids(&root).expect("persist IDs before intent as production does");
        let intent = serde_json::json!({"purpose": "join", "issuer": "https://installation.test/idp", "name": "Independent Node", "peer": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"});
        super::persist_setup_intent(&root, &intent).expect("persist intent before owner work");
        super::persist_setup_intent(&root, &intent).expect("exact retry");
        assert_eq!(
            super::read_setup_intent(&root).expect("offline reopen"),
            intent
        );
        assert!(
            super::persist_setup_intent(
                &root,
                &serde_json::json!({"purpose":"create", "issuer":"https://localhost:443/idp"})
            )
            .is_err()
        );
        assert_eq!(
            super::read_setup_intent(&root).expect("retained identity"),
            intent
        );
        fs::write(root.join("node-setup.json"), b"{broken").expect("corrupt journal");
        assert!(super::persist_setup_intent(&root, &intent).is_err());
        assert_eq!(
            fs::read(root.join("node-setup.json")).expect("preserved corruption"),
            b"{broken"
        );
        fs::remove_dir_all(root).expect("intent fixture cleanup");
    }

    #[test]
    fn completed_node_with_unavailable_local_contexts_preserves_completion_for_retry() {
        let root = std::env::temp_dir().join(format!("setup-unavailable-{}", Id::now_v7()));
        let ids = load_or_create_setup_ids(&root).expect("stable references");
        assert_eq!(
            super::local_setup_stage(&root, false).expect("incomplete"),
            "installation"
        );
        for name in [SETUP_READY_FILE, super::DEVICE_READY_FILE] {
            crate::setup_completion::write(&root, name, &ids.installation_id.to_string())
                .expect("previous completed stages");
        }
        assert_eq!(
            super::local_setup_stage(&root, false).expect("not unauthorized or new installation"),
            "unavailable"
        );
        assert!(setup_ready(&root).expect("persisted completion retained"));
        assert_eq!(
            super::local_setup_stage(&root, true).expect("successful local retry needs no peer"),
            "ready"
        );
        fs::remove_dir_all(root).expect("unavailable fixture cleanup");
    }

    #[test]
    fn initial_administrator_has_exact_security_sync_and_signer_grants() {
        use idp_model::contract::IdentityAction;
        for action in [
            IdentityAction::ReplicaSignersEnroll,
            IdentityAction::IdpSecuritySync,
            IdentityAction::ManagementSecuritySync,
        ] {
            assert!(
                super::INITIAL_ADMIN_ACTIONS.contains(&action),
                "initial administrator needs exact {action:?} grant"
            );
        }
        assert!(
            super::INITIAL_ADMIN_ACTIONS
                .iter()
                .all(|action| !action.application_scoped() && action.permission() != "*")
        );
    }

    #[test]
    fn rejects_legacy_shared_database_without_deleting_it() {
        let root = std::env::temp_dir().join(format!("legacy-state-{}", uuid::Uuid::new_v4()));
        let data_dir = root.join("data");
        let config_dir = root.join("config");
        fs::create_dir_all(&data_dir).expect("create temporary data directory");
        fs::create_dir_all(&config_dir).expect("create temporary config directory");
        let legacy_database = config_dir.join("lidp.redb");
        fs::write(&legacy_database, b"legacy").expect("write legacy database marker");

        let error = reject_legacy_state(&data_dir, &config_dir)
            .expect_err("legacy shared database must require explicit reset");
        assert!(error.to_string().contains("reset it explicitly"));
        assert!(legacy_database.is_file());
        fs::remove_dir_all(root).expect("remove temporary legacy-state fixture");
    }

    #[test]
    fn readiness_marker_is_durable_and_bound_to_the_installation() {
        let data_dir = std::env::temp_dir().join(format!("setup-ready-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data_dir).expect("create readiness fixture");
        let ids = load_or_create_setup_ids(&data_dir).expect("create setup manifest");
        assert!(
            !setup_ready(&data_dir).expect("missing readiness marker means setup is incomplete")
        );
        crate::setup_completion::write(
            &data_dir,
            SETUP_READY_FILE,
            &ids.installation_id.to_string(),
        )
        .expect("write installation readiness marker");
        assert!(setup_ready(&data_dir).expect("valid marker and manifest mean setup is ready"));
        crate::setup_completion::read(
            &data_dir,
            SETUP_READY_FILE,
            &ids.installation_id.to_string(),
        )
        .expect("verify readiness marker for this installation");
        assert!(
            crate::setup_completion::read(&data_dir, SETUP_READY_FILE, &Id::now_v7().to_string())
                .is_err()
        );
        fs::remove_dir_all(data_dir).expect("remove readiness marker fixture");
    }

    #[cfg(unix)]
    #[test]
    fn setup_ready_rejects_symlink_markers() {
        use std::os::unix::fs::symlink;

        let data_dir =
            std::env::temp_dir().join(format!("setup-ready-link-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data_dir).expect("create readiness fixture");
        let marker = data_dir.join("setup-ready");
        let target = data_dir.join("marker-target");
        fs::write(&target, Id::now_v7().to_string()).expect("write marker target");
        symlink(&target, &marker).expect("create readiness symlink");
        assert!(setup_ready(&data_dir).is_err());
        fs::remove_dir_all(data_dir).expect("remove readiness fixture");
    }

    #[test]
    fn setup_ids_are_persisted_and_reused() {
        let data_dir = std::env::temp_dir().join(format!("setup-ids-{}", uuid::Uuid::new_v4()));
        let first = load_or_create_setup_ids(&data_dir).expect("create setup manifest");
        let second = load_or_create_setup_ids(&data_dir).expect("reuse setup manifest");

        assert_eq!(first.installation_id, second.installation_id);
        assert_eq!(first.administrator_id, second.administrator_id);
        assert_eq!(first.credential_id, second.credential_id);
        assert_eq!(first.role_id, second.role_id);
        assert_eq!(first.permission_ids, second.permission_ids);
        assert_eq!(
            first.management_to_idp_client_id,
            second.management_to_idp_client_id
        );
        assert_eq!(
            first.storage_to_idp_client_id,
            second.storage_to_idp_client_id
        );
        assert_eq!(
            first.storage_to_management_client_id,
            second.storage_to_management_client_id
        );
        assert_eq!(
            first.idp_to_management_client_id,
            second.idp_to_management_client_id
        );
        assert!(data_dir.join("setup-ids.json").is_file());
        fs::remove_dir_all(data_dir).expect("remove temporary setup manifest");
    }

    #[tokio::test]
    async fn keyring_failure_during_reset_preserves_authoritative_references_and_owner_state() {
        let root = std::env::temp_dir().join(format!("reset-keyring-{}", Id::now_v7()));
        let data_dir = root.join("data");
        let config_dir = root.join("config");
        let ids = load_or_create_setup_ids(&data_dir).expect("stable local secret IDs");
        super::persist_setup_intent(
            &data_dir,
            &serde_json::json!({"purpose":"create", "issuer":"https://reset.test/idp"}),
        )
        .expect("canonical issuer");
        fs::create_dir_all(data_dir.join("services/idp")).expect("owner state");
        fs::write(data_dir.join("services/idp/idp.redb"), b"state").expect("retained state");
        let error = super::reset::run(&data_dir, &config_dir, |_| async {
            Err(std::io::Error::other(
                "keyring unavailable after partial deletion",
            ))
        })
        .await
        .expect_err("must retain prerequisites");
        assert!(error.to_string().contains("keyring unavailable"));
        assert!(!setup_ready(&data_dir).expect("reset pending"));
        assert!(data_dir.join(super::reset::JOURNAL).is_file());
        assert!(data_dir.join("services/idp/idp.redb").is_file());
        super::reset::run(&data_dir, &config_dir, |references| async move {
            assert_eq!(references.ids.installation_id, ids.installation_id);
            assert_eq!(references.issuer, "https://reset.test/idp");
            Ok(())
        })
        .await
        .expect("idempotent deletion retry completes cleanup");
        assert!(!data_dir.join("setup-ids.json").exists());
        assert!(!data_dir.join("services").exists());
        fs::remove_dir_all(root).expect("reset fixture cleanup");
    }

    #[test]
    fn refuses_corrupt_setup_manifest_without_replacing_it_or_deleting_owner_state() {
        let data_dir = std::env::temp_dir().join(format!("setup-corrupt-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(data_dir.join("services/idp")).expect("create IdP data directory");
        let idp_database = data_dir.join("services/idp/idp.redb");
        fs::write(&idp_database, b"owner data").expect("write owner data marker");
        let manifest = data_dir.join("setup-ids.json");
        let corrupt_manifest = b"{not valid json";
        fs::write(&manifest, corrupt_manifest).expect("write corrupt setup manifest");

        let error = load_or_create_setup_ids(&data_dir)
            .expect_err("corrupt setup manifest must require explicit reset");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("explicit reset is required"));
        assert_eq!(
            fs::read(&manifest).expect("read retained manifest"),
            corrupt_manifest
        );
        assert!(idp_database.is_file());
        fs::remove_dir_all(data_dir).expect("remove corrupt-manifest fixture");
    }

    #[test]
    fn refuses_owner_state_without_a_setup_manifest() {
        let data_dir = std::env::temp_dir().join(format!("setup-partial-{}", uuid::Uuid::new_v4()));
        let idp_database = data_dir.join("services/idp/idp.redb");
        fs::create_dir_all(idp_database.parent().expect("IdP database parent"))
            .expect("create IdP data directory");
        fs::write(&idp_database, b"owner data").expect("write owner data marker");

        let error = load_or_create_setup_ids(&data_dir)
            .expect_err("partial owner state must not get new stable IDs");
        assert!(error.to_string().contains("explicit reset"));
        assert!(idp_database.is_file());
        fs::remove_dir_all(data_dir).expect("remove temporary owner-state fixture");
    }
}
