use std::{
    fs,
    fs::OpenOptions,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    sync::Mutex as StdMutex,
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
use idp_server::{AppConfig as IdpAppConfig, OwnerProvisioner, delete_device_identity};
use management_server::{AppConfig as ManagementAppConfig, MANAGEMENT_APPLICATION_URI};
use model::contract::{MANAGEMENT_REPLICATION_ADMIT_SCOPE, MANAGEMENT_REPLICATION_READ_SCOPE};
use serde_json::{Value, json};
use storage_server::AppConfig as StorageAppConfig;
use tauri::{AppHandle, Manager, Wry, async_runtime::Mutex};
use tokio::net::TcpListener;
use unified_server::{ServiceClientCredentials, UnifiedConfig, UnifiedRuntime};

use crate::localhost_server::{
    LocalhostServer, localhost_server_base_url, reserve_localhost_listener,
    start_unified_localhost_server, verify_unified_localhost_server,
};
use crate::{local_api, service_secrets, service_secrets::ServiceRelationship, setup};

static SETUP_IDS_LOCK: StdMutex<()> = StdMutex::new(());

const SETUP_READY_FILE: &str = "setup-ready";

const INITIAL_ADMIN_ACTIONS: [IdentityAction; 19] = [
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
];

#[derive(Debug)]
struct SetupIds {
    installation_id: Id,
    administrator_id: Id,
    credential_id: Id,
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
    let ids = load_or_create_setup_ids(&app_data_dir).map_err(|error| error.to_string())?;

    let mut idp_config = IdpAppConfig::default();
    idp_config.data_dir = app_data_dir
        .join("services/idp")
        .to_string_lossy()
        .into_owned();
    idp_config.oauth2.issuer = format!("{base_url}/idp");
    idp_config.api_public_uri = format!("{base_url}/idp");
    idp_config.ui_public_uri = base_url.clone();
    let idp = OwnerProvisioner::open(&idp_config)
        .await
        .map_err(|error| error.to_string())?;
    let administrator_id = idp
        .ensure_initial_user(ids.administrator_id, ids.credential_id, &name, &password)
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

    provision_service_clients(
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
        let restore = async {
            let (listener, base_url) = reserve_unified_localhost_server(&app_handle)
                .await
                .map_err(io::Error::other)?;
            init_unified_localhost_server(
                &app_handle,
                init_setup_router(),
                listener,
                base_url.clone(),
            )
            .await
            .map_err(io::Error::other)?;
            crate::localhost_server::verify_localhost_server(&base_url).await
        }
        .await;
        return match restore {
            Ok(()) => Err(error.to_string()),
            Err(restore_error) => Err(format!(
                "unified runtime startup failed ({error}); setup status listener restore failed ({restore_error})"
            )),
        };
    }

    Ok(administrator_id.to_string())
}

async fn provision_service_clients(
    idp: &OwnerProvisioner,
    ids: &SetupIds,
    base_url: &str,
    idp_audience: &str,
    storage_audience: &str,
) -> io::Result<()> {
    provision_service_client(
        idp,
        ids,
        ServiceRelationship::ManagementToIdp,
        ids.management_to_idp_client_id,
        "Management",
        &format!("{base_url}/management"),
        "Management service to IdP",
        idp_audience,
        &[IDP_TOKEN_VALIDATE_SCOPE, IDP_DEVICE_LOOKUP_SCOPE],
    )
    .await?;
    provision_service_client(
        idp,
        ids,
        ServiceRelationship::StorageToIdp,
        ids.storage_to_idp_client_id,
        "Storage",
        &format!("{base_url}/storage"),
        "Storage service to IdP",
        idp_audience,
        &[
            IDP_TOKEN_VALIDATE_SCOPE,
            IDP_DEVICE_LOOKUP_SCOPE,
            IDP_DEVICE_LIST_SCOPE,
        ],
    )
    .await?;
    provision_service_client(
        idp,
        ids,
        ServiceRelationship::StorageToManagement,
        ids.storage_to_management_client_id,
        "Storage",
        &format!("{base_url}/storage"),
        "Storage service to Management",
        storage_audience,
        &[
            MANAGEMENT_REPLICATION_READ_SCOPE,
            MANAGEMENT_REPLICATION_ADMIT_SCOPE,
        ],
    )
    .await?;
    provision_service_client(
        idp,
        ids,
        ServiceRelationship::IdpToManagement,
        ids.idp_to_management_client_id,
        "IdP",
        &format!("{base_url}/idp"),
        "IdP service to Management",
        MANAGEMENT_APPLICATION_URI,
        &[MANAGEMENT_PERMISSION_EVALUATE_SCOPE],
    )
    .await
}

async fn provision_service_client(
    idp: &OwnerProvisioner,
    ids: &SetupIds,
    relationship: ServiceRelationship,
    client_id: Id,
    application_name: &str,
    application_uri: &str,
    client_name: &str,
    audience: &str,
    scopes: &[&str],
) -> io::Result<()> {
    let client_secret =
        service_secrets::ensure_secret(ids.installation_id, relationship, client_id).map_err(
            |error| {
                io::Error::other(format!(
                    "could not persist {client_name} credential: {error}"
                ))
            },
        )?;
    idp.ensure_infrastructure_client(service_client_registration(
        client_id,
        client_secret,
        application_name,
        application_uri,
        client_name,
        audience,
        scopes,
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
    idp.oauth2.issuer = idp_api.clone();
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
    application_name: &str,
    application_uri: &str,
    client_name: &str,
    audience: &str,
    scopes: &[&str],
) -> ClientRegistration {
    ClientRegistration {
        application: ApplicationRegistration {
            name: Some(application_name.to_owned()),
            uri: application_uri.to_owned(),
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
        allowed_audiences: vec![audience.to_owned()],
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        software_statement: None,
        software_id: None,
        software_version: None,
    }
}

pub fn setup_ready(app_data_dir: &Path) -> io::Result<bool> {
    let marker_path = app_data_dir.join(SETUP_READY_FILE);
    let metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup readiness marker is not a regular file",
        ));
    }
    let ids = read_setup_ids(&app_data_dir.join("setup-ids.json"))?;
    verify_setup_ready_marker(app_data_dir, ids.installation_id)?;
    Ok(true)
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
    verify_setup_ready_marker(&app_data_dir, ids.installation_id)?;
    let config = unified_runtime_config(&app_data_dir, listener.local_addr()?, &base_url, &ids)?;
    let mut runtime = UnifiedRuntime::build_on_listener(config, listener, base_url.clone()).await?;
    let router = runtime.router();
    let listener = runtime.take_listener()?;
    let server = match start_unified_localhost_server(router, listener, &app_data_dir) {
        Ok(server) => server,
        Err(error) => {
            runtime.shutdown().await?;
            return Err(io::Error::other(error));
        }
    };
    set_localhost_server(app_handle, server).await;
    set_localhost_server_state(app_handle, base_url.clone(), true).await;

    if let Err(error) = verify_unified_localhost_server(&base_url).await {
        set_localhost_server_state(app_handle, String::new(), false).await;
        close(app_handle).await?;
        runtime.shutdown().await?;
        return Err(error);
    }
    if let Err(error) = runtime.start_background_tasks().await {
        close(app_handle).await?;
        runtime.shutdown().await?;
        return Err(error);
    }
    store_unified_runtime(app_handle, runtime).await;
    if persist_ready {
        if let Err(error) = write_setup_ready_marker(&app_data_dir, ids.installation_id) {
            close(app_handle).await?;
            return Err(error);
        }
    }
    Ok(())
}

fn verify_setup_ready_marker(app_data_dir: &Path, installation_id: Id) -> io::Result<()> {
    let path = app_data_dir.join(SETUP_READY_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup readiness marker is not a regular file",
        ));
    }
    let marker = fs::read_to_string(path)?;
    if marker.trim() != installation_id.to_string() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "setup readiness marker does not match the installation manifest",
        ));
    }
    Ok(())
}

fn write_setup_ready_marker(app_data_dir: &Path, installation_id: Id) -> io::Result<()> {
    let marker_path = app_data_dir.join(SETUP_READY_FILE);
    if fs::symlink_metadata(&marker_path).is_ok() {
        return verify_setup_ready_marker(app_data_dir, installation_id);
    }
    let temporary_path = app_data_dir.join(format!(".{SETUP_READY_FILE}-{installation_id}.tmp"));
    if let Ok(metadata) = fs::symlink_metadata(&temporary_path) {
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "setup readiness temporary path is not a regular file",
            ));
        }
        if fs::read_to_string(&temporary_path)?.trim() != installation_id.to_string() {
            fs::remove_file(&temporary_path)?;
        } else {
            fs::rename(&temporary_path, &marker_path)?;
            return fs::File::open(app_data_dir)?.sync_all();
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    if let Err(error) = writeln!(file, "{installation_id}").and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, &marker_path)?;
    fs::File::open(app_data_dir)?.sync_all()
}

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
    if manifest_path.exists() {
        return read_setup_ids(&manifest_path);
    }
    for path in [
        app_data_dir.join("services/idp/idp.redb"),
        app_data_dir.join("services/management/management.redb"),
    ] {
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "owner state exists without the setup manifest at {}; explicit reset is required",
                    path.display()
                ),
            ));
        }
    }

    fs::create_dir_all(app_data_dir)?;
    let ids = SetupIds {
        installation_id: Id::now_v7(),
        administrator_id: Id::now_v7(),
        credential_id: Id::now_v7(),
        role_id: Id::now_v7(),
        permission_ids: INITIAL_ADMIN_ACTIONS.iter().map(|_| Id::now_v7()).collect(),
        management_to_idp_client_id: Id::now_v7(),
        storage_to_idp_client_id: Id::now_v7(),
        storage_to_management_client_id: Id::now_v7(),
        idp_to_management_client_id: Id::now_v7(),
    };
    let value = json!({
        "version": 1,
        "installation_id": ids.installation_id.to_string(),
        "administrator_id": ids.administrator_id.to_string(),
        "credential_id": ids.credential_id.to_string(),
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
    if let Err(error) = fs::rename(&temporary_path, &manifest_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    Ok(ids)
}

fn read_setup_ids(path: &Path) -> io::Result<SetupIds> {
    let value: Value = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("setup manifest is corrupt ({error}); explicit reset is required"),
        )
    })?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
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

#[tauri::command]
pub async fn get_setup_stage(app_handle: AppHandle<Wry>) -> Result<String, String> {
    let app_data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    setup_ready(&app_data_dir)
        .map(|ready| if ready { "ready" } else { "installation" }.to_owned())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn reset_device(app_handle: AppHandle<Wry>) -> Result<(), String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;

    let ids_path = data_dir.join("setup-ids.json");
    let setup_ids = if ids_path.exists() {
        Some(read_setup_ids(&ids_path).map_err(|error| error.to_string())?)
    } else {
        None
    };
    close(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    delete_device_identity().map_err(|error| error.to_string())?;
    reset_local_installation(
        &data_dir,
        &config_dir,
        setup_ids.as_ref(),
        service_secrets::delete_secret,
    )
    .map_err(|error| error.to_string())?;
    app_handle.exit(0);
    Ok(())
}

fn reset_local_installation(
    data_dir: &Path,
    config_dir: &Path,
    setup_ids: Option<&SetupIds>,
    mut delete_secret: impl FnMut(Id, ServiceRelationship, Id) -> io::Result<()>,
) -> io::Result<()> {
    if let Some(ids) = setup_ids {
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
            delete_secret(ids.installation_id, relationship, client_id)?;
        }
    }
    remove_local_reset_data(data_dir, config_dir)
}

fn remove_local_reset_data(data_dir: &Path, config_dir: &Path) -> io::Result<()> {
    remove_path(&data_dir.join("lidp.redb"))?;
    remove_path(&config_dir.join("lidp.redb"))?;
    remove_path(&data_dir.join("vaults"))?;
    remove_path(&data_dir.join("storage-residency.json"))?;
    remove_path(&data_dir.join("services"))?;
    remove_path(&data_dir.join("setup-ids.json"))?;
    remove_path(&data_dir.join(SETUP_READY_FILE))?;
    remove_path(&data_dir.join("https-port"))
}

fn remove_path(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
mod tests {
    use std::fs;

    use idp_model::model::Id;

    use super::{
        load_or_create_setup_ids, reject_legacy_state, remove_local_reset_data,
        reset_local_installation, setup_ready, verify_setup_ready_marker, write_setup_ready_marker,
    };

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
        write_setup_ready_marker(&data_dir, ids.installation_id)
            .expect("write installation readiness marker");
        assert!(setup_ready(&data_dir).expect("valid marker and manifest mean setup is ready"));
        verify_setup_ready_marker(&data_dir, ids.installation_id)
            .expect("verify readiness marker for this installation");
        assert!(verify_setup_ready_marker(&data_dir, Id::now_v7()).is_err());
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

    #[test]
    fn explicit_reset_removes_unified_service_state_and_readiness() {
        let root = std::env::temp_dir().join(format!("reset-state-{}", uuid::Uuid::new_v4()));
        let data_dir = root.join("data");
        let config_dir = root.join("config");
        fs::create_dir_all(data_dir.join("services/idp")).expect("create service data root");
        fs::write(data_dir.join("services/idp/idp.redb"), b"state")
            .expect("write service state marker");
        fs::write(data_dir.join("setup-ids.json"), b"ids").expect("write setup manifest marker");
        fs::write(data_dir.join("setup-ready"), b"ready").expect("write setup readiness marker");

        remove_local_reset_data(&data_dir, &config_dir).expect("remove explicit reset state");
        assert!(!data_dir.join("services").exists());
        assert!(!data_dir.join("setup-ids.json").exists());
        assert!(!data_dir.join("setup-ready").exists());
        fs::remove_dir_all(root).expect("remove reset state fixture");
    }

    #[test]
    fn keyring_failure_during_reset_preserves_manifest_and_service_state() {
        let root = std::env::temp_dir().join(format!("reset-keyring-{}", uuid::Uuid::new_v4()));
        let data_dir = root.join("data");
        let config_dir = root.join("config");
        let ids = load_or_create_setup_ids(&data_dir).expect("create setup manifest");
        fs::create_dir_all(data_dir.join("services/idp")).expect("create IdP state directory");
        fs::write(data_dir.join("services/idp/idp.redb"), b"state")
            .expect("write IdP state marker");

        let error = reset_local_installation(&data_dir, &config_dir, Some(&ids), |_, _, _| {
            Err(std::io::Error::other("keyring unavailable"))
        })
        .expect_err("reset must stop if keyring cleanup fails");
        assert!(error.to_string().contains("keyring unavailable"));
        assert!(data_dir.join("setup-ids.json").is_file());
        assert!(data_dir.join("services/idp/idp.redb").is_file());
        fs::remove_dir_all(root).expect("remove reset retry fixture");
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
