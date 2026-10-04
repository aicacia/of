use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::Router;

use idp_server::{
    AppConfig, DeviceIdentity, RouterState, delete_device_identity, open_device_identity,
    storage_router,
};
use idp_service::{
    oauth2::OAuth2Service,
    replica::{
        DbApplicationRepo, DbClientRepo, DbKeyRepo, DbOAuth2AuthorizationCodeRepo,
        DbOAuth2RefreshTokenRepo, DbOAuth2UserConsentRepo, DbUserRepo,
    },
    repo::{KeyService, PrivateKeyKeyringRepo},
};
use management_service::{
    DeviceRepo, HostedControlPlane, ManagementService,
    replica::{DbDeviceRepo, DbPermissionRepo, DbRoleRepo, DbSelectionPolicyRepo},
};
use tauri::{AppHandle, Manager, Wry, async_runtime::Mutex};
use tokio::{net::TcpListener, time::timeout};
use tower_http::cors::CorsLayer;

use crate::localhost_server::{
    LocalhostServer, localhost_server_base_url, reserve_localhost_listener,
    start_unified_localhost_server,
};
use crate::{local_api, scoped_transport::AppFileSystemRuntime, setup, setup::SetupState};

#[derive(Clone, Default)]
pub struct LocalhostServerState {
    pub base_url: String,
    pub ready: bool,
}

pub fn init_setup_router(
    app_config: Arc<AppConfig>,
    database: Arc<NativeEngine>,
    device_identity: Arc<DeviceIdentity>,
) -> Router {
    Router::new().nest(
        "/lidp",
        setup::router(SetupState {
            database,
            app_config,
            device_identity,
        }),
    )
}

pub fn init_router(
    app_config: Arc<AppConfig>,
    database: Arc<NativeEngine>,
    file_systems: Arc<AppFileSystemRuntime>,
    device_identity: Arc<DeviceIdentity>,
    control_plane: Option<Arc<HostedControlPlane>>,
) -> io::Result<(Router, Arc<RouterState>)> {
    let key_service = Arc::new(KeyService::new(
        DbKeyRepo::new(database.clone()),
        PrivateKeyKeyringRepo::new(&app_config.oauth2.issuer),
        app_config.key_namespace.clone(),
    ));

    let oauth2_service = Arc::new(OAuth2Service::new(
        DbApplicationRepo::new(database.clone()),
        DbClientRepo::new(database.clone(), key_service.clone()),
        DbOAuth2AuthorizationCodeRepo::new(database.clone()),
        DbOAuth2RefreshTokenRepo::new(database.clone()),
        DbUserRepo::new(database.clone(), app_config.password.clone()),
        DbOAuth2UserConsentRepo::new(database.clone()),
        key_service.clone(),
        app_config.oauth2.clone(),
    ));

    let router_state = RouterState::new(
        &app_config.ui_public_uri,
        &app_config.api_public_uri,
        database.clone(),
        oauth2_service.clone(),
        Arc::new(DbDeviceRepo::new(database.clone())),
        device_identity,
    )
    .with_storage_file_systems(Arc::clone(&file_systems));
    let router_state = Arc::new(match control_plane {
        Some(control_plane) => router_state.with_hosted_control_plane(control_plane),
        None => router_state,
    });
    let idp_router = idp_server::openapi_router(router_state.as_ref().clone(), "/lidp");
    let management_service = Arc::new(ManagementService::new(
        DbPermissionRepo::new(database.clone()),
        DbRoleRepo::new(database.clone()),
    ));
    let management_control_plane = Arc::new(
        HostedControlPlane::new_with_services(
            &app_config.api_public_uri,
            &format!(
                "{}/storage/",
                app_config.api_public_uri.trim_end_matches('/')
            ),
            &app_config.oauth2.issuer,
        )
        .map_err(io::Error::other)?,
    );
    let storage_audience = app_config
        .storage_audience
        .as_deref()
        .unwrap_or(&app_config.api_public_uri);
    let management_state = management_server::RouterState::new(
        &app_config.api_public_uri,
        management_service,
        Arc::new(DbSelectionPolicyRepo::new(database.clone())),
        management_control_plane,
        storage_audience,
    );
    let management_router = management_server::openapi_router(management_state, "/idp-management");

    let storage_router = storage_router(router_state.as_ref().clone(), file_systems);
    Ok((
        idp_router
            .split_for_parts()
            .0
            .merge(management_router.split_for_parts().0)
            .merge(storage_router)
            .merge(local_api::router())
            .layer(CorsLayer::very_permissive().allow_private_network(true)),
        router_state,
    ))
}

pub async fn init_database(
    app_handle: AppHandle<Wry>,
    app_config: Arc<AppConfig>,
) -> io::Result<Arc<NativeEngine>> {
    let database = Arc::new(
        open_native_engine(PathBuf::from(&app_config.data_dir).join("lidp.redb"))
            .map_err(io::Error::other)?,
    );
    if !database
        .table_names()
        .await
        .map_err(io::Error::other)?
        .is_empty()
    {
        idp_model::replica::up(&database)
            .await
            .map_err(io::Error::other)?;
    }

    app_handle.manage(database.clone());

    Ok(database)
}

pub fn init_app_config(
    app_handle: &AppHandle<Wry>,
    data_dir: impl AsRef<Path>,
) -> tauri::Result<Arc<AppConfig>> {
    if !data_dir.as_ref().exists() {
        fs::create_dir_all(&data_dir)?;
    }

    let config_path = data_dir.as_ref().join("config.yaml");
    let mut app_config = if config_path.exists() {
        AppConfig::try_from(config_path.as_path())
            .map_err(|e| tauri::Error::Io(io::Error::other(e)))?
    } else {
        let mut default_config = AppConfig::default();

        default_config.data_dir = data_dir.as_ref().to_string_lossy().into_owned();
        default_config.oauth2.issuer = "https://localhost".to_owned();
        default_config.ui_public_uri = "https://localhost".to_owned();
        default_config.api_public_uri = "https://localhost".to_owned();
        fs::write(
            &config_path,
            yaml_serde::to_string(&default_config)
                .map_err(|e| tauri::Error::Io(io::Error::other(e)))?,
        )?;
        default_config
    };
    app_config.data_dir = data_dir.as_ref().to_string_lossy().into_owned();

    let app_config = Arc::new(app_config);
    app_handle.manage(app_config.clone());
    Ok(app_config)
}

#[tauri::command]
pub async fn get_localhost_server_base_url(app_handle: AppHandle<Wry>) -> String {
    localhost_server_base_url_for(&app_handle).await
}

#[tauri::command]
pub async fn reset_device(app_handle: AppHandle<Wry>) -> Result<(), String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;

    if let Some(router_state) = app_handle.try_state::<Arc<RouterState>>() {
        let public_key = router_state.device_identity.endpoint_id().to_string();
        let request = router_state.device_identity.self_revocation_request();
        if let Some(control_plane) = &router_state.hosted_control_plane {
            let _ = timeout(Duration::from_secs(2), control_plane.revoke_self(request)).await;
        } else {
            let _ = timeout(
                Duration::from_secs(2),
                router_state.devices.revoke_self(&public_key),
            )
            .await;
        }
    }

    close(&app_handle)
        .await
        .map_err(|error| error.to_string())?;
    delete_device_identity().map_err(|error| error.to_string())?;
    remove_local_reset_data(&data_dir).map_err(|error| error.to_string())?;
    app_handle.exit(0);
    Ok(())
}

fn remove_local_reset_data(data_dir: &Path) -> io::Result<()> {
    remove_path(&data_dir.join("lidp.redb"))?;
    remove_path(&data_dir.join("vaults"))?;
    remove_path(&data_dir.join("storage-residency.json"))
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

pub async fn init_scoped_file_system_runtime(
    app_handle: &AppHandle<Wry>,
    _: &AppConfig,
) -> tauri::Result<()> {
    let data_dir = app_handle.path().app_data_dir()?;
    let local_peer = app_handle
        .try_state::<Arc<DeviceIdentity>>()
        .ok_or_else(|| tauri::Error::Io(io::Error::other("device identity is missing")))?
        .endpoint_id();
    let runtime = AppFileSystemRuntime::new(data_dir, local_peer).map_err(tauri::Error::Io)?;
    app_handle.manage(Arc::new(runtime));
    Ok(())
}

pub async fn init_device_identity(app_handle: &AppHandle<Wry>) -> tauri::Result<()> {
    let identity = open_device_identity().await?;
    app_handle.manage(Arc::new(identity));
    Ok(())
}

pub async fn init_unified_localhost_server(
    app_handle: &AppHandle<Wry>,
    router: Router,
    listener: TcpListener,
    base_url: String,
) -> tauri::Result<String> {
    let data_dir = app_handle.path().app_data_dir()?;
    let server = start_unified_localhost_server(router, listener, &data_dir);
    app_handle.manage(Mutex::new(Some(server)));

    set_localhost_server_state(app_handle, base_url.clone(), true).await;
    Ok(base_url)
}

pub async fn reserve_unified_localhost_server(
    app_handle: &AppHandle<Wry>,
) -> tauri::Result<(TcpListener, String)> {
    let app_data_dir = app_handle.path().app_data_dir()?;
    let (listener, port) = reserve_localhost_listener(&app_data_dir)
        .await
        .map_err(|err| tauri::Error::Io(io::Error::other(err)))?;
    Ok((listener, localhost_server_base_url(port)))
}

pub fn app_config_for_localhost_base_url(
    app_config: Arc<AppConfig>,
    base_url: &str,
) -> Arc<AppConfig> {
    let mut config = app_config.as_ref().clone();
    config.oauth2.issuer = format!("{base_url}/lidp");
    config.ui_public_uri = base_url.to_owned();
    config.api_public_uri = base_url.to_owned();
    Arc::new(config)
}

pub async fn close(app_handle: &AppHandle<Wry>) -> io::Result<()> {
    set_localhost_server_state(app_handle, String::new(), false).await;
    if let Some(server) = app_handle.try_state::<Mutex<Option<LocalhostServer>>>() {
        if let Some(server) = server.lock().await.take() {
            server.close().await?;
        }
    }

    Ok(())
}
