use idp_model::contract::DeviceState;
use idp_server::DeviceIdentity;
use management_service::{DeviceRepo, replica::DbDeviceRepo};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent, Wry};
#[cfg(any(windows, target_os = "linux"))]
use tauri_plugin_deep_link::DeepLinkExt;

use crate::app;
use crate::hosted_control_plane::HostedControlPlane;
use crate::scoped_transport::AppFileSystemRuntime;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }));
    }

    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .invoke_handler(tauri::generate_handler![
            app::get_localhost_server_base_url,
            app::reset_device
        ])
        .setup(|app| {
            let app_config =
                app::init_app_config(app.handle(), app.handle().path().app_config_dir()?)?;
            let app_data_dir = app.handle().path().app_data_dir()?;
            tauri::async_runtime::block_on(crate::localhost_server::ensure_localhost_certificate(
                &app_data_dir,
            ))?;

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Debug)
                        .build(),
                )?;
            }
            if cfg!(any(windows, target_os = "linux")) {
                app.deep_link().register_all()?;
            }

            tauri::async_runtime::block_on(app::init_device_identity(app.handle()))?;
            tauri::async_runtime::block_on(app::init_scoped_file_system_runtime(
                app.handle(),
                &app_config,
            ))?;

            let app_handle = app.handle().clone();
            tauri::async_runtime::block_on(async {
                let (listener, base_url) =
                    app::reserve_unified_localhost_server(&app_handle).await?;
                app::set_localhost_server_state(&app_handle, base_url.clone(), false).await;
                let runtime_config = app::app_config_for_localhost_base_url(app_config, &base_url);
                let control_plane = runtime_config
                    .control_plane_uri
                    .as_deref()
                    .map(HostedControlPlane::new)
                    .transpose()
                    .expect("control plane URI must be valid")
                    .map(std::sync::Arc::new);

                let database =
                    app::init_database(app_handle.clone(), runtime_config.clone()).await?;
                let file_systems = app_handle
                    .try_state::<std::sync::Arc<AppFileSystemRuntime>>()
                    .expect("vault runtime must initialize")
                    .inner()
                    .clone();
                let device_identity = app_handle
                    .try_state::<std::sync::Arc<DeviceIdentity>>()
                    .expect("device identity must initialize")
                    .inner()
                    .clone();

                let ready = DbDeviceRepo::new(database.clone())
                    .list()
                    .await
                    .map(|devices| {
                        devices
                            .iter()
                            .any(|device| device.state == DeviceState::Approved)
                    })
                    .unwrap_or(false);

                let router = if ready {
                    let (router, router_state) = app::init_router(
                        runtime_config,
                        database,
                        file_systems,
                        device_identity,
                        control_plane.clone(),
                    )
                    .map_err(tauri::Error::Io)?;
                    app_handle.manage(router_state.clone());
                    router
                } else {
                    app::init_setup_router(database)
                };
                app::init_unified_localhost_server(&app_handle, router, listener, base_url.clone())
                    .await?;

                if crate::localhost_server::verify_localhost_server(&base_url)
                    .await
                    .is_err()
                {
                    crate::localhost_server::invalidate_localhost_certificate_trust(&app_data_dir)
                        .map_err(tauri::Error::Io)?;
                    crate::localhost_server::ensure_localhost_certificate(&app_data_dir)
                        .await
                        .map_err(tauri::Error::Io)?;
                    crate::localhost_server::verify_localhost_server(&base_url)
                        .await
                        .map_err(tauri::Error::Io)?;
                }

                Ok::<(), tauri::Error>(())
            })?;

            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Local")
                    .inner_size(800.0, 600.0)
                    .resizable(true)
                    .fullscreen(false)
                    .build()?;
            if cfg!(debug_assertions) {
                window.open_devtools();
            }
            Ok(())
        })
        .on_window_event(on_window_event)
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn on_window_event(window: &Window<Wry>, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();
        let app_handle = window.app_handle().clone();
        tauri::async_runtime::spawn(async move {
            app::close(&app_handle).await.expect("failed to close app");
            app_handle.exit(0);
        });
    }
}
