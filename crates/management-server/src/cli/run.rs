use std::{
    fs::create_dir_all,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use api::serve;
use clap::Parser;
use cli::{CliArgs, CliServerCommand, shutdown_signal};
use db::open_native_engine;
use env_logger::Env;

use management_service::HostedControlPlane;
use tokio::{select, spawn, time::sleep};
use tokio_util::sync::CancellationToken;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::{AppConfig, build_router};

pub async fn run() -> io::Result<()> {
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(error) => eprintln!("failed to load .env file: {error}"),
    }

    let args = CliArgs::parse();
    let cancellation_token = CancellationToken::new();
    let app_config = Arc::new(match AppConfig::try_from(Path::new(&args.config)) {
        Ok(app_config) => app_config,
        Err(error) => {
            eprintln!("failed to load config {:?}: {error}", args.config);
            AppConfig::default()
        }
    });

    if app_config.idp_api_base.trim().is_empty()
        || app_config.storage_api_base.trim().is_empty()
        || app_config.expected_issuer.trim().is_empty()
        || app_config.storage_audience.trim().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "idp_api_base, storage_api_base, expected_issuer and storage_audience are required",
        ));
    }

    let idp_client_id = std::env::var("SERVER_IDP_OAUTH_CLIENT_ID").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SERVER_IDP_OAUTH_CLIENT_ID is required",
        )
    })?;
    let idp_client_secret = std::env::var("SERVER_IDP_OAUTH_CLIENT_SECRET").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SERVER_IDP_OAUTH_CLIENT_SECRET is required",
        )
    })?;
    let idp_service_audience = std::env::var("SERVER_IDP_SERVICE_AUDIENCE").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SERVER_IDP_SERVICE_AUDIENCE is required",
        )
    })?;
    let control_plane = Arc::new(
        HostedControlPlane::new_with_services(
            &app_config.idp_api_base,
            &app_config.storage_api_base,
            &app_config.expected_issuer,
        )
        .and_then(|control_plane| {
            control_plane.with_idp_service_client(
                idp_client_id,
                idp_client_secret,
                idp_service_audience,
            )
        })
        .and_then(|control_plane| match app_config.idp_permission_evaluator_client_id.as_deref() {
            Some(client_id) => control_plane.with_permission_evaluator(client_id),
            None => Ok(control_plane),
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
    );

    env_logger::Builder::from_env(Env::default().default_filter_or(&app_config.log_level)).init();

    create_dir_all(&app_config.data_dir)?;
    let engine = Arc::new(
        open_native_engine(Path::new(&app_config.data_dir).join("management.redb"))
            .map_err(io::Error::other)?,
    );
    let router = build_router(
        engine,
        &app_config.api_public_uri,
        app_config.server.prefix(),
        &app_config.storage_audience,
        control_plane,
    )
    .await
    .map_err(io::Error::other)?
    .layer(CorsLayer::very_permissive().allow_private_network(true))
    .layer(TraceLayer::new_for_http())
    .layer(CompressionLayer::new().gzip(app_config.server.gzip))
    .into();

    let run_serve = |host: Option<IpAddr>, port: Option<u16>| {
        let addr = SocketAddr::from((
            host.unwrap_or(app_config.server.host),
            port.unwrap_or(app_config.server.port),
        ));
        spawn(serve(router, addr, cancellation_token.clone()))
    };

    let command_handle = match args.command {
        #[cfg(feature = "completions")]
        Some(CliServerCommand::Completions { shell }) => {
            spawn(async move { cli::run_completions(shell).await })
        }
        Some(CliServerCommand::Serve { serve }) => run_serve(serve.host, serve.port),
        None => run_serve(None, None),
    };

    shutdown_signal(cancellation_token).await;

    let shutdown_timeout = Duration::from_secs(10);
    let mut command_handle = command_handle;
    select! {
        result = &mut command_handle => match result {
            Ok(Ok(())) => log::info!("server shutdown complete"),
            Ok(Err(error)) => log::error!("command error: {error}"),
            Err(error) => log::error!("join error: {error}"),
        },
        _ = sleep(shutdown_timeout) => {
            log::warn!("server shutdown timed out after {shutdown_timeout:?}, aborting serve task");
            command_handle.abort();
            sleep(Duration::from_millis(100)).await;
        }
    }

    Ok(())
}
