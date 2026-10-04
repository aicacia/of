use std::{io, path::Path};

use clap::Parser;
use cli::{CliArgs, CliServerCommand, shutdown_signal};
use env_logger::Env;
use tokio::task::JoinHandle;

use crate::{UnifiedConfig, UnifiedRuntime};

pub async fn run() -> io::Result<()> {
    let _ = dotenvy::dotenv();
    let args = CliArgs::parse();
    #[cfg(feature = "completions")]
    if let Some(CliServerCommand::Completions { shell }) = args.command.as_ref() {
        return cli::run_completions(*shell).await;
    }

    let mut config = UnifiedConfig::try_from(Path::new(&args.config))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if let Some(CliServerCommand::Serve { serve }) = args.command {
        if let Some(host) = serve.host {
            config.listen_addr.set_ip(host);
        }
        if let Some(port) = serve.port {
            config.listen_addr.set_port(port);
        }
    }
    env_logger::Builder::from_env(Env::default().default_filter_or(&config.idp.log_level)).init();

    let runtime = UnifiedRuntime::build(config).await?;
    let cancellation_token = runtime.cancellation_token();
    let mut server_task: JoinHandle<io::Result<()>> = tokio::spawn(runtime.serve());
    tokio::select! {
        result = &mut server_task => result.map_err(io::Error::other)??,
        () = shutdown_signal(cancellation_token) => {
            server_task.await.map_err(io::Error::other)??;
        }
    }
    Ok(())
}
