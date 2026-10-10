use std::{
    io,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use cli::{CliArgs, CliServerServe, shutdown_signal};
use env_logger::Env;
use tokio::task::JoinHandle;

use crate::{LocalProvisioner, UnifiedConfig};

type UnifiedArgs = CliArgs<UnifiedCommand>;

#[derive(Subcommand, Debug)]
enum UnifiedCommand {
    Serve {
        #[command(flatten)]
        serve: CliServerServe,
    },
    /// Explicit restricted local Installation setup; does not start a server.
    Provision {
        /// Authorize a new intent only when all local roots are absent.
        #[arg(long, requires = "administrator")]
        fresh: bool,
        #[arg(long, requires = "fresh")]
        administrator: Option<String>,
        #[arg(long, requires = "fresh")]
        node: Option<String>,
        /// Existing operator-only regular file containing one password line.
        #[arg(long)]
        password_file: PathBuf,
    },
    #[cfg(feature = "completions")]
    Completions { shell: clap_complete::Shell },
}

pub async fn run() -> io::Result<()> {
    let _ = dotenvy::dotenv();
    let args = UnifiedArgs::parse();
    #[cfg(feature = "completions")]
    if let Some(UnifiedCommand::Completions { shell }) = args.command.as_ref() {
        use clap::CommandFactory;
        clap_complete::generate(
            *shell,
            &mut UnifiedArgs::command(),
            "unified-server",
            &mut io::stdout(),
        );
        return Ok(());
    }
    let mut config = UnifiedConfig::try_from(Path::new(&args.config))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    env_logger::Builder::from_env(Env::default().default_filter_or(&config.idp.log_level)).init();
    match args.command {
        Some(UnifiedCommand::Provision {
            fresh,
            administrator,
            node,
            password_file,
        }) => {
            let mut local = if fresh {
                LocalProvisioner::create(
                    config,
                    administrator
                        .as_deref()
                        .expect("clap requires an initial administrator"),
                    node.as_deref().unwrap_or("Local Node"),
                    &password_file,
                )?
            } else {
                LocalProvisioner::open(config)?
            };
            local.provision(&password_file).await?;
            println!(
                "Local provisioning is complete and currently ready. Start serving explicitly."
            );
            return Ok(());
        }
        Some(UnifiedCommand::Serve { serve }) => {
            if let Some(host) = serve.host {
                config.listen_addr.set_ip(host);
            }
            if let Some(port) = serve.port {
                config.listen_addr.set_port(port);
            }
        }
        _ => (),
    }
    let local = LocalProvisioner::open(config)?;
    let runtime = local.build_runtime().await?;
    let cancellation_token = runtime.cancellation_token();
    let mut server_task: JoinHandle<io::Result<()>> = tokio::spawn(runtime.serve());
    tokio::select! {
        result = &mut server_task => result.map_err(io::Error::other)??,
        () = shutdown_signal(cancellation_token) => {
            server_task.await.map_err(io::Error::other)??;
        }
    }
    drop(local);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::UnifiedArgs;

    #[test]
    fn explicit_local_provisioning_command_accepts_only_file_password_input() {
        UnifiedArgs::try_parse_from([
            "unified-server",
            "provision",
            "--fresh",
            "--administrator",
            "operator",
            "--password-file",
            "protected-password",
        ])
        .expect("actual CLI exposes restricted explicit local provisioning");
        UnifiedArgs::try_parse_from([
            "unified-server",
            "provision",
            "--password-file",
            "protected-password",
        ])
        .expect("exact continuation does not redeclare freshness or names");
        assert!(
            UnifiedArgs::try_parse_from([
                "unified-server",
                "provision",
                "--password",
                "raw-password"
            ])
            .is_err()
        );
        assert!(
            UnifiedArgs::try_parse_from([
                "unified-server",
                "provision",
                "--fresh",
                "--password-file",
                "protected-password"
            ])
            .is_err()
        );
        assert!(
            UnifiedArgs::try_parse_from([
                "unified-server",
                "provision",
                "--administrator",
                "different",
                "--password-file",
                "protected-password"
            ])
            .is_err()
        );
    }
}
