use std::{net::SocketAddr, path::Path};

use serde::Deserialize;

pub struct ServiceClientCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
}

pub struct UnifiedConfig {
    pub listen_addr: SocketAddr,
    pub endpoint_data_dir: std::path::PathBuf,
    pub idp: idp_server::AppConfig,
    pub management: management_server::AppConfig,
    pub storage: storage_server::AppConfig,
    pub management_idp_client: ServiceClientCredentials,
    pub storage_idp_client: ServiceClientCredentials,
    pub storage_management_client: ServiceClientCredentials,
}

#[derive(Deserialize)]
#[serde(default)]
struct FileConfig {
    listen_addr: String,
    endpoint_data_dir: String,
    idp: idp_server::AppConfig,
    management: management_server::AppConfig,
    storage: storage_server::AppConfig,
    service_clients: ServiceClientConfig,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:3000".to_owned(),
            endpoint_data_dir: "unified-data".to_owned(),
            idp: idp_server::AppConfig::default(),
            management: management_server::AppConfig::default(),
            storage: storage_server::AppConfig::default(),
            service_clients: ServiceClientConfig::default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ServiceClientConfig {
    management_idp: ClientConfig,
    storage_idp: ClientConfig,
    storage_management: ClientConfig,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ClientConfig {
    client_id: String,
    audience: String,
}

impl TryFrom<&Path> for UnifiedConfig {
    type Error = config::ConfigError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let file: FileConfig = config::Config::builder()
            .add_source(config::File::with_name(path.to_string_lossy().as_ref()))
            .add_source(
                config::Environment::with_prefix("UNIFIED")
                    .prefix_separator("__")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()?;
        let listen_addr = file.listen_addr.parse().map_err(|error| {
            config::ConfigError::Message(format!("invalid listen_addr: {error}"))
        })?;
        let service_clients = file.service_clients;

        Ok(Self {
            listen_addr,
            endpoint_data_dir: file.endpoint_data_dir.into(),
            idp: file.idp,
            management: file.management,
            storage: file.storage,
            management_idp_client: load_credentials(
                service_clients.management_idp,
                "UNIFIED_MANAGEMENT_IDP_CLIENT_SECRET",
            )?,
            storage_idp_client: load_credentials(
                service_clients.storage_idp,
                "UNIFIED_STORAGE_IDP_CLIENT_SECRET",
            )?,
            storage_management_client: load_credentials(
                service_clients.storage_management,
                "UNIFIED_STORAGE_MANAGEMENT_CLIENT_SECRET",
            )?,
        })
    }
}

fn load_credentials(
    config: ClientConfig,
    secret_variable: &str,
) -> Result<ServiceClientCredentials, config::ConfigError> {
    let client_secret = std::env::var(secret_variable)
        .map_err(|_| config::ConfigError::Message(format!("{secret_variable} must be set")))?;
    Ok(ServiceClientCredentials {
        client_id: config.client_id,
        client_secret,
        audience: config.audience,
    })
}
