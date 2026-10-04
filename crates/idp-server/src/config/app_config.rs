use std::path::Path;

use api::{Environment, ServerConfig};
use idp_service::{PasswordConfig, oauth2::OAuth2Config};
use serde::{Deserialize, Serialize};

use super::PairingConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub data_dir: String,
    pub oauth2: OAuth2Config,
    pub password: PasswordConfig,
    pub pairing: PairingConfig,
    pub key_namespace: String,
    pub control_plane_uri: Option<String>,
    pub log_level: String,
    pub ui_public_uri: String,
    pub api_public_uri: String,
    /// Expected audience/resource for IdP service access tokens.
    /// Defaults to `api_public_uri` when omitted; configurable as `LIDP_SERVICE_AUDIENCE`.
    pub service_audience: Option<String>,

    pub env: Environment,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            data_dir: "data".to_string(),
            oauth2: OAuth2Config::default(),
            password: PasswordConfig::default(),
            pairing: PairingConfig::default(),
            key_namespace: "lidp".to_string(),
            control_plane_uri: None,
            ui_public_uri: "https://lidp.localhost:1355".to_string(),
            api_public_uri: "https://idp-api.localhost:1355".to_string(),
            service_audience: None,
            log_level: "DEBUG".to_string(),
            env: Environment::default(),
        }
    }
}

impl TryFrom<&Path> for AppConfig {
    type Error = config::ConfigError;

    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        config::Config::builder()
            .add_source(config::File::with_name(
                config_path.to_string_lossy().as_ref(),
            ))
            .add_source(config::Environment::with_prefix("LIDP"))
            .build()?
            .try_deserialize()
    }
}
