use std::path::Path;

use api::ServerConfig;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub data_dir: String,

    pub log_level: String,
    pub api_public_uri: String,
    pub idp_api_base: String,
    pub storage_api_base: String,
    pub expected_issuer: String,
    pub storage_audience: String,
    pub idp_permission_evaluator_client_id: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            data_dir: "data".to_string(),

            log_level: "DEBUG".to_string(),
            api_public_uri: "https://management-api.localhost:1355".to_string(),
            idp_api_base: String::new(),
            storage_api_base: String::new(),
            expected_issuer: String::new(),
            storage_audience: String::new(),
            idp_permission_evaluator_client_id: None,
        }
    }
}

impl<'a> TryFrom<&'a Path> for AppConfig {
    type Error = config::ConfigError;

    fn try_from(config_path: &'a Path) -> Result<Self, Self::Error> {
        config::Config::builder()
            .add_source(config::File::with_name(
                config_path.to_string_lossy().as_ref(),
            ))
            .add_source(config::Environment::with_prefix("SERVER"))
            .build()?
            .try_deserialize()
    }
}
