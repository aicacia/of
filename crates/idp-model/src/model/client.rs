#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use chrono::{DateTime, Utc};

use super::Id;
use crate::contract::{
    ApplicationRegistration, ClientProfile, ClientRegistration, ClientType, GrantType,
    ResponseType, TokenEndpointAuthMethod,
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Client {
    pub id: Id,

    pub application_id: Id,

    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_hash: String,

    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub client_id_issued_at: Option<DateTime<Utc>>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub client_secret_expires_at: Option<DateTime<Utc>>,

    pub client_name: String,
    pub client_uri: String,

    #[serde(with = "model::json_vec")]
    pub redirect_uris: Vec<String>,

    #[serde(with = "super::sql_enum::client_type")]
    pub client_type: ClientType,
    #[serde(with = "super::sql_enum::client_profile")]
    pub profile: ClientProfile,

    #[serde(with = "super::sql_enum::token_endpoint_auth_method")]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,

    #[serde(with = "model::json_vec")]
    pub allowed_grant_types: Vec<GrantType>,

    #[serde(with = "model::json_vec")]
    pub response_types: Vec<ResponseType>,

    #[serde(with = "model::json_vec")]
    pub allowed_scopes: Vec<String>,

    #[serde(with = "model::json_vec")]
    pub allowed_audiences: Vec<String>,

    pub logo_uri: Option<String>,

    #[serde(with = "model::json_vec")]
    pub contacts: Vec<String>,

    pub terms_of_service_uri: Option<String>,

    pub policy_uri: Option<String>,

    pub software_statement: Option<String>,

    pub software_id: Option<String>,

    pub software_version: Option<String>,

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl From<Client> for ClientRegistration {
    fn from(val: Client) -> Self {
        ClientRegistration {
            // The URI of the application associated with the client.
            application: ApplicationRegistration {
                name: Some(val.client_name.clone()),
                uri: val.client_uri.clone(),
                description: None,
            },
            client_id: Some(val.client_id),
            client_secret: None,
            client_id_issued_at: val.client_id_issued_at.map(|dt| dt.timestamp()),
            client_secret_expires_at: val.client_secret_expires_at.map(|dt| dt.timestamp()),
            client_name: val.client_name,
            client_uri: Some(val.client_uri),
            redirect_uris: val.redirect_uris,
            client_type: val.client_type,
            profile: val.profile,
            token_endpoint_auth_method: val.token_endpoint_auth_method,
            allowed_grant_types: val.allowed_grant_types,
            response_types: val.response_types,
            allowed_scopes: val.allowed_scopes,
            allowed_audiences: val.allowed_audiences,
            logo_uri: val.logo_uri,
            contacts: val.contacts,
            terms_of_service_uri: val.terms_of_service_uri,
            policy_uri: val.policy_uri,
            software_statement: val.software_statement,
            software_id: val.software_id,
            software_version: val.software_version,
        }
    }
}
