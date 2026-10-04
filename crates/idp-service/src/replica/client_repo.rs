use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryDelete, QueryExpr,
    QueryExprValue, QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row,
    RowCodec, Statement, Uuid, Value,
};
use idp_model::{
    contract::{
        ClientProfile, ClientRegistration, ClientType, EntityType, TokenEndpointAuthMethod,
    },
    model::{Client, Id},
    replica::{SecurityRow, SecurityTable, allows_token_issuance},
};

use crate::{
    PasswordConfig, encrypt_password,
    replica::DbKeyRepo,
    repo::{ClientRepo, KeyService, PrivateKeyRepo, RepoError, RepoResult},
};

const TABLE: &str = "clients";
const COLUMNS: [&str; 25] = [
    "id",
    "application_id",
    "client_id",
    "client_secret_hash",
    "client_id_issued_at",
    "client_secret_expires_at",
    "client_name",
    "client_uri",
    "redirect_uris",
    "client_type",
    "profile",
    "token_endpoint_auth_method",
    "allowed_grant_types",
    "response_types",
    "allowed_scopes",
    "allowed_audiences",
    "logo_uri",
    "contacts",
    "terms_of_service_uri",
    "policy_uri",
    "software_statement",
    "software_id",
    "software_version",
    "created_at",
    "updated_at",
];

pub struct DbClientRepo<K, R, P = crate::repo::PrivateKeyKeyringRepo>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
    P: PrivateKeyRepo + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
    key_service: Arc<KeyService<DbKeyRepo<K, R>, P>>,
}

impl<K, R, P> DbClientRepo<K, R, P>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
    P: PrivateKeyRepo + Send + Sync,
{
    #[must_use]
    pub const fn new(
        engine: Arc<Engine<K, R>>,
        key_service: Arc<KeyService<DbKeyRepo<K, R>, P>>,
    ) -> Self {
        Self {
            engine,
            key_service,
        }
    }

    async fn clients(&self, predicate: Option<QueryExpr>) -> RepoResult<Vec<Client>> {
        let revoked_at = QueryExpr::Value(QueryExprValue::Column(column("revoked_at")));
        let active = QueryExpr::Or(
            Box::new(QueryExpr::IsNull(Box::new(revoked_at.clone()))),
            Box::new(QueryExpr::GreaterThan(
                Box::new(revoked_at),
                Box::new(QueryExpr::Value(QueryExprValue::Value(Value::Integer(
                    Utc::now().timestamp(),
                )))),
            )),
        );
        let predicate = Some(match predicate {
            Some(predicate) => QueryExpr::And(Box::new(predicate), Box::new(active)),
            None => active,
        });
        let mut results = self
            .engine
            .execute(vec![Statement::Query(select(predicate))])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing client query result".into()))?
            .rows_as::<ClientRow>()
            .map_err(row_error)?
            .into_iter()
            .map(Client::try_from)
            .collect()
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_token_issuance(&self.engine, &[SecurityRow::new(SecurityTable::Client, id)])
            .await
            .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted client".into()))
        }
    }

    async fn application_id(&self, registration: &ClientRegistration) -> RepoResult<Id> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Select(QuerySelect {
                from: QueryFrom {
                    table: "applications".into(),
                    joins: vec![],
                },
                projection: vec![QueryColumn::new("applications".into(), "id".into())],
                distinct: false,
                predicate: Some(equals_in(
                    "applications",
                    "uri",
                    Value::Text(registration.application.uri.clone()),
                )),
                aggregates: vec![],
                text_concats: vec![],
                group_by: vec![],
                order_by: vec![],
                limit: None,
                offset: None,
                having: None,
            }))])
            .await
            .map_err(db_error)?;
        let rows = results
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing application query result".into()))?
            .rows_as::<ApplicationIdRow>()
            .map_err(row_error)?;
        if let Some(row) = rows.into_iter().next() {
            return Ok(row.id);
        }

        let now = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        let id = Id::now_v7();
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: "applications".into(),
                row: Row::new(vec![
                    Value::Uuid(id),
                    Value::Text(
                        registration
                            .application
                            .name
                            .clone()
                            .unwrap_or_else(|| registration.client_name.clone()),
                    ),
                    Value::Text(registration.application.uri.clone()),
                    registration
                        .application
                        .description
                        .clone()
                        .map_or(Value::Null, Value::Text),
                    Value::Integer(now.timestamp()),
                    Value::Integer(now.timestamp()),
                ]),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(id)
    }
}

impl<K, R, P> ClientRepo for DbClientRepo<K, R, P>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
    P: PrivateKeyRepo + Send + Sync,
{
    async fn find_client_by_id(&self, id: Id) -> RepoResult<Option<Client>> {
        let client = self
            .clients(Some(equals("id", Value::Uuid(id))))
            .await?
            .into_iter()
            .next();
        if let Some(client) = client.as_ref() {
            self.ensure_clear(client.id).await?;
        }
        Ok(client)
    }

    async fn find_client_by_client_id(&self, client_id: &str) -> RepoResult<Option<Client>> {
        let client = self
            .clients(Some(equals("client_id", Value::Text(client_id.into()))))
            .await?
            .into_iter()
            .next();
        if let Some(client) = client.as_ref() {
            self.ensure_clear(client.id).await?;
        }
        Ok(client)
    }

    async fn list_clients(&self, offset: u32, limit: u32) -> RepoResult<Vec<Client>> {
        let clients = self.clients(None).await?;
        let clients = clients
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect::<Vec<_>>();
        for client in &clients {
            self.ensure_clear(client.id).await?;
        }
        Ok(clients)
    }

    async fn create_client(&self, registration: ClientRegistration) -> RepoResult<Client> {
        let client_id = registration
            .client_id
            .clone()
            .ok_or_else(|| RepoError::InvalidInput("client_id is required".into()))?;
        let client_secret = match registration.client_type {
            ClientType::Confidential => registration
                .client_secret
                .clone()
                .filter(|secret| !secret.trim().is_empty())
                .ok_or_else(|| {
                    RepoError::InvalidInput(
                        "client_secret is required for confidential client key material".into(),
                    )
                })?,
            ClientType::Public => String::new(),
        };
        let client_secret_hash = if registration.client_type == ClientType::Confidential {
            encrypt_password(&PasswordConfig::default(), &client_secret)
                .map_err(|error| RepoError::Other(error.into()))?
        } else {
            String::new()
        };
        let application_id = self.application_id(&registration).await?;
        let now = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        let client = Client {
            id: Id::now_v7(),
            application_id,
            client_id,
            client_secret_hash,
            client_id_issued_at: registration
                .client_id_issued_at
                .map(timestamp)
                .transpose()?,
            client_secret_expires_at: registration
                .client_secret_expires_at
                .map(timestamp)
                .transpose()?,
            client_name: registration.client_name,
            client_uri: registration
                .client_uri
                .unwrap_or_else(|| registration.application.uri.clone()),
            redirect_uris: registration.redirect_uris,
            client_type: registration.client_type,
            profile: registration.profile,
            token_endpoint_auth_method: registration.token_endpoint_auth_method,
            allowed_grant_types: registration.allowed_grant_types,
            response_types: registration.response_types,
            allowed_scopes: registration.allowed_scopes,
            allowed_audiences: registration.allowed_audiences,
            logo_uri: registration.logo_uri,
            contacts: registration.contacts,
            terms_of_service_uri: registration.terms_of_service_uri,
            policy_uri: registration.policy_uri,
            software_statement: registration.software_statement,
            software_id: registration.software_id,
            software_version: registration.software_version,
            created_at: now,
            updated_at: now,
        };
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: ClientRow::from(&client).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;

        self.key_service
            .ensure_entity_master_key(EntityType::Client, client.id, "")?;
        self.key_service
            .create_key(
                None,
                EntityType::Client,
                client.id,
                true,
                client.client_name.clone(),
                None,
            )
            .await?;
        Ok(client)
    }

    async fn update_client(&self, client: Client) -> RepoResult<Client> {
        self.ensure_clear(client.id).await?;
        let updated_at = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        self.engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: ClientRow::from(&client).assignments(updated_at.timestamp()),
                predicate: Some(equals("id", Value::Uuid(client.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(Client {
            updated_at,
            ..client
        })
    }

    async fn delete_client_by_client_id(&self, client_id: &str) -> RepoResult<()> {
        let client = self
            .find_client_by_client_id(client_id)
            .await?
            .ok_or_else(|| RepoError::InvalidInput("client not found".into()))?;
        self.engine
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(),
                predicate: Some(equals("id", Value::Uuid(client.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ApplicationIdRow {
    id: Uuid,
}

impl FromRow for ApplicationIdRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
        })
    }
}

#[derive(Debug)]
struct ClientRow {
    id: Uuid,
    application_id: Uuid,
    client_id: String,
    client_secret_hash: String,
    client_id_issued_at: Option<i64>,
    client_secret_expires_at: Option<i64>,
    client_name: String,
    client_uri: String,
    redirect_uris: String,
    client_type: i64,
    profile: i64,
    token_endpoint_auth_method: i64,
    allowed_grant_types: String,
    response_types: String,
    allowed_scopes: String,
    allowed_audiences: String,
    logo_uri: Option<String>,
    contacts: String,
    terms_of_service_uri: Option<String>,
    policy_uri: Option<String>,
    software_statement: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for ClientRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            application_id: db::decode(
                db::value(row, columns, "application_id")?,
                "application_id",
            )?,
            client_id: db::decode(db::value(row, columns, "client_id")?, "client_id")?,
            client_secret_hash: db::decode(
                db::value(row, columns, "client_secret_hash")?,
                "client_secret_hash",
            )?,
            client_id_issued_at: db::decode(
                db::value(row, columns, "client_id_issued_at")?,
                "client_id_issued_at",
            )?,
            client_secret_expires_at: db::decode(
                db::value(row, columns, "client_secret_expires_at")?,
                "client_secret_expires_at",
            )?,
            client_name: db::decode(db::value(row, columns, "client_name")?, "client_name")?,
            client_uri: db::decode(db::value(row, columns, "client_uri")?, "client_uri")?,
            redirect_uris: db::decode(db::value(row, columns, "redirect_uris")?, "redirect_uris")?,
            client_type: db::decode(db::value(row, columns, "client_type")?, "client_type")?,
            profile: db::decode(db::value(row, columns, "profile")?, "profile")?,
            token_endpoint_auth_method: db::decode(
                db::value(row, columns, "token_endpoint_auth_method")?,
                "token_endpoint_auth_method",
            )?,
            allowed_grant_types: db::decode(
                db::value(row, columns, "allowed_grant_types")?,
                "allowed_grant_types",
            )?,
            response_types: db::decode(
                db::value(row, columns, "response_types")?,
                "response_types",
            )?,
            allowed_scopes: db::decode(
                db::value(row, columns, "allowed_scopes")?,
                "allowed_scopes",
            )?,
            allowed_audiences: db::decode(
                db::value(row, columns, "allowed_audiences")?,
                "allowed_audiences",
            )?,
            logo_uri: db::decode(db::value(row, columns, "logo_uri")?, "logo_uri")?,
            contacts: db::decode(db::value(row, columns, "contacts")?, "contacts")?,
            terms_of_service_uri: db::decode(
                db::value(row, columns, "terms_of_service_uri")?,
                "terms_of_service_uri",
            )?,
            policy_uri: db::decode(db::value(row, columns, "policy_uri")?, "policy_uri")?,
            software_statement: db::decode(
                db::value(row, columns, "software_statement")?,
                "software_statement",
            )?,
            software_id: db::decode(db::value(row, columns, "software_id")?, "software_id")?,
            software_version: db::decode(
                db::value(row, columns, "software_version")?,
                "software_version",
            )?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}

impl TryFrom<ClientRow> for Client {
    type Error = RepoError;

    fn try_from(row: ClientRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            application_id: row.application_id,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            client_id_issued_at: row.client_id_issued_at.map(timestamp).transpose()?,
            client_secret_expires_at: row.client_secret_expires_at.map(timestamp).transpose()?,
            client_name: row.client_name,
            client_uri: row.client_uri,
            redirect_uris: json(&row.redirect_uris)?,
            client_type: client_type(row.client_type)?,
            profile: profile(row.profile)?,
            token_endpoint_auth_method: token_endpoint_auth_method(row.token_endpoint_auth_method)?,
            allowed_grant_types: json(&row.allowed_grant_types)?,
            response_types: json(&row.response_types)?,
            allowed_scopes: json(&row.allowed_scopes)?,
            allowed_audiences: json(&row.allowed_audiences)?,
            logo_uri: row.logo_uri,
            contacts: json(&row.contacts)?,
            terms_of_service_uri: row.terms_of_service_uri,
            policy_uri: row.policy_uri,
            software_statement: row.software_statement,
            software_id: row.software_id,
            software_version: row.software_version,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}

impl From<&Client> for ClientRow {
    fn from(client: &Client) -> Self {
        Self {
            id: client.id,
            application_id: client.application_id,
            client_id: client.client_id.clone(),
            client_secret_hash: client.client_secret_hash.clone(),
            client_id_issued_at: client.client_id_issued_at.map(|value| value.timestamp()),
            client_secret_expires_at: client
                .client_secret_expires_at
                .map(|value| value.timestamp()),
            client_name: client.client_name.clone(),
            client_uri: client.client_uri.clone(),
            redirect_uris: json_string(&client.redirect_uris),
            client_type: client.client_type as i64,
            profile: client.profile as i64,
            token_endpoint_auth_method: client.token_endpoint_auth_method as i64,
            allowed_grant_types: json_string(&client.allowed_grant_types),
            response_types: json_string(&client.response_types),
            allowed_scopes: json_string(&client.allowed_scopes),
            allowed_audiences: json_string(&client.allowed_audiences),
            logo_uri: client.logo_uri.clone(),
            contacts: json_string(&client.contacts),
            terms_of_service_uri: client.terms_of_service_uri.clone(),
            policy_uri: client.policy_uri.clone(),
            software_statement: client.software_statement.clone(),
            software_id: client.software_id.clone(),
            software_version: client.software_version.clone(),
            created_at: client.created_at.timestamp(),
            updated_at: client.updated_at.timestamp(),
        }
    }
}

impl ClientRow {
    fn assignments(self, updated_at: i64) -> Vec<QueryUpdateAssignment> {
        vec![
            assignment("application_id", Value::Uuid(self.application_id)),
            assignment("client_secret_hash", Value::Text(self.client_secret_hash)),
            assignment(
                "client_id_issued_at",
                self.client_id_issued_at.map_or(Value::Null, Value::Integer),
            ),
            assignment(
                "client_secret_expires_at",
                self.client_secret_expires_at
                    .map_or(Value::Null, Value::Integer),
            ),
            assignment("client_name", Value::Text(self.client_name)),
            assignment("client_uri", Value::Text(self.client_uri)),
            assignment("redirect_uris", Value::Text(self.redirect_uris)),
            assignment("client_type", Value::Integer(self.client_type)),
            assignment("profile", Value::Integer(self.profile)),
            assignment(
                "token_endpoint_auth_method",
                Value::Integer(self.token_endpoint_auth_method),
            ),
            assignment("allowed_grant_types", Value::Text(self.allowed_grant_types)),
            assignment("response_types", Value::Text(self.response_types)),
            assignment("allowed_scopes", Value::Text(self.allowed_scopes)),
            assignment("allowed_audiences", Value::Text(self.allowed_audiences)),
            assignment("logo_uri", self.logo_uri.map_or(Value::Null, Value::Text)),
            assignment("contacts", Value::Text(self.contacts)),
            assignment(
                "terms_of_service_uri",
                self.terms_of_service_uri.map_or(Value::Null, Value::Text),
            ),
            assignment(
                "policy_uri",
                self.policy_uri.map_or(Value::Null, Value::Text),
            ),
            assignment(
                "software_statement",
                self.software_statement.map_or(Value::Null, Value::Text),
            ),
            assignment(
                "software_id",
                self.software_id.map_or(Value::Null, Value::Text),
            ),
            assignment(
                "software_version",
                self.software_version.map_or(Value::Null, Value::Text),
            ),
            assignment("updated_at", Value::Integer(updated_at)),
        ]
    }
}

impl From<ClientRow> for Row {
    fn from(row: ClientRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.application_id),
            Value::Text(row.client_id),
            Value::Text(row.client_secret_hash),
            row.client_id_issued_at.map_or(Value::Null, Value::Integer),
            row.client_secret_expires_at
                .map_or(Value::Null, Value::Integer),
            Value::Text(row.client_name),
            Value::Text(row.client_uri),
            Value::Text(row.redirect_uris),
            Value::Integer(row.client_type),
            Value::Integer(row.profile),
            Value::Integer(row.token_endpoint_auth_method),
            Value::Text(row.allowed_grant_types),
            Value::Text(row.response_types),
            Value::Text(row.allowed_scopes),
            Value::Text(row.allowed_audiences),
            row.logo_uri.map_or(Value::Null, Value::Text),
            Value::Text(row.contacts),
            row.terms_of_service_uri.map_or(Value::Null, Value::Text),
            row.policy_uri.map_or(Value::Null, Value::Text),
            row.software_statement.map_or(Value::Null, Value::Text),
            row.software_id.map_or(Value::Null, Value::Text),
            row.software_version.map_or(Value::Null, Value::Text),
            Value::Null,
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn json<T: serde::de::DeserializeOwned>(value: &str) -> RepoResult<T> {
    serde_json::from_str(value).map_err(RepoError::other)
}
fn json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("client fields are serializable")
}
fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid client timestamp".into()))
}
fn client_type(value: i64) -> RepoResult<ClientType> {
    match value {
        0 => Ok(ClientType::Confidential),
        1 => Ok(ClientType::Public),
        _ => Err(RepoError::InvalidInput("invalid client type".into())),
    }
}
fn profile(value: i64) -> RepoResult<ClientProfile> {
    match value {
        0 => Ok(ClientProfile::Web),
        1 => Ok(ClientProfile::UserAgentBased),
        2 => Ok(ClientProfile::Native),
        _ => Err(RepoError::InvalidInput("invalid client profile".into())),
    }
}
fn token_endpoint_auth_method(value: i64) -> RepoResult<TokenEndpointAuthMethod> {
    match value {
        0 => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        1 => Ok(TokenEndpointAuthMethod::ClientSecretPost),
        2 => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        3 => Ok(TokenEndpointAuthMethod::ClientSecretJwt),
        4 => Ok(TokenEndpointAuthMethod::None),
        _ => Err(RepoError::InvalidInput(
            "invalid client token endpoint auth method".into(),
        )),
    }
}
fn db_error(error: db::EngineError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}
fn row_error(error: FromRowError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}
fn from() -> QueryFrom {
    QueryFrom {
        table: TABLE.into(),
        joins: vec![],
    }
}
fn column(column: &str) -> QueryColumn {
    QueryColumn::new(TABLE.into(), column.into())
}
fn equals(column_name: &str, value: Value) -> QueryExpr {
    equals_in(TABLE, column_name, value)
}
fn equals_in(table: &str, column_name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(QueryColumn::new(
            table.into(),
            column_name.into(),
        )))),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}
fn assignment(column_name: &str, value: Value) -> QueryUpdateAssignment {
    QueryUpdateAssignment {
        column: column(column_name),
        value: QueryExprValue::Value(value),
    }
}
fn select(predicate: Option<QueryExpr>) -> Query {
    Query::Select(QuerySelect {
        from: from(),
        projection: COLUMNS.into_iter().map(column).collect(),
        distinct: false,
        predicate,
        aggregates: vec![],
        text_concats: vec![],
        group_by: vec![],
        order_by: vec![],
        limit: None,
        offset: None,
        having: None,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use idp_model::{
        contract::{ApplicationRegistration, ClientProfile, GrantType, ResponseType},
        replica::up,
    };

    use crate::{
        oauth2::{OAuth2Config, OAuth2Service},
        replica::{
            DbApplicationRepo, DbOAuth2AuthorizationCodeRepo, DbOAuth2RefreshTokenRepo,
            DbOAuth2UserConsentRepo, DbUserRepo,
        },
        repo::KeyRepo,
        util::verify_password,
    };

    use super::*;

    #[derive(Default)]
    struct TestPrivateKeyRepo(Mutex<HashMap<(String, String), key::DerivedKey>>);
    impl PrivateKeyRepo for TestPrivateKeyRepo {
        fn load(
            &self,
            namespace: &str,
            path: &key::DerivationPath,
        ) -> RepoResult<Option<key::DerivedKey>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(namespace.into(), path.to_string()))
                .cloned())
        }
        fn store(&self, namespace: &str, key: &key::DerivedKey) -> RepoResult<()> {
            self.0
                .lock()
                .unwrap()
                .insert((namespace.into(), key.to_string()), key.clone());
            Ok(())
        }
        fn delete(&self, namespace: &str, path: &key::DerivationPath) -> RepoResult<()> {
            self.0
                .lock()
                .unwrap()
                .remove(&(namespace.into(), path.to_string()));
            Ok(())
        }
    }

    fn registration(client_type: ClientType, client_secret: Option<&str>) -> ClientRegistration {
        ClientRegistration {
            application: ApplicationRegistration {
                name: Some("App".into()),
                uri: "https://app.example".into(),
                description: None,
            },
            client_id: Some(format!("{client_type}-client")),
            client_secret: client_secret.map(str::to_owned),
            client_id_issued_at: None,
            client_secret_expires_at: None,
            client_name: "Client".into(),
            client_uri: None,
            logo_uri: None,
            contacts: vec![],
            terms_of_service_uri: None,
            policy_uri: None,
            client_type,
            profile: ClientProfile::Web,
            redirect_uris: vec!["https://app.example/callback".into()],
            allowed_grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            allowed_scopes: vec!["openid".into()],
            allowed_audiences: vec!["https://storage.example".into()],
            token_endpoint_auth_method: match client_type {
                ClientType::Public => TokenEndpointAuthMethod::None,
                ClientType::Confidential => TokenEndpointAuthMethod::ClientSecretPost,
            },
            software_statement: None,
            software_id: None,
            software_version: None,
        }
    }

    #[tokio::test]
    async fn client_secrets_are_disclosed_only_on_creation_and_rotation() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.expect("initialize current IdP schema");
        let key_service = Arc::new(KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            TestPrivateKeyRepo::default(),
            "test",
        ));
        let service = OAuth2Service::new(
            DbApplicationRepo::new(Arc::clone(&engine)),
            DbClientRepo::new(Arc::clone(&engine), Arc::clone(&key_service)),
            DbOAuth2AuthorizationCodeRepo::new(Arc::clone(&engine)),
            DbOAuth2RefreshTokenRepo::new(Arc::clone(&engine)),
            DbUserRepo::new(Arc::clone(&engine), PasswordConfig::default()),
            DbOAuth2UserConsentRepo::new(Arc::clone(&engine)),
            key_service,
            OAuth2Config::default(),
        );
        let created = service
            .register_client(registration(
                ClientType::Confidential,
                Some("initial-secret"),
            ))
            .await
            .expect("register confidential client");
        let client_id = created.client_id.as_deref().expect("created client has ID");
        assert_eq!(created.client_secret.as_deref(), Some("initial-secret"));
        assert_eq!(
            service
                .get_client(client_id)
                .await
                .expect("get client")
                .client_secret,
            None
        );
        assert!(
            service
                .list_clients(0, 10)
                .await
                .expect("list clients")
                .iter()
                .all(|client| client.client_secret.is_none())
        );
        let rotated = service
            .update_client(
                client_id,
                registration(ClientType::Confidential, Some("rotated-secret")),
            )
            .await
            .expect("rotate client secret");
        assert_eq!(rotated.client_secret.as_deref(), Some("rotated-secret"));
        let stored = service
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .expect("read rotated client")
            .expect("client exists");
        assert!(
            verify_password("rotated-secret", &stored.client_secret_hash)
                .expect("stored verifier is valid")
        );
        assert!(
            !verify_password("initial-secret", &stored.client_secret_hash)
                .expect("stored verifier is valid")
        );
        assert!(
            serde_json::to_value(&stored)
                .expect("serialize client")
                .get("client_secret_hash")
                .is_none()
        );
        let updated = service
            .update_client(client_id, registration(ClientType::Confidential, None))
            .await
            .expect("update client without rotating secret");
        assert_eq!(updated.client_secret, None);
        let unchanged = service
            .client_repo
            .find_client_by_client_id(client_id)
            .await
            .expect("read updated client")
            .expect("client exists");
        assert_eq!(unchanged.client_secret_hash, stored.client_secret_hash);
    }

    #[tokio::test]
    async fn creates_public_and_confidential_clients_with_root_keys() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.unwrap();
        let key_service = Arc::new(KeyService::new(
            DbKeyRepo::new(Arc::clone(&engine)),
            TestPrivateKeyRepo::default(),
            "test",
        ));
        let repo = DbClientRepo::new(engine, Arc::clone(&key_service));
        for (client_type, secret) in [
            (ClientType::Public, None),
            (ClientType::Confidential, Some("secret")),
        ] {
            let client = repo
                .create_client(registration(client_type, secret))
                .await
                .unwrap();
            if let Some(secret) = secret {
                assert_ne!(client.client_secret_hash, secret);
                assert!(
                    crate::util::verify_password(secret, &client.client_secret_hash)
                        .expect("stored verifier is valid")
                );
                assert!(
                    !crate::util::verify_password("wrong-secret", &client.client_secret_hash)
                        .expect("stored verifier is valid")
                );
            } else {
                assert!(client.client_secret_hash.is_empty());
            }
            let response: ClientRegistration = client.clone().into();
            assert_eq!(response.client_secret, None);
            assert_eq!(
                repo.find_client_by_client_id(&client.client_id)
                    .await
                    .unwrap(),
                Some(client.clone())
            );
            assert_eq!(
                repo.find_client_by_id(client.id).await.unwrap(),
                Some(client.clone())
            );
            assert!(
                key_service
                    .key_repo()
                    .find_active_entity_root_key(EntityType::Client, client.id)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}
