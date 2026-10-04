use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryExpr, QueryExprValue,
    QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, RowCodec,
    Statement, Uuid, Value,
};
use idp_model::{
    contract::CodeChallengeMethod,
    model::{Id, OAuth2AuthorizationCode},
    replica::{SecurityRow, SecurityTable, allows_token_issuance},
};
use sha2::{Digest, Sha256};

use crate::{
    generate_random_string,
    repo::{OAuth2AuthorizationCodeRepo, RepoError, RepoResult},
};

const TABLE: &str = "oauth2_authorization_codes";
const COLUMNS: [&str; 14] = [
    "id",
    "code_hash",
    "client_id",
    "key_id",
    "redirect_uri",
    "scopes",
    "resource",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "expires_at",
    "consumed_at",
    "created_at",
    "updated_at",
];

pub struct DbOAuth2AuthorizationCodeRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbOAuth2AuthorizationCodeRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn find(&self, code: &str) -> RepoResult<Option<OAuth2AuthorizationCode>> {
        let row = self
            .rows(select(Some(equals(
                "code_hash",
                Value::Text(code_hash(code)),
            ))))
            .await?
            .into_iter()
            .next()
            .map(OAuth2AuthorizationCode::try_from)
            .transpose()?;
        if let Some(row) = row.as_ref() {
            self.ensure_clear(row.id).await?;
        }
        Ok(row.map(|row| OAuth2AuthorizationCode {
            code: code.into(),
            ..row
        }))
    }

    async fn rows(&self, query: Query) -> RepoResult<Vec<AuthorizationCodeRow>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| {
                RepoError::InvalidInput("missing authorization code query result".into())
            })?
            .rows_as::<AuthorizationCodeRow>()
            .map_err(row_error)
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_token_issuance(
            &self.engine,
            &[SecurityRow::new(SecurityTable::OAuthAuthorizationCode, id)],
        )
        .await
        .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput(
                "conflicted authorization code".into(),
            ))
        }
    }
}

impl<K, R> OAuth2AuthorizationCodeRepo for DbOAuth2AuthorizationCodeRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    async fn create_authorization_code(
        &self,
        client_id: String,
        key_id: Id,
        redirect_uri: String,
        scopes: Vec<String>,
        resource: Option<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
        nonce: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<OAuth2AuthorizationCode> {
        let now = now();
        let code = OAuth2AuthorizationCode {
            id: Id::now_v7(),
            code: generate_random_string::<32>(),
            client_id,
            key_id,
            redirect_uri,
            scopes,
            resource,
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at,
            consumed_at: None,
            created_at: now,
            updated_at: now,
        };
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: AuthorizationCodeRow::from(&code).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        self.ensure_clear(code.id).await?;
        Ok(code)
    }

    async fn find_authorization_code_by_code(
        &self,
        code: &str,
    ) -> RepoResult<Option<OAuth2AuthorizationCode>> {
        self.find(code).await
    }

    async fn consume_authorization_code(
        &self,
        id: Id,
        consumed_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        self.ensure_clear(id).await?;
        let code = self
            .rows(select(Some(equals("id", Value::Uuid(id)))))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| RepoError::InvalidInput("authorization code not found".into()))?;
        if code.consumed_at.is_some() {
            return Err(RepoError::InvalidInput(
                "authorization code already consumed".into(),
            ));
        }
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![
                    assignment("consumed_at", Value::Integer(consumed_at.timestamp())),
                    assignment("updated_at", Value::Integer(consumed_at.timestamp())),
                ],
                predicate: Some(QueryExpr::And(
                    Box::new(equals("id", Value::Uuid(id))),
                    Box::new(QueryExpr::IsNull(Box::new(QueryExpr::Value(
                        QueryExprValue::Column(column("consumed_at")),
                    )))),
                )),
                returning: Some(vec![column("id")]),
            }))])
            .await
            .map_err(db_error)?;
        let updated = results
            .pop()
            .ok_or_else(|| {
                RepoError::InvalidInput("missing authorization code update result".into())
            })?
            .rows;
        if updated.is_empty() {
            return Err(RepoError::InvalidInput(
                "authorization code not found or already consumed".into(),
            ));
        }
        self.ensure_clear(id).await
    }
}

#[derive(Debug)]
struct AuthorizationCodeRow {
    id: Uuid,
    code: String,
    client_id: String,
    key_id: Uuid,
    redirect_uri: String,
    scopes: String,
    resource: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<i64>,
    nonce: Option<String>,
    expires_at: i64,
    consumed_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for AuthorizationCodeRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            code: db::decode(db::value(row, columns, "code_hash")?, "code_hash")?,
            client_id: db::decode(db::value(row, columns, "client_id")?, "client_id")?,
            key_id: db::decode(db::value(row, columns, "key_id")?, "key_id")?,
            redirect_uri: db::decode(db::value(row, columns, "redirect_uri")?, "redirect_uri")?,
            scopes: db::decode(db::value(row, columns, "scopes")?, "scopes")?,
            resource: db::decode(db::value(row, columns, "resource")?, "resource")?,
            code_challenge: db::decode(
                db::value(row, columns, "code_challenge")?,
                "code_challenge",
            )?,
            code_challenge_method: db::decode(
                db::value(row, columns, "code_challenge_method")?,
                "code_challenge_method",
            )?,
            nonce: db::decode(db::value(row, columns, "nonce")?, "nonce")?,
            expires_at: db::decode(db::value(row, columns, "expires_at")?, "expires_at")?,
            consumed_at: db::decode(db::value(row, columns, "consumed_at")?, "consumed_at")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}

impl TryFrom<AuthorizationCodeRow> for OAuth2AuthorizationCode {
    type Error = RepoError;

    fn try_from(row: AuthorizationCodeRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            code: row.code,
            client_id: row.client_id,
            key_id: row.key_id,
            redirect_uri: row.redirect_uri,
            scopes: serde_json::from_str(&row.scopes)
                .map_err(|error| RepoError::Other(Box::new(error)))?,
            resource: row.resource,
            code_challenge: row.code_challenge,
            code_challenge_method: row
                .code_challenge_method
                .map(code_challenge_method)
                .transpose()?,
            nonce: row.nonce,
            expires_at: timestamp(row.expires_at)?,
            consumed_at: row.consumed_at.map(timestamp).transpose()?,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}

impl From<&OAuth2AuthorizationCode> for AuthorizationCodeRow {
    fn from(code: &OAuth2AuthorizationCode) -> Self {
        Self {
            id: code.id,
            code: code_hash(&code.code),
            client_id: code.client_id.clone(),
            key_id: code.key_id,
            redirect_uri: code.redirect_uri.clone(),
            scopes: serde_json::to_string(&code.scopes)
                .expect("authorization code scopes serialize"),
            resource: code.resource.clone(),
            code_challenge: code.code_challenge.clone(),
            code_challenge_method: code.code_challenge_method.map(|method| method as i64),
            nonce: code.nonce.clone(),
            expires_at: code.expires_at.timestamp(),
            consumed_at: None,
            created_at: code.created_at.timestamp(),
            updated_at: code.updated_at.timestamp(),
        }
    }
}

impl From<AuthorizationCodeRow> for Row {
    fn from(row: AuthorizationCodeRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Text(row.code),
            Value::Text(row.client_id),
            Value::Null,
            Value::Uuid(row.key_id),
            Value::Text(row.redirect_uri),
            Value::Text(row.scopes),
            row.resource.map_or(Value::Null, Value::Text),
            Value::Null,
            row.code_challenge.map_or(Value::Null, Value::Text),
            row.code_challenge_method
                .map_or(Value::Null, Value::Integer),
            row.nonce.map_or(Value::Null, Value::Text),
            Value::Integer(row.expires_at),
            row.consumed_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn code_hash(code: &str) -> String {
    format!("{:x}", Sha256::digest(code.as_bytes()))
}

fn code_challenge_method(value: i64) -> RepoResult<CodeChallengeMethod> {
    match value {
        0 => Ok(CodeChallengeMethod::S256),
        _ => Err(RepoError::InvalidInput(
            "invalid code challenge method".into(),
        )),
    }
}
fn now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds is valid")
}
fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid authorization code timestamp".into()))
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
fn column(name: &str) -> QueryColumn {
    QueryColumn::new(TABLE.into(), name.into())
}
fn equals(name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(column(name)))),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}
fn assignment(name: &str, value: Value) -> QueryUpdateAssignment {
    QueryUpdateAssignment {
        column: column(name),
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
    use super::*;
    use chrono::Duration;
    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use idp_model::replica::up;
    use std::sync::Arc;

    #[tokio::test]
    async fn concurrent_consumers_have_one_winner() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.unwrap();
        let repo = DbOAuth2AuthorizationCodeRepo::new(engine);
        let code = repo
            .create_authorization_code(
                "client".into(),
                Id::now_v7(),
                "https://app.example/callback".into(),
                vec!["openid".into()],
                None,
                None,
                None,
                None,
                now() + Duration::minutes(5),
            )
            .await
            .unwrap();
        assert_eq!(
            repo.find_authorization_code_by_code(&code.code)
                .await
                .unwrap(),
            Some(code.clone())
        );
        let (first, second) = tokio::join!(
            repo.consume_authorization_code(code.id, now()),
            repo.consume_authorization_code(code.id, now()),
        );
        assert_ne!(first.is_ok(), second.is_ok());
        assert!(
            repo.find_authorization_code_by_code(&code.code)
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_some()
        );
    }
}
