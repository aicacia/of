use std::sync::Arc;

use db::{
    Engine, Kernel, Query, QueryColumn, QueryExpr, QueryExprValue, QueryFrom, QueryInsert,
    QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, RowCodec, Statement, Value,
};
use idp_model::{
    model::Id,
    replica::{SecurityRow, SecurityTable, allows_token_issuance},
};
use sha2::{Digest, Sha256};

use crate::repo::{OAuth2RefreshToken, OAuth2RefreshTokenRepo, RepoError, RepoResult};

const TABLE: &str = "oauth2_refresh_tokens";

pub struct DbOAuth2RefreshTokenRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbOAuth2RefreshTokenRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_token_issuance(
            &self.engine,
            &[SecurityRow::new(SecurityTable::OAuthRefreshToken, id)],
        )
        .await
        .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted refresh token".into()))
        }
    }
}

impl<K, R> OAuth2RefreshTokenRepo for DbOAuth2RefreshTokenRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    async fn issue_refresh_token(
        &self,
        token: OAuth2RefreshToken,
        previous: Option<&str>,
    ) -> RepoResult<()> {
        let previous_id = if let Some(previous) = previous {
            let results = self
                .engine
                .execute(vec![select(
                    &["id"],
                    Some(equals("token_hash", Value::Text(token_hash(previous)))),
                )])
                .await
                .map_err(db_error)?;
            let row = results[0].rows.first().ok_or_else(invalid_grant)?;
            let id: Id = db::decode(&row.values[0], "id")
                .map_err(|error| RepoError::InvalidInput(error.to_string()))?;
            self.ensure_clear(id).await?;
            Some(id)
        } else {
            None
        };
        let id = Id::now_v7();
        let row = Row::new(vec![
            Value::Uuid(id),
            Value::Text(token_hash(&token.token)),
            Value::Uuid(token.client_id),
            Value::Uuid(token.user_id),
            Value::Text(serde_json::to_string(&token.scopes).map_err(json_error)?),
            token.resource.map_or(Value::Null, Value::Text),
            token
                .authorization_details
                .map(|details| serde_json::to_string(&details))
                .transpose()
                .map_err(json_error)?
                .map_or(Value::Null, Value::Text),
            Value::Integer(token.expires_at),
            Value::Null,
            Value::Null,
            Value::Integer(token.created_at),
            Value::Integer(token.created_at),
        ]);
        let mut transaction = self.engine.transaction().await.map_err(db_error)?;
        if let Some(id) = previous_id {
            let predicate = and(
                and(
                    and(
                        equals("id", Value::Uuid(id)),
                        equals(
                            "token_hash",
                            Value::Text(token_hash(
                                previous.expect("previous ID requires a token"),
                            )),
                        ),
                    ),
                    equals("client_id", Value::Uuid(token.client_id)),
                ),
                and(
                    equals("user_id", Value::Uuid(token.user_id)),
                    and(
                        is_null("consumed_at"),
                        and(
                            is_null("revoked_at"),
                            QueryExpr::GreaterThan(
                                Box::new(expr("expires_at")),
                                Box::new(QueryExpr::Value(QueryExprValue::Value(Value::Integer(
                                    token.created_at,
                                )))),
                            ),
                        ),
                    ),
                ),
            );
            let results = transaction
                .execute(vec![update("consumed_at", token.created_at, predicate)])
                .await
                .map_err(db_error)?;
            if results[0].rows.len() != 1 {
                transaction.rollback().await.map_err(db_error)?;
                return Err(invalid_grant());
            }
        }
        transaction
            .execute(vec![insert(row)])
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        if let Some(id) = previous_id {
            self.ensure_clear(id).await?;
        }
        self.ensure_clear(id).await
    }

    async fn revoke_refresh_token(
        &self,
        token: &str,
        client_id: Id,
        revoked_at: i64,
    ) -> RepoResult<()> {
        self.engine
            .execute(vec![update(
                "revoked_at",
                revoked_at,
                and(
                    equals("token_hash", Value::Text(token_hash(token))),
                    and(
                        equals("client_id", Value::Uuid(client_id)),
                        is_null("revoked_at"),
                    ),
                ),
            )])
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

fn insert(row: Row) -> Statement {
    Statement::Query(Query::Insert(QueryInsert {
        table: TABLE.into(),
        row,
        returning: None,
    }))
}
fn update(name: &str, now: i64, predicate: QueryExpr) -> Statement {
    Statement::Query(Query::Update(QueryUpdate {
        from: from(),
        assignments: vec![assignment(name, now), assignment("updated_at", now)],
        predicate: Some(predicate),
        returning: Some(vec![column("id")]),
    }))
}
fn select(columns: &[&str], predicate: Option<QueryExpr>) -> Statement {
    Statement::Query(Query::Select(QuerySelect {
        from: from(),
        projection: columns.iter().map(|name| column(name)).collect(),
        distinct: false,
        predicate,
        aggregates: vec![],
        text_concats: vec![],
        group_by: vec![],
        order_by: vec![],
        limit: None,
        offset: None,
        having: None,
    }))
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
fn expr(name: &str) -> QueryExpr {
    QueryExpr::Value(QueryExprValue::Column(column(name)))
}
fn equals(name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(expr(name)),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}
fn is_null(name: &str) -> QueryExpr {
    QueryExpr::IsNull(Box::new(expr(name)))
}
fn and(left: QueryExpr, right: QueryExpr) -> QueryExpr {
    QueryExpr::And(Box::new(left), Box::new(right))
}
fn assignment(name: &str, now: i64) -> QueryUpdateAssignment {
    QueryUpdateAssignment {
        column: column(name),
        value: QueryExprValue::Value(Value::Integer(now)),
    }
}
fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
fn invalid_grant() -> RepoError {
    RepoError::InvalidInput("refresh token is expired, revoked, consumed, or not found".into())
}
fn db_error(error: db::EngineError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}
fn json_error(error: serde_json::Error) -> RepoError {
    RepoError::Other(Box::new(error))
}

#[cfg(test)]
#[path = "refresh_token_tests.rs"]
mod tests;
