use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Database, FromRow, FromRowError, Query, QueryColumn, QueryDelete, QueryExpr, QueryExprValue,
    QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, Statement, Uuid,
    Value,
};
use idp_model::{
    model::{Id, OAuth2UserConsent},
    replica::{SecurityRow, SecurityTable, allows_authorization},
};

use crate::repo::{OAuth2UserConsentRepo, RepoError, RepoResult};

const TABLE: &str = "oauth2_user_consents";
const COLUMNS: [&str; 7] = [
    "id",
    "user_id",
    "client_id",
    "redirect_uri",
    "scope",
    "created_at",
    "updated_at",
];

pub struct DbOAuth2UserConsentRepo {
    engine: Arc<Database>,
}

impl DbOAuth2UserConsentRepo {
    #[must_use]
    pub const fn new(engine: Arc<Database>) -> Self {
        Self { engine }
    }

    async fn rows(&self, query: Query) -> RepoResult<Vec<ConsentRow>> {
        let mut results = self
            .engine
            .client()
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing user consent query result".into()))?
            .rows_as::<ConsentRow>()
            .map_err(row_error)
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_authorization(
            &self.engine,
            &[SecurityRow::new(SecurityTable::OAuthUserConsent, id)],
        )
        .await
        .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted user consent".into()))
        }
    }

    async fn find(&self, predicate: QueryExpr) -> RepoResult<Option<OAuth2UserConsent>> {
        let consent = self
            .rows(select(Some(predicate)))
            .await?
            .into_iter()
            .next()
            .map(OAuth2UserConsent::try_from)
            .transpose()?;
        if let Some(consent) = consent.as_ref() {
            self.ensure_clear(consent.id).await?;
        }
        Ok(consent)
    }
}

impl OAuth2UserConsentRepo for DbOAuth2UserConsentRepo {
    async fn upsert_user_consent(
        &self,
        user_id: Id,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
    ) -> RepoResult<OAuth2UserConsent> {
        let existing = self
            .find(identity(user_id, client_id, redirect_uri, scope))
            .await?;
        let now = now();
        let (consent, existing) = match existing {
            Some(consent) => (consent, true),
            None => (
                OAuth2UserConsent {
                    id: Id::now_v7(),
                    user_id,
                    client_id: client_id.into(),
                    redirect_uri: redirect_uri.into(),
                    scope: scope.into(),
                    created_at: now,
                    updated_at: now,
                },
                false,
            ),
        };
        let updated_at = if existing && now.timestamp() <= consent.updated_at.timestamp() {
            consent.updated_at + chrono::Duration::seconds(1)
        } else {
            now
        };
        let statement = if existing {
            Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![assignment(
                    "updated_at",
                    Value::Integer(updated_at.timestamp()),
                )],
                predicate: Some(equals("id", Value::Uuid(consent.id))),
                returning: None,
            })
        } else {
            Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: ConsentRow::from(&consent).into(),
                returning: None,
            })
        };
        self.engine
            .client()
            .execute(vec![Statement::Query(statement)])
            .await
            .map_err(db_error)?;
        self.ensure_clear(consent.id).await?;
        Ok(OAuth2UserConsent {
            updated_at,
            ..consent
        })
    }

    async fn find_user_consent(
        &self,
        user_id: Id,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
    ) -> RepoResult<Option<OAuth2UserConsent>> {
        self.find(identity(user_id, client_id, redirect_uri, scope))
            .await
    }

    async fn list_user_consents(
        &self,
        user_id: Id,
        offset: u32,
        limit: u32,
    ) -> RepoResult<Vec<OAuth2UserConsent>> {
        let consents = self
            .rows(select(Some(equals("user_id", Value::Uuid(user_id)))))
            .await?
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(OAuth2UserConsent::try_from)
            .collect::<RepoResult<Vec<_>>>()?;
        for consent in &consents {
            self.ensure_clear(consent.id).await?;
        }
        Ok(consents)
    }

    async fn find_user_consent_by_id(
        &self,
        consent_id: Id,
    ) -> RepoResult<Option<OAuth2UserConsent>> {
        self.find(equals("id", Value::Uuid(consent_id))).await
    }

    async fn delete_user_consent_by_id(&self, consent_id: Id) -> RepoResult<()> {
        self.ensure_clear(consent_id).await?;
        self.engine
            .client()
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(),
                predicate: Some(equals("id", Value::Uuid(consent_id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ConsentRow {
    id: Uuid,
    user_id: Uuid,
    client_id: String,
    redirect_uri: String,
    scope: String,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for ConsentRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            user_id: db::decode(db::value(row, columns, "user_id")?, "user_id")?,
            client_id: db::decode(db::value(row, columns, "client_id")?, "client_id")?,
            redirect_uri: db::decode(db::value(row, columns, "redirect_uri")?, "redirect_uri")?,
            scope: db::decode(db::value(row, columns, "scope")?, "scope")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}
impl TryFrom<ConsentRow> for OAuth2UserConsent {
    type Error = RepoError;
    fn try_from(row: ConsentRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            client_id: row.client_id,
            redirect_uri: row.redirect_uri,
            scope: row.scope,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<&OAuth2UserConsent> for ConsentRow {
    fn from(consent: &OAuth2UserConsent) -> Self {
        Self {
            id: consent.id,
            user_id: consent.user_id,
            client_id: consent.client_id.clone(),
            redirect_uri: consent.redirect_uri.clone(),
            scope: consent.scope.clone(),
            created_at: consent.created_at.timestamp(),
            updated_at: consent.updated_at.timestamp(),
        }
    }
}
impl From<ConsentRow> for Row {
    fn from(row: ConsentRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.user_id),
            Value::Text(row.client_id),
            Value::Text(row.redirect_uri),
            Value::Text(row.scope),
            Value::Null,
            Value::Null,
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}
fn now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds is valid")
}
fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid user consent timestamp".into()))
}
fn db_error(error: db::QueryError) -> RepoError {
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
fn identity(user_id: Id, client_id: &str, redirect_uri: &str, scope: &str) -> QueryExpr {
    QueryExpr::And(
        Box::new(equals("user_id", Value::Uuid(user_id))),
        Box::new(QueryExpr::And(
            Box::new(equals("client_id", Value::Text(client_id.into()))),
            Box::new(QueryExpr::And(
                Box::new(equals("redirect_uri", Value::Text(redirect_uri.into()))),
                Box::new(equals("scope", Value::Text(scope.into()))),
            )),
        )),
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
    use idp_model::replica::up;
    use std::sync::Arc;
    #[tokio::test]
    async fn upserts_and_deletes_uuid_consents() {
        let engine = Arc::new(db::Database::in_memory());
        up(&engine).await.unwrap();
        let repo = DbOAuth2UserConsentRepo::new(engine);
        let user_id = Id::now_v7();
        let consent = repo
            .upsert_user_consent(user_id, "client", "https://app.example/callback", "openid")
            .await
            .unwrap();
        let updated = repo
            .upsert_user_consent(user_id, "client", "https://app.example/callback", "openid")
            .await
            .unwrap();
        assert_eq!(updated.id, consent.id);
        assert!(updated.updated_at > consent.updated_at);
        assert_eq!(
            repo.list_user_consents(user_id, 0, 1).await.unwrap()[0].id,
            consent.id
        );
        repo.delete_user_consent_by_id(consent.id).await.unwrap();
        assert_eq!(
            repo.find_user_consent_by_id(consent.id).await.unwrap(),
            None
        );
    }
}
