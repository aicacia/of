use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Database, FromRow, FromRowError, Query, QueryColumn, QueryDelete, QueryExpr, QueryExprValue,
    QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, Statement, Uuid,
    Value,
};
use idp_model::{
    model::{Application, Id},
    replica::{SecurityRow, SecurityTable, allows_token_issuance},
};

use crate::repo::{ApplicationRepo, RepoError, RepoResult};

const TABLE: &str = "applications";
const COLUMNS: [&str; 6] = [
    "id",
    "name",
    "uri",
    "description",
    "created_at",
    "updated_at",
];

pub struct DbApplicationRepo {
    engine: Arc<Database>,
}

impl DbApplicationRepo {
    #[must_use]
    pub const fn new(engine: Arc<Database>) -> Self {
        Self { engine }
    }

    async fn find(&self, column: &str, value: Value) -> RepoResult<Option<Application>> {
        let query = select(Some(equals(column, value)));
        let mut rows = self
            .engine
            .client()
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        let rows = rows
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing application query result".into()))?;
        let application = rows
            .rows_as::<ApplicationRow>()
            .map_err(row_error)?
            .into_iter()
            .next()
            .map(Application::try_from)
            .transpose()?;
        if let Some(application) = application.as_ref() {
            self.ensure_clear(application.id).await?;
        }
        Ok(application)
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_token_issuance(
            &self.engine,
            &[SecurityRow::new(SecurityTable::Application, id)],
        )
        .await
        .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted application".into()))
        }
    }
}

impl ApplicationRepo for DbApplicationRepo {
    async fn find_by_id(&self, application_id: Id) -> RepoResult<Option<Application>> {
        self.find("id", Value::Uuid(application_id)).await
    }

    async fn find_by_uri(&self, uri: &str) -> RepoResult<Option<Application>> {
        self.find("uri", Value::Text(uri.into())).await
    }

    async fn list_applications(&self, offset: u32, limit: u32) -> RepoResult<Vec<Application>> {
        let mut rows = self
            .engine
            .client()
            .execute(vec![Statement::Query(select(None))])
            .await
            .map_err(db_error)?;
        let rows = rows
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing application query result".into()))?;
        let applications = rows.rows_as::<ApplicationRow>().map_err(row_error)?;
        let applications = applications
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(Application::try_from)
            .collect::<RepoResult<Vec<_>>>()?;
        for application in &applications {
            self.ensure_clear(application.id).await?;
        }
        Ok(applications)
    }

    async fn create_application(
        &self,
        name: String,
        uri: String,
        description: Option<String>,
    ) -> RepoResult<Application> {
        let now = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        let application = Application {
            id: Id::now_v7(),
            name,
            uri,
            description,
            created_at: now,
            updated_at: now,
        };
        self.engine
            .client()
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: ApplicationRow::from(&application).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(application)
    }

    async fn update_application(&self, application: Application) -> RepoResult<Application> {
        self.ensure_clear(application.id).await?;
        let updated_at = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        self.engine
            .client()
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![
                    assignment("name", Value::Text(application.name.clone())),
                    assignment("uri", Value::Text(application.uri.clone())),
                    assignment(
                        "description",
                        application
                            .description
                            .clone()
                            .map_or(Value::Null, Value::Text),
                    ),
                    assignment("updated_at", Value::Integer(updated_at.timestamp())),
                ],
                predicate: Some(equals("id", Value::Uuid(application.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(Application {
            updated_at,
            ..application
        })
    }

    async fn delete_application_by_id(&self, application_id: Id) -> RepoResult<()> {
        self.ensure_clear(application_id).await?;
        if self.find_by_id(application_id).await?.is_none() {
            return Err(RepoError::InvalidInput("application not found".into()));
        }
        self.engine
            .client()
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(),
                predicate: Some(equals("id", Value::Uuid(application_id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ApplicationRow {
    id: Uuid,
    name: String,
    uri: String,
    description: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for ApplicationRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            name: db::decode(db::value(row, columns, "name")?, "name")?,
            uri: db::decode(db::value(row, columns, "uri")?, "uri")?,
            description: db::decode(db::value(row, columns, "description")?, "description")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}

impl TryFrom<ApplicationRow> for Application {
    type Error = RepoError;

    fn try_from(row: ApplicationRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            name: row.name,
            uri: row.uri,
            description: row.description,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}

impl From<&Application> for ApplicationRow {
    fn from(application: &Application) -> Self {
        Self {
            id: application.id,
            name: application.name.clone(),
            uri: application.uri.clone(),
            description: application.description.clone(),
            created_at: application.created_at.timestamp(),
            updated_at: application.updated_at.timestamp(),
        }
    }
}

impl From<ApplicationRow> for Row {
    fn from(row: ApplicationRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Text(row.name),
            Value::Text(row.uri),
            row.description.map_or(Value::Null, Value::Text),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid application timestamp".into()))
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

fn column(column: &str) -> QueryColumn {
    QueryColumn::new(TABLE.into(), column.into())
}

fn equals(column_name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(column(
            column_name,
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
    use std::sync::Arc;

    use idp_model::replica::up;

    use super::*;

    #[tokio::test]
    async fn creates_updates_and_deletes_uuid_applications() {
        let engine = Arc::new(db::Database::in_memory());
        up(&engine).await.unwrap();
        let repo = DbApplicationRepo::new(Arc::clone(&engine));

        let created = repo
            .create_application("App".into(), "https://app.example".into(), None)
            .await
            .unwrap();
        assert_eq!(
            repo.find_by_id(created.id).await.unwrap(),
            Some(created.clone())
        );
        assert_eq!(
            repo.find_by_uri("https://app.example").await.unwrap(),
            Some(created.clone())
        );

        let updated = repo
            .update_application(Application {
                name: "Renamed".into(),
                ..created.clone()
            })
            .await
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        repo.delete_application_by_id(created.id).await.unwrap();
        assert_eq!(repo.find_by_id(created.id).await.unwrap(), None);
    }
}
