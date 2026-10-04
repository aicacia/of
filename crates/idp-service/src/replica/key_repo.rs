use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryDelete, QueryExpr,
    QueryExprValue, QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row,
    RowCodec, Statement, Uuid, Value,
};
use idp_model::{
    contract::{EntityType, JwkPublic},
    model::{Id, Key},
    replica::allows_authentication,
};

use crate::repo::{KeyRepo, RepoError, RepoResult};

const TABLE: &str = "keys";
const COLUMNS: [&str; 13] = [
    "id",
    "parent_id",
    "entity_type",
    "entity_id",
    "derivation_path",
    "derivation_index",
    "hardened",
    "name",
    "revoked_at",
    "expires_at",
    "created_at",
    "updated_at",
    "public_jwk",
];

pub struct DbKeyRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbKeyRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn keys(&self) -> RepoResult<Vec<Key>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(select(None))])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| RepoError::InvalidInput("missing key query result".into()))?
            .rows_as::<KeyRow>()
            .map_err(row_error)?
            .into_iter()
            .map(Key::try_from)
            .collect()
    }

    async fn ensure_clear(&self, id: Id) -> RepoResult<()> {
        if allows_authentication(&self.engine, &[], &[id])
            .await
            .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(RepoError::InvalidInput("conflicted key".into()))
        }
    }
}

impl<K, R> KeyRepo for DbKeyRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction> + Send + Sync,
{
    async fn set_public_jwk(&self, id: Id, jwk: JwkPublic) -> RepoResult<Key> {
        if jwk.kid != id.to_string() {
            return Err(RepoError::InvalidInput(
                "public key ID does not match key".into(),
            ));
        }
        self.ensure_clear(id).await?;
        let encoded =
            serde_json::to_string(&jwk).map_err(|error| RepoError::Other(Box::new(error)))?;
        let results = self
            .engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![QueryUpdateAssignment {
                    column: column("public_jwk"),
                    value: QueryExprValue::Value(Value::Text(encoded)),
                }],
                predicate: Some(QueryExpr::And(
                    Box::new(equals("id", Value::Uuid(id))),
                    Box::new(QueryExpr::IsNull(Box::new(QueryExpr::Value(
                        QueryExprValue::Column(column("public_jwk")),
                    )))),
                )),
                returning: Some(COLUMNS.into_iter().map(column).collect()),
            }))])
            .await
            .map_err(db_error)?;
        if results[0].rows.len() != 1 {
            return Err(RepoError::InvalidInput(
                "public key is already set or key is missing".into(),
            ));
        }
        self.ensure_clear(id).await?;
        let mut keys = results[0].rows_as::<KeyRow>().map_err(row_error)?;
        Key::try_from(keys.pop().expect("one updated key row"))
    }

    async fn list_active(&self) -> RepoResult<Vec<Key>> {
        let now = Utc::now();
        let keys = self
            .keys()
            .await?
            .into_iter()
            .filter(|key| active(key, now))
            .collect::<Vec<_>>();
        for key in &keys {
            self.ensure_clear(key.id).await?;
        }
        Ok(keys)
    }

    async fn list_by_entity_type_and_id(
        &self,
        entity_type: EntityType,
        entity_id: Id,
    ) -> RepoResult<Vec<Key>> {
        let now = Utc::now();
        let keys = self
            .keys()
            .await?
            .into_iter()
            .filter(|key| {
                key.entity_type == entity_type && key.entity_id == entity_id && active(key, now)
            })
            .collect::<Vec<_>>();
        for key in &keys {
            self.ensure_clear(key.id).await?;
        }
        Ok(keys)
    }

    async fn find_by_id(&self, id: Id) -> RepoResult<Option<Key>> {
        let key = self
            .keys()
            .await?
            .into_iter()
            .find(|key| key.id == id && active(key, Utc::now()));
        if let Some(key) = key.as_ref() {
            self.ensure_clear(key.id).await?;
        }
        Ok(key)
    }

    async fn find_by_entity_type_and_id(
        &self,
        entity_type: EntityType,
        entity_id: Id,
    ) -> RepoResult<Option<Key>> {
        self.find_active_entity_root_key(entity_type, entity_id)
            .await
    }

    async fn find_active_entity_root_key(
        &self,
        entity_type: EntityType,
        entity_id: Id,
    ) -> RepoResult<Option<Key>> {
        let key = self
            .list_by_entity_type_and_id(entity_type, entity_id)
            .await?
            .into_iter()
            .filter(|key| key.parent_id.is_none())
            .max_by_key(|key| key.created_at);
        Ok(key)
    }

    async fn delete_by_entity_type_and_id(
        &self,
        entity_type: EntityType,
        entity_id: Id,
    ) -> RepoResult<()> {
        self.engine
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(),
                predicate: Some(QueryExpr::And(
                    Box::new(equals("entity_type", Value::Integer(entity_type as i64))),
                    Box::new(equals("entity_id", Value::Uuid(entity_id))),
                )),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn create_key(
        &self,
        parent_id: Option<Id>,
        entity_type: EntityType,
        entity_id: Id,
        hardened: bool,
        name: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> RepoResult<Key> {
        let parent = match parent_id {
            Some(id) => Some(
                self.find_by_id(id)
                    .await?
                    .ok_or_else(|| RepoError::InvalidInput("parent key not found".into()))?,
            ),
            None => None,
        };
        let derivation_index = match self
            .keys()
            .await?
            .into_iter()
            .filter(|key| key.parent_id == parent_id)
            .map(|key| key.derivation_index)
            .max()
        {
            Some(index) => index
                .checked_add(1)
                .ok_or_else(|| RepoError::InvalidInput("key derivation index exhausted".into()))?,
            None => 0,
        };
        let now = Utc::now()
            .with_nanosecond(0)
            .expect("zero nanoseconds is valid");
        let key = Key {
            id: Id::now_v7(),
            parent_id,
            entity_type,
            entity_id,
            derivation_path: Key::build_derivation_path(
                parent.as_ref().map(|key| key.derivation_path.as_str()),
                derivation_index,
                hardened,
            ),
            derivation_index,
            hardened,
            name,
            public_jwk: None,
            revoked_at: None,
            expires_at,
            created_at: now,
            updated_at: now,
        };
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: KeyRow::from(&key).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(key)
    }
}

#[derive(Debug)]
struct KeyRow {
    id: Uuid,
    parent_id: Option<Uuid>,
    entity_type: i64,
    entity_id: Uuid,
    derivation_path: String,
    derivation_index: i64,
    hardened: i64,
    name: String,
    revoked_at: Option<i64>,
    expires_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    public_jwk: Option<String>,
}

impl FromRow for KeyRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            parent_id: db::decode(db::value(row, columns, "parent_id")?, "parent_id")?,
            entity_type: db::decode(db::value(row, columns, "entity_type")?, "entity_type")?,
            entity_id: db::decode(db::value(row, columns, "entity_id")?, "entity_id")?,
            derivation_path: db::decode(
                db::value(row, columns, "derivation_path")?,
                "derivation_path",
            )?,
            derivation_index: db::decode(
                db::value(row, columns, "derivation_index")?,
                "derivation_index",
            )?,
            hardened: db::decode(db::value(row, columns, "hardened")?, "hardened")?,
            name: db::decode(db::value(row, columns, "name")?, "name")?,
            revoked_at: db::decode(db::value(row, columns, "revoked_at")?, "revoked_at")?,
            expires_at: db::decode(db::value(row, columns, "expires_at")?, "expires_at")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
            public_jwk: db::decode(db::value(row, columns, "public_jwk")?, "public_jwk")?,
        })
    }
}

impl TryFrom<KeyRow> for Key {
    type Error = RepoError;

    fn try_from(row: KeyRow) -> RepoResult<Self> {
        Ok(Self {
            id: row.id,
            parent_id: row.parent_id,
            entity_type: match row.entity_type {
                0 => EntityType::User,
                1 => EntityType::Client,
                _ => return Err(RepoError::InvalidInput("invalid key entity type".into())),
            },
            entity_id: row.entity_id,
            derivation_path: row.derivation_path,
            derivation_index: u32::try_from(row.derivation_index)
                .map_err(|_| RepoError::InvalidInput("invalid key derivation index".into()))?,
            hardened: row.hardened != 0,
            name: row.name,
            revoked_at: row.revoked_at.map(timestamp).transpose()?,
            expires_at: row.expires_at.map(timestamp).transpose()?,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
            public_jwk: row
                .public_jwk
                .map(|value| serde_json::from_str(&value))
                .transpose()
                .map_err(|error| RepoError::Other(Box::new(error)))?,
        })
    }
}

impl From<&Key> for KeyRow {
    fn from(key: &Key) -> Self {
        Self {
            id: key.id,
            parent_id: key.parent_id,
            entity_type: key.entity_type as i64,
            entity_id: key.entity_id,
            derivation_path: key.derivation_path.clone(),
            derivation_index: i64::from(key.derivation_index),
            hardened: i64::from(key.hardened),
            name: key.name.clone(),
            revoked_at: key.revoked_at.map(|value| value.timestamp()),
            expires_at: key.expires_at.map(|value| value.timestamp()),
            created_at: key.created_at.timestamp(),
            updated_at: key.updated_at.timestamp(),
            public_jwk: key.public_jwk.as_ref().map(|jwk| {
                serde_json::to_string(jwk).expect("public JWK contains only serializable fields")
            }),
        }
    }
}

impl From<KeyRow> for Row {
    fn from(row: KeyRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            row.parent_id.map_or(Value::Null, Value::Uuid),
            Value::Integer(row.entity_type),
            Value::Uuid(row.entity_id),
            Value::Text(row.derivation_path),
            Value::Integer(row.derivation_index),
            Value::Integer(row.hardened),
            Value::Text(row.name),
            row.revoked_at.map_or(Value::Null, Value::Integer),
            row.expires_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
            row.public_jwk.map_or(Value::Null, Value::Text),
        ])
    }
}

fn active(key: &Key, now: DateTime<Utc>) -> bool {
    key.revoked_at.is_none_or(|revoked_at| revoked_at > now)
        && key.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn timestamp(value: i64) -> RepoResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| RepoError::InvalidInput("invalid key timestamp".into()))
}

fn db_error(error: db::EngineError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}

fn row_error(error: FromRowError) -> RepoError {
    RepoError::InvalidInput(error.to_string())
}

fn column(column: &str) -> QueryColumn {
    QueryColumn::new(TABLE.into(), column.into())
}

fn equals(name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(column(name)))),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}

fn from() -> QueryFrom {
    QueryFrom {
        table: TABLE.into(),
        joins: vec![],
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

    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use idp_model::replica::up;

    use super::*;

    #[tokio::test]
    async fn creates_uuid_keys_with_unique_sibling_paths() {
        let engine = Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        up(&engine).await.unwrap();
        let repo = DbKeyRepo::new(engine);
        let entity_id = Id::now_v7();

        let first = repo
            .create_key(
                None,
                EntityType::User,
                entity_id,
                true,
                "first".into(),
                None,
            )
            .await
            .unwrap();
        let second = repo
            .create_key(
                None,
                EntityType::User,
                entity_id,
                true,
                "second".into(),
                None,
            )
            .await
            .unwrap();
        let child = repo
            .create_key(
                Some(first.id),
                EntityType::User,
                entity_id,
                false,
                "child".into(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            (first.derivation_index, first.derivation_path.as_str()),
            (0, "m/0'")
        );
        assert_eq!(
            (second.derivation_index, second.derivation_path.as_str()),
            (1, "m/1'")
        );
        assert_eq!(
            (child.derivation_index, child.derivation_path.as_str()),
            (0, "m/0'/0")
        );
        assert_eq!(repo.find_by_id(first.id).await.unwrap(), Some(first));
    }
}
