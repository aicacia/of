use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryDelete, QueryExpr,
    QueryExprValue, QueryFrom, QueryInsert, QuerySelect, Row, RowCodec, Statement, Uuid, Value,
};
use idp_model::{
    model::{Id, Permission},
    replica::{SecurityRow, SecurityTable, allows_authorization},
};

use crate::{ManagementError, ManagementResult, PermissionRepo};

const PERMISSIONS: &str = "permissions";
const ROLES: &str = "roles";
const ROLE_PERMISSIONS: &str = "role_permissions";
const PERMISSION_COLUMNS: [&str; 7] = [
    "id",
    "application_id",
    "name",
    "description",
    "revoked_at",
    "created_at",
    "updated_at",
];
const ROLE_COLUMNS: [&str; 3] = ["id", "application_id", "revoked_at"];
const ROLE_PERMISSION_COLUMNS: [&str; 4] = ["id", "role_id", "permission_id", "revoked_at"];

pub struct DbPermissionRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbPermissionRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn rows<T: FromRow>(&self, query: Query) -> ManagementResult<Vec<T>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| ManagementError::InvalidInput("missing query result".into()))?
            .rows_as::<T>()
            .map_err(row_error)
    }

    async fn ensure_clear(&self, rows: &[SecurityRow]) -> ManagementResult<()> {
        if allows_authorization(&self.engine, rows)
            .await
            .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(ManagementError::InvalidInput(
                "conflicted permission state".into(),
            ))
        }
    }

    async fn permission(
        &self,
        application_id: Id,
        permission_id: Id,
    ) -> ManagementResult<Option<Permission>> {
        let permission = self
            .rows::<PermissionRow>(select(PERMISSIONS, &PERMISSION_COLUMNS))
            .await?
            .into_iter()
            .find(|row| {
                row.id == permission_id
                    && row.application_id == application_id
                    && row.revoked_at.is_none()
            })
            .map(Permission::try_from)
            .transpose()?;
        if let Some(permission) = &permission {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::Permission, permission.id)])
                .await?;
        }
        Ok(permission)
    }

    async fn role(&self, application_id: Id, role_id: Id) -> ManagementResult<Option<RoleRow>> {
        let role = self
            .rows::<RoleRow>(select(ROLES, &ROLE_COLUMNS))
            .await?
            .into_iter()
            .find(|row| {
                row.id == role_id
                    && row.application_id == application_id
                    && row.revoked_at.is_none()
            });
        if let Some(role) = &role {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::Role, role.id)])
                .await?;
        }
        Ok(role)
    }

    async fn role_permission(
        &self,
        role_id: Id,
        permission_id: Id,
    ) -> ManagementResult<Option<RolePermissionRow>> {
        let relation = self
            .rows::<RolePermissionRow>(select(ROLE_PERMISSIONS, &ROLE_PERMISSION_COLUMNS))
            .await?
            .into_iter()
            .find(|row| {
                row.role_id == role_id
                    && row.permission_id == permission_id
                    && row.revoked_at.is_none()
            });
        if let Some(relation) = relation {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::RolePermission, relation.id)])
                .await?;
            Ok(Some(relation))
        } else {
            Ok(None)
        }
    }
}

impl<K, R> PermissionRepo for DbPermissionRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    async fn list_permissions(
        &self,
        application_id: Id,
        offset: u32,
        limit: u32,
    ) -> ManagementResult<Vec<Permission>> {
        let permissions = self
            .rows::<PermissionRow>(select(PERMISSIONS, &PERMISSION_COLUMNS))
            .await?
            .into_iter()
            .filter(|row| row.application_id == application_id && row.revoked_at.is_none())
            .map(Permission::try_from)
            .collect::<ManagementResult<Vec<_>>>()?;
        for permission in &permissions {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::Permission, permission.id)])
                .await?;
        }
        Ok(permissions
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn create_permission(
        &self,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> ManagementResult<Permission> {
        self.create_permission_with_id(Id::now_v7(), application_id, name, description)
            .await
    }

    async fn create_permission_with_id(
        &self,
        id: Id,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> ManagementResult<Permission> {
        if id.is_nil() {
            return Err(ManagementError::InvalidInput(
                "permission ID must not be nil".into(),
            ));
        }
        let now = now();
        let permission = Permission {
            id,
            application_id,
            name: name.into(),
            description: description.map(str::to_owned),
            created_at: now,
            updated_at: now,
        };
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: PERMISSIONS.into(),
                row: PermissionRow::from(&permission).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        self.ensure_clear(&[SecurityRow::new(SecurityTable::Permission, permission.id)])
            .await?;
        Ok(permission)
    }

    async fn find_permission_by_id(
        &self,
        application_id: Id,
        permission_id: Id,
    ) -> ManagementResult<Option<Permission>> {
        self.permission(application_id, permission_id).await
    }

    async fn delete_permission_by_id(
        &self,
        application_id: Id,
        permission_id: Id,
    ) -> ManagementResult<()> {
        self.permission(application_id, permission_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("permission not found".into()))?;
        self.engine
            .execute(vec![Statement::Query(delete(PERMISSIONS, permission_id))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn add_permission_to_role(
        &self,
        application_id: Id,
        role_id: Id,
        permission_id: Id,
    ) -> ManagementResult<()> {
        self.role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        self.permission(application_id, permission_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("permission not found".into()))?;
        if self
            .role_permission(role_id, permission_id)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let now = now().timestamp();
        let relation = RolePermissionRow {
            id: Id::now_v7(),
            role_id,
            permission_id,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        let relation_id = relation.id;
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: ROLE_PERMISSIONS.into(),
                row: relation.into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        self.ensure_clear(&[SecurityRow::new(SecurityTable::RolePermission, relation_id)])
            .await
    }

    async fn remove_permission_from_role(
        &self,
        application_id: Id,
        role_id: Id,
        permission_id: Id,
    ) -> ManagementResult<()> {
        self.role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        self.permission(application_id, permission_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("permission not found".into()))?;
        let relation = self
            .role_permission(role_id, permission_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role permission not found".into()))?;
        self.engine
            .execute(vec![Statement::Query(delete(
                ROLE_PERMISSIONS,
                relation.id,
            ))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn list_role_permissions(
        &self,
        application_id: Id,
        role_id: Id,
    ) -> ManagementResult<Vec<Permission>> {
        self.role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        let relations = self
            .rows::<RolePermissionRow>(select(ROLE_PERMISSIONS, &ROLE_PERMISSION_COLUMNS))
            .await?;
        let permissions = self
            .rows::<PermissionRow>(select(PERMISSIONS, &PERMISSION_COLUMNS))
            .await?;
        let mut result = Vec::new();
        for relation in relations.into_iter().filter(|row| row.role_id == role_id) {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::RolePermission, relation.id)])
                .await?;
            if let Some(permission) = permissions.iter().find(|row| {
                row.id == relation.permission_id && row.application_id == application_id
            }) {
                let permission = Permission::try_from(permission.clone())?;
                self.ensure_clear(&[SecurityRow::new(SecurityTable::Permission, permission.id)])
                    .await?;
                result.push(permission);
            }
        }
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }
}

#[derive(Clone, Debug)]
struct PermissionRow {
    id: Uuid,
    application_id: Uuid,
    name: String,
    description: Option<String>,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for PermissionRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            application_id: db::decode(
                db::value(row, columns, "application_id")?,
                "application_id",
            )?,
            name: db::decode(db::value(row, columns, "name")?, "name")?,
            description: db::decode(db::value(row, columns, "description")?, "description")?,
            revoked_at: db::decode(db::value(row, columns, "revoked_at")?, "revoked_at")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}
impl TryFrom<PermissionRow> for Permission {
    type Error = ManagementError;
    fn try_from(row: PermissionRow) -> ManagementResult<Self> {
        Ok(Self {
            id: row.id,
            application_id: row.application_id,
            name: row.name,
            description: row.description,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
        })
    }
}
impl From<&Permission> for PermissionRow {
    fn from(permission: &Permission) -> Self {
        Self {
            id: permission.id,
            application_id: permission.application_id,
            name: permission.name.clone(),
            description: permission.description.clone(),
            revoked_at: None,
            created_at: permission.created_at.timestamp(),
            updated_at: permission.updated_at.timestamp(),
        }
    }
}
impl From<PermissionRow> for Row {
    fn from(row: PermissionRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.application_id),
            Value::Text(row.name),
            row.description.map_or(Value::Null, Value::Text),
            Value::Null,
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

#[derive(Debug)]
struct RoleRow {
    id: Uuid,
    application_id: Uuid,
    revoked_at: Option<i64>,
}
impl FromRow for RoleRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            application_id: db::decode(
                db::value(row, columns, "application_id")?,
                "application_id",
            )?,
            revoked_at: db::decode(db::value(row, columns, "revoked_at")?, "revoked_at")?,
        })
    }
}

#[derive(Debug)]
struct RolePermissionRow {
    id: Uuid,
    role_id: Uuid,
    permission_id: Uuid,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}
impl FromRow for RolePermissionRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            role_id: db::decode(db::value(row, columns, "role_id")?, "role_id")?,
            permission_id: db::decode(db::value(row, columns, "permission_id")?, "permission_id")?,
            revoked_at: db::decode(db::value(row, columns, "revoked_at")?, "revoked_at")?,
            created_at: 0,
            updated_at: 0,
        })
    }
}
impl From<RolePermissionRow> for Row {
    fn from(row: RolePermissionRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.role_id),
            Value::Uuid(row.permission_id),
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
fn timestamp(value: i64) -> ManagementResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| ManagementError::InvalidInput("invalid permission timestamp".into()))
}
fn db_error(error: db::EngineError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
}
fn row_error(error: FromRowError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
}
fn column(table: &str, name: &str) -> QueryColumn {
    QueryColumn::new(table.into(), name.into())
}
fn select(table: &str, columns: &[&str]) -> Query {
    Query::Select(QuerySelect {
        from: QueryFrom {
            table: table.into(),
            joins: vec![],
        },
        projection: columns.iter().map(|name| column(table, name)).collect(),
        distinct: false,
        predicate: None,
        aggregates: vec![],
        text_concats: vec![],
        group_by: vec![],
        order_by: vec![],
        limit: None,
        offset: None,
        having: None,
    })
}
fn delete(table: &str, id: Id) -> Query {
    Query::Delete(QueryDelete {
        from: QueryFrom {
            table: table.into(),
            joins: vec![],
        },
        predicate: Some(QueryExpr::Equals(
            Box::new(QueryExpr::Value(QueryExprValue::Column(column(
                table, "id",
            )))),
            Box::new(QueryExpr::Value(QueryExprValue::Value(Value::Uuid(id)))),
        )),
        returning: None,
    })
}
