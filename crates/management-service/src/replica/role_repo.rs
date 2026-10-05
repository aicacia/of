use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryDelete, QueryExpr,
    QueryExprValue, QueryFrom, QueryInsert, QuerySelect, Row, RowCodec, Statement, Uuid, Value,
};
use idp_model::{
    model::{Id, Permission, Role},
    replica::{SecurityRow, SecurityTable, allows_authorization},
};

use crate::{ManagementError, ManagementResult, RoleRepo};

const ROLES: &str = "roles";
const PERMISSIONS: &str = "permissions";
const ROLE_PERMISSIONS: &str = "role_permissions";
const USER_ROLES: &str = "application_user_roles";
const ROLE_COLUMNS: [&str; 7] = [
    "id",
    "application_id",
    "name",
    "description",
    "revoked_at",
    "created_at",
    "updated_at",
];
const PERMISSION_COLUMNS: [&str; 7] = [
    "id",
    "application_id",
    "name",
    "description",
    "revoked_at",
    "created_at",
    "updated_at",
];
const ROLE_PERMISSION_COLUMNS: [&str; 4] = ["id", "role_id", "permission_id", "revoked_at"];
const USER_ROLE_COLUMNS: [&str; 7] = [
    "id",
    "user_id",
    "application_id",
    "role_id",
    "revoked_at",
    "created_at",
    "updated_at",
];

pub struct DbRoleRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbRoleRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    #[must_use]
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn rows<T: FromRow>(&self, table: &str, columns: &[&str]) -> ManagementResult<Vec<T>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(select(table, columns))])
            .await
            .map_err(db_error)?;
        results
            .pop()
            .ok_or_else(|| ManagementError::InvalidInput("missing query result".into()))?
            .rows_as::<T>()
            .map_err(row_error)
    }

    async fn roles(&self) -> ManagementResult<Vec<RoleRow>> {
        self.rows(ROLES, &ROLE_COLUMNS).await
    }

    async fn permissions(&self) -> ManagementResult<Vec<PermissionRow>> {
        self.rows(PERMISSIONS, &PERMISSION_COLUMNS).await
    }

    async fn role_permissions(&self) -> ManagementResult<Vec<RolePermissionRow>> {
        self.rows(ROLE_PERMISSIONS, &ROLE_PERMISSION_COLUMNS).await
    }

    async fn user_roles(&self) -> ManagementResult<Vec<UserRoleRow>> {
        self.rows(USER_ROLES, &USER_ROLE_COLUMNS).await
    }

    async fn ensure_clear(&self, rows: &[SecurityRow]) -> ManagementResult<()> {
        if allows_authorization(&self.engine, rows)
            .await
            .map_err(db_error)?
        {
            Ok(())
        } else {
            Err(ManagementError::InvalidInput(
                "conflicted authorization state".into(),
            ))
        }
    }

    async fn ensure_role_clear(&self, role_id: Id) -> ManagementResult<()> {
        self.ensure_clear(&[SecurityRow::new(SecurityTable::Role, role_id)])
            .await
    }

    async fn role(&self, application_id: Id, role_id: Id) -> ManagementResult<Option<Role>> {
        let role = self
            .roles()
            .await?
            .into_iter()
            .find(|role| {
                role.id == role_id
                    && role.application_id == application_id
                    && role.revoked_at.is_none()
            })
            .map(Role::try_from)
            .transpose()?;
        if let Some(role) = &role {
            self.ensure_role_clear(role.id).await?;
        }
        Ok(role)
    }

    async fn active_user_role(
        &self,
        application_id: Id,
        user_id: Id,
        role_id: Id,
    ) -> ManagementResult<Option<UserRoleRow>> {
        let user_role = self.user_roles().await?.into_iter().find(|user_role| {
            user_role.application_id == application_id
                && user_role.user_id == user_id
                && user_role.role_id == role_id
                && user_role.revoked_at.is_none()
        });
        if let Some(user_role) = &user_role {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::UserRole, user_role.id)])
                .await?;
        }
        Ok(user_role)
    }
}

impl<K, R> RoleRepo for DbRoleRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    async fn list_roles(
        &self,
        application_id: Id,
        offset: u32,
        limit: u32,
    ) -> ManagementResult<Vec<Role>> {
        let mut roles = self
            .roles()
            .await?
            .into_iter()
            .filter(|role| role.application_id == application_id && role.revoked_at.is_none())
            .map(Role::try_from)
            .collect::<ManagementResult<Vec<_>>>()?;
        roles.sort_by_key(|role| role.name.clone());
        let roles = roles
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect::<Vec<_>>();
        for role in &roles {
            self.ensure_role_clear(role.id).await?;
        }
        Ok(roles)
    }

    async fn create_role(
        &self,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> ManagementResult<Role> {
        self.create_role_with_id(Id::now_v7(), application_id, name, description)
            .await
    }

    async fn create_role_with_id(
        &self,
        id: Id,
        application_id: Id,
        name: &str,
        description: Option<&str>,
    ) -> ManagementResult<Role> {
        if id.is_nil() {
            return Err(ManagementError::InvalidInput(
                "role ID must not be nil".into(),
            ));
        }
        let now = now();
        let role = Role {
            id,
            application_id,
            name: name.into(),
            description: description.map(str::to_owned),
            created_at: now,
            updated_at: now,
        };
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: ROLES.into(),
                row: RoleRow::from(&role).into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(role)
    }

    async fn find_role_by_id(
        &self,
        application_id: Id,
        role_id: Id,
    ) -> ManagementResult<Option<Role>> {
        self.role(application_id, role_id).await
    }

    async fn delete_role_by_id(&self, application_id: Id, role_id: Id) -> ManagementResult<()> {
        let role = self
            .role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        let mut relationships = self
            .role_permissions()
            .await?
            .into_iter()
            .filter(|role_permission| {
                role_permission.role_id == role.id && role_permission.revoked_at.is_none()
            })
            .map(|role_permission| {
                SecurityRow::new(SecurityTable::RolePermission, role_permission.id)
            })
            .collect::<Vec<_>>();
        relationships.extend(
            self.user_roles()
                .await?
                .into_iter()
                .filter(|user_role| user_role.role_id == role.id && user_role.revoked_at.is_none())
                .map(|user_role| SecurityRow::new(SecurityTable::UserRole, user_role.id)),
        );
        self.ensure_clear(&relationships).await?;
        self.engine
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(ROLES),
                predicate: Some(equals(ROLES, "id", Value::Uuid(role.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn add_role_to_user(
        &self,
        application_id: Id,
        user_id: Id,
        role_id: Id,
    ) -> ManagementResult<()> {
        self.role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        if self
            .active_user_role(application_id, user_id, role_id)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let now = now();
        self.engine
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: USER_ROLES.into(),
                row: UserRoleRow {
                    id: Id::now_v7(),
                    user_id,
                    application_id,
                    role_id,
                    revoked_at: None,
                    created_at: now.timestamp(),
                    updated_at: now.timestamp(),
                }
                .into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn remove_role_from_user(
        &self,
        application_id: Id,
        user_id: Id,
        role_id: Id,
    ) -> ManagementResult<()> {
        self.role(application_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("role not found".into()))?;
        let user_role = self
            .active_user_role(application_id, user_id, role_id)
            .await?
            .ok_or_else(|| ManagementError::InvalidInput("user role not found".into()))?;
        self.engine
            .execute(vec![Statement::Query(Query::Delete(QueryDelete {
                from: from(USER_ROLES),
                predicate: Some(equals(USER_ROLES, "id", Value::Uuid(user_role.id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn list_user_roles(
        &self,
        application_id: Id,
        user_id: Id,
    ) -> ManagementResult<Vec<Role>> {
        let user_roles = self
            .user_roles()
            .await?
            .into_iter()
            .filter(|user_role| {
                user_role.application_id == application_id
                    && user_role.user_id == user_id
                    && user_role.revoked_at.is_none()
            })
            .collect::<Vec<_>>();
        for user_role in &user_roles {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::UserRole, user_role.id)])
                .await?;
        }
        let mut roles = Vec::new();
        for user_role in user_roles {
            if let Some(role) = self.role(application_id, user_role.role_id).await? {
                roles.push(role);
            }
        }
        roles.sort_by_key(|role| role.name.clone());
        Ok(roles)
    }

    async fn list_user_roles_across_applications(
        &self,
        user_id: Id,
    ) -> ManagementResult<Vec<Role>> {
        let user_roles = self
            .user_roles()
            .await?
            .into_iter()
            .filter(|user_role| user_role.user_id == user_id && user_role.revoked_at.is_none())
            .collect::<Vec<_>>();
        for user_role in &user_roles {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::UserRole, user_role.id)])
                .await?;
        }
        let mut roles = Vec::new();
        for user_role in user_roles {
            if let Some(role) = self
                .role(user_role.application_id, user_role.role_id)
                .await?
            {
                roles.push(role);
            }
        }
        roles.sort_by_key(|role| (role.application_id, role.name.clone()));
        Ok(roles)
    }

    async fn list_user_permissions(
        &self,
        application_id: Id,
        user_id: Id,
    ) -> ManagementResult<Vec<Permission>> {
        let roles = self.list_user_roles(application_id, user_id).await?;
        let role_ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
        let role_permissions = self
            .role_permissions()
            .await?
            .into_iter()
            .filter(|row| role_ids.contains(&row.role_id) && row.revoked_at.is_none())
            .collect::<Vec<_>>();
        for row in &role_permissions {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::RolePermission, row.id)])
                .await?;
        }
        let permission_ids = role_permissions
            .iter()
            .map(|row| row.permission_id)
            .collect::<Vec<_>>();
        let mut permissions = self
            .permissions()
            .await?
            .into_iter()
            .filter(|permission| {
                permission.application_id == application_id
                    && permission_ids.contains(&permission.id)
                    && permission.revoked_at.is_none()
            })
            .map(Permission::try_from)
            .collect::<ManagementResult<Vec<_>>>()?;
        permissions.sort_by_key(|permission| permission.name.clone());
        for permission in &permissions {
            self.ensure_clear(&[SecurityRow::new(SecurityTable::Permission, permission.id)])
                .await?;
        }
        Ok(permissions)
    }

    async fn has_user_application_permission(
        &self,
        user_id: Id,
        application_id: Id,
        permission_name: &str,
    ) -> ManagementResult<bool> {
        let permissions = self.list_user_permissions(application_id, user_id).await?;
        Ok(permissions
            .iter()
            .any(|permission| permission_matches(&permission.name, permission_name)))
    }
}

#[derive(Debug)]
struct RoleRow {
    id: Uuid,
    application_id: Uuid,
    name: String,
    description: Option<String>,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for RoleRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode(row, columns, "id")?,
            application_id: decode(row, columns, "application_id")?,
            name: decode(row, columns, "name")?,
            description: decode(row, columns, "description")?,
            revoked_at: decode(row, columns, "revoked_at")?,
            created_at: decode(row, columns, "created_at")?,
            updated_at: decode(row, columns, "updated_at")?,
        })
    }
}

impl TryFrom<RoleRow> for Role {
    type Error = ManagementError;

    fn try_from(row: RoleRow) -> ManagementResult<Self> {
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

impl From<&Role> for RoleRow {
    fn from(role: &Role) -> Self {
        Self {
            id: role.id,
            application_id: role.application_id,
            name: role.name.clone(),
            description: role.description.clone(),
            revoked_at: None,
            created_at: role.created_at.timestamp(),
            updated_at: role.updated_at.timestamp(),
        }
    }
}

impl From<RoleRow> for Row {
    fn from(row: RoleRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.application_id),
            Value::Text(row.name),
            row.description.map_or(Value::Null, Value::Text),
            row.revoked_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

#[derive(Debug)]
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
            id: decode(row, columns, "id")?,
            application_id: decode(row, columns, "application_id")?,
            name: decode(row, columns, "name")?,
            description: decode(row, columns, "description")?,
            revoked_at: decode(row, columns, "revoked_at")?,
            created_at: decode(row, columns, "created_at")?,
            updated_at: decode(row, columns, "updated_at")?,
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

#[derive(Debug)]
struct RolePermissionRow {
    id: Uuid,
    role_id: Uuid,
    permission_id: Uuid,
    revoked_at: Option<i64>,
}

impl FromRow for RolePermissionRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode(row, columns, "id")?,
            role_id: decode(row, columns, "role_id")?,
            permission_id: decode(row, columns, "permission_id")?,
            revoked_at: decode(row, columns, "revoked_at")?,
        })
    }
}

#[derive(Debug)]
struct UserRoleRow {
    id: Uuid,
    user_id: Uuid,
    application_id: Uuid,
    role_id: Uuid,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for UserRoleRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: decode(row, columns, "id")?,
            user_id: decode(row, columns, "user_id")?,
            application_id: decode(row, columns, "application_id")?,
            role_id: decode(row, columns, "role_id")?,
            revoked_at: decode(row, columns, "revoked_at")?,
            created_at: decode(row, columns, "created_at")?,
            updated_at: decode(row, columns, "updated_at")?,
        })
    }
}

impl From<UserRoleRow> for Row {
    fn from(row: UserRoleRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Uuid(row.user_id),
            Value::Uuid(row.application_id),
            Value::Uuid(row.role_id),
            row.revoked_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn decode<T: db::FromValue>(row: &Row, columns: &[&str], name: &str) -> Result<T, FromRowError> {
    db::decode(db::value(row, columns, name)?, name)
}

fn timestamp(value: i64) -> ManagementResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| ManagementError::InvalidInput("invalid timestamp".into()))
}

fn now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds is valid")
}

fn db_error(error: db::EngineError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
}

fn row_error(error: FromRowError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
}

fn from(table: &str) -> QueryFrom {
    QueryFrom {
        table: table.into(),
        joins: vec![],
    }
}

fn column(table: &str, name: &str) -> QueryColumn {
    QueryColumn::new(table.into(), name.into())
}

fn equals(table: &str, name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(column(
            table, name,
        )))),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}

fn select(table: &str, columns: &[&str]) -> Query {
    Query::Select(QuerySelect {
        from: from(table),
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

fn permission_matches(granted: &str, required: &str) -> bool {
    if granted == "*" || granted == required {
        return true;
    }
    let Some(prefix) = granted.strip_suffix('*') else {
        return false;
    };
    if required.starts_with(prefix) {
        return true;
    }
    prefix
        .strip_suffix(':')
        .is_some_and(|prefix| required.starts_with(&format!("{prefix}.")))
        || prefix
            .strip_suffix('.')
            .is_some_and(|prefix| required.starts_with(&format!("{prefix}:")))
}
