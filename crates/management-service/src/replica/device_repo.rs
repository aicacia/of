use std::sync::Arc;

use chrono::{DateTime, Timelike, Utc};
use db::{
    Database, FromRow, FromRowError, Query, QueryColumn, QueryDelete, QueryExpr, QueryExprValue,
    QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, Statement, Uuid,
    Value,
};
use idp_model::{
    contract::{DeviceState, TrustedDevice},
    model::{Device, Id},
    replica::allows_tunnel_access,
};

use crate::{DeviceRepo, ManagementError, ManagementResult};

const TABLE: &str = "devices";
const COLUMNS: [&str; 10] = [
    "id",
    "owner_subject",
    "name",
    "public_key",
    "address",
    "state",
    "approved_at",
    "revoked_at",
    "created_at",
    "updated_at",
];

pub struct DbDeviceRepo {
    engine: Arc<Database>,
}

impl DbDeviceRepo {
    #[must_use]
    pub const fn new(engine: Arc<Database>) -> Self {
        Self { engine }
    }

    /// Caller verifies exact mutation permission and an active new User in IdP.
    pub async fn transfer_owned(
        &self,
        device_id: Id,
        old_owner: &str,
        new_owner: &str,
    ) -> ManagementResult<bool> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(false);
        };
        self.ensure_clear(device_id).await?;
        if row.state != DeviceState::Approved
            || row.owner_subject != old_owner
            || old_owner == new_owner
        {
            return Ok(false);
        }
        let mut transaction = self.engine.client().transaction().await.map_err(db_error)?;
        for table in [TABLE, "local_device_enrollments"] {
            if !transaction
                .row_conflicts(table, &Row::new(vec![Value::Uuid(device_id)]))
                .await
                .map_err(db_error)?
                .is_empty()
            {
                return Err(ManagementError::InvalidInput("conflicted device".into()));
            }
        }
        let Query::Select(mut query) = select() else {
            unreachable!("Device query is a Select")
        };
        query.predicate = Some(QueryExpr::And(
            Box::new(equals("id", Value::Uuid(device_id))),
            Box::new(QueryExpr::And(
                Box::new(equals("owner_subject", Value::Text(old_owner.to_owned()))),
                Box::new(equals(
                    "state",
                    Value::Integer(DeviceState::Approved as i64),
                )),
            )),
        ));
        let results = transaction
            .execute(vec![Statement::Query(Query::Select(query))])
            .await
            .map_err(db_error)?;
        if results.iter().all(|result| result.rows.is_empty()) {
            return Ok(false);
        }
        transaction
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![
                    assignment("owner_subject", Value::Text(new_owner.to_owned())),
                    assignment("updated_at", Value::Integer(now().timestamp())),
                ],
                predicate: Some(equals("id", Value::Uuid(device_id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn records(&self) -> ManagementResult<Vec<DeviceRow>> {
        let mut results = self
            .engine
            .client()
            .execute(vec![Statement::Query(select())])
            .await
            .map_err(db_error)?;
        let mut rows = results
            .pop()
            .ok_or_else(|| ManagementError::InvalidInput("missing device query result".into()))?
            .rows_as::<DeviceRow>()
            .map_err(row_error)?;
        for row in &mut rows {
            let results = self.engine.client().translate_and_execute(
                &format!("SELECT enrollment_code_hash, enrollment_expires_at, pairing_accepting_public_key FROM local_device_enrollments WHERE device_id = CAST('{}' AS UUID)", row.id),
                &db::SqlTranslator,
            ).await.map_err(db_error)?;
            if let Some(local) = results[0].rows.first() {
                row.enrollment_code_hash =
                    db::decode(&local.values[0], "enrollment_code_hash").map_err(row_error)?;
                row.enrollment_expires_at =
                    db::decode(&local.values[1], "enrollment_expires_at").map_err(row_error)?;
                row.pairing_accepting_public_key =
                    db::decode(&local.values[2], "pairing_accepting_public_key")
                        .map_err(row_error)?;
            }
        }
        if rows.iter().any(|row| row.owner_subject.trim().is_empty()) {
            return Err(ManagementError::InvalidInput(
                "device record has no owner".into(),
            ));
        }
        Ok(rows)
    }

    async fn record(&self, id: Id) -> ManagementResult<Option<DeviceRow>> {
        Ok(self.records().await?.into_iter().find(|row| row.id == id))
    }

    async fn ensure_clear(&self, id: Id) -> ManagementResult<()> {
        if allows_tunnel_access(&self.engine, &[id])
            .await
            .map_err(db_error)?
            && self
                .engine
                .client()
                .row_conflicts("local_device_enrollments", &Row::new(vec![Value::Uuid(id)]))
                .await
                .map_err(db_error)?
                .is_empty()
        {
            Ok(())
        } else {
            Err(ManagementError::InvalidInput("conflicted device".into()))
        }
    }

    async fn update(
        &self,
        id: Id,
        assignments: Vec<QueryUpdateAssignment>,
    ) -> ManagementResult<()> {
        let terminal = assignments.iter().any(|assignment| {
            assignment.column.column == "state"
                && matches!(
                    assignment.value,
                    QueryExprValue::Value(Value::Integer(1 | 2))
                )
        });
        let mut transaction = self.engine.client().transaction().await.map_err(db_error)?;
        transaction
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments,
                predicate: Some(equals("id", Value::Uuid(id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        if terminal {
            transaction
                .execute(vec![Statement::Query(local_enrollment_delete(id))])
                .await
                .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }
}

impl DeviceRepo for DbDeviceRepo {
    async fn create(
        &self,
        owner_subject: String,
        name: String,
        public_key: String,
        address: String,
        enrollment_code_hash: Vec<u8>,
        enrollment_expires_at: i64,
    ) -> ManagementResult<Device> {
        if owner_subject.trim().is_empty() {
            return Err(ManagementError::InvalidInput(
                "device owner is required".into(),
            ));
        }
        let now = now();
        let state = if self.records().await?.is_empty() {
            DeviceState::Approved
        } else {
            DeviceState::Pending
        };
        let row = DeviceRow {
            id: Id::now_v7(),
            owner_subject,
            name,
            public_key,
            address,
            enrollment_code_hash: (state == DeviceState::Pending).then_some(enrollment_code_hash),
            enrollment_expires_at: (state == DeviceState::Pending).then_some(enrollment_expires_at),
            pairing_accepting_public_key: None,
            state,
            approved_at: None,
            revoked_at: None,
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
        };
        let mut transaction = self.engine.client().transaction().await.map_err(db_error)?;
        transaction
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: row.clone().into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        if row.state == DeviceState::Pending {
            transaction
                .execute(vec![Statement::Query(local_enrollment_insert(&row))])
                .await
                .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        row.try_into()
    }

    async fn create_pairing(
        &self,
        name: String,
        public_key: String,
        address: String,
        accepting_public_key: String,
    ) -> ManagementResult<Device> {
        let owner_subject = self
            .records()
            .await?
            .into_iter()
            .find(|device| {
                device.public_key == accepting_public_key
                    && !device.owner_subject.trim().is_empty()
                    && device.state == DeviceState::Approved
            })
            .map(|device| device.owner_subject)
            .ok_or_else(|| ManagementError::InvalidInput("approving device has no owner".into()))?;
        let now = now();
        let row = DeviceRow {
            id: Id::now_v7(),
            owner_subject,
            name,
            public_key,
            address,
            enrollment_code_hash: None,
            enrollment_expires_at: None,
            pairing_accepting_public_key: Some(accepting_public_key),
            state: DeviceState::Pending,
            approved_at: None,
            revoked_at: None,
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
        };
        let mut transaction = self.engine.client().transaction().await.map_err(db_error)?;
        transaction
            .execute(vec![Statement::Query(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: row.clone().into(),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        if row.state == DeviceState::Pending {
            transaction
                .execute(vec![Statement::Query(local_enrollment_insert(&row))])
                .await
                .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        row.try_into()
    }

    async fn pending_pairing(&self, device_id: Id) -> ManagementResult<Option<(Device, String)>> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(None);
        };
        self.ensure_clear(device_id).await?;
        if row.state != DeviceState::Pending {
            return Ok(None);
        }
        let Some(key) = row.pairing_accepting_public_key.clone() else {
            return Ok(None);
        };
        Ok(Some((row.try_into()?, key)))
    }

    async fn approve_pairing(&self, device_id: Id) -> ManagementResult<Option<Device>> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(None);
        };
        self.ensure_clear(device_id).await?;
        if row.state != DeviceState::Pending || row.pairing_accepting_public_key.is_none() {
            return Ok(None);
        }
        let updated_at = now();
        self.update(
            device_id,
            vec![
                assignment("state", Value::Integer(DeviceState::Approved as i64)),
                assignment("updated_at", Value::Integer(updated_at.timestamp())),
            ],
        )
        .await?;
        DeviceRow {
            state: DeviceState::Approved,
            pairing_accepting_public_key: None,
            updated_at: updated_at.timestamp(),
            ..row
        }
        .try_into()
        .map(Some)
    }

    async fn has_any(&self) -> ManagementResult<bool> {
        Ok(!self.records().await?.is_empty())
    }

    async fn list(&self) -> ManagementResult<Vec<Device>> {
        let rows = self.records().await?;
        for row in &rows {
            self.ensure_clear(row.id).await?;
        }
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn find_approved_by_public_key(
        &self,
        public_key: &str,
    ) -> ManagementResult<Option<Device>> {
        let mut matching = self
            .records()
            .await?
            .into_iter()
            .filter(|row| row.public_key == public_key);
        let Some(row) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() || row.state != DeviceState::Approved {
            return Ok(None);
        }
        self.ensure_clear(row.id).await?;
        row.try_into().map(Some)
    }

    async fn list_owned(&self, owner_subject: &str) -> ManagementResult<Vec<Device>> {
        let rows = self.records().await?;
        let mut devices = Vec::new();
        for row in rows
            .into_iter()
            .filter(|row| row.owner_subject == owner_subject)
        {
            self.ensure_clear(row.id).await?;
            devices.push(row.try_into()?);
        }
        Ok(devices)
    }

    async fn list_approved(&self, owner_subject: &str) -> ManagementResult<Vec<TrustedDevice>> {
        let rows = self.records().await?;
        let mut devices = Vec::new();
        for row in rows
            .into_iter()
            .filter(|row| row.state == DeviceState::Approved && row.owner_subject == owner_subject)
        {
            self.ensure_clear(row.id).await?;
            devices.push(TrustedDevice {
                public_key: row.public_key,
                address: row.address,
            });
        }
        Ok(devices)
    }

    async fn are_approved(
        &self,
        local_public_key: &str,
        remote_public_key: &str,
    ) -> ManagementResult<bool> {
        let rows = self.records().await?;
        let mut local = false;
        let mut remote = false;
        for row in rows
            .into_iter()
            .filter(|row| row.state == DeviceState::Approved)
        {
            self.ensure_clear(row.id).await?;
            local |= row.public_key == local_public_key;
            remote |= row.public_key == remote_public_key;
        }
        Ok(local && remote)
    }

    async fn approve(
        &self,
        device_id: Id,
        enrollment_code_hash: &[u8],
    ) -> ManagementResult<Option<Device>> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(None);
        };
        self.ensure_clear(device_id).await?;
        if row.state != DeviceState::Pending
            || row.enrollment_code_hash.as_deref() != Some(enrollment_code_hash)
            || row
                .enrollment_expires_at
                .is_none_or(|expires_at| expires_at <= now().timestamp())
        {
            return Ok(None);
        }
        let updated_at = now();
        self.update(
            device_id,
            vec![
                assignment("state", Value::Integer(DeviceState::Approved as i64)),
                assignment("updated_at", Value::Integer(updated_at.timestamp())),
            ],
        )
        .await?;
        DeviceRow {
            state: DeviceState::Approved,
            enrollment_code_hash: None,
            enrollment_expires_at: None,
            updated_at: updated_at.timestamp(),
            ..row
        }
        .try_into()
        .map(Some)
    }

    async fn rename(
        &self,
        owner_subject: &str,
        device_id: Id,
        name: String,
    ) -> ManagementResult<Option<Device>> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(None);
        };
        self.ensure_clear(device_id).await?;
        if row.owner_subject != owner_subject || row.state == DeviceState::Revoked {
            return Ok(None);
        }
        let updated_at = now();
        self.update(
            device_id,
            vec![
                assignment("name", Value::Text(name.clone())),
                assignment("updated_at", Value::Integer(updated_at.timestamp())),
            ],
        )
        .await?;
        DeviceRow {
            name,
            updated_at: updated_at.timestamp(),
            ..row
        }
        .try_into()
        .map(Some)
    }

    async fn revoke(
        &self,
        owner_subject: &str,
        device_id: Id,
        protected_public_key: &str,
    ) -> ManagementResult<bool> {
        let Some(row) = self.record(device_id).await? else {
            return Ok(false);
        };
        self.ensure_clear(device_id).await?;
        if row.owner_subject != owner_subject || row.public_key == protected_public_key {
            return Ok(false);
        }
        if row.state == DeviceState::Revoked {
            return Ok(true);
        }
        let rows = self.records().await?;
        for other in rows
            .iter()
            .filter(|other| other.state == DeviceState::Approved)
        {
            self.ensure_clear(other.id).await?;
        }
        if row.state == DeviceState::Approved
            && rows
                .iter()
                .filter(|other| other.state == DeviceState::Approved)
                .count()
                <= 1
        {
            return Ok(false);
        }
        let updated_at = now();
        self.update(
            device_id,
            vec![
                assignment("state", Value::Integer(DeviceState::Revoked as i64)),
                assignment("revoked_at", Value::Integer(updated_at.timestamp())),
                assignment("updated_at", Value::Integer(updated_at.timestamp())),
            ],
        )
        .await?;
        Ok(true)
    }

    async fn revoke_self(&self, public_key: &str) -> ManagementResult<bool> {
        let rows = self.records().await?;
        let mut found = false;
        for row in rows.into_iter().filter(|row| row.public_key == public_key) {
            found = true;
            self.ensure_clear(row.id).await?;
            if row.state == DeviceState::Revoked {
                continue;
            }
            let updated_at = now();
            self.update(
                row.id,
                vec![
                    assignment("state", Value::Integer(DeviceState::Revoked as i64)),
                    assignment("revoked_at", Value::Integer(updated_at.timestamp())),
                    assignment("updated_at", Value::Integer(updated_at.timestamp())),
                ],
            )
            .await?;
        }
        Ok(found)
    }
}

#[derive(Clone, Debug)]
struct DeviceRow {
    id: Uuid,
    owner_subject: String,
    name: String,
    public_key: String,
    address: String,
    enrollment_code_hash: Option<Vec<u8>>,
    enrollment_expires_at: Option<i64>,
    pairing_accepting_public_key: Option<String>,
    state: DeviceState,
    approved_at: Option<i64>,
    revoked_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl FromRow for DeviceRow {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        let state = db::decode::<i64>(db::value(row, columns, "state")?, "state")?;
        let state = match state {
            0 => DeviceState::Pending,
            1 => DeviceState::Approved,
            2 => DeviceState::Revoked,
            _ => {
                return Err(FromRowError::InvalidValue {
                    column: "state".into(),
                    expected: db::ValueType::Integer,
                    actual: db::ValueType::Integer,
                });
            }
        };
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            owner_subject: db::decode(db::value(row, columns, "owner_subject")?, "owner_subject")?,
            name: db::decode(db::value(row, columns, "name")?, "name")?,
            public_key: db::decode(db::value(row, columns, "public_key")?, "public_key")?,
            address: db::decode(db::value(row, columns, "address")?, "address")?,
            enrollment_code_hash: None,
            enrollment_expires_at: None,
            pairing_accepting_public_key: None,
            state,
            approved_at: db::decode(db::value(row, columns, "approved_at")?, "approved_at")?,
            revoked_at: db::decode(db::value(row, columns, "revoked_at")?, "revoked_at")?,
            created_at: db::decode(db::value(row, columns, "created_at")?, "created_at")?,
            updated_at: db::decode(db::value(row, columns, "updated_at")?, "updated_at")?,
        })
    }
}

impl TryFrom<DeviceRow> for Device {
    type Error = ManagementError;

    fn try_from(row: DeviceRow) -> ManagementResult<Self> {
        Ok(Self {
            id: row.id,
            owner_subject: row.owner_subject,
            name: row.name,
            public_key: row.public_key,
            address: row.address,
            state: row.state,
            created_at: timestamp(row.created_at)?,
            updated_at: timestamp(row.updated_at)?,
            revoked_at: row.revoked_at.map(timestamp).transpose()?,
        })
    }
}

impl From<DeviceRow> for Row {
    fn from(row: DeviceRow) -> Self {
        Row::new(vec![
            Value::Uuid(row.id),
            Value::Text(row.owner_subject),
            Value::Text(row.name),
            Value::Text(row.public_key),
            Value::Text(row.address),
            Value::Integer(row.state as i64),
            row.approved_at.map_or(Value::Null, Value::Integer),
            row.revoked_at.map_or(Value::Null, Value::Integer),
            Value::Integer(row.created_at),
            Value::Integer(row.updated_at),
        ])
    }
}

fn local_enrollment_insert(row: &DeviceRow) -> Query {
    Query::Insert(QueryInsert {
        table: "local_device_enrollments".into(),
        row: Row::new(vec![
            Value::Uuid(row.id),
            row.enrollment_code_hash
                .clone()
                .map_or(Value::Null, Value::Blob),
            row.enrollment_expires_at
                .map_or(Value::Null, Value::Integer),
            row.pairing_accepting_public_key
                .clone()
                .map_or(Value::Null, Value::Text),
        ]),
        returning: None,
    })
}

fn local_enrollment_delete(id: Id) -> Query {
    Query::Delete(QueryDelete {
        from: QueryFrom {
            table: "local_device_enrollments".into(),
            joins: vec![],
        },
        predicate: Some(QueryExpr::Equals(
            Box::new(QueryExpr::Value(QueryExprValue::Column(QueryColumn::new(
                "local_device_enrollments".into(),
                "device_id".into(),
            )))),
            Box::new(QueryExpr::Value(QueryExprValue::Value(Value::Uuid(id)))),
        )),
        returning: None,
    })
}

fn now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds is valid")
}

fn timestamp(value: i64) -> ManagementResult<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| ManagementError::InvalidInput("invalid device timestamp".into()))
}

fn db_error(error: db::QueryError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
}

fn row_error(error: FromRowError) -> ManagementError {
    ManagementError::InvalidInput(error.to_string())
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

fn select() -> Query {
    Query::Select(QuerySelect {
        from: from(),
        projection: COLUMNS.into_iter().map(column).collect(),
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

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use db::Database;
    use idp_model::contract::DeviceState;

    use crate::{DeviceRepo, replica::DbDeviceRepo};

    async fn repo() -> DbDeviceRepo {
        let engine = Arc::new(db::Database::in_memory());
        idp_model::replica::up(&engine)
            .await
            .expect("initialize replica schema");
        DbDeviceRepo::new(engine)
    }

    #[tokio::test]
    async fn enrollment_secrets_are_local_durable_and_removed_on_approval() {
        let path = std::env::temp_dir().join(format!(
            "local-enrollment-{}.redb",
            idp_model::model::Id::now_v7()
        ));
        let pending;
        let paired;
        {
            let database = Arc::new(Database::open(&path).expect("open local identity"));
            idp_model::replica::up(&database)
                .await
                .expect("initialize new schema");
            let repo = DbDeviceRepo::new(Arc::clone(&database));
            repo.create(
                "owner".into(),
                "primary".into(),
                "primary".into(),
                "addr".into(),
                vec![],
                0,
            )
            .await
            .expect("approve first local device");
            pending = repo
                .create(
                    "owner".into(),
                    "pending".into(),
                    "pending".into(),
                    "addr".into(),
                    vec![42; 32],
                    chrono::Utc::now().timestamp() + 300,
                )
                .await
                .expect("store local enrollment")
                .id;
            paired = repo
                .create_pairing(
                    "paired".into(),
                    "paired".into(),
                    "addr".into(),
                    "primary".into(),
                )
                .await
                .expect("store local pairing")
                .id;
            let public = database
                .client()
                .translate_and_execute("SELECT * FROM devices", &db::SqlTranslator)
                .await
                .expect("query syncable devices")
                .remove(0);
            assert!(public.columns.iter().all(|column| {
                ![
                    "enrollment_code_hash",
                    "enrollment_expires_at",
                    "pairing_accepting_public_key",
                ]
                .contains(&column.name.as_str())
            }));
        }
        {
            let database = Arc::new(Database::open(&path).expect("reopen identity offline"));
            let repo = DbDeviceRepo::new(Arc::clone(&database));
            assert!(
                repo.approve(pending, &[0; 32])
                    .await
                    .expect("wrong enrollment code denies")
                    .is_none()
            );
            assert!(
                repo.approve(pending, &[42; 32])
                    .await
                    .expect("stored code approves")
                    .is_some()
            );
            assert_eq!(
                repo.pending_pairing(paired)
                    .await
                    .expect("pending pairing persisted")
                    .expect("local pairing exists")
                    .1,
                "primary"
            );
            assert!(
                repo.approve_pairing(paired)
                    .await
                    .expect("approve local pairing")
                    .is_some()
            );
            let rows = database
                .client()
                .translate_and_execute(
                    "SELECT device_id FROM local_device_enrollments",
                    &db::SqlTranslator,
                )
                .await
                .expect("read local pending workflow");
            assert!(rows[0].rows.is_empty());
        }
        std::fs::remove_file(path).expect("remove enrollment fixture");
    }

    #[tokio::test]
    async fn device_owner_persists_and_pairing_inherits_approved_owner() {
        let repo = repo().await;
        let enrolled = repo
            .create(
                "subject-a".into(),
                "primary".into(),
                "primary-key".into(),
                "address".into(),
                Vec::new(),
                0,
            )
            .await
            .expect("create first device");
        assert_eq!(enrolled.state, DeviceState::Approved);
        assert_eq!(enrolled.owner_subject, "subject-a");
        assert_eq!(repo.list().await.expect("list devices"), [enrolled]);

        let paired = repo
            .create_pairing(
                "paired".into(),
                "paired-key".into(),
                "address".into(),
                "primary-key".into(),
            )
            .await
            .expect("create paired device");
        assert_eq!(paired.owner_subject, "subject-a");
        let approved = repo
            .approve_pairing(paired.id)
            .await
            .expect("approve pairing")
            .expect("paired device exists");
        assert_eq!(approved.owner_subject, "subject-a");
        assert_eq!(repo.list().await.expect("list devices")[1], approved);
    }

    #[tokio::test]
    async fn device_mutations_and_listing_require_owner() {
        let repo = repo().await;
        let device = repo
            .create(
                "owner".into(),
                "primary".into(),
                "primary-key".into(),
                "address".into(),
                Vec::new(),
                0,
            )
            .await
            .expect("create device");
        assert!(
            repo.list_owned("other")
                .await
                .expect("list other devices")
                .is_empty()
        );
        assert_eq!(
            repo.list_owned("owner").await.expect("list owned devices"),
            std::slice::from_ref(&device)
        );
        assert!(
            repo.rename("other", device.id, "changed".into())
                .await
                .expect("deny rename")
                .is_none()
        );
        assert!(
            !repo
                .revoke("other", device.id, "another-key")
                .await
                .expect("deny revoke")
        );
        assert_eq!(
            repo.list_owned("owner").await.expect("reload device"),
            std::slice::from_ref(&device)
        );
        assert!(
            repo.rename("owner", device.id, "renamed".into())
                .await
                .expect("rename owned device")
                .is_some()
        );
    }

    #[tokio::test]
    async fn transport_key_resolves_only_to_one_approved_device() {
        let repo = repo().await;
        let approved = repo
            .create(
                "owner".into(),
                "approved".into(),
                "transport-key".into(),
                "address".into(),
                Vec::new(),
                0,
            )
            .await
            .expect("create approved device");
        assert_eq!(
            repo.find_approved_by_public_key("transport-key")
                .await
                .expect("resolve approved transport key"),
            Some(approved)
        );
        assert!(
            repo.find_approved_by_public_key("unknown-key")
                .await
                .expect("resolve unknown transport key")
                .is_none()
        );

        repo.create(
            "owner".into(),
            "pending".into(),
            "pending-key".into(),
            "address".into(),
            vec![1],
            i64::MAX,
        )
        .await
        .expect("create pending device");
        assert!(
            repo.find_approved_by_public_key("pending-key")
                .await
                .expect("resolve pending transport key")
                .is_none()
        );
    }

    #[tokio::test]
    async fn trusted_devices_are_scoped_to_owner_and_approval() {
        let repo = repo().await;
        let first = repo
            .create(
                "owner-a".into(),
                "first".into(),
                "key-a".into(),
                "addr-a".into(),
                Vec::new(),
                0,
            )
            .await
            .expect("create approved device");
        let second = repo
            .create(
                "owner-b".into(),
                "second".into(),
                "key-b".into(),
                "addr-b".into(),
                vec![1],
                i64::MAX,
            )
            .await
            .expect("create pending device");
        assert!(
            repo.list_approved("owner-b")
                .await
                .expect("list pending owner")
                .is_empty()
        );
        repo.approve(second.id, &[1])
            .await
            .expect("approve device")
            .expect("pending device exists");
        let own = repo.list_approved("owner-a").await.expect("list owner a");
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].public_key, first.public_key);
        let other = repo.list_approved("owner-b").await.expect("list owner b");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].public_key, second.public_key);
        repo.revoke("owner-b", second.id, "key-a")
            .await
            .expect("revoke device");
        assert!(
            repo.revoke("owner-b", second.id, "key-a")
                .await
                .expect("retry exact revocation after a lost acknowledgement")
        );
        assert!(
            !repo
                .revoke("owner-a", second.id, "key-a")
                .await
                .expect("wrong owner cannot acknowledge revocation")
        );
        assert!(
            !repo
                .revoke("owner-b", second.id, "key-b")
                .await
                .expect("protected endpoint cannot acknowledge revocation")
        );
        assert!(
            !repo
                .revoke("owner-b", idp_model::model::Id::now_v7(), "key-a")
                .await
                .expect("unknown Device is not a successful revocation")
        );
        assert!(
            repo.list_approved("owner-b")
                .await
                .expect("list revoked owner")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn device_owners_survive_database_reopen() {
        let path = std::env::temp_dir().join(format!(
            "management-device-reopen-{}-{}.redb",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_nanos()
        ));
        let enrolled_id;
        let paired_id;
        {
            let engine: Arc<Database> =
                Arc::new(Database::open(&path).expect("open durable test database"));
            idp_model::replica::up(&engine)
                .await
                .expect("initialize replica schema");
            let repo = DbDeviceRepo::new(engine);
            let enrolled = repo
                .create(
                    "subject-a".into(),
                    "primary".into(),
                    "primary-key".into(),
                    "address".into(),
                    Vec::new(),
                    0,
                )
                .await
                .expect("create enrolled device");
            let paired = repo
                .create_pairing(
                    "paired".into(),
                    "paired-key".into(),
                    "address".into(),
                    "primary-key".into(),
                )
                .await
                .expect("create paired device");
            repo.approve_pairing(paired.id)
                .await
                .expect("approve pairing")
                .expect("paired device exists");
            enrolled_id = enrolled.id;
            paired_id = paired.id;
        }

        {
            let engine: Arc<Database> =
                Arc::new(Database::open(&path).expect("reopen durable test database"));
            let repo = DbDeviceRepo::new(engine);
            let devices = repo.list().await.expect("load devices after reopen");
            let enrolled = devices
                .iter()
                .find(|device| device.id == enrolled_id)
                .expect("enrolled device exists after reopen");
            let paired = devices
                .iter()
                .find(|device| device.id == paired_id)
                .expect("paired device exists after reopen");
            assert_eq!(enrolled.owner_subject, "subject-a");
            assert_eq!(paired.owner_subject, "subject-a");
            assert_eq!(paired.state, DeviceState::Approved);
        }
        std::fs::remove_file(path).expect("remove durable test database");
    }

    #[tokio::test]
    async fn device_creation_rejects_empty_owner() {
        let repo = repo().await;
        assert!(
            repo.create(
                "  ".into(),
                "ownerless".into(),
                "ownerless-key".into(),
                "address".into(),
                Vec::new(),
                0,
            )
            .await
            .is_err()
        );
        assert!(!repo.has_any().await.expect("check device records"));
    }

    #[tokio::test]
    async fn pairing_rejects_pending_approver() {
        let repo = repo().await;
        repo.create(
            "subject-a".into(),
            "primary".into(),
            "primary-key".into(),
            "address".into(),
            Vec::new(),
            0,
        )
        .await
        .expect("create first device");
        repo.create(
            "subject-b".into(),
            "pending".into(),
            "pending-key".into(),
            "address".into(),
            Vec::new(),
            0,
        )
        .await
        .expect("create pending device");

        assert!(
            repo.create_pairing(
                "paired".into(),
                "paired-key".into(),
                "address".into(),
                "pending-key".into(),
            )
            .await
            .is_err()
        );
    }
}
