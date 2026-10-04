use std::sync::Arc;

use db::{
    Engine, FromRow, FromRowError, Kernel, Query, QueryColumn, QueryExpr, QueryExprValue,
    QueryFrom, QueryInsert, QuerySelect, QueryUpdate, QueryUpdateAssignment, Row, RowCodec,
    Statement, Uuid, Value,
};
use idp_model::contract::DeviceState;

use crate::{DeviceRepo, ManagementError, ManagementResult};

use super::DbDeviceRepo;

const TABLE: &str = "device_selection_policies";
const RESOURCE_TABLE: &str = "device_resource_selections";
const COLUMNS: [&str; 6] = [
    "device_id",
    "owner_subject",
    "application_id",
    "selected_kind",
    "selected_id",
    "admin_allowed",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionPolicy {
    pub device_id: Uuid,
    pub owner_subject: String,
    pub application_id: Option<Uuid>,
    pub selected_kind: Option<String>,
    pub selected_id: Option<Uuid>,
    pub admin_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedResource {
    pub device_id: Uuid,
    pub owner_subject: String,
    pub application_id: Uuid,
    pub kind: String,
    pub resource_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResourceSelection {
    id: Uuid,
    device_id: Uuid,
    owner_subject: String,
    application_id: Uuid,
    selected_kind: String,
    selected_id: Uuid,
    selected: bool,
}

impl FromRow for ResourceSelection {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            id: db::decode(db::value(row, columns, "id")?, "id")?,
            device_id: db::decode(db::value(row, columns, "device_id")?, "device_id")?,
            owner_subject: db::decode(db::value(row, columns, "owner_subject")?, "owner_subject")?,
            application_id: db::decode(
                db::value(row, columns, "application_id")?,
                "application_id",
            )?,
            selected_kind: db::decode(db::value(row, columns, "selected_kind")?, "selected_kind")?,
            selected_id: db::decode(db::value(row, columns, "selected_id")?, "selected_id")?,
            selected: db::decode(db::value(row, columns, "selected")?, "selected")?,
        })
    }
}

impl FromRow for SelectionPolicy {
    fn from_row(row: &Row, columns: &[&str]) -> Result<Self, FromRowError> {
        Ok(Self {
            device_id: db::decode(db::value(row, columns, "device_id")?, "device_id")?,
            owner_subject: db::decode(db::value(row, columns, "owner_subject")?, "owner_subject")?,
            application_id: db::decode(
                db::value(row, columns, "application_id")?,
                "application_id",
            )?,
            selected_kind: db::decode(db::value(row, columns, "selected_kind")?, "selected_kind")?,
            selected_id: db::decode(db::value(row, columns, "selected_id")?, "selected_id")?,
            admin_allowed: db::decode(db::value(row, columns, "admin_allowed")?, "admin_allowed")?,
        })
    }
}

pub struct DbSelectionPolicyRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    engine: Arc<Engine<K, R>>,
}

impl<K, R> DbSelectionPolicyRepo<K, R>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    pub const fn new(engine: Arc<Engine<K, R>>) -> Self {
        Self { engine }
    }

    async fn clear(&self, device_id: Uuid) -> ManagementResult<()> {
        if self
            .engine
            .row_conflicts(TABLE, &key(device_id))
            .await
            .map_err(db_error)?
            .is_empty()
        {
            Ok(())
        } else {
            Err(invalid("conflicted selection policy"))
        }
    }

    async fn record(&self, device_id: Uuid) -> ManagementResult<Option<SelectionPolicy>> {
        self.resolve_convergent_conflicts(device_id).await?;
        self.clear(device_id).await?;
        let policy = self.raw_record(device_id).await?;
        self.clear(device_id).await?;
        Ok(policy)
    }

    async fn resolve_convergent_conflicts(&self, device_id: Uuid) -> ManagementResult<()> {
        let conflicts = self
            .engine
            .row_conflict_values(TABLE, &key(device_id))
            .await
            .map_err(db_error)?;
        let mut resolutions = Vec::new();
        for (column, values) in conflicts {
            let resolution = match column.as_str() {
                "application_id" | "selected_kind" | "selected_id"
                    if values.contains(&Value::Null) =>
                {
                    Value::Null
                }
                "admin_allowed" if values.contains(&Value::Bool(false)) => Value::Bool(false),
                _ => return Err(invalid("conflicted selection policy")),
            };
            resolutions.push((column, resolution));
        }
        if !resolutions.is_empty() {
            self.engine
                .resolve_row(TABLE, &key(device_id), resolutions)
                .await
                .map_err(db_error)?;
        }
        Ok(())
    }

    async fn resource_selected(
        &self,
        device_id: Uuid,
        owner_subject: &str,
        application_id: Uuid,
        kind: &str,
        resource_id: Uuid,
    ) -> ManagementResult<bool> {
        let id = resource_selection_id(device_id, owner_subject, application_id, kind, resource_id);
        let conflicts = self
            .engine
            .row_conflict_values(RESOURCE_TABLE, &key(id))
            .await
            .map_err(db_error)?;
        if !conflicts.is_empty() {
            let mut resolutions = Vec::new();
            for (column, values) in conflicts {
                if column != "selected" || !values.contains(&Value::Bool(false)) {
                    return Err(invalid("conflicted resource selection"));
                }
                resolutions.push((column, Value::Bool(false)));
            }
            self.engine
                .resolve_row(RESOURCE_TABLE, &key(id), resolutions)
                .await
                .map_err(db_error)?;
        }
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Select(QuerySelect {
                from: resource_from(),
                projection: [
                    "id",
                    "device_id",
                    "owner_subject",
                    "application_id",
                    "selected_kind",
                    "selected_id",
                    "selected",
                ]
                .into_iter()
                .map(resource_column)
                .collect(),
                distinct: false,
                predicate: Some(resource_equals("id", Value::Uuid(id))),
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
            .ok_or_else(|| invalid("missing resource selection query result"))?
            .rows_as::<ResourceSelection>()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(rows.into_iter().any(|selection| {
            selection.id == id
                && selection.device_id == device_id
                && selection.owner_subject == owner_subject
                && selection.application_id == application_id
                && selection.selected_kind == kind
                && selection.selected_id == resource_id
                && selection.selected
        }))
    }

    async fn set_resource_selected(&self, policy: &SelectionPolicy) -> ManagementResult<()> {
        let (Some(application_id), Some(kind), Some(resource_id)) = (
            policy.application_id,
            policy.selected_kind.as_deref(),
            policy.selected_id,
        ) else {
            return Ok(());
        };
        if self
            .resource_selected(
                policy.device_id,
                &policy.owner_subject,
                application_id,
                kind,
                resource_id,
            )
            .await?
        {
            return Ok(());
        }
        let id = resource_selection_id(
            policy.device_id,
            &policy.owner_subject,
            application_id,
            kind,
            resource_id,
        );
        let exists = !self
            .engine
            .row_conflicts(RESOURCE_TABLE, &key(id))
            .await
            .map_err(db_error)?
            .is_empty()
            || self.resource_selection_exists(id).await?;
        let query = if exists {
            Query::Update(QueryUpdate {
                from: resource_from(),
                assignments: vec![assignment_for(
                    RESOURCE_TABLE,
                    "selected",
                    Value::Bool(true),
                )],
                predicate: Some(resource_equals("id", Value::Uuid(id))),
                returning: None,
            })
        } else {
            Query::Insert(QueryInsert {
                table: RESOURCE_TABLE.into(),
                row: Row::new(vec![
                    Value::Uuid(id),
                    Value::Uuid(policy.device_id),
                    Value::Text(policy.owner_subject.clone()),
                    Value::Uuid(application_id),
                    Value::Text(kind.to_owned()),
                    Value::Uuid(resource_id),
                    Value::Bool(true),
                ]),
                returning: None,
            })
        };
        self.engine
            .execute(vec![Statement::Query(query)])
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn resource_selection_exists(&self, id: Uuid) -> ManagementResult<bool> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Select(QuerySelect {
                from: resource_from(),
                projection: [
                    "id",
                    "device_id",
                    "owner_subject",
                    "application_id",
                    "selected_kind",
                    "selected_id",
                    "selected",
                ]
                .into_iter()
                .map(resource_column)
                .collect(),
                distinct: false,
                predicate: Some(resource_equals("id", Value::Uuid(id))),
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
        Ok(!results
            .pop()
            .ok_or_else(|| invalid("missing resource selection query result"))?
            .rows
            .is_empty())
    }

    async fn raw_record(&self, device_id: Uuid) -> ManagementResult<Option<SelectionPolicy>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Select(QuerySelect {
                from: from(),
                projection: COLUMNS.into_iter().map(column).collect(),
                distinct: false,
                predicate: Some(equals("device_id", Value::Uuid(device_id))),
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
            .ok_or_else(|| invalid("missing selection policy query result"))?
            .rows_as::<SelectionPolicy>()
            .map_err(|error| invalid(error.to_string()))?;
        Ok(rows.into_iter().next())
    }

    pub async fn selected_resources_for_device(
        &self,
        device_id: Uuid,
    ) -> ManagementResult<Vec<SelectedResource>> {
        let mut results = self
            .engine
            .execute(vec![Statement::Query(Query::Select(QuerySelect {
                from: resource_from(),
                projection: [
                    "id",
                    "device_id",
                    "owner_subject",
                    "application_id",
                    "selected_kind",
                    "selected_id",
                    "selected",
                ]
                .into_iter()
                .map(resource_column)
                .collect(),
                distinct: false,
                predicate: Some(resource_equals("device_id", Value::Uuid(device_id))),
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
            .ok_or_else(|| invalid("missing resource selection query result"))?
            .rows_as::<ResourceSelection>()
            .map_err(|error| invalid(error.to_string()))?;
        let mut selected = Vec::new();
        for selection in rows {
            if selection.device_id == device_id
                && selection.selected
                && self
                    .resource_selected(
                        device_id,
                        &selection.owner_subject,
                        selection.application_id,
                        &selection.selected_kind,
                        selection.selected_id,
                    )
                    .await?
            {
                selected.push(SelectedResource {
                    device_id,
                    owner_subject: selection.owner_subject,
                    application_id: selection.application_id,
                    kind: selection.selected_kind,
                    resource_id: selection.selected_id,
                });
            }
        }
        Ok(selected)
    }

    pub async fn peers_selected_for_sync(
        &self,
        devices: &DbDeviceRepo<K, R>,
        local_public_key: &str,
        remote_public_key: &str,
        owner_subject: &str,
        application_id: Uuid,
        kind: &str,
        resource_id: Uuid,
    ) -> ManagementResult<bool> {
        if local_public_key == remote_public_key
            || owner_subject.trim().is_empty()
            || !matches!(kind, "database" | "filesystem")
        {
            return Ok(false);
        }
        let records = devices.list().await?;
        for public_key in [local_public_key, remote_public_key] {
            let mut matching = records
                .iter()
                .filter(|device| device.public_key == public_key);
            let Some(device) = matching.next() else {
                return Ok(false);
            };
            if matching.next().is_some()
                || device.state != DeviceState::Approved
                || device.owner_subject != owner_subject
            {
                return Ok(false);
            }
            let Some(policy) = self.get(device.id, owner_subject, application_id).await? else {
                return Ok(false);
            };
            if !policy.admin_allowed
                || !self
                    .resource_selected(device.id, owner_subject, application_id, kind, resource_id)
                    .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn get(
        &self,
        device_id: Uuid,
        owner_subject: &str,
        _application_id: Uuid,
    ) -> ManagementResult<Option<SelectionPolicy>> {
        let policy = self.record(device_id).await?;
        if let Some(policy) = &policy {
            if policy.owner_subject != owner_subject {
                return Err(invalid("selection policy owner mismatch"));
            }
            if policy.application_id.is_some() != policy.selected_kind.is_some()
                || policy.selected_kind.is_some() != policy.selected_id.is_some()
            {
                return Err(invalid("incomplete selection policy"));
            }
        }
        Ok(policy)
    }

    // Caller must validate device ownership, authorization, and resource catalog membership.
    pub async fn set_prevalidated(&self, policy: SelectionPolicy) -> ManagementResult<()> {
        if policy.owner_subject.trim().is_empty()
            || policy.application_id.is_some() != policy.selected_kind.is_some()
            || policy.selected_kind.is_some() != policy.selected_id.is_some()
            || policy
                .selected_kind
                .as_ref()
                .is_some_and(|kind| kind.is_empty())
        {
            return Err(invalid("invalid selection policy"));
        }
        let old = self.record(policy.device_id).await?;
        if let Some(old) = &old {
            if old.owner_subject != policy.owner_subject {
                return Err(invalid("selection policy owner mismatch"));
            }
            if old.application_id.is_some() != old.selected_kind.is_some()
                || old.selected_kind.is_some() != old.selected_id.is_some()
            {
                return Err(invalid("incomplete selection policy"));
            }
            if policy.selected_id.is_some() && !old.admin_allowed {
                return Err(invalid("administrator has restricted selection"));
            }
        }
        let selection_unchanged = old.as_ref().is_some_and(|old| {
            old.application_id == policy.application_id
                && old.selected_kind == policy.selected_kind
                && old.selected_id == policy.selected_id
        });
        let query = if selection_unchanged {
            None
        } else if old.is_some() {
            Some(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![
                    assignment(
                        "application_id",
                        policy.application_id.map_or(Value::Null, Value::Uuid),
                    ),
                    assignment(
                        "selected_kind",
                        policy
                            .selected_kind
                            .clone()
                            .map_or(Value::Null, Value::Text),
                    ),
                    assignment(
                        "selected_id",
                        policy.selected_id.map_or(Value::Null, Value::Uuid),
                    ),
                ],
                predicate: Some(equals("device_id", Value::Uuid(policy.device_id))),
                returning: None,
            }))
        } else {
            Some(Query::Insert(QueryInsert {
                table: TABLE.into(),
                row: Row::new(vec![
                    Value::Uuid(policy.device_id),
                    Value::Text(policy.owner_subject.clone()),
                    policy.application_id.map_or(Value::Null, Value::Uuid),
                    policy
                        .selected_kind
                        .clone()
                        .map_or(Value::Null, Value::Text),
                    policy.selected_id.map_or(Value::Null, Value::Uuid),
                    Value::Bool(policy.admin_allowed),
                ]),
                returning: None,
            }))
        };
        if let Some(query) = query {
            self.engine
                .execute(vec![Statement::Query(query)])
                .await
                .map_err(db_error)?;
        }
        self.clear(policy.device_id).await?;
        if policy.selected_id.is_none() {
            self.engine
                .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                    from: resource_from(),
                    assignments: vec![assignment_for(
                        RESOURCE_TABLE,
                        "selected",
                        Value::Bool(false),
                    )],
                    predicate: Some(resource_equals("device_id", Value::Uuid(policy.device_id))),
                    returning: None,
                }))])
                .await
                .map_err(db_error)?;
            Ok(())
        } else {
            self.set_resource_selected(&policy).await
        }
    }

    // Caller must validate permission to change the admin restriction.
    pub async fn set_admin_allowed_prevalidated(
        &self,
        device_id: Uuid,
        owner_subject: &str,
        admin_allowed: bool,
    ) -> ManagementResult<bool> {
        if owner_subject.trim().is_empty() {
            return Ok(false);
        }
        let Some(policy) = self.record(device_id).await? else {
            self.set_prevalidated(SelectionPolicy {
                device_id,
                owner_subject: owner_subject.to_owned(),
                application_id: None,
                selected_kind: None,
                selected_id: None,
                admin_allowed,
            })
            .await?;
            return Ok(true);
        };
        if policy.owner_subject != owner_subject {
            return Ok(false);
        }
        if policy.admin_allowed == admin_allowed {
            return Ok(true);
        }
        self.engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: from(),
                assignments: vec![assignment("admin_allowed", Value::Bool(admin_allowed))],
                predicate: Some(equals("device_id", Value::Uuid(device_id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        self.clear(device_id).await?;
        Ok(true)
    }

    pub async fn deselect_resource_owned(
        &self,
        device_id: Uuid,
        owner_subject: &str,
        application_id: Uuid,
        kind: &str,
        resource_id: Uuid,
    ) -> ManagementResult<bool> {
        let Some(policy) = self.record(device_id).await? else {
            return Ok(false);
        };
        if owner_subject.is_empty() || policy.owner_subject != owner_subject {
            return Ok(false);
        }
        if !self
            .resource_selected(device_id, owner_subject, application_id, kind, resource_id)
            .await?
        {
            return Ok(false);
        }
        let id = resource_selection_id(device_id, owner_subject, application_id, kind, resource_id);
        self.engine
            .execute(vec![Statement::Query(Query::Update(QueryUpdate {
                from: resource_from(),
                assignments: vec![assignment_for(
                    RESOURCE_TABLE,
                    "selected",
                    Value::Bool(false),
                )],
                predicate: Some(resource_equals("id", Value::Uuid(id))),
                returning: None,
            }))])
            .await
            .map_err(db_error)?;
        Ok(true)
    }

    pub async fn deselect_owned(
        &self,
        device_id: Uuid,
        owner_subject: &str,
    ) -> ManagementResult<bool> {
        let conflicts = self
            .engine
            .row_conflict_values(TABLE, &key(device_id))
            .await
            .map_err(db_error)?;
        if conflicts.iter().any(|(column, _)| {
            !matches!(
                column.as_str(),
                "application_id" | "selected_kind" | "selected_id"
            )
        }) {
            return Err(invalid(
                "conflicted selection policy ownership or admin restriction",
            ));
        }
        let Some(policy) = self.raw_record(device_id).await? else {
            return Ok(false);
        };
        if owner_subject.is_empty() || policy.owner_subject != owner_subject {
            return Ok(false);
        }
        if !conflicts.is_empty() {
            self.engine
                .resolve_row(
                    TABLE,
                    &key(device_id),
                    conflicts
                        .into_iter()
                        .map(|(column, _)| (column, Value::Null))
                        .collect(),
                )
                .await
                .map_err(db_error)?;
            self.clear(device_id).await?;
        }
        let policy = self
            .record(device_id)
            .await?
            .ok_or_else(|| invalid("selection policy not found"))?;
        if policy.application_id.is_none()
            && policy.selected_kind.is_none()
            && policy.selected_id.is_none()
        {
            return Ok(true);
        }
        self.engine
            .execute(vec![
                Statement::Query(Query::Update(QueryUpdate {
                    from: resource_from(),
                    assignments: vec![assignment_for(
                        RESOURCE_TABLE,
                        "selected",
                        Value::Bool(false),
                    )],
                    predicate: Some(resource_equals("device_id", Value::Uuid(device_id))),
                    returning: None,
                })),
                Statement::Query(Query::Update(QueryUpdate {
                    from: from(),
                    assignments: ["application_id", "selected_kind", "selected_id"]
                        .into_iter()
                        .map(|column| assignment(column, Value::Null))
                        .collect(),
                    predicate: Some(equals("device_id", Value::Uuid(device_id))),
                    returning: None,
                })),
            ])
            .await
            .map_err(db_error)?;
        self.clear(device_id).await?;
        Ok(true)
    }
}

fn invalid(message: impl Into<String>) -> ManagementError {
    ManagementError::InvalidInput(message.into())
}

fn db_error(error: db::EngineError) -> ManagementError {
    invalid(error.to_string())
}

fn key(id: Uuid) -> Row {
    Row::new(vec![Value::Uuid(id)])
}

fn resource_selection_id(
    device_id: Uuid,
    owner_subject: &str,
    application_id: Uuid,
    kind: &str,
    resource_id: Uuid,
) -> Uuid {
    let mut identity = Vec::with_capacity(16 * 3 + owner_subject.len() + kind.len() + 16);
    identity.extend_from_slice(device_id.as_bytes());
    identity.extend_from_slice(&(owner_subject.len() as u64).to_be_bytes());
    identity.extend_from_slice(owner_subject.as_bytes());
    identity.extend_from_slice(application_id.as_bytes());
    identity.extend_from_slice(&(kind.len() as u64).to_be_bytes());
    identity.extend_from_slice(kind.as_bytes());
    identity.extend_from_slice(resource_id.as_bytes());
    Uuid::new_v5(&Uuid::NAMESPACE_URL, &identity)
}

fn resource_from() -> QueryFrom {
    QueryFrom {
        table: RESOURCE_TABLE.into(),
        joins: vec![],
    }
}

fn resource_column(name: &str) -> QueryColumn {
    QueryColumn::new(RESOURCE_TABLE.into(), name.into())
}

fn resource_equals(name: &str, value: Value) -> QueryExpr {
    QueryExpr::Equals(
        Box::new(QueryExpr::Value(QueryExprValue::Column(resource_column(
            name,
        )))),
        Box::new(QueryExpr::Value(QueryExprValue::Value(value))),
    )
}

fn assignment_for(table: &str, name: &str, value: Value) -> QueryUpdateAssignment {
    QueryUpdateAssignment {
        column: QueryColumn::new(table.into(), name.into()),
        value: QueryExprValue::Value(value),
    }
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

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use db::{NativeEngine, Value, open_native_engine};
    use idp_model::contract::DeviceState;
    use ofdb_sql_sync::{apply_sync_state_batch_for, export_sync_state_for};

    use crate::{DeviceRepo, replica::DbDeviceRepo};

    use super::{DbSelectionPolicyRepo, SelectionPolicy, TABLE, assignment, from, key};

    async fn sync_replica(
        source: &db::Engine<db::InMemoryKernel, db::AutomergeRowCodec>,
        destination: &db::Engine<db::InMemoryKernel, db::AutomergeRowCodec>,
    ) {
        apply_sync_state_batch_for(
            destination,
            export_sync_state_for(source)
                .await
                .expect("export replica state"),
        )
        .await
        .expect("apply replica state");
    }

    #[tokio::test]
    async fn sync_requires_two_approved_matching_selected_devices() {
        let engine = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize replica");
        let devices = DbDeviceRepo::new(Arc::clone(&engine));
        let policies = DbSelectionPolicyRepo::new(engine);
        let local = devices
            .create(
                "owner".into(),
                "local".into(),
                "local-key".into(),
                "addr".into(),
                vec![],
                0,
            )
            .await
            .expect("create local device");
        let remote = devices
            .create(
                "owner".into(),
                "remote".into(),
                "remote-key".into(),
                "addr".into(),
                vec![1],
                i64::MAX,
            )
            .await
            .expect("create remote device");
        let application_id = db::Uuid::now_v7();
        let resource_id = db::Uuid::now_v7();
        let selected = |device_id| SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(resource_id),
            admin_allowed: true,
        };
        for device in [&local, &remote] {
            policies
                .set_prevalidated(selected(device.id))
                .await
                .expect("select resource");
        }
        let admitted = || {
            policies.peers_selected_for_sync(
                &devices,
                "local-key",
                "remote-key",
                "owner",
                application_id,
                "database",
                resource_id,
            )
        };
        assert_eq!(remote.state, DeviceState::Pending);
        assert!(!admitted().await.expect("pending peer denied"));
        devices
            .approve(remote.id, &[1])
            .await
            .expect("approve peer")
            .expect("pending peer exists");
        assert!(admitted().await.expect("matching peers admitted"));
        assert!(
            policies
                .selected_resources_for_device(remote.id)
                .await
                .expect("list selected resources")
                .iter()
                .any(|resource| {
                    resource.kind == "database" && resource.resource_id == resource_id
                })
        );
        let filesystem_id = db::Uuid::now_v7();
        for device in [&local, &remote] {
            policies
                .set_prevalidated(SelectionPolicy {
                    device_id: device.id,
                    owner_subject: "owner".into(),
                    application_id: Some(application_id),
                    selected_kind: Some("filesystem".into()),
                    selected_id: Some(filesystem_id),
                    admin_allowed: true,
                })
                .await
                .expect("select filesystem without replacing database");
        }
        assert!(admitted().await.expect("database remains selected"));
        assert!(
            policies
                .peers_selected_for_sync(
                    &devices,
                    "local-key",
                    "remote-key",
                    "owner",
                    application_id,
                    "filesystem",
                    filesystem_id,
                )
                .await
                .expect("filesystem selected on both peers")
        );
        for (owner, application, kind, id) in [
            ("other", application_id, "database", resource_id),
            ("owner", db::Uuid::now_v7(), "database", resource_id),
            ("owner", application_id, "filesystem", resource_id),
            ("owner", application_id, "database", db::Uuid::now_v7()),
        ] {
            assert!(!matches!(
                policies
                    .peers_selected_for_sync(
                        &devices,
                        "local-key",
                        "remote-key",
                        owner,
                        application,
                        kind,
                        id,
                    )
                    .await,
                Ok(true)
            ));
        }
        assert!(
            !policies
                .peers_selected_for_sync(
                    &devices,
                    "local-key",
                    "unknown",
                    "owner",
                    application_id,
                    "database",
                    resource_id,
                )
                .await
                .expect("unknown peer denied")
        );
        policies
            .deselect_owned(remote.id, "owner")
            .await
            .expect("deselect peer");
        assert!(
            policies
                .selected_resources_for_device(remote.id)
                .await
                .expect("list after deselection")
                .is_empty()
        );
        assert!(!admitted().await.expect("deselected peer denied"));
        policies
            .set_prevalidated(selected(remote.id))
            .await
            .expect("reselect peer");
        policies
            .set_admin_allowed_prevalidated(remote.id, "owner", false)
            .await
            .expect("restrict peer");
        assert!(
            policies
                .selected_resources_for_device(remote.id)
                .await
                .expect("list restricted device selections")
                .iter()
                .any(|resource| {
                    resource.kind == "database" && resource.resource_id == resource_id
                })
        );
        assert!(!admitted().await.expect("restricted peer denied"));
        policies
            .set_admin_allowed_prevalidated(remote.id, "owner", true)
            .await
            .expect("restore peer");
        devices
            .revoke("owner", remote.id, "local-key")
            .await
            .expect("revoke remote peer");
        assert!(!admitted().await.expect("revoked peer denied"));
    }

    #[tokio::test]
    async fn replicated_revocation_blocks_previously_selected_peer() {
        let source = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        let destination = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&source)
            .await
            .expect("initialize source replica");

        let devices = DbDeviceRepo::new(Arc::clone(&source));
        let policies = DbSelectionPolicyRepo::new(Arc::clone(&source));
        let local = devices
            .create(
                "owner".into(),
                "local".into(),
                "local-key".into(),
                "addr".into(),
                vec![],
                0,
            )
            .await
            .expect("create local device");
        let remote = devices
            .create(
                "owner".into(),
                "remote".into(),
                "remote-key".into(),
                "addr".into(),
                vec![1],
                i64::MAX,
            )
            .await
            .expect("create remote device");
        devices
            .approve(remote.id, &[1])
            .await
            .expect("approve remote device")
            .expect("remote device exists");

        let application_id = db::Uuid::now_v7();
        let resource_id = db::Uuid::now_v7();
        for device in [&local, &remote] {
            policies
                .set_prevalidated(SelectionPolicy {
                    device_id: device.id,
                    owner_subject: "owner".into(),
                    application_id: Some(application_id),
                    selected_kind: Some("database".into()),
                    selected_id: Some(resource_id),
                    admin_allowed: true,
                })
                .await
                .expect("select resource");
        }
        sync_replica(&source, &destination).await;

        let destination_devices = DbDeviceRepo::new(Arc::clone(&destination));
        let destination_policies = DbSelectionPolicyRepo::new(Arc::clone(&destination));
        assert!(
            destination_policies
                .peers_selected_for_sync(
                    &destination_devices,
                    "local-key",
                    "remote-key",
                    "owner",
                    application_id,
                    "database",
                    resource_id,
                )
                .await
                .expect("initial selection admits peer")
        );

        devices
            .revoke("owner", remote.id, "local-key")
            .await
            .expect("revoke remote device");
        assert!(
            destination_policies
                .peers_selected_for_sync(
                    &destination_devices,
                    "local-key",
                    "remote-key",
                    "owner",
                    application_id,
                    "database",
                    resource_id,
                )
                .await
                .expect("stale replica remains temporarily permissive"),
            "a peer may sync only while its local policy has not converged"
        );
        sync_replica(&source, &destination).await;
        assert!(
            !destination_policies
                .peers_selected_for_sync(
                    &destination_devices,
                    "local-key",
                    "remote-key",
                    "owner",
                    application_id,
                    "database",
                    resource_id,
                )
                .await
                .expect("replicated revocation denies peer")
        );
    }

    #[tokio::test]
    async fn selection_cannot_lift_local_or_replicated_admin_restriction() {
        let first = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        let second = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&first)
            .await
            .expect("initialize replica");
        let first_repo = DbSelectionPolicyRepo::new(Arc::clone(&first));
        let second_repo = DbSelectionPolicyRepo::new(Arc::clone(&second));
        let device_id = db::Uuid::now_v7();
        let application_id = db::Uuid::now_v7();
        let mut stale = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(db::Uuid::now_v7()),
            admin_allowed: true,
        };
        first_repo
            .set_prevalidated(stale.clone())
            .await
            .expect("create policy");
        sync_replica(&first, &second).await;
        assert!(
            !second_repo
                .set_admin_allowed_prevalidated(db::Uuid::now_v7(), " ", false)
                .await
                .expect("missing owner")
        );
        assert!(
            !second_repo
                .set_admin_allowed_prevalidated(device_id, "other", false)
                .await
                .expect("wrong owner")
        );
        assert!(
            second_repo
                .set_admin_allowed_prevalidated(device_id, "owner", false)
                .await
                .expect("restrict admin")
        );
        assert!(
            second_repo
                .set_admin_allowed_prevalidated(device_id, "owner", false)
                .await
                .expect("restriction already set")
        );

        stale.selected_id = Some(db::Uuid::now_v7());
        first_repo
            .set_prevalidated(stale.clone())
            .await
            .expect("offline selection");
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;
        for (engine, repo) in [(&first, &first_repo), (&second, &second_repo)] {
            assert!(
                engine
                    .row_conflicts(TABLE, &key(device_id))
                    .await
                    .expect("read conflicts")
                    .is_empty()
            );
            let mut expected = stale.clone();
            expected.admin_allowed = false;
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("read restricted selection"),
                Some(expected)
            );
        }

        stale.admin_allowed = false;
        let expected = stale.clone();
        stale.selected_id = Some(db::Uuid::now_v7());
        assert!(first_repo.set_prevalidated(stale).await.is_err());
        assert_eq!(
            first_repo
                .get(device_id, "owner", application_id)
                .await
                .expect("read local restriction"),
            Some(expected)
        );
    }

    #[tokio::test]
    async fn unselected_admin_restriction_survives_restart_and_blocks_selection() {
        let path =
            std::env::temp_dir().join(format!("selection-policy-{}.redb", db::Uuid::now_v7()));
        let device_id = db::Uuid::now_v7();
        let application_id = db::Uuid::now_v7();
        {
            let engine = Arc::new(open_native_engine(&path).expect("open database"));
            idp_model::replica::up(&engine)
                .await
                .expect("create schema");
            let repo = DbSelectionPolicyRepo::new(engine);
            assert!(
                repo.set_admin_allowed_prevalidated(device_id, "owner", false)
                    .await
                    .expect("restrict unselected device")
            );
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("read policy")
                    .expect("policy exists")
                    .selected_id,
                None
            );
        }
        {
            let engine = Arc::new(open_native_engine(&path).expect("reopen database"));
            let repo = DbSelectionPolicyRepo::new(engine);
            assert!(
                !repo
                    .get(device_id, "owner", application_id)
                    .await
                    .expect("read restriction")
                    .expect("policy exists")
                    .admin_allowed
            );
            assert!(
                repo.set_prevalidated(SelectionPolicy {
                    device_id,
                    owner_subject: "owner".into(),
                    application_id: Some(application_id),
                    selected_kind: Some("database".into()),
                    selected_id: Some(db::Uuid::now_v7()),
                    admin_allowed: true,
                })
                .await
                .is_err()
            );
            assert!(
                repo.deselect_owned(device_id, "owner")
                    .await
                    .expect("owner can deselect")
            );
            assert!(
                !repo
                    .get(device_id, "owner", application_id)
                    .await
                    .expect("read restriction")
                    .expect("policy exists")
                    .admin_allowed
            );
        }
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn concurrent_reselection_and_deselection_resolves_to_deselected() {
        let first = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        let second = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&first)
            .await
            .expect("initialize first replica");
        let first_devices = DbDeviceRepo::new(Arc::clone(&first));
        let second_devices = DbDeviceRepo::new(Arc::clone(&second));
        let local = first_devices
            .create(
                "owner".into(),
                "local".into(),
                "local-key".into(),
                "addr".into(),
                vec![],
                0,
            )
            .await
            .expect("create local device");
        let remote = first_devices
            .create_pairing(
                "remote".into(),
                "remote-key".into(),
                "addr".into(),
                "local-key".into(),
            )
            .await
            .expect("pair remote device");
        first_devices
            .approve_pairing(remote.id)
            .await
            .expect("approve peer")
            .expect("paired peer exists");
        let first_repo = DbSelectionPolicyRepo::new(Arc::clone(&first));
        let second_repo = DbSelectionPolicyRepo::new(Arc::clone(&second));
        let device_id = remote.id;
        let application_id = db::Uuid::now_v7();
        let mut selected = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(db::Uuid::now_v7()),
            admin_allowed: true,
        };
        first_repo
            .set_prevalidated(SelectionPolicy {
                device_id: local.id,
                ..selected.clone()
            })
            .await
            .expect("select local peer");

        first_repo
            .set_prevalidated(selected.clone())
            .await
            .expect("create shared selection");
        sync_replica(&first, &second).await;
        assert_eq!(
            second_repo
                .get(device_id, "owner", application_id)
                .await
                .expect("shared selection"),
            Some(selected.clone())
        );
        for (repo, devices) in [
            (&first_repo, &first_devices),
            (&second_repo, &second_devices),
        ] {
            assert!(
                repo.peers_selected_for_sync(
                    devices,
                    "local-key",
                    "remote-key",
                    "owner",
                    application_id,
                    "database",
                    selected.selected_id.expect("selected resource"),
                )
                .await
                .expect("replicated peers admitted")
            );
        }

        selected.selected_id = Some(db::Uuid::now_v7());
        first_repo
            .set_prevalidated(selected.clone())
            .await
            .expect("reselect offline");
        let mut deselected = selected.clone();
        deselected.application_id = None;
        deselected.selected_kind = None;
        deselected.selected_id = None;
        second_repo
            .set_prevalidated(deselected.clone())
            .await
            .expect("deselect offline");
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;

        for (engine, repo, devices) in [
            (&first, &first_repo, &first_devices),
            (&second, &second_repo, &second_devices),
        ] {
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("deselection wins concurrent selection"),
                Some(deselected.clone())
            );
            assert!(
                engine
                    .row_conflicts(TABLE, &key(device_id))
                    .await
                    .expect("read conflicts after deterministic resolution")
                    .is_empty()
            );
            assert!(
                !repo
                    .peers_selected_for_sync(
                        devices,
                        "local-key",
                        "remote-key",
                        "owner",
                        application_id,
                        "database",
                        selected.selected_id.expect("selected resource"),
                    )
                    .await
                    .expect("deselected peers are denied")
            );
        }
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;
        for repo in [&first_repo, &second_repo] {
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("read replicated deselection"),
                Some(deselected.clone())
            );
        }

        first_repo
            .set_prevalidated(selected.clone())
            .await
            .expect("deliberately reselect");
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;
        for repo in [&first_repo, &second_repo] {
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("read reselect"),
                Some(selected.clone())
            );
        }
    }

    #[tokio::test]
    async fn owner_and_admin_conflicts_cannot_be_deselected() {
        let first = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        let second = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&first)
            .await
            .expect("initialize replica");
        let first_repo = DbSelectionPolicyRepo::new(Arc::clone(&first));
        let second_repo = DbSelectionPolicyRepo::new(Arc::clone(&second));
        let device_id = db::Uuid::now_v7();
        let application_id = db::Uuid::now_v7();
        let selected = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(db::Uuid::now_v7()),
            admin_allowed: true,
        };
        first_repo
            .set_prevalidated(selected.clone())
            .await
            .expect("initial selection");
        sync_replica(&first, &second).await;

        for (engine, owner) in [(&first, "other"), (&second, "third")] {
            engine
                .execute(vec![db::Statement::Query(db::Query::Update(
                    db::QueryUpdate {
                        from: from(),
                        assignments: vec![assignment("owner_subject", Value::Text(owner.into()))],
                        predicate: Some(super::equals("device_id", Value::Uuid(device_id))),
                        returning: None,
                    },
                ))])
                .await
                .expect("concurrent owner change");
        }
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;
        assert!(
            first
                .row_conflicts(TABLE, &key(device_id))
                .await
                .expect("owner conflicts")
                .contains(&"owner_subject".into())
        );
        for repo in [&first_repo, &second_repo] {
            for owner in ["owner", "other", "third"] {
                assert!(repo.deselect_owned(device_id, owner).await.is_err());
            }
        }

        let other_device = db::Uuid::now_v7();
        let mut other_policy = selected.clone();
        other_policy.device_id = other_device;
        first_repo
            .set_prevalidated(other_policy.clone())
            .await
            .expect("second selection");
        sync_replica(&first, &second).await;
        for (engine, allowed) in [(&first, false), (&second, false), (&second, true)] {
            engine
                .execute(vec![db::Statement::Query(db::Query::Update(
                    db::QueryUpdate {
                        from: from(),
                        assignments: vec![assignment("admin_allowed", Value::Bool(allowed))],
                        predicate: Some(super::equals("device_id", Value::Uuid(other_device))),
                        returning: None,
                    },
                ))])
                .await
                .expect("concurrent admin change");
        }
        sync_replica(&first, &second).await;
        sync_replica(&second, &first).await;
        assert!(
            first
                .row_conflicts(TABLE, &key(other_device))
                .await
                .expect("admin conflicts")
                .contains(&"admin_allowed".into())
        );
        for repo in [&first_repo, &second_repo] {
            assert!(repo.deselect_owned(other_device, "owner").await.is_err());
            assert!(
                !repo
                    .get(other_device, "owner", application_id)
                    .await
                    .expect("admin restriction conflict resolves fail-closed")
                    .expect("selection remains stored")
                    .admin_allowed
            );
        }
    }

    #[tokio::test]
    async fn selection_survives_reopen_and_rejects_wrong_namespace() {
        let path = std::env::temp_dir().join(format!(
            "management-selection-{}-{}.redb",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let device_id = db::Uuid::now_v7();
        let application_id = db::Uuid::now_v7();
        let selected_id = db::Uuid::now_v7();
        let policy = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(selected_id),
            admin_allowed: false,
        };
        {
            let engine: Arc<NativeEngine> =
                Arc::new(open_native_engine(&path).expect("open database"));
            idp_model::replica::up(&engine)
                .await
                .expect("migrate database");
            DbSelectionPolicyRepo::new(engine)
                .set_prevalidated(policy.clone())
                .await
                .expect("write validated selection");
        }
        {
            let engine: Arc<NativeEngine> =
                Arc::new(open_native_engine(&path).expect("reopen database"));
            let repo = DbSelectionPolicyRepo::new(engine);
            assert_eq!(
                repo.get(device_id, "owner", application_id)
                    .await
                    .expect("read selection"),
                Some(policy)
            );
            assert!(repo.get(device_id, "other", application_id).await.is_err());
        }
        std::fs::remove_file(path).expect("remove database");
    }

    #[tokio::test]
    async fn offline_deselection_keeps_admin_restriction_and_checks_owner() {
        let engine = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize replica schema");
        let repo = DbSelectionPolicyRepo::new(engine);
        let device_id = db::Uuid::now_v7();
        let application_id = db::Uuid::now_v7();
        let mut policy = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: Some(application_id),
            selected_kind: Some("database".into()),
            selected_id: Some(db::Uuid::now_v7()),
            admin_allowed: false,
        };
        repo.set_prevalidated(policy.clone())
            .await
            .expect("set selection");
        assert!(
            !repo
                .deselect_owned(db::Uuid::now_v7(), "owner")
                .await
                .expect("missing policy")
        );
        assert!(
            !repo
                .deselect_owned(device_id, "other")
                .await
                .expect("wrong owner")
        );
        assert_eq!(
            repo.get(device_id, "owner", application_id)
                .await
                .expect("unchanged selection"),
            Some(policy.clone())
        );
        assert!(
            repo.deselect_owned(device_id, "owner")
                .await
                .expect("offline deselection")
        );
        assert!(
            repo.deselect_owned(device_id, "owner")
                .await
                .expect("already deselected")
        );
        policy.application_id = None;
        policy.selected_kind = None;
        policy.selected_id = None;
        assert_eq!(
            repo.get(device_id, "owner", application_id)
                .await
                .expect("read policy"),
            Some(policy)
        );
    }

    #[tokio::test]
    async fn admin_restriction_without_selection_and_switch_after_deselect() {
        let engine = Arc::new(db::Engine::new(
            db::InMemoryKernel::new(),
            db::AutomergeRowCodec::new(),
        ));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize replica schema");
        let repo = DbSelectionPolicyRepo::new(engine);
        let device_id = db::Uuid::now_v7();
        let app_a = db::Uuid::now_v7();
        let app_b = db::Uuid::now_v7();
        let mut policy = SelectionPolicy {
            device_id,
            owner_subject: "owner".into(),
            application_id: None,
            selected_kind: None,
            selected_id: None,
            admin_allowed: false,
        };
        repo.set_prevalidated(policy.clone())
            .await
            .expect("restrict admin with no selection");
        assert_eq!(
            repo.get(device_id, "owner", app_b)
                .await
                .expect("read unselected policy"),
            Some(policy.clone())
        );
        assert!(repo.get(device_id, "other", app_b).await.is_err());

        assert!(
            repo.set_prevalidated(SelectionPolicy {
                application_id: Some(app_a),
                selected_kind: Some("database".into()),
                selected_id: Some(db::Uuid::now_v7()),
                ..policy.clone()
            })
            .await
            .is_err()
        );
        repo.set_admin_allowed_prevalidated(device_id, "owner", true)
            .await
            .expect("lift restriction");
        policy.admin_allowed = true;
        policy.application_id = Some(app_a);
        policy.selected_kind = Some("database".into());
        policy.selected_id = Some(db::Uuid::now_v7());
        repo.set_prevalidated(policy.clone())
            .await
            .expect("select app A");
        let mut app_a_filesystem = policy.clone();
        app_a_filesystem.selected_kind = Some("filesystem".into());
        app_a_filesystem.selected_id = Some(db::Uuid::now_v7());
        repo.set_prevalidated(app_a_filesystem.clone())
            .await
            .expect("select filesystem alongside database");
        let mut app_b_policy = policy.clone();
        app_b_policy.application_id = Some(app_b);
        app_b_policy.selected_id = Some(db::Uuid::now_v7());
        repo.set_prevalidated(app_b_policy.clone())
            .await
            .expect("select app B without replacing app A");
        assert!(
            repo.resource_selected(
                device_id,
                "owner",
                app_a,
                "database",
                policy.selected_id.expect("app A resource")
            )
            .await
            .expect("check app A database")
        );
        assert!(
            repo.resource_selected(
                device_id,
                "owner",
                app_a,
                "filesystem",
                app_a_filesystem.selected_id.expect("app A filesystem")
            )
            .await
            .expect("check app A filesystem")
        );
        let app_a_resource = policy.selected_id.expect("app A resource");
        let app_a_filesystem_id = app_a_filesystem.selected_id.expect("app A filesystem");
        let selected = repo
            .selected_resources_for_device(device_id)
            .await
            .expect("list selected resources");
        assert_eq!(selected.len(), 3);
        assert!(selected.iter().any(|resource| {
            resource.application_id == app_a
                && resource.kind == "database"
                && resource.resource_id == app_a_resource
        }));
        assert!(selected.iter().any(|resource| {
            resource.application_id == app_a
                && resource.kind == "filesystem"
                && resource.resource_id == app_a_filesystem_id
        }));
        assert!(
            repo.deselect_resource_owned(
                device_id,
                "owner",
                app_a,
                "filesystem",
                app_a_filesystem_id,
            )
            .await
            .expect("deselect only app A filesystem")
        );
        assert!(
            repo.resource_selected(device_id, "owner", app_a, "database", app_a_resource)
                .await
                .expect("database remains selected")
        );
        let selected = repo
            .selected_resources_for_device(device_id)
            .await
            .expect("list resources after deselection");
        assert_eq!(selected.len(), 2);
        assert!(!selected.iter().any(|resource| {
            resource.application_id == app_a
                && resource.kind == "filesystem"
                && resource.resource_id == app_a_filesystem_id
        }));
        repo.set_prevalidated(app_a_filesystem.clone())
            .await
            .expect("reselect app A filesystem");
        let app_b_resource = app_b_policy.selected_id.expect("app B resource");

        policy.application_id = None;
        policy.selected_kind = None;
        policy.selected_id = None;
        repo.set_prevalidated(policy.clone())
            .await
            .expect("deselect app A");
        assert_eq!(
            repo.get(device_id, "owner", app_b)
                .await
                .expect("read after deselect"),
            Some(policy.clone())
        );
        repo.set_prevalidated(app_b_policy.clone())
            .await
            .expect("select app B");
        assert_eq!(
            repo.get(device_id, "owner", app_b)
                .await
                .expect("read app B"),
            Some(app_b_policy.clone())
        );
        assert!(
            !repo
                .resource_selected(device_id, "owner", app_a, "database", app_a_resource)
                .await
                .expect("app A was deselected")
        );
        assert!(
            !repo
                .resource_selected(device_id, "owner", app_a, "filesystem", app_a_filesystem_id,)
                .await
                .expect("app A filesystem was deselected")
        );
        assert!(
            repo.resource_selected(device_id, "owner", app_b, "database", app_b_resource)
                .await
                .expect("app B remains selected")
        );
    }
}
