use db::Value;
use idp_model::{contract::JwkPublic, model::Id};
use idp_service::security_sync::public_security_tables;
use ofdb_sql::{SyncCandidateView, SyncRowView, SyncTableView};

pub(super) struct PeerBinding {
    pub member: Id,
    pub endpoint: String,
    pub owner: Id,
}

pub(super) fn validate(
    view: &SyncCandidateView,
    installation: &str,
    bindings: &[PeerBinding],
) -> Result<(), String> {
    for table in &view.tables {
        let public = public_security_tables()
            .into_iter()
            .find(|public| public.name() == table.name)
            .ok_or_else(invalid)?;
        if table.columns.len() != public.columns().len()
            || table
                .columns
                .iter()
                .any(|column| !public.columns().contains(&column.as_str()))
        {
            return Err(invalid());
        }
        for row in &table.rows {
            if row.deleted {
                continue;
            }
            if row.row.values.len() != table.columns.len() {
                return Err(invalid());
            }
            for (column, value) in table.columns.iter().zip(&row.row.values) {
                if !public.permits_historical_value(column, value)
                    || !permits_installation(&table.name, column, value, installation)
                {
                    return Err("invalid public security historical value".into());
                }
            }
            for (column, values) in &row.conflicts {
                if values.iter().any(|value| {
                    !public.permits_historical_value(column, value)
                        || !permits_installation(&table.name, column, value, installation)
                }) {
                    return Err("invalid public security historical value".into());
                }
            }
            match table.name.as_str() {
                "devices" => validate_device(table, row, bindings)?,
                "idp_replica_members" => validate_member(view, table, row, bindings)?,
                "idp_replica_signers" => validate_signer(table, row)?,
                _ => {}
            }
        }
    }
    Ok(())
}

pub(super) fn permits_installation(
    table: &str,
    column: &str,
    value: &Value,
    installation: &str,
) -> bool {
    if matches!(
        (table, column),
        ("idp_replica_members", "installation_id" | "issuer") | ("idp_replica_signers", "issuer")
    ) {
        matches!(value, Value::Null) || matches!(value, Value::Text(text) if text == installation)
    } else {
        true
    }
}

fn field<'a>(table: &SyncTableView, row: &'a SyncRowView, column: &str) -> Option<&'a Value> {
    if row.deleted || row.conflicts.iter().any(|(name, _)| name == column) {
        return None;
    }
    table
        .columns
        .iter()
        .position(|name| name == column)
        .and_then(|index| row.row.values.get(index))
}

fn uuid(table: &SyncTableView, row: &SyncRowView, column: &str) -> Option<Id> {
    match field(table, row, column) {
        Some(Value::Uuid(id)) => Some(*id),
        _ => None,
    }
}

fn text<'a>(table: &SyncTableView, row: &'a SyncRowView, column: &str) -> Option<&'a str> {
    match field(table, row, column) {
        Some(Value::Text(text)) => Some(text),
        _ => None,
    }
}

fn validate_device(
    table: &SyncTableView,
    row: &SyncRowView,
    bindings: &[PeerBinding],
) -> Result<(), String> {
    let owner = text(table, row, "owner_subject")
        .map(|owner| owner.parse::<Id>().map_err(|_| invalid()))
        .transpose()?;
    if owner.is_some_and(|id| id.is_nil()) {
        return Err(invalid());
    }
    if let Some(binding) = bindings.iter().find(|binding| binding.member == row.id)
        && (text(table, row, "public_key").is_some_and(|endpoint| endpoint != binding.endpoint)
            || owner.is_some_and(|owner| owner != binding.owner))
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_member(
    view: &SyncCandidateView,
    table: &SyncTableView,
    row: &SyncRowView,
    bindings: &[PeerBinding],
) -> Result<(), String> {
    let member = uuid(table, row, "member_id");

    let endpoint = text(table, row, "endpoint_id");
    if let Some(endpoint) = endpoint {
        let parsed = endpoint
            .parse::<iroh::EndpointId>()
            .map_err(|_| invalid())?;
        if parsed.to_string() != endpoint {
            return Err(invalid());
        }
    }
    if let Some(binding) = bindings
        .iter()
        .find(|binding| Some(binding.member) == member)
        && endpoint.is_some_and(|endpoint| endpoint != binding.endpoint)
    {
        return Err(invalid());
    }
    if let (Some(member), Some(endpoint), Some(devices)) = (
        member,
        endpoint,
        view.tables.iter().find(|table| table.name == "devices"),
    ) && let Some(device) = devices
        .rows
        .iter()
        .find(|device| device.id == member && !device.deleted)
        && text(devices, device, "public_key").is_some_and(|key| key != endpoint)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_signer(table: &SyncTableView, row: &SyncRowView) -> Result<(), String> {
    if let (Some(member), Some(active)) = (
        uuid(table, row, "member_id"),
        uuid(table, row, "active_member_id"),
    ) && member != active
    {
        return Err(invalid());
    }
    if let (Some(key), Some(jwk)) = (uuid(table, row, "key_id"), text(table, row, "public_jwk")) {
        let jwk: JwkPublic = serde_json::from_str(jwk).map_err(|_| invalid())?;
        if jwk.kid != key.to_string() {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn validate_node_join(
    view: &SyncCandidateView,
    installation: &str,
    approval: &idp_server::NodeJoinApproval,
) -> Result<(), String> {
    let request = &approval.request;
    validate(
        view,
        installation,
        &[PeerBinding {
            member: request.member_id,
            endpoint: request.endpoint_id.clone(),
            owner: approval.owner_subject,
        }],
    )?;
    let key: Id = request.public_signer.kid.parse().map_err(|_| invalid())?;
    for table in &view.tables {
        for row in &table.rows {
            if row.deleted {
                continue;
            }
            if table.name == "devices"
                && row.id == request.member_id
                && text(table, row, "name").is_some_and(|name| name != request.name)
            {
                return Err(invalid());
            }
            if table.name == "idp_replica_signers"
                && (uuid(table, row, "key_id") == Some(key)
                    || uuid(table, row, "active_member_id") == Some(request.member_id))
            {
                if uuid(table, row, "key_id").is_some_and(|id| id != key)
                    || uuid(table, row, "member_id").is_some_and(|id| id != request.member_id)
                {
                    return Err(invalid());
                }
                if let Some(public) = text(table, row, "public_jwk") {
                    let public: JwkPublic = serde_json::from_str(public).map_err(|_| invalid())?;
                    if public != request.public_signer {
                        return Err(invalid());
                    }
                }
            }
        }
    }
    Ok(())
}

fn invalid() -> String {
    "invalid public security candidate".into()
}
