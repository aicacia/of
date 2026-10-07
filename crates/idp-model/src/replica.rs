use include_dir::{Dir, include_dir};

use db::{Engine, EngineResult, Kernel, Row, RowCodec, SqlTranslator, Uuid, Value};

static MIGRATIONS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/replica_migrations");

pub async fn up<K, R>(engine: &Engine<K, R>) -> EngineResult<()>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    for file in MIGRATIONS.files() {
        for statement in file
            .contents_utf8()
            .expect("replica migration must be UTF-8")
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            engine
                .translate_and_execute(statement, &SqlTranslator)
                .await?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityTable {
    Application,
    Client,
    Credential,
    Device,
    Key,
    OAuthAuthorizationCode,
    OAuthRefreshToken,
    OAuthUserConsent,
    Permission,
    Role,
    RolePermission,
    UserRole,
    ReplicaMember,
    ReplicaSigner,
}

impl SecurityTable {
    const fn name(self) -> &'static str {
        match self {
            Self::Application => "applications",
            Self::Client => "clients",
            Self::Credential => "credentials",
            Self::Device => "devices",
            Self::Key => "keys",
            Self::OAuthAuthorizationCode => "oauth2_authorization_codes",
            Self::OAuthRefreshToken => "oauth2_refresh_tokens",
            Self::OAuthUserConsent => "oauth2_user_consents",
            Self::Permission => "permissions",
            Self::Role => "roles",
            Self::RolePermission => "role_permissions",
            Self::UserRole => "application_user_roles",
            Self::ReplicaMember => "idp_replica_members",
            Self::ReplicaSigner => "idp_replica_signers",
        }
    }

    const fn is_token_state(self) -> bool {
        matches!(self, Self::OAuthAuthorizationCode | Self::OAuthRefreshToken)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityRow {
    pub table: SecurityTable,
    pub id: Uuid,
}

impl SecurityRow {
    #[must_use]
    pub const fn new(table: SecurityTable, id: Uuid) -> Self {
        Self { table, id }
    }

    fn key(self) -> Row {
        Row::new(vec![Value::Uuid(self.id)])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionAudit {
    pub id: Uuid,
    pub administrator_id: Uuid,
    pub table: SecurityTable,
    pub row_id: Uuid,
    pub columns: Vec<String>,
    pub created_at: i64,
}

pub async fn allows_authentication<K, R>(
    engine: &Engine<K, R>,
    credentials: &[Uuid],
    keys: &[Uuid],
) -> EngineResult<bool>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    let mut rows = Vec::with_capacity(credentials.len() + keys.len());
    rows.extend(
        credentials
            .iter()
            .copied()
            .map(|id| SecurityRow::new(SecurityTable::Credential, id)),
    );
    rows.extend(
        keys.iter()
            .copied()
            .map(|id| SecurityRow::new(SecurityTable::Key, id)),
    );
    clear(engine, &rows).await
}

pub async fn allows_authorization<K, R>(
    engine: &Engine<K, R>,
    rows: &[SecurityRow],
) -> EngineResult<bool>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    clear(engine, rows).await
}

pub async fn allows_token_issuance<K, R>(
    engine: &Engine<K, R>,
    rows: &[SecurityRow],
) -> EngineResult<bool>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    clear(engine, rows).await
}

pub async fn allows_tunnel_access<K, R>(
    engine: &Engine<K, R>,
    devices: &[Uuid],
) -> EngineResult<bool>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    let rows = devices
        .iter()
        .copied()
        .map(|id| SecurityRow::new(SecurityTable::Device, id))
        .collect::<Vec<_>>();
    clear(engine, &rows).await
}

pub async fn resolve<K, R>(
    engine: &Engine<K, R>,
    administrator_id: Uuid,
    row: SecurityRow,
    values: Vec<(String, Value)>,
    created_at: i64,
) -> EngineResult<Option<ResolutionAudit>>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    let conflicts = engine.row_conflicts(row.table.name(), &row.key()).await?;
    if conflicts.is_empty()
        || (row.table.is_token_state()
            && conflicts.iter().any(|column| column == "consumed_at")
            && !values
                .iter()
                .any(|(column, value)| column == "consumed_at" && !matches!(value, Value::Null)))
    {
        return Ok(None);
    }

    let audit = ResolutionAudit {
        id: Uuid::now_v7(),
        administrator_id,
        table: row.table,
        row_id: row.id,
        columns: conflicts,
        created_at,
    };
    engine
        .resolve_row(row.table.name(), &row.key(), values)
        .await?;
    engine
        .translate_and_execute(&resolution_insert(&audit), &SqlTranslator)
        .await?;
    Ok(Some(audit))
}

async fn clear<K, R>(engine: &Engine<K, R>, rows: &[SecurityRow]) -> EngineResult<bool>
where
    K: Kernel,
    R: RowCodec<K::Transaction>,
{
    for &row in rows {
        if !engine
            .row_conflicts(row.table.name(), &row.key())
            .await?
            .is_empty()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn resolution_insert(audit: &ResolutionAudit) -> String {
    format!(
        "INSERT INTO idp_conflict_resolutions (id, administrator_id, table_name, row_id, columns, created_at) VALUES (CAST('{}' AS UUID), CAST('{}' AS UUID), '{}', CAST('{}' AS UUID), '{}', {})",
        audit.id,
        audit.administrator_id,
        audit.table.name(),
        audit.row_id,
        audit.columns.join(","),
        audit.created_at,
    )
}

#[cfg(test)]
mod tests {
    use db::{AutomergeRowCodec, Engine, InMemoryKernel};
    use futures::executor::block_on;
    use ofdb_sql::{apply_sync_state_batch_for, export_sync_state_for};

    use super::{
        SecurityRow, SecurityTable, allows_authentication, allows_authorization,
        allows_token_issuance, allows_tunnel_access, resolve, up,
    };

    const ADMIN: u128 = 100;
    const DEVICE: u128 = 1;
    const CLIENT: u128 = 2;
    const ROLE: u128 = 3;
    const CREDENTIAL: u128 = 4;
    const KEY: u128 = 5;
    const CODE: u128 = 6;
    const REFRESH: u128 = 7;

    #[test]
    fn initializes_idempotently_with_uuid_primary_keys_and_unique_devices() {
        block_on(async {
            let engine = Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new());
            up(&engine).await.unwrap();
            up(&engine).await.unwrap();

            let clients_schema = engine.table_schema("clients").await.unwrap();
            assert!(
                clients_schema
                    .columns
                    .iter()
                    .any(|column| column.name == "allowed_audiences")
            );

            for table in [
                "users",
                "user_emails",
                "user_phone_numbers",
                "credentials",
                "keys",
                "applications",
                "clients",
                "devices",
                "roles",
                "permissions",
                "role_permissions",
                "application_user_roles",
                "oauth2_authorization_codes",
                "oauth2_user_consents",
                "oauth2_refresh_tokens",
                "idp_conflict_resolutions",
                "idp_replica_members",
                "idp_replica_signers",
            ] {
                let schema = engine.table_schema(table).await.unwrap();
                assert_eq!(schema.columns[0].name, "id");
                assert_eq!(
                    schema
                        .columns
                        .iter()
                        .filter(|column| column.primary_key)
                        .count(),
                    1
                );
            }

            engine
                .translate_and_execute(
                    "INSERT INTO devices (id, public_key) VALUES (CAST('00000000-0000-0000-0000-000000000001' AS UUID), 'key')",
                    &db::SqlTranslator,
                )
                .await
                .unwrap();
            assert!(engine
                .translate_and_execute(
                    "INSERT INTO devices (id, public_key) VALUES (CAST('00000000-0000-0000-0000-000000000002' AS UUID), 'key')",
                    &db::SqlTranslator,
                )
                .await
                .is_err());

            engine
                .translate_and_execute(
                    "INSERT INTO idp_replica_members (id, installation_id, member_id, endpoint_id, issuer, approved_at) VALUES (CAST('00000000-0000-0000-0000-000000000010' AS UUID), 'installation-a', CAST('00000000-0000-0000-0000-000000000011' AS UUID), 'endpoint-a', 'https://issuer.example', 1)",
                    &db::SqlTranslator,
                )
                .await
                .expect("insert first replica membership");
            assert!(engine
                .translate_and_execute(
                    "INSERT INTO idp_replica_members (id, installation_id, member_id, endpoint_id, issuer, approved_at) VALUES (CAST('00000000-0000-0000-0000-000000000012' AS UUID), 'installation-a', CAST('00000000-0000-0000-0000-000000000011' AS UUID), 'endpoint-b', 'https://issuer.example', 1)",
                    &db::SqlTranslator,
                )
                .await
                .is_err());
            assert!(engine
                .translate_and_execute(
                    "INSERT INTO idp_replica_members (id, installation_id, member_id, endpoint_id, issuer, approved_at) VALUES (CAST('00000000-0000-0000-0000-000000000013' AS UUID), 'installation-a', CAST('00000000-0000-0000-0000-000000000014' AS UUID), 'endpoint-a', 'https://issuer.example', 1)",
                    &db::SqlTranslator,
                )
                .await
                .is_err());
        });
    }

    #[test]
    fn security_decisions_fail_closed_until_an_administrator_resolves_the_selected_state() {
        block_on(async {
            let source = Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new());
            let destination = Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new());
            up(&source).await.unwrap();
            seed(&source).await;
            apply_sync_state_batch_for(&destination, export_sync_state_for(&source).await.unwrap())
                .await
                .unwrap();

            for (table, id, column) in [
                ("devices", DEVICE, "state"),
                ("clients", CLIENT, "client_name"),
                ("roles", ROLE, "name"),
                ("credentials", CREDENTIAL, "active"),
                ("keys", KEY, "name"),
                ("oauth2_authorization_codes", CODE, "consumed_at"),
                ("oauth2_refresh_tokens", REFRESH, "consumed_at"),
            ] {
                update(&source, table, id, column, "1").await;
                update(&destination, table, id, column, "2").await;
            }
            synchronize(&source, &destination).await;
            synchronize(&destination, &source).await;

            assert!(
                !allows_tunnel_access(&source, &[uuid(DEVICE)])
                    .await
                    .unwrap()
            );
            assert!(
                !allows_token_issuance(
                    &source,
                    &[SecurityRow::new(SecurityTable::Client, uuid(CLIENT))],
                )
                .await
                .unwrap()
            );
            assert!(
                !allows_authorization(
                    &source,
                    &[SecurityRow::new(SecurityTable::Role, uuid(ROLE))],
                )
                .await
                .unwrap()
            );
            assert!(
                !allows_authentication(&source, &[uuid(CREDENTIAL)], &[uuid(KEY)])
                    .await
                    .unwrap()
            );
            assert!(
                !allows_token_issuance(
                    &source,
                    &[
                        SecurityRow::new(SecurityTable::OAuthAuthorizationCode, uuid(CODE)),
                        SecurityRow::new(SecurityTable::OAuthRefreshToken, uuid(REFRESH)),
                    ],
                )
                .await
                .unwrap()
            );

            let code = SecurityRow::new(SecurityTable::OAuthAuthorizationCode, uuid(CODE));
            assert!(
                resolve(
                    &source,
                    uuid(ADMIN),
                    code,
                    vec![("consumed_at".to_owned(), db::Value::Null)],
                    3,
                )
                .await
                .unwrap()
                .is_none()
            );
            let audit = resolve(
                &source,
                uuid(ADMIN),
                code,
                vec![("consumed_at".to_owned(), db::Value::Integer(1))],
                3,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(audit.row_id, uuid(CODE));
            assert_eq!(
                source
                    .translate_and_execute(
                        "SELECT id FROM idp_conflict_resolutions",
                        &db::SqlTranslator,
                    )
                    .await
                    .unwrap()[0]
                    .rows
                    .len(),
                1
            );
            assert!(allows_token_issuance(&source, &[code]).await.unwrap());
        });
    }

    async fn seed(engine: &Engine<InMemoryKernel, AutomergeRowCodec>) {
        for (table, id, column, value) in [
            ("devices", DEVICE, "state", "0"),
            ("clients", CLIENT, "client_name", "'client'"),
            ("roles", ROLE, "name", "'role'"),
            ("credentials", CREDENTIAL, "active", "0"),
            ("keys", KEY, "name", "'key'"),
            ("oauth2_authorization_codes", CODE, "consumed_at", "NULL"),
            ("oauth2_refresh_tokens", REFRESH, "consumed_at", "NULL"),
        ] {
            engine
                .translate_and_execute(
                    &format!(
                        "INSERT INTO {table} (id, {column}) VALUES (CAST('{}' AS UUID), {value})",
                        uuid(id)
                    ),
                    &db::SqlTranslator,
                )
                .await
                .unwrap();
        }
    }

    async fn synchronize(
        source: &Engine<InMemoryKernel, AutomergeRowCodec>,
        destination: &Engine<InMemoryKernel, AutomergeRowCodec>,
    ) {
        apply_sync_state_batch_for(destination, export_sync_state_for(source).await.unwrap())
            .await
            .unwrap();
    }

    async fn update(
        engine: &Engine<InMemoryKernel, AutomergeRowCodec>,
        table: &str,
        id: u128,
        column: &str,
        value: &str,
    ) {
        let result = engine
            .translate_and_execute(
                &format!(
                    "UPDATE {table} SET {column} = {value} WHERE id = CAST('{}' AS UUID)",
                    uuid(id)
                ),
                &db::SqlTranslator,
            )
            .await;
        assert!(result.is_ok(), "{table}: {result:?}");
    }

    fn uuid(value: u128) -> db::Uuid {
        db::Uuid::from_u128(value)
    }
}
