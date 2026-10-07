use db::{Database, SqlTranslator};

const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS roles (id UUID PRIMARY KEY, application_id UUID, name TEXT, description TEXT, revoked_at INTEGER, created_at INTEGER, updated_at INTEGER)",
    "CREATE UNIQUE INDEX IF NOT EXISTS roles_application_name ON roles (application_id, name)",
    "CREATE TABLE IF NOT EXISTS permissions (id UUID PRIMARY KEY, application_id UUID, name TEXT, description TEXT, revoked_at INTEGER, created_at INTEGER, updated_at INTEGER)",
    "CREATE UNIQUE INDEX IF NOT EXISTS permissions_application_name ON permissions (application_id, name)",
    "CREATE TABLE IF NOT EXISTS role_permissions (id UUID PRIMARY KEY, role_id UUID, permission_id UUID, revoked_at INTEGER, created_at INTEGER, updated_at INTEGER)",
    "CREATE UNIQUE INDEX IF NOT EXISTS role_permissions_role_permission ON role_permissions (role_id, permission_id)",
    "CREATE TABLE IF NOT EXISTS application_user_roles (id UUID PRIMARY KEY, user_id UUID, application_id UUID, role_id UUID, revoked_at INTEGER, created_at INTEGER, updated_at INTEGER)",
    "CREATE UNIQUE INDEX IF NOT EXISTS application_user_roles_user_application_role ON application_user_roles (user_id, application_id, role_id)",
    "CREATE TABLE IF NOT EXISTS device_selection_policies (device_id UUID PRIMARY KEY, owner_subject TEXT NOT NULL, application_id UUID, selected_kind TEXT, selected_id UUID, admin_allowed BOOLEAN NOT NULL)",
    "CREATE TABLE IF NOT EXISTS device_resource_selections (id UUID PRIMARY KEY, device_id UUID NOT NULL, owner_subject TEXT NOT NULL, application_id UUID NOT NULL, selected_kind TEXT NOT NULL, selected_id UUID NOT NULL, selected BOOLEAN NOT NULL)",
];

pub async fn up(engine: &Database) -> Result<(), db::QueryError> {
    for statement in MIGRATIONS {
        engine
            .client()
            .translate_and_execute(statement, &SqlTranslator)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::up;

    #[tokio::test]
    async fn initializes_management_tables_without_identity_tables() {
        let engine = db::Database::in_memory();

        up(&engine).await.expect("initialize management schema");

        for table in ["roles", "permissions", "device_selection_policies"] {
            engine
                .client()
                .translate_and_execute(&format!("SELECT * FROM {table}"), &db::SqlTranslator)
                .await
                .expect("management-owned table exists");
        }
        for table in ["users", "applications", "clients", "devices", "keys"] {
            assert!(
                engine
                    .client()
                    .translate_and_execute(&format!("SELECT * FROM {table}"), &db::SqlTranslator)
                    .await
                    .is_err()
            );
        }
    }
}
