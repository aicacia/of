/// Policy records belong to Management, never the IdP store. Admission and each apply
/// still require authenticated peer provenance and locally evaluated permission.
pub const PUBLIC_POLICY_TABLES: &[&str] = &[
    "roles",
    "permissions",
    "role_permissions",
    "application_user_roles",
    "device_selection_policies",
    "device_resource_selections",
];

#[must_use]
pub fn public_policy_columns(table: &str) -> Option<&'static [&'static str]> {
    Some(match table {
        "roles" | "permissions" => &[
            "id",
            "application_id",
            "name",
            "description",
            "revoked_at",
            "created_at",
            "updated_at",
        ],
        "role_permissions" => &[
            "id",
            "role_id",
            "permission_id",
            "revoked_at",
            "created_at",
            "updated_at",
        ],
        "application_user_roles" => &[
            "id",
            "user_id",
            "application_id",
            "role_id",
            "revoked_at",
            "created_at",
            "updated_at",
        ],
        "device_selection_policies" => &[
            "device_id",
            "owner_subject",
            "application_id",
            "selected_kind",
            "selected_id",
            "admin_allowed",
        ],
        "device_resource_selections" => &[
            "id",
            "device_id",
            "owner_subject",
            "application_id",
            "selected_kind",
            "selected_id",
            "selected",
        ],
        _ => return None,
    })
}

#[must_use]
pub fn permits_policy_table(table: &str) -> bool {
    PUBLIC_POLICY_TABLES.contains(&table)
}

#[cfg(test)]
mod tests {
    use super::permits_policy_table;

    #[cfg(feature = "replica")]
    #[tokio::test]
    async fn public_policy_columns_match_only_the_owned_schema() {
        let database = db::Database::in_memory();
        crate::replica::up(&database)
            .await
            .expect("declare policy schema");
        for table in super::PUBLIC_POLICY_TABLES {
            let expected =
                super::public_policy_columns(table).expect("explicitly reviewed policy table");
            let result = database
                .client()
                .translate_and_execute(
                    &alloc::format!("SELECT * FROM {table} LIMIT 0"),
                    &db::SqlTranslator,
                )
                .await
                .expect("public schema columns");
            assert_eq!(result[0].columns.len(), expected.len());
            assert!(
                result[0]
                    .columns
                    .iter()
                    .all(|column| expected.contains(&column.name.as_str()))
            );
        }
        assert_eq!(
            super::public_policy_columns("local_client_credentials"),
            None
        );
        assert_eq!(super::public_policy_columns("devices"), None);
        assert_eq!(super::public_policy_columns("unknown"), None);
    }

    #[test]
    fn policy_sync_is_context_local_and_explicitly_allowlisted() {
        assert!(permits_policy_table("role_permissions"));
        assert!(permits_policy_table("device_selection_policies"));
        assert!(permits_policy_table("device_resource_selections"));
        for table in [
            "users",
            "credentials",
            "clients",
            "keys",
            "devices",
            "oauth2_refresh_tokens",
            "local_client_credentials",
            "local_credential_secrets",
            "local_device_enrollments",
            "unknown",
        ] {
            assert!(!permits_policy_table(table));
        }
    }
}
