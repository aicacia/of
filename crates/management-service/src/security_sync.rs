/// Policy records belong to Management, never the IdP store. Admission and each apply
/// still require authenticated peer provenance and locally evaluated permission.
pub const PUBLIC_POLICY_TABLES: &[&str] = &[
    "roles",
    "permissions",
    "role_permissions",
    "application_user_roles",
];

#[must_use]
pub fn permits_policy_table(table: &str) -> bool {
    PUBLIC_POLICY_TABLES.contains(&table)
}

#[cfg(test)]
mod tests {
    use super::permits_policy_table;

    #[test]
    fn policy_sync_is_context_local_and_explicitly_allowlisted() {
        assert!(permits_policy_table("role_permissions"));
        for table in [
            "users",
            "credentials",
            "clients",
            "keys",
            "devices",
            "oauth2_refresh_tokens",
            "unknown",
        ] {
            assert!(!permits_policy_table(table));
        }
    }
}
