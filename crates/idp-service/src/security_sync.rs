use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicSecurityTable {
    Users,
    Applications,
    Clients,
    Keys,
    Devices,
    Members,
    Signers,
    Consents,
    AuthorizationCodes,
    RefreshTokens,
}

impl PublicSecurityTable {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Applications => "applications",
            Self::Clients => "clients",
            Self::Keys => "keys",
            Self::Devices => "devices",
            Self::Members => "idp_replica_members",
            Self::Signers => "idp_replica_signers",
            Self::Consents => "oauth2_user_consents",
            Self::AuthorizationCodes => "oauth2_authorization_codes",
            Self::RefreshTokens => "oauth2_refresh_tokens",
        }
    }

    /// This is a projection contract, not permission to export opaque whole-row CRDT state.
    #[must_use]
    pub const fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Users => &[
                "id",
                "handle",
                "name",
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "profile",
                "picture",
                "website",
                "sex",
                "birthdate",
                "zoneinfo",
                "locale",
                "created_at",
                "updated_at",
            ],
            Self::Applications => &[
                "id",
                "name",
                "uri",
                "description",
                "created_at",
                "updated_at",
            ],
            Self::Clients => &[
                "id",
                "application_id",
                "client_id",
                "client_id_issued_at",
                "client_secret_expires_at",
                "client_name",
                "client_uri",
                "redirect_uris",
                "client_type",
                "profile",
                "token_endpoint_auth_method",
                "allowed_grant_types",
                "response_types",
                "allowed_scopes",
                "allowed_audiences",
                "logo_uri",
                "contacts",
                "terms_of_service_uri",
                "policy_uri",
                "software_statement",
                "software_id",
                "software_version",
                "revoked_at",
                "created_at",
                "updated_at",
            ],
            Self::Keys => &[
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
            ],
            Self::Devices => &[
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
            ],
            Self::Members => &[
                "id",
                "installation_id",
                "member_id",
                "endpoint_id",
                "issuer",
                "approved_at",
                "revoked_at",
            ],
            Self::Signers => &[
                "id",
                "member_id",
                "active_member_id",
                "key_id",
                "issuer",
                "public_jwk",
                "approved_at",
                "revoked_at",
                "expires_at",
            ],
            Self::Consents => &[
                "id",
                "user_id",
                "client_id",
                "redirect_uri",
                "scope",
                "authorization_details",
                "revoked_at",
                "created_at",
                "updated_at",
            ],
            Self::AuthorizationCodes => &[
                "id",
                "code_hash",
                "client_id",
                "user_id",
                "key_id",
                "redirect_uri",
                "scopes",
                "resource",
                "authorization_details",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "expires_at",
                "consumed_at",
                "created_at",
                "updated_at",
            ],
            Self::RefreshTokens => &[
                "id",
                "token_hash",
                "client_id",
                "user_id",
                "scopes",
                "resource",
                "authorization_details",
                "expires_at",
                "consumed_at",
                "revoked_at",
                "created_at",
                "updated_at",
            ],
        }
    }

    fn nullable(self, column: &str) -> bool {
        if column == "id" {
            return false;
        }
        match self {
            Self::Keys => column != "derivation_index",
            Self::Devices => column != "owner_subject",
            Self::Members => column == "revoked_at",
            Self::Signers => matches!(column, "active_member_id" | "revoked_at" | "expires_at"),
            _ => true,
        }
    }

    fn permits_value(self, column: &str, value: &serde_json::Value) -> bool {
        if value.is_null() {
            return self.nullable(column);
        }
        let uuid = matches!(
            column,
            "id" | "parent_id"
                | "entity_id"
                | "application_id"
                | "user_id"
                | "member_id"
                | "active_member_id"
                | "key_id"
        ) || (column == "client_id" && self != Self::Clients);
        if uuid {
            return value
                .as_str()
                .and_then(|text| idp_model::model::Id::parse_str(text).ok())
                .is_some_and(|id| !id.is_nil() && (column != "id" || id.get_version_num() == 7));
        }
        let integer = matches!(
            column,
            "sex"
                | "entity_type"
                | "derivation_index"
                | "hardened"
                | "state"
                | "client_type"
                | "token_endpoint_auth_method"
                | "code_challenge_method"
        ) || column.ends_with("_at")
            || (self == Self::Clients && column == "profile");
        if integer {
            value.as_i64().is_some()
        } else {
            value.is_string()
        }
    }

    /// Validate a complete SQL-shaped public projection, not provenance or import authorization.
    #[must_use]
    pub fn permits_record(
        self,
        record: &serde_json::Map<alloc::string::String, serde_json::Value>,
    ) -> bool {
        if record.len() != self.columns().len()
            || self.columns().iter().any(|column| {
                record
                    .get(*column)
                    .is_none_or(|value| !self.permits_value(column, value))
            })
        {
            return false;
        }
        if let Some(public) = record.get("public_jwk").filter(|value| !value.is_null()) {
            let Some(text) = public.as_str() else {
                return false;
            };
            let Ok(decoded) = serde_json::from_str::<serde_json::Value>(text) else {
                return false;
            };
            let Some(public) = decoded.as_object() else {
                return false;
            };
            if public.keys().any(|field| {
                !["kid", "use", "alg", "kty", "crv", "x", "y"].contains(&field.as_str())
            }) {
                return false;
            }
            if serde_json::from_value::<idp_model::contract::JwkPublic>(serde_json::Value::Object(
                public.clone(),
            ))
            .ok()
            .is_none_or(|jwk| crate::oauth2::verifing_key_from_jwt(&jwk).is_err())
            {
                return false;
            }
        }
        for field in ["code_hash", "token_hash"] {
            if let Some(hash) = record.get(field).filter(|value| !value.is_null())
                && hash.as_str().is_none_or(|hash| {
                    hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return false;
            }
        }
        true
    }
}

#[must_use]
pub fn public_security_tables() -> Vec<PublicSecurityTable> {
    use PublicSecurityTable as T;
    alloc::vec![
        T::Users,
        T::Applications,
        T::Clients,
        T::Keys,
        T::Devices,
        T::Members,
        T::Signers,
        T::Consents,
        T::AuthorizationCodes,
        T::RefreshTokens
    ]
}

#[cfg(test)]
mod tests {
    use super::PublicSecurityTable;
    #[cfg(feature = "replica")]
    use super::public_security_tables;

    #[test]
    fn projections_require_complete_typed_records() {
        let table = PublicSecurityTable::Users;
        let mut record: serde_json::Map<alloc::string::String, serde_json::Value> = table
            .columns()
            .iter()
            .map(|column| ((*column).into(), serde_json::Value::Null))
            .collect();
        record.insert(
            "id".into(),
            serde_json::json!("01900000-0000-7000-8000-000000000001"),
        );
        assert!(
            table.permits_record(&record),
            "complete nullable SQL projection"
        );
        for column in table.columns() {
            let mut incomplete = record.clone();
            incomplete.remove(*column);
            assert!(
                !table.permits_record(&incomplete),
                "missing {column} must not implicitly erase state"
            );
        }
        for (column, value) in [
            ("id", serde_json::Value::Null),
            ("id", serde_json::json!("not-a-uuid")),
            ("created_at", serde_json::json!("1")),
            ("created_at", serde_json::json!(1.5)),
            ("name", serde_json::json!({"password": "secret"})),
        ] {
            let mut malformed = record.clone();
            malformed.insert(column.into(), value);
            assert!(
                !table.permits_record(&malformed),
                "invalid type for {column}"
            );
        }
    }

    #[cfg(feature = "replica")]
    #[tokio::test]
    async fn projections_match_actual_schema_columns_and_types() {
        use db::{AutomergeRowCodec, Engine, InMemoryKernel, ValueType};
        let engine =
            alloc::sync::Arc::new(Engine::new(InMemoryKernel::new(), AutomergeRowCodec::new()));
        idp_model::replica::up(&engine)
            .await
            .expect("initialize actual schema");
        let public = serde_json::json!({"kid": idp_model::model::Id::now_v7(), "use": "sig", "alg": "ES256K", "kty": "Ec", "crv": "secp256k1",
            "x": "eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5g", "y": "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg"});
        for table in public_security_tables() {
            let schema = engine
                .table_schema(table.name())
                .await
                .expect("public table schema");
            let mut record = serde_json::Map::new();
            for column in &schema.columns {
                if [
                    "client_secret_hash",
                    "enrollment_code_hash",
                    "enrollment_expires_at",
                    "pairing_accepting_public_key",
                ]
                .contains(&column.name.as_str())
                {
                    continue;
                }
                assert!(
                    table.columns().contains(&column.name.as_str()),
                    "{table:?} missing actual column {}",
                    column.name
                );
                let value = match column.r#type {
                    ValueType::Uuid => serde_json::json!(idp_model::model::Id::now_v7()),
                    ValueType::Integer => serde_json::json!(1),
                    ValueType::Text => serde_json::json!("fixture"),
                    _ => panic!("unexpected public column type"),
                };
                record.insert(column.name.clone(), value);
            }
            assert_eq!(
                record.len(),
                table.columns().len(),
                "no invented projection columns"
            );
            for hash in ["code_hash", "token_hash"] {
                if record.contains_key(hash) {
                    record.insert(hash.into(), serde_json::json!("a".repeat(64)));
                }
            }
            if record.contains_key("public_jwk") {
                record.insert(
                    "public_jwk".into(),
                    serde_json::json!(serde_json::to_string(&public).expect("SQL JWK text")),
                );
            }
            assert!(
                table.permits_record(&record),
                "complete schema-shaped {table:?} projection"
            );
            for column in table.columns() {
                let mut missing = record.clone();
                missing.remove(*column);
                assert!(
                    !table.permits_record(&missing),
                    "{table:?} requires {column} even when SQL-nullable"
                );
            }
            for forbidden in [
                "password",
                "secret_hash",
                "client_secret",
                "client_secret_hash",
                "enrollment_code_hash",
                "device_code",
                "code",
                "token",
                "private_key",
                "d",
            ] {
                let mut injected = record.clone();
                injected.insert(forbidden.into(), serde_json::json!("secret"));
                assert!(
                    !table.permits_record(&injected),
                    "{table:?} must not project {forbidden}"
                );
            }
            for hash in ["code_hash", "token_hash"] {
                if record.contains_key(hash) {
                    let mut raw = record.clone();
                    raw.insert(hash.into(), serde_json::json!("raw-grant"));
                    assert!(
                        !table.permits_record(&raw),
                        "raw grant is not hashed lifecycle data"
                    );
                }
            }
            for column in &schema.columns {
                if !record.contains_key(&column.name) {
                    continue;
                }
                let mut wrong = record.clone();
                wrong.insert(column.name.clone(), serde_json::json!(false));
                assert!(
                    !table.permits_record(&wrong),
                    "{table:?} accepts wrong type for {}",
                    column.name
                );
            }
        }
    }
}
