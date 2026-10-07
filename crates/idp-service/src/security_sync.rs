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
                "scopes",
                "created_at",
                "updated_at",
            ],
            Self::AuthorizationCodes => &[
                "id",
                "code_hash",
                "client_id",
                "key_id",
                "redirect_uri",
                "scopes",
                "resource",
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

    /// Reject unknown fields and private JWK material before handing records to a sync adapter.
    #[must_use]
    pub fn permits_record(
        self,
        record: &serde_json::Map<alloc::string::String, serde_json::Value>,
    ) -> bool {
        if !record.contains_key("id")
            || record
                .keys()
                .any(|column| !self.columns().contains(&column.as_str()))
        {
            return false;
        }
        if let Some(public) = record.get("public_jwk") {
            let decoded;
            let public = if let Some(text) = public.as_str() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                    return false;
                };
                decoded = value;
                &decoded
            } else {
                public
            };
            let Some(public) = public.as_object() else {
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
            if let Some(hash) = record.get(field)
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
    use super::{PublicSecurityTable, public_security_tables};

    #[test]
    fn projections_exclude_passwords_secrets_private_keys_and_raw_grants() {
        for table in public_security_tables() {
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
                let mut record = serde_json::json!({"id": "fixture"});
                record
                    .as_object_mut()
                    .expect("record")
                    .insert(forbidden.into(), serde_json::json!("secret"));
                assert!(
                    !table.permits_record(record.as_object().expect("record")),
                    "{table:?} admitted {forbidden}"
                );
            }
        }
        let public = serde_json::json!({"id": "fixture", "client_id": "client"});
        assert!(PublicSecurityTable::Clients.permits_record(public.as_object().expect("record")));
        let raw = serde_json::json!({"id": "fixture", "token_hash": "raw-refresh-token"});
        assert!(
            !PublicSecurityTable::RefreshTokens.permits_record(raw.as_object().expect("record"))
        );
    }
}
