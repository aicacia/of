#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use crate::model::{Id, Key};

use super::{
    EntityType, JwkPrivate, JwkPrivateParameters, JwkPublic, JwkPublicParameters, JwsAlgorithm,
    KeyUse,
};

/// Public enrollment state. Only the designated authority may approve this record.
/// Deserialization, configuration, and JWK possession do not establish its provenance.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IdpSignerRecord {
    pub member_id: Id,
    pub key_id: Id,
    pub issuer: String,
    pub public_jwk: JwkPublic,
    pub approved_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub expires_at: Option<i64>,
}

impl IdpSignerRecord {
    /// Check metadata binding on an authority-sourced snapshot, not approval provenance
    /// or cryptographic validity. Verification must validate the public point and signature.
    pub fn matches(&self, member_id: Id, key_id: Id, issuer: &str, now: i64) -> bool {
        self.member_id == member_id
            && self.key_id == key_id
            && !issuer.is_empty()
            && issuer.trim() == issuer
            && !issuer.ends_with('/')
            && self.issuer == issuer
            && self.public_jwk.kid == key_id.to_string()
            && self.public_jwk.r#use == KeyUse::Signature
            && self.public_jwk.alg == JwsAlgorithm::EdDSA
            && matches!(&self.public_jwk.params, JwkPublicParameters::Ec { crv, .. } if crv == "secp256k1")
            && self.approved_at.is_some_and(|approved| approved <= now)
            && self.revoked_at.is_none()
            && self.expires_at.is_none_or(|expires| expires > now)
    }

    /// Compare public material only. Issuance must also derive the public point from
    /// the local secret and validate it; caller-supplied JWK coordinates are not proof.
    pub fn matches_local_public_material(&self, private: Option<&JwkPrivate>) -> bool {
        private.is_some_and(|private| {
            matches!(private.params, JwkPrivateParameters::Ec { .. })
                && JwkPublic::from(private.clone()) == self.public_jwk
        })
    }
}

/// Subject binding is resolved independently of the IdP member's signer key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenPrincipalBinding {
    pub entity_type: EntityType,
    pub entity_id: Id,
    pub key_id: Id,
}

impl TokenPrincipalBinding {
    /// The caller must also resolve a live User/Client and its current active root.
    pub fn matches_active_root(&self, root: &Key, now: i64) -> bool {
        self.key_id == root.id
            && self.entity_type == root.entity_type
            && self.entity_id == root.entity_id
            && root.parent_id.is_none()
            && root.revoked_at.is_none()
            && root
                .expires_at
                .is_none_or(|expires| expires.timestamp() > now)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;

    use super::{IdpSignerRecord, TokenPrincipalBinding};
    use crate::{
        contract::{
            EntityType, JwkPrivate, JwkPrivateParameters, JwkPublic, JwkPublicParameters,
            JwsAlgorithm, KeyUse,
        },
        model::{Id, Key},
    };

    fn signer() -> IdpSignerRecord {
        let key_id = Id::from_u128(1);
        IdpSignerRecord {
            member_id: Id::from_u128(2),
            key_id,
            issuer: "https://installation.example".to_string(),
            public_jwk: JwkPublic {
                kid: key_id.to_string(),
                r#use: KeyUse::Signature,
                alg: JwsAlgorithm::EdDSA,
                params: JwkPublicParameters::Ec {
                    crv: "secp256k1".to_string(),
                    x: "not-a-point".to_string(),
                    y: "not-a-point".to_string(),
                },
            },
            approved_at: Some(10),
            revoked_at: None,
            expires_at: Some(30),
        }
    }

    #[test]
    fn signer_contract_requires_explicit_approval_and_exact_issuer_binding() {
        let record = signer();
        let valid = |record: &IdpSignerRecord| {
            record.matches(
                record.member_id,
                record.key_id,
                "https://installation.example",
                20,
            )
        };
        assert!(valid(&record));
        assert!(!record.matches(Id::from_u128(3), record.key_id, &record.issuer, 20));
        assert!(!record.matches(record.member_id, Id::from_u128(3), &record.issuer, 20));
        for issuer in [
            "",
            "https://listener.example",
            "https://installation.example/",
            " https://installation.example",
        ] {
            assert!(!record.matches(record.member_id, record.key_id, issuer, 20));
        }
        assert!(!record.matches(record.member_id, record.key_id, &record.issuer, 30));
        let mut pending = record.clone();
        pending.approved_at = None;
        assert!(!valid(&pending));
        pending.approved_at = Some(21);
        assert!(!valid(&pending));
        pending.approved_at = Some(10);
        pending.public_jwk.kid = Id::from_u128(3).to_string();
        assert!(!valid(&pending));
        pending.public_jwk = record.public_jwk.clone();
        pending.revoked_at = Some(20);
        assert!(!valid(&pending));
        assert!(!record.matches_local_public_material(None));
        let mut private = JwkPrivate {
            kid: record.key_id.to_string(),
            r#use: KeyUse::Signature,
            alg: JwsAlgorithm::EdDSA,
            params: JwkPrivateParameters::Ec {
                crv: "secp256k1".to_string(),
                x: "not-a-point".to_string(),
                y: "not-a-point".to_string(),
                d: "local-only".to_string(),
            },
        };
        assert!(record.matches_local_public_material(Some(&private)));
        private.kid = Id::from_u128(3).to_string();
        assert!(!record.matches_local_public_material(Some(&private)));
        private.params = JwkPrivateParameters::Oct {
            k: "unsupported".to_string(),
        };
        assert!(!record.matches_local_public_material(Some(&private)));
    }

    #[test]
    fn signer_contract_keeps_subject_and_signer_independent() {
        let record = signer();
        let now = chrono::DateTime::from_timestamp(20, 0).expect("valid test time");
        let mut root = Key {
            id: Id::from_u128(3),
            parent_id: None,
            entity_type: EntityType::User,
            entity_id: Id::from_u128(4),
            derivation_path: "m/0'".to_string(),
            derivation_index: 0,
            name: "subject".to_string(),
            hardened: true,
            public_jwk: None,
            revoked_at: None,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };
        let binding = TokenPrincipalBinding {
            entity_type: root.entity_type,
            entity_id: root.entity_id,
            key_id: root.id,
        };
        assert_ne!(binding.key_id, record.key_id);
        assert_ne!(binding.entity_id, record.member_id);
        assert!(binding.matches_active_root(&root, 20));
        root.entity_type = EntityType::Client;
        assert!(!binding.matches_active_root(&root, 20));
        root.entity_type = EntityType::User;
        root.entity_id = record.member_id;
        assert!(!binding.matches_active_root(&root, 20));
        root.entity_id = binding.entity_id;
        root.revoked_at = Some(now);
        assert!(!binding.matches_active_root(&root, 20));
    }
}
