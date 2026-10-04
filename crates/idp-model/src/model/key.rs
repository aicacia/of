use core::str::FromStr;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use key::{DerivationPath, DerivedKey, KeyResult};

use super::Id;
use crate::contract::{
    EntityType, JwkPrivate, JwkPrivateParameters, JwkPublic, JwkPublicParameters, JwsAlgorithm,
    KeyUse,
};
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Key {
    pub id: Id,

    pub parent_id: Option<Id>,

    #[serde(with = "super::sql_enum::entity_type")]
    pub entity_type: EntityType,
    pub entity_id: Id,

    #[serde(deserialize_with = "super::none_to_default")]
    pub derivation_path: String,
    pub derivation_index: u32,
    pub name: String,
    pub hardened: bool,
    pub public_jwk: Option<JwkPublic>,

    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl Key {
    pub fn to_jwk_private(&self, derived_key: &DerivedKey) -> KeyResult<JwkPrivate> {
        let (x, y, d) = derived_key.to_xyd()?;

        let jwt = JwkPrivate {
            r#use: KeyUse::Signature,
            kid: self.id.to_string(),
            alg: JwsAlgorithm::EdDSA,
            params: JwkPrivateParameters::Ec {
                crv: "secp256k1".to_string(),
                x: STANDARD_NO_PAD.encode(x),
                y: STANDARD_NO_PAD.encode(y),
                d: STANDARD_NO_PAD.encode(d),
            },
        };

        Ok(jwt)
    }

    pub fn to_jwk_public(&self, derived_key: &DerivedKey) -> KeyResult<JwkPublic> {
        let (x, y) = derived_key.to_xy()?;

        let jwt = JwkPublic {
            r#use: KeyUse::Signature,
            kid: self.id.to_string(),
            alg: JwsAlgorithm::EdDSA,
            params: JwkPublicParameters::Ec {
                crv: "secp256k1".to_string(),
                x: STANDARD_NO_PAD.encode(x),
                y: STANDARD_NO_PAD.encode(y),
            },
        };

        Ok(jwt)
    }

    pub fn derivation_path(&self) -> KeyResult<DerivationPath> {
        let derivation_path = DerivationPath::from_str(&self.derivation_path)?;
        Ok(derivation_path)
    }

    #[must_use]
    pub fn build_derivation_path(
        parent_derivation_path: Option<&str>,
        derivation_index: u32,
        hardened: bool,
    ) -> String {
        let mut path = String::new();

        if let Some(parent_path) = parent_derivation_path {
            path.push_str(parent_path);
        } else {
            path.push('m');
        }

        if hardened {
            path.push_str(&format!("/{derivation_index}'"));
        } else {
            path.push_str(&format!("/{derivation_index}"));
        }

        path
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use key::DerivationPath;

    use super::Key;

    #[test]
    fn builds_valid_bip32_paths_from_sibling_indices() {
        let root = Key::build_derivation_path(None, 0, true);
        let child = Key::build_derivation_path(Some(&root), 1, false);

        assert_eq!(root, "m/0'");
        assert_eq!(child, "m/0'/1");
        assert_ne!(
            Key::build_derivation_path(None, 0, false),
            Key::build_derivation_path(None, 1, false)
        );
        DerivationPath::from_str(&child).unwrap();
    }
}
