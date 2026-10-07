#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use model::contract::StandardClaims;
use serde::{Deserialize, Serialize};

use crate::{contract::UserInfo, model::Id};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "serde_json::Value")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct IdTokenClaims {
    #[serde(flatten)]
    pub standard_claims: StandardClaims,
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub principal_key_id: Id,
    #[serde(
        flatten,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_user_info"
    )]
    pub user_info: Option<UserInfo>,
}

fn serialize_user_info<S: serde::Serializer>(
    info: &Option<UserInfo>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut value = serde_json::to_value(info).map_err(serde::ser::Error::custom)?;
    if let Some(fields) = value.as_object_mut() {
        fields.remove("sub");
    }
    value.serialize(serializer)
}

impl TryFrom<serde_json::Value> for IdTokenClaims {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        #[derive(Deserialize)]
        struct BoundClaims {
            #[serde(flatten)]
            standard_claims: StandardClaims,
            principal_key_id: Id,
        }
        let bound: BoundClaims = serde_json::from_value(value.clone())?;
        let user_info = if value.get("updated_at").is_some() {
            Some(serde_json::from_value(value)?)
        } else {
            None
        };
        Ok(Self {
            standard_claims: bound.standard_claims,
            principal_key_id: bound.principal_key_id,
            user_info,
        })
    }
}
