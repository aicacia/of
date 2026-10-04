#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

use crate::contract::JwkPublic;

use super::{JwkPrivateParameters, JwsAlgorithm, KeyUse};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct JwkPrivate {
    /// Key use (sig, enc)
    #[serde(rename = "use")]
    pub r#use: KeyUse,

    pub kid: String,

    /// Algorithm intended for use
    pub alg: JwsAlgorithm,

    #[serde(flatten)]
    pub params: JwkPrivateParameters,
}

impl From<JwkPrivate> for JwkPublic {
    fn from(val: JwkPrivate) -> Self {
        JwkPublic {
            r#use: val.r#use,
            kid: val.kid,
            alg: val.alg,
            params: val.params.into(),
        }
    }
}
