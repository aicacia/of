#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum JwsAlgorithm {
    #[serde(rename = "RS256")]
    RS256,
    #[serde(rename = "RS384")]
    RS384,
    #[serde(rename = "RS512")]
    RS512,
    #[serde(rename = "ES256")]
    ES256,
    #[serde(rename = "ES256K")]
    ES256K,
    #[serde(rename = "ES384")]
    ES384,
    #[serde(rename = "ES512")]
    ES512,
    #[serde(rename = "PS256")]
    PS256,
    #[serde(rename = "PS384")]
    PS384,
    #[serde(rename = "PS512")]
    PS512,
    #[serde(rename = "EdDSA")]
    EdDSA,
}
