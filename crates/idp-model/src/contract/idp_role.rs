use serde::{Deserialize, Serialize};

/// Local operator designation, not device approval or replica enrollment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdpRole {
    Authority,
    Replica,
}
