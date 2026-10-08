mod middleware;
mod openapi;
mod openapi_router;
mod pairing_acceptance;
mod routes;

mod state;

pub use middleware::authorize_bearer;
pub(crate) use middleware::{authorize_bearer_any_principal, authorize_bearer_client};
pub use openapi_router::openapi_router;
pub use pairing_acceptance::{
    PairingAcceptanceController, PairingAcceptanceControllerSlot, TimedPairingAcceptanceController,
};

pub use state::{DeviceIdentity, RouterState};
