use axum::{Json, Router, routing::get};
use idp_model::contract::{SetupStage, SetupStatus};

pub fn router() -> Router {
    Router::new().route("/setup/status", get(status))
}

async fn status() -> Json<SetupStatus> {
    Json(SetupStatus {
        stage: SetupStage::Installation,
    })
}
