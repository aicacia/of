use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use db::NativeEngine;
use idp_model::contract::{DeviceState, SetupStage, SetupStatus};
use management_service::{DeviceRepo, replica::DbDeviceRepo};

#[derive(Clone)]
pub struct SetupState {
    pub database: Arc<NativeEngine>,
}

pub fn router(state: SetupState) -> Router {
    Router::new()
        .route("/setup/status", get(status))
        .with_state(state)
}

async fn status(State(state): State<SetupState>) -> Result<Json<SetupStatus>, StatusCode> {
    if state
        .database
        .table_names()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_empty()
    {
        return Ok(Json(SetupStatus {
            stage: SetupStage::Installation,
        }));
    }
    let devices = DbDeviceRepo::new(state.database);
    let devices = devices
        .list()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stage = if devices
        .iter()
        .any(|device| device.state == DeviceState::Approved)
    {
        SetupStage::Ready
    } else if devices.is_empty() {
        SetupStage::Installation
    } else {
        SetupStage::Device
    };
    Ok(Json(SetupStatus { stage }))
}
