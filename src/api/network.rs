//! Linux networking endpoints: bridges and VLANs.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::network::{Bridge, CreateBridgeRequest, CreateVlanRequest, Vlan};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/network/bridges", get(list_bridges).post(create_bridge))
        .route("/network/vlans", get(list_vlans).post(create_vlan))
}

async fn list_bridges(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<Bridge>>> {
    user.require(Permission::NetworkRead)?;
    Ok(Json(state.services.network.list_bridges().await?))
}

async fn create_bridge(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateBridgeRequest>,
) -> ApiResult<(StatusCode, Json<Bridge>)> {
    user.require(Permission::NetworkWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let bridge = operations
        .run(
            "network.create_bridge",
            Some("bridge"),
            None,
            move || async move { operation_services.network.create_bridge(req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(bridge)))
}

async fn list_vlans(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<Vlan>>> {
    user.require(Permission::NetworkRead)?;
    Ok(Json(state.services.network.list_vlans().await?))
}

async fn create_vlan(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateVlanRequest>,
) -> ApiResult<(StatusCode, Json<Vlan>)> {
    user.require(Permission::NetworkWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let vlan = operations
        .run(
            "network.create_vlan",
            Some("vlan"),
            None,
            move || async move { operation_services.network.create_vlan(req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(vlan)))
}
