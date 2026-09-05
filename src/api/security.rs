//! Security posture endpoints: the current broker split inventory.
//!
//! This is a read-only, authenticated view of the residual root-equivalent
//! surface documented in the service layer. It exists so the "the broker split
//! is not finished yet" state is machine-checkable rather than prose-only.

use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::broker::BrokerSplitInventory;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/system/broker-split", get(broker_split))
}

async fn broker_split(user: AuthUser) -> ApiResult<Json<BrokerSplitInventory>> {
    user.require(Permission::OperationsRead)?;
    Ok(Json(BrokerSplitInventory::current(
        crate::services::now_ts(),
    )))
}
