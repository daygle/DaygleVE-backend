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
    let broker_enabled: bool = {
        #[cfg(unix)]
        {
            match std::env::var_os("DAYGLEVE_BROKER_SOCKET")
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from)
            {
                Some(path) => crate::broker::client::BrokerClient::new(path)
                    .ping()
                    .await
                    .is_ok(),
                None => false,
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let inventory = if broker_enabled {
        let mut inventory = BrokerSplitInventory::current(crate::services::now_ts());
        inventory.current_execution = daygleve_schema::broker::HostExecution::Broker;
        inventory.broker_split_incomplete = false;
        inventory.note = Some(
            "Privileged host requests are configured to use the root-owned broker; real-host systemd/AppArmor validation remains required.".to_string(),
        );
        for subsystem in &mut inventory.subsystems {
            subsystem.mode = daygleve_schema::broker::BrokerMode::Delegated;
            subsystem.execution = daygleve_schema::broker::HostExecution::Broker;
            subsystem.current_actions.clear();
        }
        inventory
    } else {
        BrokerSplitInventory::current(crate::services::now_ts())
    };
    Ok(Json(inventory))
}
