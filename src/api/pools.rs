//! Resource pool endpoints: CRUD over pools plus their resolved membership.
//!
//! Pools are metadata (see [`crate::services::pool`]); membership lives on the
//! guests, so member listing and the "pool not empty" delete guard are computed
//! here by scanning VMs and containers — the API layer is where both guest
//! services are reachable.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::pool::{
    CreateResourcePoolRequest, PoolMember, PoolMemberKind, ResourcePool, ResourcePoolDetail,
    ResourcePoolSummary, UpdateResourcePoolRequest,
};

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

/// Guard a guest's requested pool assignment: a non-empty pool reference must
/// name an existing pool. An empty or absent value (no pool / clear) is fine.
/// Called by the VM and container create/update handlers before they persist.
pub(crate) async fn ensure_pool_assignment(
    state: &AppState,
    pool: &Option<String>,
) -> ApiResult<()> {
    if let Some(name) = pool {
        if !name.trim().is_empty() {
            state.services.pools.ensure_exists(name).await?;
        }
    }
    Ok(())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/pools", get(list).post(create))
        .route("/pools/{id}", get(detail).patch(update).delete(delete))
}

/// Resolve the guests currently assigned to `pool_name` by scanning VM and
/// container summaries.
async fn members_of(state: &AppState, pool_name: &str) -> ApiResult<Vec<PoolMember>> {
    let mut members = Vec::new();
    for vm in state.services.kvm.list().await? {
        if vm.pool.as_deref() == Some(pool_name) {
            members.push(PoolMember {
                kind: PoolMemberKind::Vm,
                id: vm.id,
                name: vm.name,
            });
        }
    }
    for ct in state.services.lxc.list().await? {
        if ct.pool.as_deref() == Some(pool_name) {
            members.push(PoolMember {
                kind: PoolMemberKind::Lxc,
                id: ct.id,
                name: ct.name,
            });
        }
    }
    Ok(members)
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ResourcePoolSummary>>> {
    user.require(Permission::PoolRead)?;
    let pools = state.services.pools.list().await?;
    let mut out = Vec::with_capacity(pools.len());
    for pool in pools {
        let member_count = members_of(&state, &pool.name).await?.len() as u32;
        out.push(ResourcePoolSummary {
            id: pool.id,
            name: pool.name,
            comment: pool.comment,
            member_count,
            created_at: pool.created_at,
        });
    }
    Ok(Json(out))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateResourcePoolRequest>,
) -> ApiResult<(StatusCode, Json<ResourcePool>)> {
    user.require(Permission::PoolWrite)?;
    let created = state.services.pools.create(req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn detail(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ResourcePoolDetail>> {
    user.require(Permission::PoolRead)?;
    let pool = state.services.pools.get(&id).await?;
    let members = members_of(&state, &pool.name).await?;
    Ok(Json(ResourcePoolDetail { pool, members }))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateResourcePoolRequest>,
) -> ApiResult<Json<ResourcePool>> {
    user.require(Permission::PoolWrite)?;
    Ok(Json(state.services.pools.update(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::PoolWrite)?;
    let pool = state.services.pools.get(&id).await?;
    let members = members_of(&state, &pool.name).await?;
    if !members.is_empty() {
        return Err(AppError::conflict(format!(
            "resource pool {:?} still has {} member(s); reassign or remove them first",
            pool.name,
            members.len()
        )));
    }
    state.services.pools.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
