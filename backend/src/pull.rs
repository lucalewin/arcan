use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use base64::prelude::*;
use shared::{ItemPull, PullRequest, PullResponse, VaultPull};
use std::collections::HashMap;

use crate::{AppStateRef, middleware::Session};

pub async fn sync_pull_handler(
    State(app): State<AppStateRef>,
    Session(user_id): Session,
    Json(payload): Json<PullRequest>,
) -> Result<Json<PullResponse>, StatusCode> {
    // 1. Authoritative check: Get all vaults this user owns
    let owned_vaults = sqlx::query!(
        "SELECT id, next_revision FROM vaults WHERE user_id = $1",
        user_id
    )
    .fetch_all(&app.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if owned_vaults.is_empty() {
        return Ok(Json(PullResponse {
            current_revisions: HashMap::new(),
            vaults: vec![],
            items: vec![],
        }));
    }

    // 2. Build parallel arrays for the UNNEST query
    let mut vault_ids = Vec::with_capacity(owned_vaults.len());
    let mut requested_revs = Vec::with_capacity(owned_vaults.len());
    let mut current_revisions = HashMap::with_capacity(owned_vaults.len());

    for v in owned_vaults {
        // If the client doesn't know about this vault, treat requested revision as 0
        let req_rev = payload.vault_revisions.get(&v.id).copied().unwrap_or(0);

        vault_ids.push(v.id);
        requested_revs.push(req_rev);
        // The highest server_revision a vault's items can currently have is next_revision - 1
        current_revisions.insert(v.id, v.next_revision - 1);
    }

    // 3. Fetch changed vaults
    let updated_vaults = sqlx::query!(
        r#"
        SELECT v.id, v.server_revision, v.is_deleted, v.encrypted_name, v.encrypted_vsk, v.created_at, v.updated_at
        FROM vaults v
        JOIN UNNEST($1::uuid[], $2::bigint[]) AS req(id, rev) ON v.id = req.id
        WHERE v.server_revision > req.rev AND v.user_id = $3
        "#,
        &vault_ids,
        &requested_revs,
        user_id
    )
    .fetch_all(&app.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let vaults = updated_vaults
        .into_iter()
        .map(|v| VaultPull {
            id: v.id,
            server_revision: v.server_revision,
            is_deleted: v.is_deleted,
            encrypted_name: BASE64_STANDARD.encode(&v.encrypted_name),
            encrypted_vsk: BASE64_STANDARD.encode(&v.encrypted_vsk),
            created_at: v.created_at.unix_timestamp(),
            updated_at: v.updated_at.unix_timestamp(),
        })
        .collect();

    // 4. Fetch changed items
    let updated_items = sqlx::query!(
        r#"
        SELECT i.id, i.vault_id, i.server_revision, i.is_deleted, i.encrypted_payload, i.created_at, i.updated_at
        FROM items i
        JOIN UNNEST($1::uuid[], $2::bigint[]) AS req(id, rev) ON i.vault_id = req.id
        WHERE i.server_revision > req.rev
        "#,
        &vault_ids,
        &requested_revs
    )
    .fetch_all(&app.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let items = updated_items
        .into_iter()
        .map(|i| ItemPull {
            id: i.id,
            vault_id: i.vault_id,
            server_revision: i.server_revision,
            is_deleted: i.is_deleted,
            // Strip the payload if the item is deleted to save bandwidth
            encrypted_payload: if i.is_deleted {
                None
            } else {
                Some(BASE64_STANDARD.encode(&i.encrypted_payload))
            },
            created_at: i.created_at.unix_timestamp(),
            updated_at: i.updated_at.unix_timestamp(),
        })
        .collect();

    Ok(Json(PullResponse {
        current_revisions,
        vaults,
        items,
    }))
}
