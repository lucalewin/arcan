use base64::{Engine, prelude::BASE64_STANDARD};
use shared::{ItemPush, PushRequest, PushResponse, VaultPush};
use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{AppStateRef, middleware::Session};

trait DecodeVault {
    fn decode(&self) -> Result<(Vec<u8>, Vec<u8>, OffsetDateTime, OffsetDateTime), StatusCode>;
}

impl DecodeVault for VaultPush {
    fn decode(&self) -> Result<(Vec<u8>, Vec<u8>, OffsetDateTime, OffsetDateTime), StatusCode> {
        let name = BASE64_STANDARD
            .decode(&self.encrypted_name)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let vsk = BASE64_STANDARD
            .decode(&self.encrypted_vsk)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let created = OffsetDateTime::from_unix_timestamp(self.created_at)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let updated = OffsetDateTime::from_unix_timestamp(self.updated_at)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        Ok((name, vsk, created, updated))
    }
}

trait DecodeItem {
    fn decode(&self) -> Result<(Vec<u8>, OffsetDateTime, OffsetDateTime), StatusCode>;
}

impl DecodeItem for ItemPush {
    fn decode(&self) -> Result<(Vec<u8>, OffsetDateTime, OffsetDateTime), StatusCode> {
        let payload = match &self.encrypted_payload {
            Some(p) => BASE64_STANDARD
                .decode(p)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
            None => Vec::new(),
        };
        let created = OffsetDateTime::from_unix_timestamp(self.created_at)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let updated = OffsetDateTime::from_unix_timestamp(self.updated_at)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        Ok((payload, created, updated))
    }
}

async fn lock_involved_vaults(
    tx: &mut Transaction<'_, Postgres>,
    payload: &PushRequest,
    user_id: Uuid,
) -> Result<HashMap<Uuid, i64>, StatusCode> {
    let mut involved = payload.vaults.iter().map(|v| v.id).collect::<Vec<_>>();
    involved.extend(payload.items.iter().map(|i| i.vault_id));
    involved.sort();
    involved.dedup();

    let mut state = HashMap::new();
    for v_id in involved {
        if let Some(r) = sqlx::query!(
            "SELECT next_revision FROM vaults WHERE id = $1 AND user_id = $2 FOR UPDATE",
            v_id,
            user_id
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            state.insert(v_id, r.next_revision);
        }
    }
    Ok(state)
}

pub async fn sync_push_handler(
    State(app): State<AppStateRef>,
    Session(user_id): Session,
    Json(payload): Json<PushRequest>,
) -> Result<(StatusCode, Json<PushResponse>), StatusCode> {
    let mut tx = app
        .pool
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut conflicts = Vec::new();
    let mut accepted = HashMap::new();

    // 1. Lock vaults
    let mut vault_state = lock_involved_vaults(&mut tx, &payload, user_id).await?;

    // 2. Process Vaults
    for vault in payload.vaults {
        let (name, vsk, created, updated) = vault.decode()?;

        if vault.base_revision == 0 {
            sqlx::query!(
                "INSERT INTO vaults (id, user_id, encrypted_name, encrypted_vsk, is_deleted, server_revision, next_revision, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 1, 2, $6, $7)",
                vault.id, user_id, name, vsk, vault.is_deleted, created, updated
            ).execute(&mut *tx).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            vault_state.insert(vault.id, 2);
            accepted.insert(vault.id, 1);
        } else {
            let current_rev = sqlx::query_scalar!(
                "SELECT server_revision FROM vaults WHERE id = $1 AND user_id = $2",
                vault.id,
                user_id
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if current_rev.is_none() || vault.base_revision < current_rev.unwrap() {
                conflicts.push(vault.id);
                continue;
            }

            let new_rev = *vault_state.get(&vault.id).unwrap();
            sqlx::query!(
                "UPDATE vaults SET encrypted_name = $1, encrypted_vsk = $2, is_deleted = $3, server_revision = $4, next_revision = $5, updated_at = $6 WHERE id = $7",
                name, vsk, vault.is_deleted, new_rev, new_rev + 1, updated, vault.id
            ).execute(&mut *tx).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            vault_state.insert(vault.id, new_rev + 1);
            accepted.insert(vault.id, new_rev);
        }
    }

    // 3. Process Items
    for item in payload.items {
        let Some(&vault_next_rev) = vault_state.get(&item.vault_id) else {
            conflicts.push(item.id);
            continue;
        };

        let (payload_bytes, created, updated) = item.decode()?;

        if item.base_revision == 0 {
            sqlx::query!(
                "INSERT INTO items (id, vault_id, encrypted_payload, is_deleted, server_revision, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                item.id, item.vault_id, payload_bytes, item.is_deleted, vault_next_rev, created, updated
            ).execute(&mut *tx).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            accepted.insert(item.id, vault_next_rev);
            vault_state.insert(item.vault_id, vault_next_rev + 1);
        } else {
            let current_rev = sqlx::query_scalar!(
                "SELECT server_revision FROM items WHERE id = $1 AND vault_id = $2",
                item.id,
                item.vault_id
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if current_rev.is_none() || item.base_revision < current_rev.unwrap() {
                conflicts.push(item.id);
                continue;
            }

            sqlx::query!(
                "UPDATE items SET encrypted_payload = $1, is_deleted = $2, server_revision = $3, updated_at = $4 WHERE id = $5 AND vault_id = $6",
                payload_bytes, item.is_deleted, vault_next_rev, updated, item.id, item.vault_id
            ).execute(&mut *tx).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            accepted.insert(item.id, vault_next_rev);
            vault_state.insert(item.vault_id, vault_next_rev + 1);
        }
    }

    // 4. Batch update vault timelines
    for (v_id, next_rev) in vault_state {
        sqlx::query!(
            "UPDATE vaults SET next_revision = $1 WHERE id = $2",
            next_rev,
            v_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // 5. Commit or Rollback
    if !conflicts.is_empty() {
        tx.rollback()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Ok((
            StatusCode::CONFLICT,
            Json(PushResponse {
                accepted_revisions: HashMap::new(),
                conflicts,
            }),
        ));
    }

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::OK,
        Json(PushResponse {
            accepted_revisions: accepted,
            conflicts: vec![],
        }),
    ))
}
