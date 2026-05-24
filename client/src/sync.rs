use base64::prelude::*;
use reqwest::Client;
use shared::{ItemPush, PullRequest, PullResponse, PushRequest, PushResponse, VaultPush};
use sqlx::SqlitePool;
use uuid::Uuid;

pub async fn push_local_changes(
    pool: &SqlitePool,
    http: &Client,
    jwt: &str,
    api_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Find unsynced vaults
    let local_vaults = sqlx::query!("SELECT * FROM vaults WHERE is_dirty = 1")
        .fetch_all(pool)
        .await?;

    let mut push_vaults = Vec::new();
    for v in local_vaults {
        push_vaults.push(VaultPush {
            id: Uuid::parse_str(&v.id)?,
            base_revision: v.server_revision,
            is_deleted: v.is_deleted != 0,
            encrypted_name: BASE64_STANDARD.encode(&v.encrypted_name),
            encrypted_vsk: BASE64_STANDARD.encode(&v.encrypted_vsk),
            created_at: v.created_at,
            updated_at: v.updated_at,
        });
    }

    // 2. Find unsynced items
    let local_items = sqlx::query!("SELECT * FROM items WHERE is_dirty = 1")
        .fetch_all(pool)
        .await?;

    let mut push_items = Vec::new();
    for i in local_items {
        push_items.push(ItemPush {
            id: Uuid::parse_str(&i.id)?,
            vault_id: Uuid::parse_str(&i.vault_id)?,
            base_revision: i.server_revision,
            is_deleted: i.is_deleted != 0,
            encrypted_payload: Some(BASE64_STANDARD.encode(&i.encrypted_payload)),
            created_at: i.created_at,
            updated_at: i.updated_at,
        });
    }

    if push_vaults.is_empty() && push_items.is_empty() {
        return Ok(()); // Nothing to push
    }

    // 3. Send Push Request
    let req_payload = PushRequest {
        vaults: push_vaults,
        items: push_items,
    };
    let res = http
        .post(format!("{}/api/v1/sync/push", api_url))
        .bearer_auth(jwt)
        .json(&req_payload)
        .send()
        .await?;

    let push_res: PushResponse = res.json().await?;

    if !push_res.conflicts.is_empty() {
        eprintln!(
            "Warning: Server reported conflicts for IDs: {:?}",
            push_res.conflicts
        );
        // Note: Real apps handle conflicts by pulling the server version and keeping the local as a duplicate.
    }

    // 4. Update local revisions based on server response
    for (id, new_rev) in push_res.accepted_revisions {
        let id_str = id.to_string();
        // Try updating vault first, if rows affected == 0, try item
        let v_res = sqlx::query!(
            "UPDATE vaults SET server_revision = ?1, is_dirty = 0 WHERE id = ?2",
            new_rev,
            id_str
        )
        .execute(pool)
        .await?;

        if v_res.rows_affected() == 0 {
            sqlx::query!(
                "UPDATE items SET server_revision = ?1, is_dirty = 0 WHERE id = ?2",
                new_rev,
                id_str
            )
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

pub async fn pull_remote_changes(
    pool: &SqlitePool,
    http: &Client,
    jwt: &str,
    api_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Calculate local high-water marks for each vault
    // This clever query unions the max revision of the vault row and its item rows
    let high_water_marks = sqlx::query!(
        r#"
        SELECT vault_id, MAX(rev) as max_rev FROM (
            SELECT id as vault_id, server_revision as rev FROM vaults
            UNION ALL
            SELECT vault_id, server_revision as rev FROM items
        )
        GROUP BY vault_id
        "#
    )
    .fetch_all(pool)
    .await?;

    let mut vault_revisions = std::collections::HashMap::new();
    for row in high_water_marks {
        if let Ok(uuid) = Uuid::parse_str(&row.vault_id.unwrap()) {
            vault_revisions.insert(uuid, row.max_rev);
        }
    }

    // 2. Request updates from server
    let res = http
        .post(format!("{}/api/v1/sync/pull", api_url))
        .bearer_auth(jwt)
        .json(&PullRequest { vault_revisions })
        .send()
        .await?;

    let pull_res: PullResponse = res.json().await?;

    // 3. Upsert Vaults
    for v in pull_res.vaults {
        let name_bytes = BASE64_STANDARD.decode(&v.encrypted_name)?;
        let vsk_bytes = BASE64_STANDARD.decode(&v.encrypted_vsk)?;
        let id_str = v.id.to_string();
        let is_del = if v.is_deleted { 1 } else { 0 };

        sqlx::query!(
            r#"
            INSERT INTO vaults (id, encrypted_name, encrypted_vsk, server_revision, is_deleted, is_dirty, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)
            ON CONFLICT(id) DO UPDATE SET
                encrypted_name = excluded.encrypted_name,
                encrypted_vsk = excluded.encrypted_vsk,
                server_revision = excluded.server_revision,
                is_deleted = excluded.is_deleted,
                updated_at = excluded.updated_at
            "#,
            id_str, name_bytes, vsk_bytes, v.server_revision, is_del, v.created_at, v.updated_at
        )
        .execute(pool)
        .await?;
    }

    // 4. Upsert Items
    for i in pull_res.items {
        // If an item is deleted, the server might send None for the payload to save bandwidth.
        // If so, just create an empty byte array for the local database to satisfy the NOT NULL constraint.
        let payload_bytes = match i.encrypted_payload {
            Some(p) => BASE64_STANDARD.decode(&p)?,
            None => Vec::new(),
        };

        let id_str = i.id.to_string();
        let vault_id_str = i.vault_id.to_string();
        let is_del = if i.is_deleted { 1 } else { 0 };

        sqlx::query!(
            r#"
            INSERT INTO items (id, vault_id, encrypted_payload, server_revision, is_deleted, is_dirty, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)
            ON CONFLICT(id) DO UPDATE SET
                encrypted_payload = excluded.encrypted_payload,
                server_revision = excluded.server_revision,
                is_deleted = excluded.is_deleted,
                updated_at = excluded.updated_at
            "#,
            id_str, vault_id_str, payload_bytes, i.server_revision, is_del, i.created_at, i.updated_at
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}
