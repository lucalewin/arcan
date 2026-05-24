use crate::state::ClientState;
use base64::prelude::*;
use chacha20poly1305::aead::OsRng;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use reqwest::Client;
use shared::{
    DefaultCipherSuite, ItemPush, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PullRequest, PullResponse, PushRequest, PushResponse, VaultPush,
};
use sqlx::SqlitePool;
use uuid::Uuid;

const API_BASE: &str = "http://127.0.0.1:3000/api/v1";

pub fn login_client_start(
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password) {
        Ok(login) => Ok((
            login.state.serialize().to_vec(),
            login.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn login_client_finish(
    password: &[u8],
    client_start: &[u8],
    server_start: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client_state = ClientLogin::<DefaultCipherSuite>::deserialize(client_start)?;
    let credential_response = CredentialResponse::deserialize(server_start)?;

    let result = client_state.finish(
        &mut OsRng,
        password,
        credential_response,
        ClientLoginFinishParameters::default(),
    )?;

    Ok(result.message.serialize().to_vec())
}

pub async fn authenticate(
    pool: &SqlitePool,
    auth_key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let state = ClientState::get(pool).await?;
    let client = Client::new();

    // 1. OPAQUE Client Start
    // You will need to wrap the opaque_ke client logic in your shared crate
    let (opaque_client_state, client_start_bytes) = login_client_start(auth_key)?;

    let start_res = client
        .post(format!("{}/auth/login/start", API_BASE))
        .json(&LoginStartRequest {
            email: state.email.clone(),
            client_start: BASE64_STANDARD.encode(client_start_bytes),
        })
        .send()
        .await?;

    let start_data: LoginStartResponse = start_res.json().await?;
    let server_start_bytes = BASE64_STANDARD.decode(&start_data.message)?;

    // 2. OPAQUE Client Finish
    let client_finish_bytes =
        login_client_finish(auth_key, &opaque_client_state, &server_start_bytes)?;

    let finish_res = client
        .post(format!("{}/auth/login/finish", API_BASE))
        .json(&LoginFinishRequest {
            email: state.email,
            attempt_id: start_data.attempt_id,
            client_finish: BASE64_STANDARD.encode(client_finish_bytes),
        })
        .send()
        .await?;

    let finish_data: LoginFinishResponse = finish_res.json().await?;

    // Return the JWT
    Ok(finish_data.access_token)
}

pub async fn push_local_changes(
    pool: &SqlitePool,
    http: &Client,
    jwt: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Find unsynced vaults
    let local_vaults = sqlx::query!("SELECT * FROM vaults WHERE server_revision = 0")
        .fetch_all(pool)
        .await?;

    let mut push_vaults = Vec::new();
    for v in local_vaults {
        push_vaults.push(VaultPush {
            id: Uuid::parse_str(&v.id)?,
            base_revision: 0, // Using 0 for new creations
            is_deleted: v.is_deleted != 0,
            encrypted_name: BASE64_STANDARD.encode(&v.encrypted_name),
            encrypted_vsk: BASE64_STANDARD.encode(&v.encrypted_vsk),
            created_at: v.created_at,
            updated_at: v.updated_at,
        });
    }

    // 2. Find unsynced items
    let local_items = sqlx::query!("SELECT * FROM items WHERE server_revision = 0")
        .fetch_all(pool)
        .await?;

    let mut push_items = Vec::new();
    for i in local_items {
        push_items.push(ItemPush {
            id: Uuid::parse_str(&i.id)?,
            vault_id: Uuid::parse_str(&i.vault_id)?,
            base_revision: 0,
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
        .post(format!("{}/sync/push", API_BASE))
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
            "UPDATE vaults SET server_revision = $1 WHERE id = $2",
            new_rev,
            id_str
        )
        .execute(pool)
        .await?;

        if v_res.rows_affected() == 0 {
            sqlx::query!(
                "UPDATE items SET server_revision = $1 WHERE id = $2",
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
        .post(format!("{}/sync/pull", API_BASE))
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
            INSERT INTO vaults (id, encrypted_name, encrypted_vsk, server_revision, is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
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
            INSERT INTO items (id, vault_id, encrypted_payload, server_revision, is_deleted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
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
