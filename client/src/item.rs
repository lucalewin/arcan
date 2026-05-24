use sqlx::SqlitePool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{decrypt_payload, encrypt_payload, pack_payload, unpack_payload};

async fn get_decrypted_vsk(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // 1. Fetch the encrypted VSK from the database
    let vault = sqlx::query!(
        "SELECT encrypted_vsk FROM vaults WHERE id = $1 AND is_deleted = 0",
        vault_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or("Vault not found or deleted")?;

    // 2. Unpack and decrypt using the KEK
    let (nonce, ciphertext) = unpack_payload(&vault.encrypted_vsk)?;

    // Note: In vault creation, we used vault_id as the AAD for the VSK
    let vsk_bytes =
        decrypt_payload(kek, ciphertext, &nonce, vault_id).map_err(|_| "Failed to decrypt VSK.")?;

    let mut vsk = [0u8; 32];
    vsk.copy_from_slice(&vsk_bytes);
    Ok(vsk)
}

pub async fn handle_item_create(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: String,
    item_type: String,
    fields: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let item_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 1. Fetch and decrypt the VSK for this vault
    let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

    // 2. Build the JSON payload
    let mut payload_map = serde_json::Map::new();
    payload_map.insert("type".to_string(), serde_json::Value::String(item_type));

    for field in fields {
        if let Some((key, value)) = field.split_once('=') {
            payload_map.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }
    let payload_json = serde_json::Value::Object(payload_map).to_string();

    // 3. Encrypt the payload with the VSK (AAD = item_id)
    let (ciphertext, nonce) = encrypt_payload(&vsk, payload_json.as_bytes(), &item_id);
    let packed_payload = pack_payload(nonce, ciphertext);

    // 4. Save to DB
    sqlx::query!(
        "INSERT INTO items (id, vault_id, encrypted_payload, server_revision, is_deleted, created_at, updated_at)
         VALUES ($1, $2, $3, 0, 0, $4, $5)",
        item_id,
        vault_id,
        packed_payload,
        now,
        now
    )
    .execute(pool)
    .await?;

    println!("Item created successfully. ID: {}", item_id);
    Ok(())
}

pub async fn handle_item_list(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get the VSK once
    let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

    // 2. Fetch all active items in the vault
    let items = sqlx::query!(
        "SELECT id, encrypted_payload FROM items WHERE vault_id = $1 AND is_deleted = 0",
        vault_id
    )
    .fetch_all(pool)
    .await?;

    if items.is_empty() {
        println!("No items found in this vault.");
        return Ok(());
    }

    println!("{:<38} | {}", "ITEM ID", "IDENTIFIER");
    println!("{:-<38}-|-{:-<30}", "", "");

    for item in items {
        // 3. Decrypt the payload
        let (nonce, ciphertext) = unpack_payload(&item.encrypted_payload)?;
        let payload_bytes = decrypt_payload(&vsk, ciphertext, &nonce, &item.id)
            .map_err(|_| "Failed to decrypt item payload. Possible corrupted data.")?;

        let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

        // Attempt to find a sensible name to display (like a title or username)
        let identifier = payload_json
            .get("title")
            .or_else(|| payload_json.get("username"))
            .or_else(|| payload_json.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown Item");

        println!("{:<38} | {}", item.id, identifier);
    }

    Ok(())
}

pub async fn handle_item_view(
    pool: &SqlitePool,
    kek: &[u8; 32],
    item_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get the item and its vault_id
    let item = sqlx::query!(
        "SELECT vault_id, encrypted_payload FROM items WHERE id = $1 AND is_deleted = 0",
        item_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or("Item not found or deleted")?;

    // 2. Get the VSK for that vault
    let vsk = get_decrypted_vsk(pool, kek, &item.vault_id).await?;

    // 3. Decrypt the payload
    let (nonce, ciphertext) = unpack_payload(&item.encrypted_payload)?;
    let payload_bytes = decrypt_payload(&vsk, ciphertext, &nonce, &item_id)
        .map_err(|_| "Failed to decrypt item payload. Possible corrupted data.")?;

    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    // 4. Pretty print the JSON
    println!("Item ID: {}", item_id);
    println!("Vault ID: {}", item.vault_id);
    println!("--- Payload ---");
    println!("{}", serde_json::to_string_pretty(&payload_json)?);

    Ok(())
}

pub async fn handle_item_delete(
    pool: &SqlitePool,
    item_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let result = sqlx::query!(
        "UPDATE items SET is_deleted = 1, updated_at = $1 WHERE id = $2",
        now,
        item_id
    )
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        println!(
            "Item {} queued for deletion. Run `arcan sync` to push.",
            item_id
        );
    } else {
        println!("Item {} not found.", item_id);
    }

    Ok(())
}
