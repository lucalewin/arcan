use sqlx::SqlitePool;
// use time::OffsetDateTime;

use crate::{
    crypto::{EncryptedPayload, decrypt_payload},
    items::envelop::{ItemEnvelope, ItemPayload},
};

pub async fn get_decrypted_vsk(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // 1. Fetch the encrypted VSK from the database
    let vault = sqlx::query!(
        "SELECT encrypted_vsk FROM vaults WHERE id = ?1 AND is_deleted = 0",
        vault_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or("Vault not found or deleted")?;

    // 2. Unpack and decrypt using the KEK
    let encrypted_payload = EncryptedPayload::unpack(&vault.encrypted_vsk)?;

    // Note: In vault creation, we used vault_id as the AAD for the VSK
    let vsk_bytes =
        decrypt_payload(kek, &encrypted_payload, vault_id).map_err(|_| "Failed to decrypt VSK.")?;

    if vsk_bytes.len() != 32 {
        return Err("Invalid VSK length after decryption".into());
    }

    let mut vsk = [0u8; 32];
    vsk.copy_from_slice(&vsk_bytes);
    Ok(vsk)
}

// pub async fn handle_item_create(
//     pool: &SqlitePool,
//     kek: &[u8; 32],
//     vault_id: String,
//     title: String,
//     tags: Vec<String>,
//     payload: crate::cli::CreateItemPayload,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let item_id = Uuid::new_v4().to_string();
//     let now = OffsetDateTime::now_utc().unix_timestamp();

//     // 1. Fetch and decrypt the VSK for this vault
//     let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

//     // 2. Build the JSON payload
//     let payload = match payload {
//         cli::CreateItemPayload::Login {
//             username,
//             password,
//             url,
//         } => ItemPayload::Login(LoginItem {
//             username,
//             password,
//             url,
//         }),
//         cli::CreateItemPayload::Note { content } => ItemPayload::Note(NoteItem { content }),
//         cli::CreateItemPayload::Totp {
//             secret,
//             account_name,
//         } => ItemPayload::Totp(TotpItem {
//             secret,
//             account_name,
//             issuer: None,
//         }),
//         cli::CreateItemPayload::Card {
//             cardholder,
//             number,
//             exp_month,
//             exp_year,
//             cvv,
//         } => ItemPayload::Card(CardItem {
//             cardholder_name: cardholder,
//             number,
//             exp_month,
//             exp_year,
//             cvv,
//         }),
//     };

//     // 3. Wrap it in the Envelope
//     let envelope = ItemEnvelope {
//         title,
//         tags: tags.into_iter().filter(|t| !t.is_empty()).collect(),
//         payload,
//     };

//     // 4. Serialize and Encrypt
//     let payload_json = serde_json::to_string(&envelope)?;
//     let packed_payload = encrypt_payload(&vsk, payload_json.as_bytes(), &item_id)?.pack();

//     // 4. Save to DB
//     sqlx::query!(
//         "INSERT INTO items (id, vault_id, encrypted_payload, server_revision, is_deleted, is_dirty, created_at, updated_at)
//          VALUES (?1, ?2, ?3, 0, 0, 1, ?4, ?5)",
//         item_id,
//         vault_id,
//         packed_payload,
//         now,
//         now
//     )
//     .execute(pool)
//     .await?;

//     println!("Item created successfully. ID: {}", item_id);
//     Ok(())
// }

pub async fn handle_item_list(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get the VSK once
    let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

    // 2. Fetch all active items in the vault
    let items = sqlx::query!(
        "SELECT id, encrypted_payload FROM items WHERE vault_id = ?1 AND is_deleted = 0",
        vault_id
    )
    .fetch_all(pool)
    .await?;

    if items.is_empty() {
        println!("No items found in this vault.");
        return Ok(());
    }

    println!("{:<38} | {:<15} | {}", "ITEM ID", "TYPE", "IDENTIFIER");
    println!("{:-<38}-|-{:-<15}-|-{:-<30}", "", "", "");

    for item in items {
        // 3. Decrypt the payload
        let encrypted_payload = EncryptedPayload::unpack(&item.encrypted_payload)?;
        let payload_bytes = decrypt_payload(&vsk, &encrypted_payload, &item.id)
            .map_err(|_| "Failed to decrypt item payload. Possible corrupted data.")?;

        let envelope: ItemEnvelope = serde_json::from_slice(&payload_bytes)?;

        let item_type_str = match envelope.payload {
            ItemPayload::Login(_) => "Login",
            ItemPayload::SshKey(_) => "SSH Key",
            ItemPayload::Totp(_) => "TOTP",
            ItemPayload::Note(_) => "Note",
            ItemPayload::Card(_) => "Card",
        };

        println!(
            "{:<38} | {:<15} | {}",
            item.id, item_type_str, envelope.title
        );
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
        "SELECT vault_id, encrypted_payload FROM items WHERE id = ?1 AND is_deleted = 0",
        item_id
    )
    .fetch_optional(pool)
    .await?
    .ok_or("Item not found or deleted")?;

    // 2. Get the VSK for that vault
    let vsk = get_decrypted_vsk(pool, kek, &item.vault_id).await?;

    // 3. Decrypt the payload
    let encrypted_payload = EncryptedPayload::unpack(&item.encrypted_payload)?;
    let payload_bytes = decrypt_payload(&vsk, &encrypted_payload, &item_id)
        .map_err(|_| "Failed to decrypt item payload. Possible corrupted data.")?;

    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    // 4. Pretty print the JSON
    println!("Item ID: {}", item_id);
    println!("Vault ID: {}", item.vault_id);
    println!("--- Payload ---");
    println!("{}", serde_json::to_string_pretty(&payload_json)?);

    Ok(())
}

// pub async fn handle_item_delete(
//     pool: &SqlitePool,
//     item_id: String,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let now = OffsetDateTime::now_utc().unix_timestamp();

//     let result = sqlx::query!(
//         "UPDATE items SET is_deleted = 1, is_dirty = 1, updated_at = ?1 WHERE id = ?2",
//         now,
//         item_id
//     )
//     .execute(pool)
//     .await?;

//     if result.rows_affected() > 0 {
//         println!(
//             "Item {} queued for deletion. Run `arcan sync` to push.",
//             item_id
//         );
//     } else {
//         println!("Item {} not found.", item_id);
//     }

//     Ok(())
// }
