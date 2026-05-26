use inquire::Select;
use sqlx::SqlitePool;
use std::io::IsTerminal;
use uuid::Uuid;

use crate::{
    crypto::{EncryptedPayload, decrypt_payload},
    items::{envelop::ItemEnvelope, handlers::get_decrypted_vsk},
};

pub async fn resolve_vault(
    pool: &SqlitePool,
    kek: &[u8; 32],
    provided_vault: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Fetch all vaults (we need them either for name matching or the TUI)
    let vaults =
        sqlx::query!("SELECT id, encrypted_name, encrypted_vsk FROM vaults WHERE is_deleted = 0")
            .fetch_all(pool)
            .await?;

    if vaults.is_empty() {
        return Err("No vaults found.".into());
    }

    match provided_vault {
        Some(input) => {
            // Check if it's already a valid UUID
            if Uuid::parse_str(&input).is_ok() {
                return Ok(input);
            }

            // It's not a UUID, so treat it as an exact name search
            for v in vaults {
                let vsk_payload = EncryptedPayload::unpack(&v.encrypted_vsk)?;
                let vsk_bytes = decrypt_payload(kek, &vsk_payload, &v.id)
                    .map_err(|_| "Failed to decrypt VSK.")?;

                let mut vsk = [0u8; 32];
                vsk.copy_from_slice(&vsk_bytes);

                let name_payload = EncryptedPayload::unpack(&v.encrypted_name)?;
                let name_bytes = decrypt_payload(&vsk, &name_payload, &v.id)
                    .map_err(|_| "Failed to decrypt vault name.")?;

                if String::from_utf8(name_bytes)? == input {
                    return Ok(v.id);
                }
            }
            Err(format!("No vault found with the name '{}'", input).into())
        }
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(
                    "Non-TTY environment detected. You must provide the --vault argument.".into(),
                );
            }

            let mut options = Vec::new();
            let mut id_map = std::collections::HashMap::new();

            for v in vaults {
                // Decrypt exactly as above to get the name...
                let vsk_payload = EncryptedPayload::unpack(&v.encrypted_vsk)?;
                let vsk_bytes = decrypt_payload(kek, &vsk_payload, &v.id)
                    .map_err(|_| "Failed to decrypt VSK.")?;

                let mut vsk = [0u8; 32];
                vsk.copy_from_slice(&vsk_bytes);

                let name_payload = EncryptedPayload::unpack(&v.encrypted_name)?;
                let name_bytes = decrypt_payload(&vsk, &name_payload, &v.id)
                    .map_err(|_| "Failed to decrypt vault name.")?;
                let name = String::from_utf8(name_bytes)?;

                options.push(name.clone());
                id_map.insert(name, v.id);
            }

            let ans = Select::new("Select a Vault:", options).prompt()?;
            Ok(id_map.get(&ans).unwrap().to_string())
        }
    }
}

pub async fn resolve_item(
    pool: &SqlitePool,
    vsk: &[u8; 32],
    vault_id: &str,
    provided_item: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let items = sqlx::query!(
        "SELECT id, encrypted_payload FROM items WHERE vault_id = $1 AND is_deleted = 0",
        vault_id
    )
    .fetch_all(pool)
    .await?;

    if items.is_empty() {
        return Err("No items found in this vault.".into());
    }

    match provided_item {
        Some(input) => {
            if Uuid::parse_str(&input).is_ok() {
                return Ok(input);
            }

            for item in items {
                let enc_payload = EncryptedPayload::unpack(&item.encrypted_payload)?;
                let payload_bytes = decrypt_payload(vsk, &enc_payload, &item.id)
                    .map_err(|_| "Failed to decrypt item payload.")?;
                let envelope: ItemEnvelope = serde_json::from_slice(&payload_bytes)?;

                if envelope.title == input {
                    return Ok(item.id);
                }
            }
            Err(format!("No item found with the title '{}' in this vault.", input).into())
        }
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(
                    "Non-TTY environment detected. You must provide the --item argument.".into(),
                );
            }

            let mut options = Vec::new();
            let mut id_map = std::collections::HashMap::new();

            for item in items {
                let enc_payload = EncryptedPayload::unpack(&item.encrypted_payload)?;
                let payload_bytes = decrypt_payload(vsk, &enc_payload, &item.id)
                    .map_err(|_| "Failed to decrypt item payload.")?;
                let envelope: ItemEnvelope = serde_json::from_slice(&payload_bytes)?;

                options.push(envelope.title.clone());
                id_map.insert(envelope.title, item.id);
                // envelope.zeroize();
            }

            let ans = Select::new("Select an Item:", options).prompt()?;
            Ok(id_map.get(&ans).unwrap().to_string())
        }
    }
}

pub async fn handle_item_view_scoped(
    pool: &SqlitePool,
    kek: &[u8; 32],
    provided_vault: Option<String>,
    provided_item: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Resolve Vault
    let vault_id = resolve_vault(pool, kek, provided_vault).await?;
    let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

    // 2. Resolve Item
    let item_id = resolve_item(pool, &vsk, &vault_id, provided_item).await?;

    // 3. View Logic
    let item_record = sqlx::query!("SELECT encrypted_payload FROM items WHERE id = $1", item_id)
        .fetch_one(pool)
        .await?;

    let enc_payload = EncryptedPayload::unpack(&item_record.encrypted_payload)?;
    let payload_bytes = decrypt_payload(&vsk, &enc_payload, &item_id)
        .map_err(|_| "Failed to decrypt item payload.")?;
    let envelope: ItemEnvelope = serde_json::from_slice(&payload_bytes)?;

    println!("\n--- {} ---", envelope.title);
    println!("{}", serde_json::to_string_pretty(&envelope.payload)?);

    Ok(())
}
