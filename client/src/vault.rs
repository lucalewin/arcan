use argon2::password_hash::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
// use rand::{RngCore, rngs::OsRng};
use sqlx::SqlitePool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::{decrypt_payload, encrypt_payload, pack_payload, unpack_payload};
// use shared::crypto::{encrypt_payload, decrypt_payload, pack_payload, unpack_payload};

pub async fn handle_vault_create(
    pool: &SqlitePool,
    kek: &[u8; 32],
    name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let vault_id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 1. Generate the Vault Sync Key (VSK)
    let mut vsk = [0u8; 32];
    OsRng.fill_bytes(&mut vsk);

    // 2. Encrypt the VSK with the KEK (AAD = vault_id)
    let (vsk_ciphertext, vsk_nonce) = encrypt_payload(kek, &vsk, &vault_id);
    let packed_encrypted_vsk = pack_payload(vsk_nonce, vsk_ciphertext);

    // 3. Encrypt the Vault Name with the VSK (AAD = vault_id)
    let (name_ciphertext, name_nonce) = encrypt_payload(&vsk, name.as_bytes(), &vault_id);
    let packed_encrypted_name = pack_payload(name_nonce, name_ciphertext);

    // 4. Save to SQLite
    sqlx::query!(
        "INSERT INTO vaults (id, encrypted_name, encrypted_vsk, server_revision, created_at, updated_at)
         VALUES ($1, $2, $3, 0, $4, $5)",
        vault_id,
        packed_encrypted_name,
        packed_encrypted_vsk,
        now,
        now
    )
    .execute(pool)
    .await?;

    println!("Vault '{}' created successfully. ID: {}", name, vault_id);
    Ok(())
}

pub async fn handle_vault_list(
    pool: &SqlitePool,
    kek: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let vaults =
        sqlx::query!("SELECT id, encrypted_name, encrypted_vsk FROM vaults WHERE is_deleted = 0")
            .fetch_all(pool)
            .await?;

    if vaults.is_empty() {
        println!("No vaults found.");
        return Ok(());
    }

    println!("{:<38} | {}", "VAULT ID", "NAME");
    println!("{:-<38}-|-{:-<20}", "", "");

    for vault in vaults {
        // 1. Unpack and decrypt the VSK using the KEK
        let (vsk_nonce, vsk_cipher) = unpack_payload(&vault.encrypted_vsk)?;
        let vsk_bytes = decrypt_payload(kek, vsk_cipher, &vsk_nonce, &vault.id)
            .map_err(|_| "Failed to decrypt VSK. Possible wrong KEK or corrupted data.")?;

        let mut vsk = [0u8; 32];
        vsk.copy_from_slice(&vsk_bytes);

        // 2. Unpack and decrypt the Name using the decrypted VSK
        let (name_nonce, name_cipher) = unpack_payload(&vault.encrypted_name)?;
        let name_bytes = decrypt_payload(&vsk, name_cipher, &name_nonce, &vault.id)
            .map_err(|_| "Failed to decrypt vault name. Possible corrupted data.")?;

        let decrypted_name = String::from_utf8(name_bytes)?;

        println!("{:<38} | {}", vault.id, decrypted_name);
    }

    Ok(())
}

pub async fn handle_vault_delete(
    pool: &SqlitePool,
    vault_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let result = sqlx::query!(
        "UPDATE vaults SET is_deleted = 1, updated_at = $1 WHERE id = $2",
        now,
        vault_id
    )
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        println!(
            "Vault {} queued for deletion. Run `arcan sync` to push.",
            vault_id
        );
    } else {
        println!("Vault {} not found.", vault_id);
    }

    Ok(())
}
