use sqlx::SqlitePool;

use crate::items::{
    handlers::get_decrypted_vsk,
    interactive::{resolve_item, resolve_vault},
};

pub async fn handle_item_delete(
    pool: &SqlitePool,
    kek: &[u8; 32],
    vault_id: Option<String>,
    item_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let vault_id = resolve_vault(pool, kek, vault_id).await?;
    let vsk = get_decrypted_vsk(pool, kek, &vault_id).await?;

    let item_id = resolve_item(pool, &vsk, &vault_id, item_id).await?;

    // 2. Delete the item from the database
    sqlx::query!(
        "DELETE FROM items WHERE id = ? AND vault_id = ?",
        item_id,
        vault_id
    )
    .execute(pool)
    .await?;

    println!("Item deleted successfully.");
    Ok(())
}
