use sqlx::SqlitePool;

#[allow(unused)]
pub struct ClientState {
    pub email: String,
    pub local_verifier: Vec<u8>,
    pub master_salt: String,
    pub last_sync_at: i64,
}

impl ClientState {
    /// Fetch the current state. Fails if the user hasn't onboarded yet.
    pub async fn get(pool: &SqlitePool) -> Result<Self, sqlx::Error> {
        sqlx::query_as!(
            ClientState,
            "SELECT email, local_verifier, master_salt, last_sync_at FROM client_state WHERE id = 1"
        )
        .fetch_one(pool)
        .await
    }

    /// Initialize or update the state.
    pub async fn upsert(
        pool: &SqlitePool,
        email: &str,
        local_verifier: &[u8],
        master_salt: &str,
        last_sync_at: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO client_state (id, email, local_verifier, master_salt, last_sync_at)
            VALUES (1, ?1, ?2, ?3, ?4)
            ON CONFLICT(id) DO UPDATE SET
                email = excluded.email,
                local_verifier = excluded.local_verifier,
                master_salt = excluded.master_salt,
                last_sync_at = excluded.last_sync_at
            "#,
            email,
            local_verifier,
            master_salt,
            last_sync_at
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Quickly update just the sync timestamp
    pub async fn update_sync_time(pool: &SqlitePool, timestamp: i64) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE client_state SET last_sync_at = ?1 WHERE id = 1",
            timestamp
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
