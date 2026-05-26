use axum::{Json, extract::State, http::StatusCode};
use shared::AccountDetailsResponse;

use crate::{AppStateRef, middleware::Session};

#[axum::debug_handler]
pub async fn account_detail_handler(
    State(state): State<AppStateRef>,
    Session(user_id): Session,
) -> Result<(StatusCode, Json<AccountDetailsResponse>), StatusCode> {
    let detials = sqlx::query!(
        "SELECT email, master_key_salt, created_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        Json(AccountDetailsResponse {
            email: detials.email,
            master_key_salt: detials.master_key_salt,
            created_at: detials.created_at.unix_timestamp(),
        }),
    ))
}
