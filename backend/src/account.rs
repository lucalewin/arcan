use axum::{Json, extract::State, http::StatusCode};
use shared::{AccountDetailsRequest, AccountDetailsResponse};

use crate::AppStateRef;

#[axum::debug_handler]
pub async fn account_detail_handler(
    State(state): State<AppStateRef>,
    // Session(user_id): Session,
    Json(payload): Json<AccountDetailsRequest>,
) -> Result<(StatusCode, Json<AccountDetailsResponse>), StatusCode> {
    let detials = sqlx::query!(
        "SELECT master_key_salt, created_at FROM users WHERE email = $1",
        payload.email
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        Json(AccountDetailsResponse {
            master_key_salt: detials.master_key_salt,
            created_at: detials.created_at.unix_timestamp(),
        }),
    ))
}
