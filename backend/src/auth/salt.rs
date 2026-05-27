use axum::{Json, extract::State, http::StatusCode};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use shared::{SaltRequest, SaltResponse};

use crate::{AppStateRef, auth::normalize_email};

pub async fn get_salt(
    State(state): State<AppStateRef>,
    Json(payload): Json<SaltRequest>,
) -> Result<Json<SaltResponse>, StatusCode> {
    let email = normalize_email(&payload.email);

    let user = sqlx::query!("SELECT master_key_salt FROM users WHERE email = $1", email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match user {
        Some(u) => Ok(Json(SaltResponse {
            salt: u.master_key_salt,
        })),
        None => {
            // Anti-Enumeration: Generate a fake deterministic salt
            let mut mac = Hmac::<Sha256>::new_from_slice(state.jwt_secret.as_bytes()).unwrap();
            mac.update(email.as_bytes());
            mac.update(b"arcan-deterministic-salt-v1");

            let fake_bytes = mac.finalize().into_bytes();
            let fake_salt = BASE64_STANDARD.encode(&fake_bytes[..16]);

            Ok(Json(SaltResponse { salt: fake_salt }))
        }
    }
}
