use crate::{AppStateRef, auth::normalize_email};
use axum::{Json, extract::State, http::StatusCode};
use base64::prelude::*;

use bytes::Bytes;
use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration, ServerSetup};
// use rand::rngs::OsRng;
use shared::{
    DefaultCipherSuite, RegistrationFinishRequest, RegistrationStartRequest,
    RegistrationStartResponse,
};

pub fn server_start(
    setup: &ServerSetup<DefaultCipherSuite>,
    account: &[u8],
    client_start: &[u8],
) -> Result<Bytes, Box<dyn std::error::Error>> {
    match ServerRegistration::<DefaultCipherSuite>::start(
        setup,
        RegistrationRequest::deserialize(client_start)?,
        account,
    ) {
        Ok(start_result) => Ok(Bytes::copy_from_slice(
            &start_result.message.serialize()[..],
        )),
        Err(err) => Err(err.to_string().into()),
    }
}

pub fn server_finish(client_finish: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let registration_upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(client_finish)?;

    let password_file = ServerRegistration::finish(registration_upload);

    Ok(password_file.serialize().to_vec())
}

pub async fn register_start(
    State(state): State<AppStateRef>,
    Json(payload): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationStartResponse>, StatusCode> {
    let email = normalize_email(&payload.email);

    let user_exists =
        sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", email)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!("DB error checking user existence: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .unwrap_or(false);

    if user_exists {
        // Prevent enumeration: Return a generic error or handle a fake OPAQUE start flow.
        // Returning 409 Conflict is standard if you don't use fake flows, but a true
        // zero-knowledge system returns a valid-looking payload that fails at finish.
        // For now, we use a distinct status code but you should log this.
        tracing::warn!("Registration attempt for existing email: {}", email);
        return Err(StatusCode::CONFLICT);
    }

    let decoded_client_start = BASE64_STANDARD
        .decode(payload.client_start)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let server_start = server_start(&state.server_setup, email.as_bytes(), &decoded_client_start)
        .map_err(|e| {
        tracing::error!("OPAQUE register start failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(RegistrationStartResponse {
        server_start: BASE64_STANDARD.encode(server_start),
    }))
}

pub async fn register_finish(
    State(state): State<AppStateRef>,
    Json(payload): Json<RegistrationFinishRequest>,
) -> Result<StatusCode, StatusCode> {
    let decoded_client_finish = BASE64_STANDARD
        .decode(payload.client_finish)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let password_file = server_finish(&decoded_client_finish).map_err(|e| {
        tracing::error!("OPAQUE register finish failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query!(
        "INSERT INTO users (email, master_key_salt, password_file) VALUES ($1, $2, $3)",
        normalize_email(&payload.email),
        payload.salt,
        password_file // Store raw BYTEA directly, no need to Base64 encode into the DB
    )
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert new user: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::CREATED)
}
