use crate::{AppStateRef, auth::normalize_email, middleware::Claims};
use axum::{Json, extract::State, http::StatusCode};
use base64::prelude::*;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use shared::{
    DefaultCipherSuite, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use opaque_ke::{
    CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginParameters,
    ServerRegistration, rand::rngs::OsRng,
};
// use rand::rngs::OsRng;
//
#[derive(Serialize, Deserialize)]
struct LoginSessionState {
    user_id: Uuid,
    salt: String,
    opaque_state: String, // Base64
}

pub async fn login_start(
    State(state): State<AppStateRef>,
    Json(payload): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, StatusCode> {
    let email = normalize_email(&payload.email);

    let user = sqlx::query!(
        "SELECT id, master_key_salt, password_file FROM users WHERE email = $1",
        email
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!("DB error fetching user: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Anti-Enumeration: If user doesn't exist, you MUST run a fake OPAQUE flow here
    // to match response times. For simplicity, we just return an Unauthorized error,
    // but in production, generate a dummy server_start.
    let Some(user) = user else {
        tracing::warn!("Login start attempt for non-existent email: {}", email);
        return Err(StatusCode::UNAUTHORIZED);
    };

    let client_start = BASE64_STANDARD
        .decode(payload.client_start)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&user.password_file)
        .map_err(|e| {
            tracing::error!("Failed to deserialize OPAQUE password file: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let credential_request = CredentialRequest::deserialize(&client_start).map_err(|e| {
        tracing::error!("Failed to deserialize OPAQUE client start: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;

    let login_start_result = ServerLogin::start(
        &mut OsRng,
        &state.server_setup,
        Some(password_file),
        credential_request,
        email.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| {
        tracing::error!("OPAQUE login start failed: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;

    let attempt_id = Uuid::new_v4();
    let session_data = LoginSessionState {
        user_id: user.id,
        salt: user.master_key_salt,
        opaque_state: BASE64_STANDARD.encode(login_start_result.state.serialize().to_vec()),
    };

    let mut redis = state.redis.clone();
    redis
        .set_ex::<_, _, ()>(
            format!("login_attempt_{}", attempt_id),
            serde_json::to_string(&session_data).unwrap(),
            120, // 2 minutes is safer for high latency clients
        )
        .await
        .map_err(|e| {
            tracing::error!("Redis set failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(LoginStartResponse {
        attempt_id,
        message: BASE64_STANDARD.encode(login_start_result.message.serialize().to_vec()),
    }))
}

use redis::AsyncCommands;

pub async fn login_finish(
    State(state): State<AppStateRef>,
    Json(payload): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, StatusCode> {
    let mut redis = state.redis.clone();
    let redis_key = format!("login_attempt_{}", payload.attempt_id);

    // Atomic fetch-and-delete prevents replay attacks
    let session_json: Option<String> = redis.get_del(&redis_key).await.map_err(|e| {
        tracing::error!("Redis get_del failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(session_str) = session_json else {
        tracing::warn!(
            "Login attempt ID not found or expired: {}",
            payload.attempt_id
        );
        return Err(StatusCode::UNAUTHORIZED);
    };

    let session_data: LoginSessionState = serde_json::from_str(&session_str).map_err(|_| {
        tracing::error!("Corrupted session data in Redis");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let client_finish = BASE64_STANDARD
        .decode(payload.client_finish)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let server_start = BASE64_STANDARD
        .decode(session_data.opaque_state)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client_finish = CredentialFinalization::deserialize(&client_finish).map_err(|e| {
        tracing::error!("Failed to deserialize OPAQUE client finish: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;
    let start_state = ServerLogin::<DefaultCipherSuite>::deserialize(&server_start)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = start_state
        .finish(client_finish, ServerLoginParameters::default())
        .map_err(|e| {
            tracing::warn!(
                "OPAQUE login finish failed for user {}: {:?}",
                session_data.user_id,
                e
            );
            StatusCode::UNAUTHORIZED
        })?;

    let now = OffsetDateTime::now_utc();
    let claims = Claims {
        sub: session_data.user_id.to_string(),
        exp: (now + Duration::days(7)).unix_timestamp() as u64,
        iat: now.unix_timestamp() as u64,
        iss: "https://sanctum.lucalewin.dev".into(),
        nbf: now.unix_timestamp() as u64,
        aud: "https://sanctum.lucalewin.dev".into(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| {
        tracing::error!("JWT encoding failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(LoginFinishResponse {
        access_token: token,
        salt: session_data.salt,
    }))
}
