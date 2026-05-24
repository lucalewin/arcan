use argon2::password_hash::SaltString;
use chacha20poly1305::aead::OsRng;
use secrecy::ExposeSecret;
use sqlx::SqlitePool;
use tokio::task;
use zeroize::Zeroize;

use crate::auth::register::register;
use crate::crypto::{derive_master_key, derive_subkey};
use crate::state::ClientState;

use crate::auth::{AUTHENTICATION_SUBKEY_INFO, VERIFICATION_SUBKEY_INFO};

/// Interactive onboarding: prompts the user for a master password, performs
/// registration with the server and stores local client state.
pub async fn handle_onboard(
    pool: &SqlitePool,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for the master password on a blocking thread to avoid blocking the runtime.
    let password =
        task::spawn_blocking(|| rpassword::prompt_password("Master Password: ")).await??;

    // Generate a random salt and derive the root key
    let root_salt = SaltString::generate(&mut OsRng);
    let mut root_key = derive_master_key(&password, &root_salt)?;
    let auth_subkey = derive_subkey(&root_key, AUTHENTICATION_SUBKEY_INFO);
    let verification_subkey = derive_subkey(&root_key, VERIFICATION_SUBKEY_INFO);

    // Zeroize the ephemeral root key ASAP.
    root_key.zeroize();

    // Register with remote
    register(email, auth_subkey.expose_secret(), &root_salt)
        .await
        .map_err(|e| {
            eprintln!("Registration failed: {}", e);
            "Registration process failed.".to_string()
        })?;

    // Store email, verifier and salt locally
    ClientState::upsert(
        pool,
        email,
        verification_subkey.expose_secret(),
        root_salt.as_str(),
        0,
    )
    .await?;

    println!("Onboarding successful for {}!", email);
    Ok(())
}
