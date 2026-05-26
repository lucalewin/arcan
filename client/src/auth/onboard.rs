use argon2::password_hash::SaltString;
use chacha20poly1305::aead::OsRng;
use secrecy::ExposeSecret;
use sqlx::SqlitePool;
use tokio::task;
use zeroize::Zeroize;

use crate::auth::login::authenticate;
use crate::auth::register::register;
use crate::crypto::{derive_master_key, derive_subkey};
use crate::state::ClientState;

use crate::auth::{AUTHENTICATION_SUBKEY_INFO, VERIFICATION_SUBKEY_INFO};

/// Interactive onboarding: prompts the user for a master password, performs
/// registration with the server and stores local client state.
pub async fn handle_onboard(
    pool: &SqlitePool,
    email: &str,
    login_existing: bool,
    api_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for the master password on a blocking thread to avoid blocking the runtime.
    let password =
        task::spawn_blocking(|| rpassword::prompt_password("Master Password: ")).await??;

    let root_salt;
    let verification_subkey;
    if !login_existing {
        // Generate a random salt and derive the root key
        root_salt = SaltString::generate(&mut OsRng);
        let mut root_key = derive_master_key(&password, &root_salt)?;
        let auth_subkey = derive_subkey(&root_key, AUTHENTICATION_SUBKEY_INFO);
        verification_subkey = derive_subkey(&root_key, VERIFICATION_SUBKEY_INFO);

        // Zeroize the ephemeral root key ASAP.
        root_key.zeroize();

        // Register with remote
        register(email, auth_subkey.expose_secret(), &root_salt, api_url)
            .await
            .map_err(|e| {
                eprintln!("Registration failed: {}", e);
                "Registration process failed.".to_string()
            })?;
    } else {
        // fetch the salt
        let client = reqwest::Client::new();

        let details = client
            .get(format!("{}/api/v1/account", api_url))
            .send()
            .await?
            .json::<shared::AccountDetailsResponse>()
            .await?;

        root_salt = SaltString::from_b64(&details.master_key_salt).map_err(|e| {
            eprintln!("Failed to parse salt from server: {}", e);
            "Invalid salt format received from server.".to_string()
        })?;
        let mut root_key = derive_master_key(&password, &root_salt)?;
        let auth_subkey = derive_subkey(&root_key, AUTHENTICATION_SUBKEY_INFO);
        verification_subkey = derive_subkey(&root_key, VERIFICATION_SUBKEY_INFO);

        // Zeroize the ephemeral root key ASAP.
        root_key.zeroize();

        let _ = authenticate(email, auth_subkey.expose_secret(), api_url)
            .await
            .map_err(|e| {
                eprintln!("Authentication failed: {}", e);
                "Authentication process failed.".to_string()
            })?;
    }

    // Store email, verifier and salt locally
    ClientState::upsert(
        pool,
        &email,
        verification_subkey.expose_secret(),
        root_salt.as_str(),
        0,
    )
    .await?;

    println!("Onboarding successful for {}!", email);
    Ok(())
}
