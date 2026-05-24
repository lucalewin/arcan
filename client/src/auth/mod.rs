use argon2::password_hash::SaltString;
use base64::prelude::*;
use secrecy::ExposeSecret;
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    auth::session::ArcanSession,
    crypto::{derive_master_key, derive_subkey},
    state::ClientState,
};

pub mod login;
pub mod register;
pub mod session;

pub(crate) const ENCRYPTION_SUBKEY_INFO: &str = "arcan-encryption";
pub(crate) const AUTHENTICATION_SUBKEY_INFO: &str = "arcan-authentication";
pub(crate) const VERIFICATION_SUBKEY_INFO: &str = "arcan-verification";

pub async fn handle_unlock(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch user salt from local DB (synced during onboard/login)
    let client_state = ClientState::get(pool).await?;
    let root_salt =
        SaltString::from_b64(&client_state.master_salt).map_err(|_| "Invalid salt in database")?;

    let password = rpassword::prompt_password("Master Password: ")?;

    // 2. Run Argon2 ONCE
    let mut root_key = derive_master_key(&password, &root_salt)?;

    // 3. Derive the local verifier from their input
    let attempt_verifier = derive_subkey(&root_key, VERIFICATION_SUBKEY_INFO);

    // 4. Securely compare the attempt against the database
    let is_valid = attempt_verifier
        .expose_secret()
        .ct_eq(client_state.local_verifier.as_slice());

    if is_valid.unwrap_u8() == 0 {
        // Scrub the root key immediately on failure
        use zeroize::Zeroize;
        root_key.zeroize();

        eprintln!("Invalid Master Password.");
        std::process::exit(1);
    }

    // 3. Derive the Key Encryption Key (KEK) using Argon2
    let kek = derive_subkey(&root_key, ENCRYPTION_SUBKEY_INFO);
    let _auth_key = derive_subkey(&root_key, AUTHENTICATION_SUBKEY_INFO);
    root_key.zeroize();

    let session = ArcanSession {
        kek: BASE64_STANDARD.encode(kek.expose_secret()),
        auth: BASE64_STANDARD.encode(_auth_key.expose_secret()),
    };

    // 4. Print the export command to stdout
    // Note: We print to stdout so `eval $(arcan unlock)` works.
    // Any logging or instructions must go to stderr using eprintln!()
    // so it doesn't break the shell evaluation.
    eprintln!("Vault unlocked. Run this command to set your session:");
    println!("export ARCAN_SESSION=\"{}\"", session.to_env());

    Ok(())
}
