use argon2::password_hash::SaltString;
use chacha20poly1305::aead::OsRng;
use clap::Parser;
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use sqlx::SqlitePool;
use zeroize::Zeroize;

use crate::{
    auth::{
        AUTHENTICATION_SUBKEY_INFO, VERIFICATION_SUBKEY_INFO, handle_unlock, login::authenticate,
        register::register, session::require_session,
    },
    cli::{Cli, Commands},
    crypto::{derive_master_key, derive_subkey},
    item::{handle_item_create, handle_item_delete, handle_item_list, handle_item_view},
    state::ClientState,
    util::generate_password,
    vault::{handle_vault_create, handle_vault_delete, handle_vault_list},
};

mod auth;
mod cli;
mod crypto;
mod item;
mod state;
mod sync;
mod util;
mod vault;

const API_BASE: &str = "http://127.0.0.1:3000/api/v1";

async fn handle_onboard(pool: &SqlitePool, email: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Prompt for Master Password securely
    let password = prompt_password("Master Password: ")?;

    // 2. Generate a random salt and derive the root key
    let root_salt = SaltString::generate(&mut OsRng);
    let mut root_key = derive_master_key(&password, &root_salt)?;
    let auth_subkey = derive_subkey(&root_key, AUTHENTICATION_SUBKEY_INFO);
    let verification_subkey = derive_subkey(&root_key, VERIFICATION_SUBKEY_INFO);

    root_key.zeroize();

    register(email, auth_subkey.expose_secret(), &root_salt)
        .await
        .map_err(|e| {
            eprintln!("Registration failed: {}", e);
            "Registration process failed.".to_string()
        })?;

    // 3. Store the email, salt, and password hash in the local DB for future logins
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = SqlitePool::connect(&database_url).await?;
    init_db(&pool).await?;

    match cli.command {
        Commands::Onboard { email } => {
            handle_onboard(&pool, &email).await?;
        }
        Commands::Unlock => {
            handle_unlock(&pool).await?;
        }
        Commands::Password { length } => {
            let password = generate_password(&util::PasswordOptions {
                length,
                numbers: true,
                uppercase: true,
                symbols: true,
            });
            println!("{}", password);
        }
        Commands::Vault { action } => {
            let session = require_session()?;
            let enc_key = session.encryption_key()?;

            match action {
                cli::VaultCommands::Create { name } => {
                    println!("Creating vault: {}", name);
                    handle_vault_create(&pool, &enc_key, name).await?;
                }
                cli::VaultCommands::List => {
                    println!("Listing vaults...");
                    handle_vault_list(&pool, &enc_key).await?;
                }
                cli::VaultCommands::Delete { id } => {
                    println!("Deleting vault with ID: {}", id);
                    handle_vault_delete(&pool, id).await?;
                }
            }
        }
        Commands::Item { action } => {
            let session = require_session()?;
            let enc_key = session.encryption_key()?;

            match action {
                cli::ItemCommands::Create { vault_id, .. } => {
                    println!("Creating item '{}' in vault {}", "name", vault_id);
                    handle_item_create(&pool, &enc_key, vault_id, "name".to_string(), vec![])
                        .await?;
                }
                cli::ItemCommands::List { vault_id } => {
                    println!("Listing items in vault {}", vault_id);
                    handle_item_list(&pool, &enc_key, vault_id).await?;
                }
                cli::ItemCommands::View { item_id } => {
                    println!("Reading item with ID: {}", item_id);
                    handle_item_view(&pool, &enc_key, item_id).await?;
                }
                cli::ItemCommands::Delete { item_id } => {
                    println!("Deleting item with ID: {}", item_id);
                    handle_item_delete(&pool, item_id).await?;
                }
            }
        }
        Commands::Sync => {
            let session = require_session()?;
            let auth_key_bytes: [u8; 32] = session.authentication_key()?;
            let http_client = reqwest::Client::new();
            let state = ClientState::get(&pool).await?;

            println!("Authenticating with server...");
            let jwt = authenticate(state.email, &auth_key_bytes).await?;

            println!("Pushing local changes...");
            sync::push_local_changes(&pool, &http_client, &jwt).await?;

            println!("Pulling remote changes...");
            sync::pull_remote_changes(&pool, &http_client, &jwt).await?;

            // Update the sync timestamp in ClientState
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            ClientState::update_sync_time(&pool, now).await?;

            println!("Sync complete.");
        }
    }

    Ok(())
}

async fn init_db(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // This runs all pending migrations automatically.
    // If the database is already up to date, it does nothing.
    sqlx::migrate!("./migrations").run(pool).await?;

    Ok(())
}
