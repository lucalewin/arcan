use std::str::FromStr;

use clap::Parser;
use directories::ProjectDirs;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};

use crate::{
    auth::{handle_unlock, login::authenticate, onboard::handle_onboard, session::require_session},
    cli::{Cli, Commands},
    config::ArcanConfig,
    items::handlers::{handle_item_create, handle_item_delete, handle_item_list, handle_item_view},
    state::ClientState,
    util::generate_password,
    vault::{handle_vault_create, handle_vault_delete, handle_vault_list},
};

mod auth;
mod cli;
mod config;
mod crypto;
mod items;
mod state;
mod sync;
mod util;
mod vault;

#[cfg(debug_assertions)]
const APP_NAME: &str = "arcan-dev";
#[cfg(not(debug_assertions))]
const APP_NAME: &str = "arcan";

// const API_BASE: &str = "http://127.0.0.1:3000/api/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    let config = ArcanConfig::load()?;

    let database_url = get_database_url()?;
    let options = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);
    let pool = SqlitePool::connect_with(options).await.expect(&format!(
        "Failed to connect to database at {}",
        database_url
    ));
    init_db(&pool).await?;

    match cli.command {
        Commands::Onboard { email } => {
            handle_onboard(&pool, &email, &config.api_url).await?;
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
                cli::ItemCommands::Create {
                    vault_id,
                    title,
                    tags,
                    payload,
                } => {
                    println!("Creating item '{}' in vault {}", "name", vault_id);
                    handle_item_create(&pool, &enc_key, vault_id, title, tags, payload).await?;
                }
                cli::ItemCommands::List { vault_id } => {
                    println!("Listing items in vault {}", vault_id);
                    handle_item_list(&pool, &enc_key, vault_id).await?;
                }
                cli::ItemCommands::View { id } => {
                    println!("Reading item with ID: {}", id);
                    handle_item_view(&pool, &enc_key, id).await?;
                }
                cli::ItemCommands::Delete { id } => {
                    println!("Deleting item with ID: {}", id);
                    handle_item_delete(&pool, id).await?;
                }
            }
        }
        Commands::Sync => {
            let session = require_session()?;
            let auth_key_bytes: [u8; 32] = session.authentication_key()?;
            let http_client = reqwest::Client::new();
            let state = ClientState::get(&pool).await?;

            println!("Authenticating with server...");
            let jwt = authenticate(state.email, &auth_key_bytes, &config.api_url).await?;

            println!("Pushing local changes...");
            sync::push_local_changes(&pool, &http_client, &jwt, &config.api_url).await?;

            println!("Pulling remote changes...");
            sync::pull_remote_changes(&pool, &http_client, &jwt, &config.api_url).await?;

            // Update the sync timestamp in ClientState
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            ClientState::update_sync_time(&pool, now).await?;

            println!("Sync complete.");
        }
    }

    Ok(())
}

fn get_database_url() -> Result<String, Box<dyn std::error::Error>> {
    match std::env::var("DATABASE_URL") {
        Ok(url) => Ok(url),
        Err(_) => {
            if cfg!(debug_assertions) {
                // In debug builds, require explicit DATABASE_URL to avoid accidental use of production DB.
                eprintln!(
                    "DATABASE_URL not set. In debug mode please set DATABASE_URL to avoid interfering with production data."
                );
                eprintln!("Example: export DATABASE_URL=\"sqlite://./dev-arcan.db\"");
                std::process::exit(1);
            } else {
                // Production default: ~/.local/arcan/arcan.db
                let Some(project_dirs) = ProjectDirs::from("dev", "lucalewin", APP_NAME) else {
                    return Err("Could not determine project directories.".into());
                };

                let data_dir = project_dirs.data_dir();
                std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");
                let db = data_dir.join("arcan.db");

                Ok(format!("sqlite://{}", db.display()))
            }
        }
    }
}

async fn init_db(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // This runs all pending migrations automatically.
    // If the database is already up to date, it does nothing.
    sqlx::migrate!("./migrations").run(pool).await?;

    Ok(())
}
