use std::env;

use argon2::password_hash::SaltString;
use base64::prelude::*;
use bytes::Bytes;
use chacha20poly1305::aead::OsRng;
use clap::Parser;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use rpassword::prompt_password;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use shared::{
    DefaultCipherSuite, RegistrationFinishRequest, RegistrationStartRequest,
    RegistrationStartResponse,
};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    cli::{Cli, Commands},
    crypto::{derive_master_key, derive_subkey},
    item::{handle_item_create, handle_item_list, handle_item_view},
    state::ClientState,
    util::generate_password,
    vault::{handle_vault_create, handle_vault_delete, handle_vault_list},
};

mod cli;
mod crypto;
mod item;
mod state;
mod sync;
mod util;
mod vault;

const ENCRYPTION_SUBKEY_INFO: &str = "arcan-encryption";
const AUTHENTICATION_SUBKEY_INFO: &str = "arcan-authentication";
const VERIFICATION_SUBKEY_INFO: &str = "arcan-verification";

#[derive(Serialize, Deserialize)]
pub struct ArcanSession {
    pub kek: String,
    pub auth: String,
}

impl ArcanSession {
    pub fn to_env(&self) -> String {
        BASE64_STANDARD.encode(serde_json::to_string(self).unwrap().as_bytes())
    }

    pub fn from_env(env_str: &str) -> Result<Self, String> {
        let decoded = BASE64_STANDARD
            .decode(env_str)
            .map_err(|_| "Failed to decode session from environment variable.".to_string())?;

        serde_json::from_slice(&decoded).map_err(|_| "Failed to parse session JSON.".to_string())
    }

    pub fn encryption_key(&self) -> Result<[u8; 32], String> {
        let decoded = BASE64_STANDARD
            .decode(&self.kek)
            .map_err(|_| "Failed to decode KEK from session.".to_string())?;

        if decoded.len() != 32 {
            return Err("Invalid KEK length in session.".to_string());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    pub fn authentication_key(&self) -> Result<[u8; 32], String> {
        let decoded = BASE64_STANDARD
            .decode(&self.auth)
            .map_err(|_| "Failed to decode auth key from session.".to_string())?;

        if decoded.len() != 32 {
            return Err("Invalid auth key length in session.".to_string());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}

pub fn client_start(password: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    match ClientRegistration::<DefaultCipherSuite>::start(&mut OsRng, password) {
        Ok(start) => Ok((
            start.state.serialize().to_vec(),
            start.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn client_finish(
    password: &[u8],
    client_state: &[u8],
    server_message: &[u8],
) -> Result<Bytes, Box<dyn std::error::Error>> {
    let client_state = match ClientRegistration::<DefaultCipherSuite>::deserialize(client_state) {
        Ok(s) => s,
        Err(err) => return Err(err.to_string().into()),
    };

    let mut rng = OsRng;

    match client_state.finish(
        &mut rng,
        password,
        RegistrationResponse::deserialize(server_message)?,
        ClientRegistrationFinishParameters::default(),
    ) {
        Ok(finish) => Ok(Bytes::copy_from_slice(&finish.message.serialize()[..])),
        Err(err) => Err(err.to_string().into()),
    }
}

pub async fn register(email: &str, password: &[u8], salt: &SaltString) -> Result<(), String> {
    let client = reqwest::Client::new();

    let (state, message) = client_start(&password).unwrap();

    let response = client
        .post("http://localhost:3000/api/v1/auth/register/start")
        .json(&RegistrationStartRequest {
            email: email.to_string(),
            client_start: BASE64_STANDARD.encode(message),
        })
        .send()
        .await
        .unwrap();

    if response.status() != 200 {
        dbg!(response);
        return Err("Registration start failed".to_string());
    }

    let response = response.json::<RegistrationStartResponse>().await.unwrap();

    let server_message = BASE64_STANDARD.decode(response.server_start).unwrap();
    let message = client_finish(&password, &state, &server_message).unwrap();

    let status = client
        .post("http://localhost:3000/api/v1/auth/register/finish")
        .json(&RegistrationFinishRequest {
            email: email.to_string(),
            salt: salt.to_string(),
            client_finish: BASE64_STANDARD.encode(message),
        })
        .send()
        .await
        .unwrap()
        .status();

    dbg!(status);

    Ok(())
}

fn require_session() -> Result<ArcanSession, String> {
    let session_str = env::var("ARCAN_SESSION").map_err(|_| {
        "Vault is locked. Run `eval $(arcan unlock --email <your_email>)` to unlock it.".to_string()
    })?;

    ArcanSession::from_env(&session_str)
}

async fn handle_unlock(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch user salt from local DB (synced during onboard/login)
    let client_state = ClientState::get(pool).await?;
    let root_salt = SaltString::from_b64(&client_state.master_salt).unwrap();

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

            match action {
                cli::VaultCommands::Create { name } => {
                    println!("Creating vault: {}", name);
                    handle_vault_create(&pool, &session.encryption_key()?, name).await?;
                }
                cli::VaultCommands::List => {
                    println!("Listing vaults...");
                    handle_vault_list(&pool, &session.encryption_key()?).await?;
                }
                cli::VaultCommands::Delete { id } => {
                    println!("Deleting vault with ID: {}", id);
                    handle_vault_delete(&pool, id).await?;
                }
            }
        }
        Commands::Item { action } => {
            let session = require_session()?;

            match action {
                cli::ItemCommands::Create { vault_id, .. } => {
                    println!("Creating item '{}' in vault {}", "name", vault_id);
                    handle_item_create(
                        &pool,
                        &session.encryption_key()?,
                        vault_id,
                        "name".to_string(),
                        vec![],
                    )
                    .await?;
                }
                cli::ItemCommands::List { vault_id } => {
                    println!("Listing items in vault {}", vault_id);
                    handle_item_list(&pool, &session.encryption_key()?, vault_id).await?;
                }
                cli::ItemCommands::View { item_id } => {
                    println!("Reading item with ID: {}", item_id);
                    handle_item_view(&pool, &session.encryption_key()?, item_id).await?;
                }
                cli::ItemCommands::Delete { item_id } => {
                    println!("Deleting item with ID: {}", item_id);
                    // handle_item_delete(&pool, id).await?;
                }
            }
        }
        Commands::Sync => {
            let session = require_session()?;
            let auth_key_bytes: [u8; 32] = session.authentication_key()?;
            let http_client = reqwest::Client::new();

            println!("Authenticating with server...");
            let jwt = sync::authenticate(&pool, &auth_key_bytes).await?;

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

// use base64::prelude::*;
// use chrono::Utc;
// use reqwest::Client;
// use shared::{ItemPush, PullRequest, PullResponse, PushRequest, VaultPush};
// use std::collections::HashMap;
// use uuid::Uuid;

// // --- Test Execution ---

// #[tokio::main]
// async fn main() {
//     let client = Client::new();
//     let base_url = "http://127.0.0.1:3000/api/v1/sync";

//     // In a real scenario, this comes from your OPAQUE login finish step.
//     // Ensure your Axum auth_middleware accepts this and injects a valid UUID into the request Extension.
//     let auth_token = "Bearer test_token_123";

//     let vault_id = Uuid::new_v4();
//     let item_id = Uuid::new_v4();
//     let now = Utc::now().timestamp();

//     println!("--- 1. Testing PUSH (Device A) ---");

//     let push_payload = PushRequest {
//         vaults: vec![VaultPush {
//             id: vault_id,
//             base_revision: 0, // 0 means new creation
//             is_deleted: false,
//             encrypted_name: BASE64_STANDARD.encode(b"My Test Vault"),
//             encrypted_vsk: BASE64_STANDARD.encode(b"dummy_vsk_key"),
//             created_at: now,
//             updated_at: now,
//         }],
//         items: vec![ItemPush {
//             id: item_id,
//             vault_id,
//             base_revision: 0,
//             is_deleted: false,
//             encrypted_payload: Some(BASE64_STANDARD.encode(b"encrypted_password_data")),
//             created_at: now,
//             updated_at: now,
//         }],
//     };

//     // let push_res = client
//     //     .post(&format!("{}/push", base_url))
//     //     .header("Authorization", auth_token)
//     //     .json(&push_payload)
//     //     .send()
//     //     .await
//     //     .expect("Failed to send push request");

//     // let status = push_res.status();
//     // let push_data: PushResponse = push_res
//     //     .json()
//     //     .await
//     //     .expect("Failed to parse Push response");

//     // println!("Status: {}", status);
//     // println!("Push Response: {:#?}\n", push_data);

//     // assert!(status.is_success(), "Push failed");

//     println!("--- 2. Testing PULL (Device B) ---");

//     // Device B knows about the vault (maybe they synced earlier), but is at revision 0
//     let mut vault_revisions = HashMap::new();
//     vault_revisions.insert(
//         Uuid::parse_str("5113b737-efc1-4017-8243-60defa38c05b").unwrap(),
//         5,
//     );

//     let pull_payload = PullRequest { vault_revisions };

//     let pull_res = client
//         .post(&format!("{}/pull", base_url)) // Note: Pull is a POST because it sends a JSON body
//         .header("Authorization", auth_token)
//         .json(&pull_payload)
//         .send()
//         .await
//         .expect("Failed to send pull request");

//     let status = pull_res.status();
//     let pull_data: PullResponse = pull_res
//         .json()
//         .await
//         .expect("Failed to parse Pull response");

//     println!("Status: {}", status);
//     println!("Pull Response: {:#?}", pull_data);

//     assert!(status.is_success(), "Pull failed");

//     // Verify we got the data back
//     assert_eq!(pull_data.vaults.len(), 1, "Expected 1 vault");
//     assert_eq!(pull_data.items.len(), 1, "Expected 1 item");
// }
