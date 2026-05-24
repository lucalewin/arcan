use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct PushRequest {
    pub vaults: Vec<VaultPush>,
    pub items: Vec<ItemPush>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultPush {
    pub id: Uuid,
    pub base_revision: i64,
    pub is_deleted: bool,
    pub encrypted_name: String,
    pub encrypted_vsk: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct ItemPush {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub base_revision: i64,
    pub is_deleted: bool,
    pub encrypted_payload: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PushResponse {
    pub accepted_revisions: HashMap<Uuid, i64>,
    pub conflicts: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PullRequest {
    pub vault_revisions: HashMap<Uuid, i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultPull {
    pub id: Uuid,
    pub server_revision: i64,
    pub is_deleted: bool,
    pub encrypted_name: String,
    pub encrypted_vsk: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ItemPull {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub server_revision: i64,
    pub is_deleted: bool,
    pub encrypted_payload: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PullResponse {
    pub current_revisions: HashMap<Uuid, i64>,
    pub vaults: Vec<VaultPull>,
    pub items: Vec<ItemPull>,
}

// --------------- OPAQUE -------------------

use opaque_ke::{CipherSuite, argon2::Argon2};

pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

// ------------------------------------------
//               Registration
// ------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub email: String,
    pub client_start: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    pub server_start: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    /// The email needs to be the same as the one
    /// used in the [`RegistrationStartRequest::email`].
    pub email: String,
    pub salt: String,
    pub client_finish: String,
}

// ------------------------------------------
//                  Login
// ------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub email: String,
    pub client_start: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    pub attempt_id: Uuid,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub email: String,
    pub attempt_id: Uuid,
    pub client_finish: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub access_token: String,
    pub salt: String,
    // TODO: add refresh_token and other nice stuff
}
