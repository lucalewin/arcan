use serde::{Deserialize, Serialize};

// 1. The Root Wrapper
#[derive(Serialize, Deserialize, Debug)]
pub struct ItemEnvelope {
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub payload: ItemPayload,
}

// 2. The Tagged Payload Enum
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemPayload {
    Login(LoginItem),
    SshKey(SshKeyItem),
    Totp(TotpItem),
    Note(NoteItem),
    Card(CardItem),
}

// 3. The Specific Payloads (Notice 'title' is gone from here)
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginItem {
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TotpItem {
    pub secret: String,
    pub account_name: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SshKeyItem {
    pub private_key: String,
    pub public_key: Option<String>,
    pub passphrase: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NoteItem {
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CardItem {
    pub cardholder_name: String,
    pub number: String, // Store without spaces
    pub exp_month: u8,
    pub exp_year: u16,
    pub cvv: String,
}
