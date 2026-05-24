use base64::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ArcanSession {
    /// Base64-encoded Key Encryption Key (KEK) for encrypting/decrypting vault keys
    pub kek: String,
    /// Base64-encoded Authentication Key for authenticating API requests
    pub auth: String,
}

impl ArcanSession {
    pub fn to_env(&self) -> String {
        BASE64_STANDARD.encode(
            serde_json::to_string(self)
                .expect("Failed to serialize ArcanSession")
                .as_bytes(),
        )
    }

    pub fn from_env(env_str: &str) -> Result<Self, String> {
        let decoded = BASE64_STANDARD
            .decode(env_str)
            .map_err(|_| "Failed to decode session from environment variable.".to_string())?;

        serde_json::from_slice(&decoded).map_err(|_| "Failed to parse session JSON.".to_string())
    }

    /// Decodes the KEK from the session and returns it as a 32-byte array.
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

    /// Decodes the Authentication Key from the session and returns it as a 32-byte array.
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

/// Reads the Arcan session from the ARCAN_SESSION environment variable.
pub fn require_session() -> Result<ArcanSession, String> {
    let session_str = std::env::var("ARCAN_SESSION").map_err(|_| {
        "Vault is locked. Run `eval $(arcan unlock --email <your_email>)` to unlock it.".to_string()
    })?;

    ArcanSession::from_env(&session_str)
}
