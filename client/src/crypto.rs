use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{SaltString, rand_core::RngCore},
};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, Payload},
};
use hkdf::Hkdf;
use secrecy::SecretBox;
use sha2::Sha256;

pub fn derive_master_key(
    password: &str,
    salt: &SaltString,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // OWASP recommended baseline parameters for Argon2id
    let params = Params::new(
        65536,    // m_cost: 64 MB memory
        3,        // t_cost: 3 iterations
        4,        // p_cost: 4 degrees of parallelism
        Some(32), // Output length: 32 bytes (256 bits) for XChaCha20
    )
    .unwrap();

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
        .expect("Failed to derive key");

    Ok(key)
}

pub fn derive_subkey(root_key: &[u8; 32], name: &str) -> SecretBox<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut derived_key = [0u8; 32];
    hk.expand(name.as_bytes(), &mut derived_key)
        .expect("HKDF expand failed");
    SecretBox::new(Box::new(derived_key))
}

pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: XNonce,
}

impl EncryptedPayload {
    /// Packs the nonce and ciphertext together for storage or transmission.
    pub fn pack(&self) -> Vec<u8> {
        let mut packed = Vec::with_capacity(24 + self.ciphertext.len());
        packed.extend_from_slice(self.nonce.as_slice());
        packed.extend_from_slice(&self.ciphertext);
        packed
    }

    /// Unpacks the nonce and ciphertext from the combined format.
    pub fn unpack(packed: &[u8]) -> Result<Self, &'static str> {
        if packed.len() < 24 + 16 {
            return Err("Payload too short to be valid XChaCha20Poly1305");
        }

        let (nonce, ciphertext) = packed.split_at(24);

        Ok(Self {
            nonce: XNonce::from_slice(nonce).clone(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

pub fn encrypt_payload(
    key: &[u8; 32],
    plaintext: &[u8],
    vault_id: &str, // Used as Associated Data
) -> Result<EncryptedPayload, Box<dyn std::error::Error>> {
    // Returns (Ciphertext, Nonce)
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);

    // Generate a random 192-bit (24-byte) nonce
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: vault_id.as_bytes(), // Binds the data to this specific vault
    };

    // The ciphertext returned here automatically includes the 16-byte Poly1305 MAC tag at the end.
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| "Encryption failed")?;

    Ok(EncryptedPayload { ciphertext, nonce })
}

pub fn decrypt_payload(
    key: &[u8; 32],
    encrypted_payload: &EncryptedPayload,
    vault_id: &str,
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);

    let payload = Payload {
        msg: &encrypted_payload.ciphertext,
        aad: vault_id.as_bytes(),
    };

    // This will fail if the ciphertext was altered, the key is wrong,
    // or the vault_id (AAD) doesn't match.
    cipher.decrypt(&encrypted_payload.nonce, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let vault = "vault-123";

        let enc = encrypt_payload(&key, plaintext, vault).expect("encryption failed");
        let decrypted = decrypt_payload(&key, &enc, vault).expect("decryption failed");
        assert_eq!(decrypted, plaintext);

        // pack/unpack roundtrip
        let packed = enc.pack();
        let unpacked = EncryptedPayload::unpack(&packed).expect("unpack failed");
        let decrypted2 =
            decrypt_payload(&key, &unpacked, vault).expect("decryption failed after unpack");
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_unpack_short_payload() {
        let short = vec![0u8; 10];
        assert!(EncryptedPayload::unpack(&short).is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_key_or_aad_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret data";
        let vault = "vault-abc";

        let enc = encrypt_payload(&key1, plaintext, vault).expect("encryption failed");

        // Wrong key should fail
        assert!(decrypt_payload(&key2, &enc, vault).is_err());

        // Wrong AAD (vault id) should fail
        assert!(decrypt_payload(&key1, &enc, "other-vault").is_err());
    }

    #[test]
    fn test_derive_subkey_deterministic() {
        let root = [0xABu8; 32];
        let s1 = derive_subkey(&root, "info");
        let s2 = derive_subkey(&root, "info");
        assert_eq!(s1.expose_secret(), s2.expose_secret());

        let s3 = derive_subkey(&root, "other");
        assert_ne!(s1.expose_secret(), s3.expose_secret());
    }
}
