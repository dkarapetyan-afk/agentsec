use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::Rng;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; KEY_SIZE]);

impl MasterKey {
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// Encrypts plaintext bytes using ChaCha20-Poly1305.
/// Output format: [12-byte random nonce] || [ciphertext with Poly1305 tag]
pub fn encrypt_bytes(key: &MasterKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption error: {}", e))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts encrypted bytes produced by `encrypt_bytes`.
pub fn decrypt_bytes(key: &MasterKey, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
    if encrypted_payload.len() < NONCE_SIZE {
        return Err(anyhow!("Ciphertext payload too short"));
    }

    let (nonce_bytes, ciphertext) = encrypted_payload.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption error (corrupted data or invalid key): {}", e))?;

    Ok(plaintext)
}

/// Derives a 32-byte master key from a user passphrase and salt using Argon2id.
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<MasterKey> {
    let mut key = [0u8; KEY_SIZE];
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2id derivation failed: {}", e))?;

    Ok(MasterKey::new(key))
}

/// Load existing master key from file or generate a new random 256-bit key.
pub fn get_or_create_master_key(path: &Path) -> Result<MasterKey> {
    if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read master key from {:?}", path))?;
        let trimmed = content.trim();
        let bytes =
            hex::decode(trimmed).with_context(|| "Invalid hex encoding in master key file")?;
        if bytes.len() != KEY_SIZE {
            return Err(anyhow!(
                "Invalid master key length: expected {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            ));
        }
        let mut key_arr = [0u8; KEY_SIZE];
        key_arr.copy_from_slice(&bytes);
        return Ok(MasterKey::new(key_arr));
    }

    let key = MasterKey::generate();
    let hex_encoded = hex::encode(key.as_bytes());

    fs::write(path, &hex_encoded)
        .with_context(|| format!("Failed to write master key to {:?}", path))?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_encryption_roundtrip() {
        let key = MasterKey::generate();
        let secret_text = b"sk-ant-api03-ultra-secret-key-123456789";

        let encrypted = encrypt_bytes(&key, secret_text).unwrap();
        assert_ne!(encrypted, secret_text);

        let decrypted = decrypt_bytes(&key, &encrypted).unwrap();
        assert_eq!(decrypted, secret_text);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let key = MasterKey::generate();
        let mut encrypted = encrypt_bytes(&key, b"hello world").unwrap();
        // Corrupt one byte
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        assert!(decrypt_bytes(&key, &encrypted).is_err());
    }

    #[test]
    fn test_master_key_file() {
        let temp_dir =
            env::temp_dir().join(format!("agentsec_crypto_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let key_path = temp_dir.join("master.key");

        let key1 = get_or_create_master_key(&key_path).unwrap();
        let key2 = get_or_create_master_key(&key_path).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
