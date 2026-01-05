//! Cryptographic utilities - encrypted storage fallback
//!
//! When TPM is unavailable, uses Argon2id + ChaCha20-Poly1305.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use std::io;
use std::path::Path;

pub type SecretBytes = SecretBox<Vec<u8>>;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

const MAGIC: &[u8; 4] = b"HWP\x01";

#[derive(Debug)]
pub enum CryptoError {
    Kdf(&'static str),
    Encryption(&'static str),
    Decryption(&'static str),
    InvalidData(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(s) => write!(f, "kdf: {}", s),
            Self::Encryption(s) => write!(f, "encrypt: {}", s),
            Self::Decryption(s) => write!(f, "decrypt: {}", s),
            Self::InvalidData(s) => write!(f, "invalid: {}", s),
            Self::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Argon2id params - OWASP recommended
fn argon2_params() -> Params {
    Params::new(64 * 1024, 3, 4, Some(KEY_LEN)).expect("valid params")
}

/// Derive key from password
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<SecretBox<[u8; KEY_LEN]>, CryptoError> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params());
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::Kdf("argon2 failed"))?;
    Ok(SecretBox::new(Box::new(key)))
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt with ChaCha20-Poly1305
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::Encryption("key"))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encryption("encrypt"))?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<SecretBytes, CryptoError> {
    let min = MAGIC.len() + SALT_LEN + NONCE_LEN + 16;
    if data.len() < min {
        return Err(CryptoError::InvalidData("too short"));
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidData("bad magic"));
    }

    let off = MAGIC.len();
    let salt = &data[off..off + SALT_LEN];
    let nonce_bytes = &data[off + SALT_LEN..off + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[off + SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, salt)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::Decryption("key"))?;

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption("wrong password or corrupted"))?;

    let secret = SecretBox::new(Box::new(plaintext.clone()));
    plaintext.zeroize();
    Ok(secret)
}

/// Encrypt to file
pub fn encrypt_to_file(data: &[u8], password: &[u8], path: &Path) -> Result<(), CryptoError> {
    let encrypted = encrypt(data, password)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&encrypted)?;
    f.sync_all()?;

    tracing::info!("encrypted to: {:?}", path);
    Ok(())
}

/// Decrypt from file
pub fn decrypt_from_file(path: &Path, password: &[u8]) -> Result<SecretBytes, CryptoError> {
    let data = std::fs::read(path)?;
    decrypt(&data, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let plain = b"test secret data";
        let pass = b"password123";
        let enc = encrypt(plain, pass).unwrap();
        let dec = decrypt(&enc, pass).unwrap();
        assert_eq!(dec.expose_secret().as_slice(), plain);
    }

    #[test]
    fn wrong_password() {
        let enc = encrypt(b"secret", b"correct").unwrap();
        assert!(decrypt(&enc, b"wrong").is_err());
    }
}
