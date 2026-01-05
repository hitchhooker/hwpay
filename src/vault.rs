//! Unified secret vault with TPM-first approach
//!
//! Manages all secrets (wallet seeds, API keys) with hardware security.
//! Tries TPM first, falls back to encrypted file storage.

use std::collections::HashMap;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretBox};

use crate::tpm::{self, TpmError};
use crate::crypto::{self, CryptoError};

/// Secret identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum SecretId {
    /// Master wallet seed for HD derivation
    WalletSeed,
    /// Stripe secret key
    StripeSecretKey,
    /// Stripe webhook secret
    StripeWebhookSecret,
    /// Custom secret by name
    Custom(String),
}

impl SecretId {
    fn filename(&self) -> String {
        match self {
            Self::WalletSeed => "wallet.sealed".into(),
            Self::StripeSecretKey => "stripe_secret.sealed".into(),
            Self::StripeWebhookSecret => "stripe_webhook.sealed".into(),
            Self::Custom(name) => format!("{}.sealed", name),
        }
    }
}

/// Secret key wrapper with auto-zeroization
pub type SecretKey = SecretBox<Vec<u8>>;

#[derive(Debug)]
pub enum VaultError {
    Tpm(TpmError),
    Crypto(CryptoError),
    NotFound(SecretId),
    InvalidSecret(String),
    PasswordRequired,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tpm(e) => write!(f, "tpm: {}", e),
            Self::Crypto(e) => write!(f, "crypto: {}", e),
            Self::NotFound(id) => write!(f, "not found: {:?}", id),
            Self::InvalidSecret(s) => write!(f, "invalid: {}", s),
            Self::PasswordRequired => write!(f, "password required (TPM unavailable)"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<TpmError> for VaultError {
    fn from(e: TpmError) -> Self {
        Self::Tpm(e)
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Storage method used for secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMethod {
    Tpm,
    EncryptedFile,
}

/// Secure vault for managing secrets
pub struct Vault {
    data_dir: PathBuf,
    /// Cached secrets (in-memory, zeroized on drop)
    cache: HashMap<SecretId, SecretKey>,
    /// Password for encrypted file fallback
    password: Option<SecretKey>,
    /// Whether TPM is being used
    uses_tpm: bool,
}

impl Vault {
    /// Open or create vault at default location (~/.hwpay)
    pub fn open(password: Option<&[u8]>) -> Result<Self, VaultError> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let data_dir = PathBuf::from(home).join(".hwpay");
        Self::open_at(data_dir, password)
    }

    /// Open vault at specific location
    pub fn open_at(data_dir: PathBuf, password: Option<&[u8]>) -> Result<Self, VaultError> {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| VaultError::Crypto(CryptoError::Io(e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| VaultError::Crypto(CryptoError::Io(e)))?;
        }

        let uses_tpm = tpm::is_available();
        if uses_tpm {
            tracing::info!("TPM available - using hardware security");
        } else {
            tracing::info!("TPM not available - using encrypted file storage");
        }

        Ok(Self {
            data_dir,
            cache: HashMap::new(),
            password: password.map(|p| SecretBox::new(Box::new(p.to_vec()))),
            uses_tpm,
        })
    }

    /// Check if TPM is being used
    pub fn uses_tpm(&self) -> bool {
        self.uses_tpm
    }

    /// Get current storage method
    pub fn storage_method(&self) -> StorageMethod {
        if self.uses_tpm {
            StorageMethod::Tpm
        } else {
            StorageMethod::EncryptedFile
        }
    }

    /// Store a secret - tries TPM first, falls back to encrypted file
    pub fn store(&mut self, id: SecretId, secret: &[u8]) -> Result<StorageMethod, VaultError> {
        let path = self.data_dir.join(id.filename());

        // Try TPM first
        if self.uses_tpm {
            match tpm::seal_to_file(secret, &path) {
                Ok(()) => {
                    self.cache.insert(id, SecretBox::new(Box::new(secret.to_vec())));
                    return Ok(StorageMethod::Tpm);
                }
                Err(TpmError::NotAvailable) => {
                    tracing::warn!("TPM became unavailable, falling back to encrypted");
                    self.uses_tpm = false;
                }
                Err(e) => return Err(VaultError::Tpm(e)),
            }
        }

        // Fall back to encrypted file
        let password = self.password.as_ref()
            .ok_or(VaultError::PasswordRequired)?;
        crypto::encrypt_to_file(secret, password.expose_secret(), &path)?;
        self.cache.insert(id, SecretBox::new(Box::new(secret.to_vec())));
        Ok(StorageMethod::EncryptedFile)
    }

    /// Load a secret
    pub fn load(&mut self, id: SecretId) -> Result<SecretKey, VaultError> {
        // Check cache first
        if let Some(secret) = self.cache.get(&id) {
            return Ok(SecretBox::new(Box::new(secret.expose_secret().clone())));
        }

        let path = self.data_dir.join(id.filename());
        if !path.exists() {
            return Err(VaultError::NotFound(id));
        }

        // Try TPM first
        let secret = if self.uses_tpm {
            match tpm::unseal_from_file(&path) {
                Ok(s) => s,
                Err(TpmError::NotAvailable) => {
                    tracing::warn!("TPM unavailable, trying encrypted");
                    self.uses_tpm = false;
                    let password = self.password.as_ref()
                        .ok_or(VaultError::PasswordRequired)?;
                    crypto::decrypt_from_file(&path, password.expose_secret())?
                }
                Err(e) => return Err(VaultError::Tpm(e)),
            }
        } else {
            let password = self.password.as_ref()
                .ok_or(VaultError::PasswordRequired)?;
            crypto::decrypt_from_file(&path, password.expose_secret())?
        };

        self.cache.insert(id.clone(), SecretBox::new(Box::new(secret.expose_secret().clone())));
        Ok(secret)
    }

    /// Check if a secret exists
    pub fn exists(&self, id: &SecretId) -> bool {
        self.cache.contains_key(id) || self.data_dir.join(id.filename()).exists()
    }

    /// Delete a secret
    pub fn delete(&mut self, id: &SecretId) -> Result<(), VaultError> {
        self.cache.remove(id);
        let path = self.data_dir.join(id.filename());
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| VaultError::Crypto(CryptoError::Io(e)))?;
        }
        Ok(())
    }

    /// Get vault status
    pub fn status(&self) -> VaultStatus {
        VaultStatus {
            tpm_available: tpm::is_available(),
            uses_tpm: self.uses_tpm,
            has_password: self.password.is_some(),
            secrets: self.list_secrets(),
        }
    }

    /// List stored secrets
    pub fn list_secrets(&self) -> Vec<SecretId> {
        let mut secrets = Vec::new();

        if self.exists(&SecretId::WalletSeed) {
            secrets.push(SecretId::WalletSeed);
        }
        if self.exists(&SecretId::StripeSecretKey) {
            secrets.push(SecretId::StripeSecretKey);
        }
        if self.exists(&SecretId::StripeWebhookSecret) {
            secrets.push(SecretId::StripeWebhookSecret);
        }

        // Check for custom secrets
        if let Ok(entries) = std::fs::read_dir(&self.data_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".sealed") {
                    let key = name.trim_end_matches(".sealed");
                    if !["wallet", "stripe_secret", "stripe_webhook"].contains(&key) {
                        secrets.push(SecretId::Custom(key.into()));
                    }
                }
            }
        }

        secrets
    }
}

#[derive(Debug)]
pub struct VaultStatus {
    pub tpm_available: bool,
    pub uses_tpm: bool,
    pub has_password: bool,
    pub secrets: Vec<SecretId>,
}

impl std::fmt::Display for VaultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Vault Status:")?;
        writeln!(f, "  TPM available: {}", self.tpm_available)?;
        writeln!(f, "  Using TPM: {}", self.uses_tpm)?;
        writeln!(f, "  Password set: {}", self.has_password)?;
        writeln!(f, "  Secrets: {:?}", self.secrets)?;
        Ok(())
    }
}
