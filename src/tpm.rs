//! TPM 2.0 hardware security module
//!
//! Seals secrets to TPM, binding them to this machine's hardware.
//! Secrets can only be unsealed on the same machine with same boot config.

use std::io;
use std::path::Path;
use std::str::FromStr;

use secrecy::SecretBox;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Digest, Public, PublicBuilder, PublicKeyedHashParameters,
        SensitiveData, SymmetricCipherParameters,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context,
};

pub type SecretBytes = SecretBox<Vec<u8>>;

#[derive(Debug)]
pub enum TpmError {
    NotAvailable,
    SealFailed(String),
    UnsealFailed(String),
    Io(io::Error),
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => write!(f, "TPM not available"),
            Self::SealFailed(s) => write!(f, "seal failed: {}", s),
            Self::UnsealFailed(s) => write!(f, "unseal failed: {}", s),
            Self::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for TpmError {}

impl From<io::Error> for TpmError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Check if TPM is available
pub fn is_available() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

fn create_context() -> Result<Context, TpmError> {
    if !is_available() {
        return Err(TpmError::NotAvailable);
    }

    let tcti = if Path::new("/dev/tpmrm0").exists() {
        TctiNameConf::Device(
            DeviceConfig::from_str("/dev/tpmrm0")
                .map_err(|e| TpmError::SealFailed(format!("device: {}", e)))?,
        )
    } else {
        TctiNameConf::Device(
            DeviceConfig::from_str("/dev/tpm0")
                .map_err(|e| TpmError::SealFailed(format!("device: {}", e)))?,
        )
    };

    let mut ctx = Context::new(tcti)
        .map_err(|e| TpmError::SealFailed(format!("context: {}", e)))?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    Ok(ctx)
}

fn create_primary_key(ctx: &mut Context) -> Result<KeyHandle, TpmError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| TpmError::SealFailed(format!("attrs: {}", e)))?;

    let sym = SymmetricCipherParameters::new(
        tss_esapi::structures::SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes256,
            mode: SymmetricMode::Cfb,
        },
    );

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_symmetric_cipher_parameters(sym)
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .map_err(|e| TpmError::SealFailed(format!("public: {}", e)))?;

    let result = ctx
        .create_primary(Hierarchy::Owner, public, None, None, None, None)
        .map_err(|e| TpmError::SealFailed(format!("primary: {}", e)))?;

    Ok(result.key_handle)
}

/// Seal data to TPM
pub fn seal(data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let mut ctx = create_context()?;
    let primary = create_primary_key(&mut ctx)?;

    let sensitive = SensitiveData::try_from(data.to_vec())
        .map_err(|_| TpmError::SealFailed("data too large".into()))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|e| TpmError::SealFailed(format!("attrs: {}", e)))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            tss_esapi::structures::KeyedHashScheme::Null,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| TpmError::SealFailed(format!("public: {}", e)))?;

    let result = ctx
        .create(primary, public, None, Some(sensitive), None, None)
        .map_err(|e| TpmError::SealFailed(format!("create: {}", e)))?;

    let private: Vec<u8> = result.out_private.value().to_vec();
    let public_buf: tss_esapi::structures::PublicBuffer = result
        .out_public
        .try_into()
        .map_err(|e: tss_esapi::Error| TpmError::SealFailed(format!("public: {}", e)))?;
    let public: Vec<u8> = public_buf.value().to_vec();

    let mut sealed = Vec::with_capacity(4 + private.len() + public.len());
    sealed.extend_from_slice(&(private.len() as u32).to_le_bytes());
    sealed.extend_from_slice(&private);
    sealed.extend_from_slice(&public);

    ctx.flush_context(primary.into()).ok();
    tracing::debug!("sealed {} bytes to TPM", data.len());
    Ok(sealed)
}

/// Unseal data from TPM
pub fn unseal(blob: &[u8]) -> Result<SecretBytes, TpmError> {
    if blob.len() < 4 {
        return Err(TpmError::UnsealFailed("invalid blob".into()));
    }

    let mut ctx = create_context()?;
    let primary = create_primary_key(&mut ctx)?;

    let private_len = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
    if blob.len() < 4 + private_len {
        return Err(TpmError::UnsealFailed("truncated".into()));
    }

    let private = tss_esapi::structures::Private::try_from(blob[4..4 + private_len].to_vec())
        .map_err(|e| TpmError::UnsealFailed(format!("private: {:?}", e)))?;

    let public_buf = tss_esapi::structures::PublicBuffer::try_from(blob[4 + private_len..].to_vec())
        .map_err(|e| TpmError::UnsealFailed(format!("public buf: {:?}", e)))?;
    let public = Public::try_from(public_buf)
        .map_err(|e| TpmError::UnsealFailed(format!("public: {:?}", e)))?;

    let key = ctx
        .load(primary, private, public)
        .map_err(|e| TpmError::UnsealFailed(format!("load: {}", e)))?;

    let unsealed = ctx
        .unseal(key.into())
        .map_err(|e| TpmError::UnsealFailed(format!("unseal: {}", e)))?;

    ctx.flush_context(key.into()).ok();
    ctx.flush_context(primary.into()).ok();

    tracing::debug!("unsealed from TPM");
    Ok(SecretBox::new(Box::new(unsealed.to_vec())))
}

/// Seal to file with restrictive permissions
pub fn seal_to_file(data: &[u8], path: &Path) -> Result<(), TpmError> {
    let sealed = seal(data)?;

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
    f.write_all(&sealed)?;
    f.sync_all()?;

    tracing::info!("sealed to TPM: {:?}", path);
    Ok(())
}

/// Unseal from file
pub fn unseal_from_file(path: &Path) -> Result<SecretBytes, TpmError> {
    let sealed = std::fs::read(path)?;
    unseal(&sealed)
}
