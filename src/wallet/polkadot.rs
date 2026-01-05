//! Polkadot/Substrate wallet with sr25519 key derivation
//!
//! Derives unique addresses per user from TPM-sealed master seed.

use schnorrkel::{MiniSecretKey, SecretKey, PublicKey, derive::ChainCode, signing_context};
use secrecy::ExposeSecret;

use crate::vault::{Vault, VaultError, SecretId};

/// SS58 prefix for Polkadot (and Asset Hub)
const POLKADOT_PREFIX: u16 = 0;

/// SS58 prefix for Kusama Asset Hub
const KUSAMA_PREFIX: u16 = 2;

/// Polkadot wallet with HD derivation
pub struct PolkadotWallet {
    master_secret: SecretKey,
}

impl PolkadotWallet {
    /// Create from vault (loads TPM-sealed seed)
    pub fn from_vault(vault: &mut Vault) -> Result<Self, VaultError> {
        let seed = vault.load(SecretId::WalletSeed)?;
        Self::from_seed(seed.expose_secret())
            .map_err(|e| VaultError::InvalidSecret(e))
    }

    /// Create from raw seed bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        let master_secret = if seed.len() == 32 {
            let mini = MiniSecretKey::from_bytes(seed)
                .map_err(|e| format!("invalid mini secret: {:?}", e))?;
            mini.expand(MiniSecretKey::ED25519_MODE)
        } else if seed.len() == 64 {
            SecretKey::from_bytes(seed)
                .map_err(|e| format!("invalid secret: {:?}", e))?
        } else {
            return Err(format!("seed must be 32 or 64 bytes, got {}", seed.len()));
        };

        Ok(Self { master_secret })
    }

    /// Derive address for user at derivation index
    /// Path: //hwpay//{user_id}//{index}
    pub fn derive_address(&self, user_id: &str, index: u32) -> String {
        self.derive_address_with_prefix(user_id, index, POLKADOT_PREFIX)
    }

    /// Derive Kusama address
    pub fn derive_kusama_address(&self, user_id: &str, index: u32) -> String {
        self.derive_address_with_prefix(user_id, index, KUSAMA_PREFIX)
    }

    /// Derive address with custom SS58 prefix
    pub fn derive_address_with_prefix(&self, user_id: &str, index: u32, prefix: u16) -> String {
        let (_, public) = self.derive_keypair(user_id, index);
        encode_ss58(&public.to_bytes(), prefix)
    }

    /// Derive keypair for signing
    pub fn derive_keypair(&self, user_id: &str, index: u32) -> (SecretKey, PublicKey) {
        let path = format!("hwpay//{}//{}", user_id, index);
        let chain_code = self.path_to_chain_code(&path);

        let (mini, _) = self.master_secret.hard_derive_mini_secret_key(
            Some(chain_code),
            b"",
        );

        let secret = mini.expand(MiniSecretKey::ED25519_MODE);
        let public = secret.to_public();
        (secret, public)
    }

    /// Sign message with derived key
    pub fn sign(&self, user_id: &str, index: u32, message: &[u8]) -> [u8; 64] {
        let (secret, public) = self.derive_keypair(user_id, index);
        let ctx = signing_context(b"substrate");
        let sig = secret.sign(ctx.bytes(message), &public);
        sig.to_bytes()
    }

    fn path_to_chain_code(&self, path: &str) -> ChainCode {
        let hash = blake3::hash(format!("HDKD:{}", path).as_bytes());
        ChainCode(*hash.as_bytes())
    }
}

/// Encode public key as SS58 address
fn encode_ss58(pubkey: &[u8; 32], prefix: u16) -> String {
    let mut data = Vec::with_capacity(35);

    if prefix < 64 {
        data.push(prefix as u8);
    } else if prefix < 16384 {
        data.push(((prefix & 0x00FC) >> 2) as u8 | 0x40);
        data.push(((prefix >> 8) as u8) | ((prefix & 0x0003) << 6) as u8);
    } else {
        panic!("prefix too large");
    }

    data.extend_from_slice(pubkey);

    // SS58 checksum
    let mut hasher = blake2b_simd::Params::new()
        .hash_length(64)
        .to_state();
    hasher.update(b"SS58PRE");
    hasher.update(&data);
    let checksum = hasher.finalize();
    data.extend_from_slice(&checksum.as_bytes()[..2]);

    bs58::encode(data).into_string()
}

/// Decode SS58 address to public key
pub fn decode_ss58(address: &str) -> Result<[u8; 32], String> {
    let data = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("invalid base58: {}", e))?;

    if data.len() < 35 {
        return Err("address too short".into());
    }

    let prefix_len = if data[0] < 64 { 1 } else { 2 };

    if data.len() != prefix_len + 32 + 2 {
        return Err(format!("invalid length: {}", data.len()));
    }

    let pubkey: [u8; 32] = data[prefix_len..prefix_len + 32]
        .try_into()
        .map_err(|_| "invalid pubkey")?;

    // Verify checksum
    let mut hasher = blake2b_simd::Params::new()
        .hash_length(64)
        .to_state();
    hasher.update(b"SS58PRE");
    hasher.update(&data[..prefix_len + 32]);
    let checksum = hasher.finalize();

    if &checksum.as_bytes()[..2] != &data[prefix_len + 32..] {
        return Err("invalid checksum".into());
    }

    Ok(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let seed = [0u8; 32];
        let wallet = PolkadotWallet::from_seed(&seed).unwrap();

        let addr1 = wallet.derive_address("user1", 0);
        let addr2 = wallet.derive_address("user1", 0);
        let addr3 = wallet.derive_address("user1", 1);
        let addr4 = wallet.derive_address("user2", 0);

        assert_eq!(addr1, addr2); // same input = same output
        assert_ne!(addr1, addr3); // different index
        assert_ne!(addr1, addr4); // different user

        // Polkadot addresses start with 1
        assert!(addr1.starts_with('1'));
    }

    #[test]
    fn ss58_roundtrip() {
        let seed = [1u8; 32];
        let wallet = PolkadotWallet::from_seed(&seed).unwrap();
        let (_, public) = wallet.derive_keypair("test", 0);

        let address = encode_ss58(&public.to_bytes(), POLKADOT_PREFIX);
        let decoded = decode_ss58(&address).unwrap();

        assert_eq!(public.to_bytes(), decoded);
    }
}
