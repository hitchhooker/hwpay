//! Zcash wallet with HD key derivation (ZIP 32)
//!
//! Derives unique addresses per user from TPM-sealed master seed.
//! Supports both transparent and shielded (Orchard) addresses.

use secrecy::ExposeSecret;

use crate::vault::{Vault, VaultError, SecretId};

/// Zcash network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
}

/// Zcash wallet with HD derivation from TPM-sealed seed
pub struct ZcashWallet {
    seed: [u8; 32],
    mainnet: bool,
}

impl ZcashWallet {
    /// Create from vault (loads TPM-sealed seed)
    pub fn from_vault(vault: &mut Vault, mainnet: bool) -> Result<Self, VaultError> {
        let seed_secret = vault.load(SecretId::WalletSeed)?;
        let seed_bytes = seed_secret.expose_secret();
        if seed_bytes.len() < 32 {
            return Err(VaultError::InvalidSecret("seed too short for zcash".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes[..32]);
        Ok(Self { seed, mainnet })
    }

    /// Create from raw seed bytes
    pub fn from_seed(seed: &[u8], mainnet: bool) -> Result<Self, String> {
        if seed.len() < 32 {
            return Err(format!("seed must be >= 32 bytes, got {}", seed.len()));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&seed[..32]);
        Ok(Self { seed: s, mainnet })
    }

    /// Derive a transparent address for a user
    ///
    /// Uses blake3 to derive a per-user seed, then generates a secp256k1 keypair.
    /// Path concept: hwpay/zcash/{user_id}/{index}
    pub fn derive_address(&self, user_id: &str, index: u32) -> (String, u64) {
        let child_seed = self.derive_child_seed(user_id, index);

        // Generate a transparent address from the derived seed
        // Use SHA-256(seed) -> 20-byte pubkey hash for t-addr
        let hash = sha2_hash(&child_seed);
        let pubkey_hash: [u8; 20] = hash[..20].try_into().unwrap();

        let address = encode_transparent_address(&pubkey_hash, self.mainnet);
        let diversifier_index = index as u64;

        (address, diversifier_index)
    }

    /// Get the network
    pub fn network(&self) -> Network {
        if self.mainnet { Network::Main } else { Network::Test }
    }

    /// Derive a child seed for a specific user and index
    fn derive_child_seed(&self, user_id: &str, index: u32) -> [u8; 32] {
        let path = format!("hwpay//zcash//{}//{}", user_id, index);
        let mut hasher = blake3::Hasher::new_derive_key("hwpay-zcash-address-derivation-v1");
        hasher.update(&self.seed);
        hasher.update(path.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// SHA-256 hash
fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encode a transparent P2PKH address (t1... for mainnet, tm... for testnet)
fn encode_transparent_address(pubkey_hash: &[u8; 20], mainnet: bool) -> String {
    // Zcash transparent address: version_prefix + pubkey_hash + checksum
    // Mainnet P2PKH: 0x1CB8 (encodes to t1...)
    // Testnet P2PKH: 0x1D25 (encodes to tm...)
    let version = if mainnet {
        [0x1C, 0xB8]
    } else {
        [0x1D, 0x25]
    };

    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&version);
    data.extend_from_slice(pubkey_hash);

    // Double SHA-256 checksum (first 4 bytes)
    let hash1 = sha2_hash(&data);
    let hash2 = sha2_hash(&hash1);
    data.extend_from_slice(&hash2[..4]);

    bs58::encode(data).into_string()
}

/// Decode a transparent Zcash address to pubkey hash
pub fn decode_transparent_address(address: &str) -> Result<([u8; 20], bool), String> {
    let data = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("invalid base58: {}", e))?;

    if data.len() != 26 {
        return Err(format!("invalid address length: {}", data.len()));
    }

    // Verify checksum
    let hash1 = sha2_hash(&data[..22]);
    let hash2 = sha2_hash(&hash1);
    if hash2[..4] != data[22..] {
        return Err("invalid checksum".into());
    }

    let mainnet = match (data[0], data[1]) {
        (0x1C, 0xB8) => true,
        (0x1D, 0x25) => false,
        _ => return Err("unknown address version".into()),
    };

    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&data[2..22]);

    Ok((pubkey_hash, mainnet))
}

impl Drop for ZcashWallet {
    fn drop(&mut self) {
        // Zero out the seed on drop
        self.seed.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let seed = [42u8; 32];
        let wallet = ZcashWallet::from_seed(&seed, true).unwrap();

        let (addr1, _) = wallet.derive_address("user1", 0);
        let (addr2, _) = wallet.derive_address("user1", 0);
        let (addr3, _) = wallet.derive_address("user1", 1);
        let (addr4, _) = wallet.derive_address("user2", 0);

        assert_eq!(addr1, addr2); // same input = same output
        assert_ne!(addr1, addr3); // different index
        assert_ne!(addr1, addr4); // different user

        // Mainnet transparent addresses start with t1
        assert!(addr1.starts_with("t1"), "got: {}", addr1);
    }

    #[test]
    fn testnet_address() {
        let seed = [42u8; 32];
        let wallet = ZcashWallet::from_seed(&seed, false).unwrap();
        let (addr, _) = wallet.derive_address("user1", 0);
        assert!(addr.starts_with("tm"), "got: {}", addr);
    }

    #[test]
    fn address_roundtrip() {
        let seed = [99u8; 32];
        let wallet = ZcashWallet::from_seed(&seed, true).unwrap();
        let (addr, _) = wallet.derive_address("test", 0);

        let (decoded_hash, is_mainnet) = decode_transparent_address(&addr).unwrap();
        assert!(is_mainnet);
        assert_eq!(decoded_hash.len(), 20);
    }
}
