//! Penumbra wallet for shielded payments
//!
//! Uses penumbra-sdk-keys for address derivation from spending keys.

use penumbra_sdk_keys::keys::{AddressIndex, SpendKey, SpendKeyBytes, FullViewingKey};
use sha2::{Sha256, Digest};
use std::str::FromStr;

/// Penumbra wallet for deriving shielded payment addresses
pub struct PenumbraWallet {
    spend_key: SpendKey,
    fvk: FullViewingKey,
}

impl PenumbraWallet {
    /// Create from 32-byte seed
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        if seed.len() < 32 {
            return Err(format!("seed must be at least 32 bytes, got {}", seed.len()));
        }

        let mut spend_key_bytes = [0u8; 32];
        spend_key_bytes.copy_from_slice(&seed[..32]);

        let spend_key = SpendKey::from(SpendKeyBytes(spend_key_bytes));
        let fvk = spend_key.full_viewing_key().clone();

        Ok(Self { spend_key, fvk })
    }

    /// Create from bech32-encoded spend key (penumbraspendkey1...)
    pub fn from_spend_key_bech32(spend_key_str: &str) -> Result<Self, String> {
        let spend_key = SpendKey::from_str(spend_key_str)
            .map_err(|e| format!("invalid spend key: {}", e))?;
        let fvk = spend_key.full_viewing_key().clone();

        Ok(Self { spend_key, fvk })
    }

    /// Compute the address index for a user
    ///
    /// Returns the u32 account index that penumbra uses internally.
    /// Store this in your database to map incoming deposits back to users.
    pub fn compute_address_index(user_id: &str, derivation_index: u32) -> u32 {
        let mut hasher = Sha256::new();
        hasher.update(b"penumbra-address-index:");
        hasher.update(user_id.as_bytes());
        hasher.update(&derivation_index.to_le_bytes());
        let hash = hasher.finalize();

        let account = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        account.wrapping_add(derivation_index)
    }

    /// Derive a payment address for a user
    ///
    /// Returns (address, address_index) where address_index is the u32 to store
    /// in your database for mapping incoming deposits back to users.
    pub fn derive_address(&self, user_id: &str, derivation_index: u32) -> (String, u32) {
        let account = Self::compute_address_index(user_id, derivation_index);
        let address_index = AddressIndex::new(account);

        let ivk = self.fvk.incoming();
        let (address, _dtk) = ivk.payment_address(address_index);

        (address.to_string(), account)
    }

    /// Derive address by raw index (for looking up by stored index)
    pub fn derive_address_by_index(&self, index: u32) -> String {
        let address_index = AddressIndex::new(index);
        let ivk = self.fvk.incoming();
        let (address, _dtk) = ivk.payment_address(address_index);
        address.to_string()
    }

    /// Get the full viewing key (for view service setup)
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Get the full viewing key encoded (for view service setup)
    pub fn full_viewing_key_encoded(&self) -> String {
        self.fvk.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_addresses() {
        let seed = [0u8; 32];
        let wallet = PenumbraWallet::from_seed(&seed).unwrap();

        let (addr1, idx1) = wallet.derive_address("user1@example.com", 0);
        let (addr2, idx2) = wallet.derive_address("user1@example.com", 1);
        let (addr3, idx3) = wallet.derive_address("user2@example.com", 0);

        // all addresses and indices should be different
        assert_ne!(addr1, addr2);
        assert_ne!(addr1, addr3);
        assert_ne!(idx1, idx2);
        assert_ne!(idx1, idx3);

        // addresses should start with penumbra1
        assert!(addr1.starts_with("penumbra1"));

        // indices should be consistent with compute_address_index
        assert_eq!(idx1, PenumbraWallet::compute_address_index("user1@example.com", 0));
        assert_eq!(idx2, PenumbraWallet::compute_address_index("user1@example.com", 1));
    }

    #[test]
    fn test_deterministic() {
        let seed = [42u8; 32];
        let wallet1 = PenumbraWallet::from_seed(&seed).unwrap();
        let wallet2 = PenumbraWallet::from_seed(&seed).unwrap();

        let (addr1, idx1) = wallet1.derive_address("test", 0);
        let (addr2, idx2) = wallet2.derive_address("test", 0);

        assert_eq!(addr1, addr2);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_derive_by_index() {
        let seed = [42u8; 32];
        let wallet = PenumbraWallet::from_seed(&seed).unwrap();

        let (addr, idx) = wallet.derive_address("user123", 0);
        let addr_by_idx = wallet.derive_address_by_index(idx);

        assert_eq!(addr, addr_by_idx);
    }
}
