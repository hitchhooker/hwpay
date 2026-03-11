//! hwpay - Hardware-secured payment processor
//!
//! A Rust library for accepting crypto and fiat payments with TPM 2.0 hardware security.
//!
//! # Features
//!
//! - **TPM 2.0 Hardware Security**: Master keys sealed to TPM, hardware-bound
//! - **Polkadot Asset Hub**: USDC/USDT via smoldot light client
//! - **Penumbra**: Shielded USDC payments (optional)
//! - **Stripe**: Credit card payments with TPM-secured API keys
//! - **HD Wallet Derivation**: Unique addresses per user with rotation support
//!
//! # Example
//!
//! ```rust,no_run
//! use hwpay::{Vault, PaymentProcessor};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize vault (tries TPM, falls back to encrypted file)
//!     let vault = Vault::open(None)?;
//!
//!     // Create payment processor
//!     let mut processor = PaymentProcessor::new(vault);
//!
//!     // Initialize polkadot wallet from sealed seed
//!     processor.init_polkadot()?;
//!
//!     // Get deposit address for a user
//!     if let Some(address) = processor.polkadot_address("user@example.com", 0) {
//!         println!("Send USDC to: {}", address);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod tpm;
pub mod crypto;
pub mod vault;
pub mod wallet;
pub mod listener;
pub mod stripe;
pub mod proxy;
pub mod sweep;

// Re-exports
pub use vault::{Vault, VaultError, SecretKey, SecretId, StorageMethod};
pub use wallet::polkadot::PolkadotWallet;
pub use listener::polkadot::PolkadotListener;
pub use listener::assethub::AssetHubListener;
pub use listener::{Deposit, DepositCallback, Asset};
pub use stripe::{StripeProcessor, StripeError, PaymentIntent, CheckoutSession, WebhookEvent};
pub use proxy::{ProxyManager, ProxyConfig, ProxyType, TierConfig, PureProxyResult, ProxyError};
pub use sweep::{Sweeper, SweepConfig, SweepResult};

#[cfg(feature = "zcash")]
pub use wallet::zcash::ZcashWallet;
#[cfg(feature = "zcash")]
pub use listener::zcash::{ZcashListener, ZcashListenerConfig};

use secrecy::SecretBox;

/// Type alias for secret bytes with auto-zeroization
pub type SecretBytes = SecretBox<Vec<u8>>;

/// Payment processor combining all payment methods
pub struct PaymentProcessor {
    vault: Vault,
    polkadot: Option<PolkadotWallet>,
}

impl PaymentProcessor {
    /// Create a new payment processor from an open vault
    pub fn new(vault: Vault) -> Self {
        Self { vault, polkadot: None }
    }

    /// Initialize polkadot wallet from vault seed
    pub fn init_polkadot(&mut self) -> Result<(), VaultError> {
        let wallet = PolkadotWallet::from_vault(&mut self.vault)?;
        self.polkadot = Some(wallet);
        Ok(())
    }

    /// Get a Polkadot deposit address for a user
    pub fn polkadot_address(&self, user_id: &str, derivation_index: u32) -> Option<String> {
        self.polkadot.as_ref().map(|w| w.derive_address(user_id, derivation_index))
    }

    /// Rotate a user's Polkadot address (returns new address and index)
    pub fn rotate_polkadot_address(&self, user_id: &str, current_index: u32) -> Option<(String, u32)> {
        self.polkadot.as_ref().map(|w| {
            let new_index = current_index + 1;
            let address = w.derive_address(user_id, new_index);
            (address, new_index)
        })
    }

    /// Get the Stripe processor (if configured)
    pub fn stripe(&mut self) -> Result<StripeProcessor, VaultError> {
        StripeProcessor::from_vault(&mut self.vault)
    }

    /// Get the underlying vault
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Get mutable vault reference
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }
}
