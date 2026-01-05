//! Blockchain listeners for deposit detection

pub mod polkadot;
pub mod assethub;

#[cfg(feature = "penumbra")]
pub mod penumbra;

use serde::{Deserialize, Serialize};

/// Detected deposit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    /// Transaction/extrinsic hash or block hash
    pub tx_hash: String,
    /// Block number
    pub block_number: u64,
    /// Source address
    pub from: String,
    /// Destination address (our derived address)
    pub to: String,
    /// Amount in human-readable format (e.g., 10.5 USDC)
    pub amount: f64,
    /// Asset identifier
    pub asset: Asset,
    /// User ID associated with this address
    pub user_id: String,
    /// Derivation index
    pub derivation_index: u32,
}

/// Supported assets
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Asset {
    /// USDC
    Usdc,
    /// USDT
    Usdt,
    /// Native DOT
    Dot,
}

impl Asset {
    /// Get decimals for this asset
    pub fn decimals(&self) -> u8 {
        match self {
            Self::Usdc | Self::Usdt => 6,
            Self::Dot => 10,
        }
    }
}

impl std::fmt::Display for Asset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usdc => write!(f, "USDC"),
            Self::Usdt => write!(f, "USDT"),
            Self::Dot => write!(f, "DOT"),
        }
    }
}

/// Callback for deposit handling
#[async_trait::async_trait]
pub trait DepositCallback: Send + Sync {
    /// Called when a deposit is detected
    async fn on_deposit(&self, deposit: Deposit) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Simple function-based callback wrapper
pub struct FnCallback<F>(pub F);

#[async_trait::async_trait]
impl<F, Fut> DepositCallback for FnCallback<F>
where
    F: Fn(Deposit) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send,
{
    async fn on_deposit(&self, deposit: Deposit) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (self.0)(deposit).await
    }
}
