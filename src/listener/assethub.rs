//! Asset Hub runtime types and event decoding
//!
//! Uses subxt dynamic event decoding to avoid compile-time metadata fetch.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::ext::scale_value::At;

use crate::listener::{Deposit, DepositCallback, Asset};

/// USDC asset ID on Asset Hub (Polkadot)
pub const USDC_ASSET_ID: u32 = 1337;
/// USDT asset ID on Asset Hub (Polkadot)
pub const USDT_ASSET_ID: u32 = 1984;

/// Default Asset Hub RPC endpoint
pub const DEFAULT_RPC_URL: &str = "wss://polkadot-asset-hub-rpc.polkadot.io";

#[derive(Debug)]
pub enum ListenerError {
    Subxt(String),
    NoAddresses,
    Decode(String),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subxt(s) => write!(f, "subxt: {}", s),
            Self::NoAddresses => write!(f, "no addresses to watch"),
            Self::Decode(s) => write!(f, "decode: {}", s),
        }
    }
}

impl std::error::Error for ListenerError {}

/// Asset Hub deposit listener with dynamic event decoding
pub struct AssetHubListener {
    /// Map of watched addresses to (user_id, derivation_index)
    watched: Arc<RwLock<HashMap<String, (String, u32)>>>,
    /// Subxt client
    client: Option<OnlineClient<PolkadotConfig>>,
    /// RPC URL
    rpc_url: String,
}

impl AssetHubListener {
    /// Create a new listener
    pub fn new() -> Self {
        Self {
            watched: Arc::new(RwLock::new(HashMap::new())),
            client: None,
            rpc_url: DEFAULT_RPC_URL.to_string(),
        }
    }

    /// Create with custom RPC URL
    pub fn with_rpc_url(rpc_url: &str) -> Self {
        Self {
            watched: Arc::new(RwLock::new(HashMap::new())),
            client: None,
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Connect to the network via RPC
    pub async fn connect(&mut self) -> Result<(), ListenerError> {
        tracing::info!("connecting to Asset Hub via {}", self.rpc_url);

        let client = OnlineClient::<PolkadotConfig>::from_url(&self.rpc_url)
            .await
            .map_err(|e| ListenerError::Subxt(format!("connect: {}", e)))?;

        self.client = Some(client);
        tracing::info!("connected to Asset Hub");
        Ok(())
    }

    /// Add an address to watch
    pub async fn watch(&self, address: String, user_id: String, index: u32) {
        let mut watched = self.watched.write().await;
        watched.insert(address.clone(), (user_id, index));
        tracing::debug!("watching address: {}", address);
    }

    /// Remove address from watch list
    pub async fn unwatch(&self, address: &str) {
        let mut watched = self.watched.write().await;
        watched.remove(address);
    }

    /// Run the listener loop - processes blocks and decodes asset transfers
    pub async fn run<C: DepositCallback>(&self, callback: C) -> Result<(), ListenerError> {
        let client = self.client.as_ref()
            .ok_or_else(|| ListenerError::Subxt("not connected".into()))?;

        tracing::info!("starting Asset Hub deposit listener");

        // Subscribe to finalized blocks
        let mut blocks = client.blocks().subscribe_finalized()
            .await
            .map_err(|e| ListenerError::Subxt(format!("subscribe: {}", e)))?;

        while let Some(block_result) = blocks.next().await {
            let block = match block_result {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("error getting block: {}", e);
                    continue;
                }
            };

            let block_number = block.number() as u64;
            let block_hash = block.hash();
            tracing::trace!("processing block {} ({})", block_number, block_hash);

            // Get events for this block
            let events = match block.events().await {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("error getting events for block {}: {}", block_number, e);
                    continue;
                }
            };

            // Process all events looking for asset transfers
            for event in events.iter() {
                let event = match event {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::trace!("error decoding event: {}", e);
                        continue;
                    }
                };

                // Check if this is Assets::Transferred by pallet/variant name
                let pallet = event.pallet_name();
                let variant = event.variant_name();

                if pallet == "Assets" && variant == "Transferred" {
                    if let Err(e) = self.handle_asset_transfer_dynamic(
                        &event,
                        block_number,
                        &format!("{:?}", block_hash),
                        &callback
                    ).await {
                        tracing::warn!("failed to decode transfer event: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an asset transfer event using dynamic field decoding
    async fn handle_asset_transfer_dynamic<C: DepositCallback>(
        &self,
        event: &subxt::events::EventDetails<PolkadotConfig>,
        block_number: u64,
        block_hash: &str,
        callback: &C,
    ) -> Result<(), ListenerError> {
        // Decode event fields dynamically using At trait
        // Assets::Transferred has fields: asset_id, from, to, amount
        let field_values = event.field_values()
            .map_err(|e| ListenerError::Decode(format!("field values: {}", e)))?;

        // Use At trait to access fields by name
        let asset_id = field_values.at("asset_id")
            .and_then(|v| v.as_u128())
            .map(|v| v as u32)
            .ok_or_else(|| ListenerError::Decode("missing asset_id".into()))?;

        let from = field_values.at("from")
            .map(|v| format!("{}", v))
            .ok_or_else(|| ListenerError::Decode("missing from".into()))?;

        let to_address = field_values.at("to")
            .map(|v| format!("{}", v))
            .ok_or_else(|| ListenerError::Decode("missing to".into()))?;

        let amount = field_values.at("amount")
            .and_then(|v| v.as_u128())
            .ok_or_else(|| ListenerError::Decode("missing amount".into()))?;

        // Check if this is to one of our watched addresses
        let watched = self.watched.read().await;
        let Some((user_id, derivation_index)) = watched.get(&to_address) else {
            return Ok(());
        };

        // Determine asset type
        let (asset, decimals) = match asset_id {
            id if id == USDC_ASSET_ID => (Asset::Usdc, 6),
            id if id == USDT_ASSET_ID => (Asset::Usdt, 6),
            _ => {
                tracing::debug!("ignoring transfer of unknown asset {}", asset_id);
                return Ok(());
            }
        };

        // Convert amount from smallest unit to decimal
        let amount_decimal = amount as f64 / 10f64.powi(decimals);

        let deposit = Deposit {
            tx_hash: block_hash.to_string(),
            block_number,
            from,
            to: to_address.clone(),
            amount: amount_decimal,
            asset,
            user_id: user_id.clone(),
            derivation_index: *derivation_index,
        };

        tracing::info!(
            "deposit detected: {} {} from {} to {} (user: {}, index: {})",
            amount_decimal,
            asset,
            deposit.from,
            deposit.to,
            user_id,
            derivation_index
        );

        // Call the callback
        if let Err(e) = callback.on_deposit(deposit).await {
            tracing::error!("callback error: {:?}", e);
        }

        Ok(())
    }
}

impl Default for AssetHubListener {
    fn default() -> Self {
        Self::new()
    }
}
