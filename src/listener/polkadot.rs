//! Polkadot Asset Hub listener
//!
//! Monitors for USDC/USDT transfers to our derived addresses.
//! Uses subxt with RPC connection (light client integration coming in future version).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use subxt::OnlineClient;

use crate::PaymentProcessor;
use crate::listener::{Deposit, DepositCallback};

/// USDC asset ID on Asset Hub
pub const USDC_ASSET_ID: u32 = 1337;
/// USDT asset ID on Asset Hub
pub const USDT_ASSET_ID: u32 = 1984;

/// Default Asset Hub RPC endpoint
pub const DEFAULT_RPC_URL: &str = "wss://polkadot-asset-hub-rpc.polkadot.io";

#[derive(Debug)]
pub enum ListenerError {
    LightClient(String),
    Subxt(String),
    NoAddresses,
    Http(String),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LightClient(s) => write!(f, "light client: {}", s),
            Self::Subxt(s) => write!(f, "subxt: {}", s),
            Self::NoAddresses => write!(f, "no addresses to watch"),
            Self::Http(s) => write!(f, "http: {}", s),
        }
    }
}

impl std::error::Error for ListenerError {}

/// Polkadot Asset Hub deposit listener using subxt
pub struct PolkadotListener {
    /// Map of watched addresses to (user_id, derivation_index)
    watched: Arc<RwLock<HashMap<String, (String, u32)>>>,
    /// Subxt client
    client: Option<OnlineClient<subxt::PolkadotConfig>>,
    /// RPC URL
    rpc_url: String,
}

impl PolkadotListener {
    /// Create a new listener
    pub async fn new(_processor: &PaymentProcessor) -> Result<Self, ListenerError> {
        Ok(Self {
            watched: Arc::new(RwLock::new(HashMap::new())),
            client: None,
            rpc_url: DEFAULT_RPC_URL.to_string(),
        })
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

        let client = OnlineClient::<subxt::PolkadotConfig>::from_url(&self.rpc_url)
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

    /// Run the listener loop
    pub async fn run<C: DepositCallback>(&self, callback: C) -> Result<(), ListenerError> {
        let client = self.client.as_ref()
            .ok_or_else(|| ListenerError::Subxt("not connected".into()))?;

        tracing::info!("starting deposit listener");

        // Subscribe to finalized blocks
        let mut blocks = client.blocks().subscribe_finalized()
            .await
            .map_err(|e| ListenerError::Subxt(format!("subscribe: {}", e)))?;

        while let Some(block_result) = blocks.next().await {
            let block = block_result.map_err(|e| ListenerError::Subxt(format!("block: {}", e)))?;
            let block_number = block.number() as u64;

            tracing::trace!("processing block {}", block_number);

            // Get extrinsics
            let extrinsics = block.extrinsics()
                .await
                .map_err(|e| ListenerError::Subxt(format!("extrinsics: {}", e)))?;

            for ext in extrinsics.iter() {
                self.process_extrinsic(&ext, block_number, &callback).await;
            }
        }

        Ok(())
    }

    async fn process_extrinsic<C: DepositCallback>(
        &self,
        _ext: &subxt::blocks::ExtrinsicDetails<subxt::PolkadotConfig, OnlineClient<subxt::PolkadotConfig>>,
        block_number: u64,
        callback: &C,
    ) {
        let watched = self.watched.read().await;
        if watched.is_empty() {
            return;
        }

        // TODO: Decode assets.transfer_keep_alive and assets.transfer calls
        // Implementation requires generated Asset Hub runtime types
        // 1. Decode the extrinsic
        // 2. Check if it's an Assets::transfer* call
        // 3. Check if asset_id is USDC or USDT
        // 4. Check if destination is in our watched list
        // 5. Create Deposit and call callback

        let _ = (block_number, callback);
    }
}

/// Simplified polling-based listener (doesn't require full light client)
pub struct PolkadotPollingListener {
    rpc_url: String,
    watched: HashMap<String, (String, u32)>,
    last_block: u64,
}

impl PolkadotPollingListener {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            watched: HashMap::new(),
            last_block: 0,
        }
    }

    pub fn watch(&mut self, address: String, user_id: String, index: u32) {
        self.watched.insert(address, (user_id, index));
    }

    /// Poll for new deposits (call periodically)
    pub async fn poll(&mut self) -> Result<Vec<Deposit>, ListenerError> {
        let client = reqwest::Client::new();

        // Get finalized head
        let resp: serde_json::Value = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "chain_getFinalizedHead",
                "params": []
            }))
            .send()
            .await
            .map_err(|e| ListenerError::Subxt(e.to_string()))?
            .json()
            .await
            .map_err(|e| ListenerError::Subxt(e.to_string()))?;

        let head_hash = resp["result"].as_str()
            .ok_or_else(|| ListenerError::Subxt("no head".into()))?;

        // Get block
        let resp: serde_json::Value = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "chain_getBlock",
                "params": [head_hash]
            }))
            .send()
            .await
            .map_err(|e| ListenerError::Subxt(e.to_string()))?
            .json()
            .await
            .map_err(|e| ListenerError::Subxt(e.to_string()))?;

        let block_num_hex = resp["result"]["block"]["header"]["number"].as_str()
            .ok_or_else(|| ListenerError::Subxt("no block number".into()))?;
        let block_num = u64::from_str_radix(&block_num_hex[2..], 16)
            .map_err(|e| ListenerError::Subxt(e.to_string()))?;

        if block_num <= self.last_block {
            return Ok(vec![]);
        }

        tracing::debug!("polling block {}", block_num);
        self.last_block = block_num;

        // TODO: Actually parse extrinsics for asset transfers
        // This requires SCALE decoding which is complex without generated types

        Ok(vec![])
    }
}
