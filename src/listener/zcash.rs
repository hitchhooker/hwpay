//! Zcash deposit listener
//!
//! Polls a Zcash node (via JSON-RPC) for incoming transactions to watched addresses.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::listener::{Deposit, Asset, DepositCallback};

/// Configuration for the Zcash listener
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZcashListenerConfig {
    /// Zcash node RPC URL (e.g., http://127.0.0.1:8232)
    pub rpc_url: String,
    /// RPC username (if auth required)
    pub rpc_user: Option<String>,
    /// RPC password (if auth required)
    pub rpc_password: Option<String>,
    /// Poll interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Minimum confirmations before crediting
    #[serde(default = "default_confirmations")]
    pub min_confirmations: u32,
}

fn default_poll_interval() -> u64 { 30 }
fn default_confirmations() -> u32 { 6 }

/// Watched address entry
struct WatchedAddress {
    address: String,
    user_id: String,
    derivation_index: u32,
}

/// Zcash deposit listener
pub struct ZcashListener {
    config: ZcashListenerConfig,
    client: reqwest::Client,
    watched: Vec<WatchedAddress>,
    /// Track processed tx hashes to avoid duplicates
    processed: HashMap<String, bool>,
    /// Last scanned block height
    last_height: u64,
}

impl ZcashListener {
    /// Create a new Zcash listener
    pub fn new(config: ZcashListenerConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            watched: Vec::new(),
            processed: HashMap::new(),
            last_height: 0,
        }
    }

    /// Add an address to watch for deposits
    pub fn watch(&mut self, address: String, user_id: String, derivation_index: u32) {
        info!("watching zcash address {} for user {}", address, user_id);
        self.watched.push(WatchedAddress {
            address,
            user_id,
            derivation_index,
        });
    }

    /// Run the listener loop
    pub async fn run<C: DepositCallback>(&mut self, callback: &C) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.watched.is_empty() {
            warn!("no addresses to watch");
            return Ok(());
        }

        info!("starting zcash listener with {} addresses, polling every {}s",
            self.watched.len(), self.config.poll_interval_secs);

        // Get current block height as starting point
        self.last_height = self.get_block_count().await?;
        info!("starting from block height {}", self.last_height);

        loop {
            if let Err(e) = self.poll(callback).await {
                error!("zcash poll error: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
        }
    }

    /// Poll for new blocks and check for deposits
    async fn poll<C: DepositCallback>(&mut self, callback: &C) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let current_height = self.get_block_count().await?;

        if current_height <= self.last_height {
            return Ok(());
        }

        // Scan new blocks
        for height in (self.last_height + 1)..=current_height {
            let block_hash = self.get_block_hash(height).await?;
            let block = self.get_block(&block_hash).await?;

            for tx_id in &block.tx {
                if self.processed.contains_key(tx_id) {
                    continue;
                }

                if let Ok(tx) = self.get_raw_transaction(tx_id).await {
                    self.check_transaction(&tx, height, callback).await;
                    self.processed.insert(tx_id.clone(), true);
                }
            }
        }

        self.last_height = current_height;
        Ok(())
    }

    /// Check a transaction for deposits to watched addresses
    async fn check_transaction<C: DepositCallback>(&self, tx: &RpcTransaction, block_height: u64, callback: &C) {
        for vout in &tx.vout {
            if let Some(addresses) = &vout.script_pub_key.addresses {
                for addr in addresses {
                    if let Some(watched) = self.watched.iter().find(|w| &w.address == addr) {
                        let deposit = Deposit {
                            tx_hash: tx.txid.clone(),
                            block_number: block_height,
                            from: String::new(), // transparent inputs would need vin lookup
                            to: watched.address.clone(),
                            amount: vout.value,
                            asset: Asset::Zec,
                            user_id: watched.user_id.clone(),
                            derivation_index: watched.derivation_index,
                        };

                        info!("detected zcash deposit: {} ZEC to {} (user {})",
                            deposit.amount, deposit.to, deposit.user_id);

                        if let Err(e) = callback.on_deposit(deposit).await {
                            error!("deposit callback failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// JSON-RPC call helper
    async fn rpc_call<T: for<'de> Deserialize<'de>>(&self, method: &str, params: serde_json::Value) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut req = self.client.post(&self.config.rpc_url)
            .json(&body);

        if let (Some(user), Some(pass)) = (&self.config.rpc_user, &self.config.rpc_password) {
            req = req.basic_auth(user, Some(pass));
        }

        let res = req.send().await?;
        let rpc_res: RpcResponse<T> = res.json().await?;

        if let Some(error) = rpc_res.error {
            return Err(format!("rpc error {}: {}", error.code, error.message).into());
        }

        rpc_res.result.ok_or_else(|| "empty rpc result".into())
    }

    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        self.rpc_call("getblockcount", serde_json::json!([])).await
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.rpc_call("getblockhash", serde_json::json!([height])).await
    }

    async fn get_block(&self, hash: &str) -> Result<RpcBlock, Box<dyn std::error::Error + Send + Sync>> {
        self.rpc_call("getblock", serde_json::json!([hash, 1])).await
    }

    async fn get_raw_transaction(&self, txid: &str) -> Result<RpcTransaction, Box<dyn std::error::Error + Send + Sync>> {
        self.rpc_call("getrawtransaction", serde_json::json!([txid, 1])).await
    }
}

// JSON-RPC types

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RpcBlock {
    tx: Vec<String>,
}

#[derive(Deserialize)]
struct RpcTransaction {
    txid: String,
    vout: Vec<RpcVout>,
}

#[derive(Deserialize)]
struct RpcVout {
    value: f64,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: RpcScriptPubKey,
}

#[derive(Deserialize)]
struct RpcScriptPubKey {
    addresses: Option<Vec<String>>,
}
