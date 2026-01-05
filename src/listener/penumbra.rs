//! Penumbra deposit listener
//!
//! Watches for incoming notes to our payment addresses via pclientd view service.
//! Uses the same approach as pcli for realtime monitoring.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use penumbra_sdk_proto::view::v1::{
    view_service_client::ViewServiceClient, BalancesRequest, NotesRequest, StatusRequest,
};
use tonic::transport::Channel;

use super::{Asset, Deposit, DepositCallback};

/// USDC asset ID on penumbra (IBC transferred from noble)
pub const USDC_ASSET_ID: &str = "transfer/channel-0/uusdc";

/// Penumbra listener configuration
pub struct PenumbraListenerConfig {
    /// View service gRPC endpoint (pclientd address, e.g., "http://localhost:8081")
    pub view_service_url: String,
}

/// Penumbra deposit listener using pclientd
pub struct PenumbraListener {
    config: PenumbraListenerConfig,
    /// Map of address_index -> (user_id, derivation_index)
    watched_indices: Arc<RwLock<HashMap<u32, (String, u32)>>>,
    /// Set of already-processed note commitments to avoid duplicates
    processed_notes: Arc<RwLock<HashSet<String>>>,
    /// Deposit callback
    callback: Option<Arc<dyn DepositCallback>>,
    /// gRPC client (initialized on first connect)
    client: Arc<RwLock<Option<ViewServiceClient<Channel>>>>,
}

impl PenumbraListener {
    pub fn new(config: PenumbraListenerConfig) -> Self {
        Self {
            config,
            watched_indices: Arc::new(RwLock::new(HashMap::new())),
            processed_notes: Arc::new(RwLock::new(HashSet::new())),
            callback: None,
            client: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the deposit callback
    pub fn with_callback<C: DepositCallback + 'static>(mut self, callback: C) -> Self {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// Register an address index to watch
    /// The address_index corresponds to the AddressIndex used during derivation
    pub async fn watch(&self, address_index: u32, user_id: &str, derivation_index: u32) {
        let mut watched = self.watched_indices.write().await;
        watched.insert(address_index, (user_id.to_string(), derivation_index));
        tracing::debug!(
            "watching penumbra address_index {} for user {}",
            address_index,
            user_id
        );
    }

    /// Stop watching an address index
    pub async fn unwatch(&self, address_index: u32) {
        let mut watched = self.watched_indices.write().await;
        watched.remove(&address_index);
    }

    /// Connect to the view service
    async fn connect(&self) -> Result<ViewServiceClient<Channel>, Box<dyn std::error::Error + Send + Sync>> {
        let mut client_lock = self.client.write().await;
        if let Some(ref client) = *client_lock {
            return Ok(client.clone());
        }

        tracing::info!("connecting to pclientd at {}", self.config.view_service_url);
        let channel = Channel::from_shared(self.config.view_service_url.clone())?
            .connect()
            .await?;
        let client = ViewServiceClient::new(channel);
        *client_lock = Some(client.clone());
        Ok(client)
    }

    /// Run the listener (connects to pclientd view service)
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "starting penumbra listener at {}",
            self.config.view_service_url
        );

        loop {
            match self.poll_deposits().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("processed {} new penumbra deposits", count);
                    }
                }
                Err(e) => {
                    tracing::error!("penumbra poll error: {}", e);
                    // reset client on error to force reconnect
                    *self.client.write().await = None;
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
        }
    }

    /// Poll for new deposits via the view service
    async fn poll_deposits(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.connect().await?;

        // first check sync status
        let status = client
            .status(StatusRequest {})
            .await?
            .into_inner();

        if status.full_sync_height == 0 {
            tracing::debug!("pclientd not yet synced, waiting...");
            return Ok(0);
        }

        // get all unspent notes
        let notes_request = NotesRequest {
            include_spent: false,
            asset_id: None, // all assets
            address_index: None, // all addresses
            amount_to_spend: None,
        };

        let response = client.notes(notes_request).await?;
        let mut stream = response.into_inner();

        let mut deposit_count = 0;
        let watched = self.watched_indices.read().await;

        while let Some(note_response) = stream.message().await? {
            let Some(note_record) = note_response.note_record else {
                continue;
            };

            // get the note commitment as unique identifier
            let commitment = note_record
                .note_commitment
                .as_ref()
                .map(|c| hex::encode(&c.inner))
                .unwrap_or_default();

            // skip if already processed
            {
                let processed = self.processed_notes.read().await;
                if processed.contains(&commitment) {
                    continue;
                }
            }

            // check if this note is for a watched address index
            let Some(addr_index) = note_record.address_index.as_ref() else {
                continue;
            };

            let address_index = addr_index.account;

            if let Some((user_id, derivation_index)) = watched.get(&address_index) {
                // extract note value
                let Some(note) = note_record.note.as_ref() else {
                    continue;
                };

                let Some(value) = note.value.as_ref() else {
                    continue;
                };

                let amount = value
                    .amount
                    .as_ref()
                    .map(|a| a.lo as u128 + ((a.hi as u128) << 64))
                    .unwrap_or(0);

                let asset_id = value
                    .asset_id
                    .as_ref()
                    .map(|a| hex::encode(&a.inner))
                    .unwrap_or_default();

                // convert amount to f64 (penumbra usdc has 6 decimals)
                let amount_decimal = amount as f64 / 1_000_000.0;

                // create deposit record
                let deposit = Deposit {
                    tx_hash: commitment.clone(),
                    from: String::new(), // penumbra notes don't reveal sender
                    to: format!("penumbra_index:{}", address_index),
                    amount: amount_decimal,
                    asset: Asset::Usdc, // TODO: check actual asset from asset_id
                    block_number: note_record.height_created,
                    user_id: user_id.clone(),
                    derivation_index: *derivation_index,
                };

                tracing::info!(
                    "detected penumbra deposit: {} units of {} for user {} (index {})",
                    amount,
                    asset_id,
                    user_id,
                    derivation_index
                );

                // mark as processed
                {
                    let mut processed = self.processed_notes.write().await;
                    processed.insert(commitment);
                }

                // call callback
                if let Some(ref callback) = self.callback {
                    if let Err(e) = callback.on_deposit(deposit).await {
                        tracing::error!("deposit callback error: {}", e);
                    }
                }

                deposit_count += 1;
            }
        }

        Ok(deposit_count)
    }

    /// Get balances for a specific address index
    pub async fn get_balance(
        &self,
        address_index: u32,
    ) -> Result<Vec<(String, u128)>, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.connect().await?;

        // create address index filter
        let account_filter = penumbra_sdk_proto::core::keys::v1::AddressIndex {
            account: address_index,
            randomizer: vec![],
        };

        let request = BalancesRequest {
            account_filter: Some(account_filter),
            asset_id_filter: None,
        };

        let response = client.balances(request).await?;
        let mut stream = response.into_inner();

        let mut balances = Vec::new();
        while let Some(balance_response) = stream.message().await? {
            let Some(balance) = balance_response.balance_view else {
                continue;
            };

            // extract asset id and amount from the balance view
            if let Some(penumbra_sdk_proto::core::asset::v1::value_view::ValueView::KnownAssetId(known)) =
                balance.value_view
            {
                if let Some(amount) = known.amount {
                    let value = amount.lo as u128 + ((amount.hi as u128) << 64);
                    let asset_id = known
                        .metadata
                        .as_ref()
                        .map(|m| m.symbol.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    balances.push((asset_id, value));
                }
            }
        }

        Ok(balances)
    }
}
