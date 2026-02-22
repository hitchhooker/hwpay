//! pure proxy management for asset hub
//!
//! creates and manages keyless proxy accounts with configurable time delays.
//! supports multi-tier wallet architecture: hot -> medium -> cold

use subxt::{OnlineClient, PolkadotConfig};
use subxt::ext::sp_core::{sr25519, Pair};

use crate::wallet::polkadot::PolkadotWallet;

/// proxy type for asset hub
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    /// can make any call
    Any,
    /// can make non-transfer calls
    NonTransfer,
    /// can only cancel proxied calls
    CancelProxy,
    /// can make asset-related calls
    Assets,
    /// can make asset transfers
    AssetOwner,
    /// can manage asset metadata
    AssetManager,
    /// can make collator selection calls
    Collator,
}

impl ProxyType {
    fn as_u8(&self) -> u8 {
        match self {
            Self::Any => 0,
            Self::NonTransfer => 1,
            Self::CancelProxy => 2,
            Self::Assets => 3,
            Self::AssetOwner => 4,
            Self::AssetManager => 5,
            Self::Collator => 6,
        }
    }
}

/// configuration for a proxy relationship
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// delay in blocks before proxy calls execute
    pub delay_blocks: u32,
    /// type of proxy (what calls are allowed)
    pub proxy_type: ProxyType,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            delay_blocks: 0,
            proxy_type: ProxyType::Any,
        }
    }
}

impl ProxyConfig {
    pub fn with_delay(delay_blocks: u32) -> Self {
        Self {
            delay_blocks,
            proxy_type: ProxyType::Any,
        }
    }

    pub fn with_type(proxy_type: ProxyType) -> Self {
        Self {
            delay_blocks: 0,
            proxy_type,
        }
    }
}

/// tier configuration for multi-wallet setup
#[derive(Debug, Clone)]
pub struct TierConfig {
    /// delay from hot to medium (blocks)
    pub hot_to_medium_delay: u32,
    /// delay from medium to cold (blocks)
    pub medium_to_cold_delay: u32,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            // ~24 hours at 6 second blocks
            hot_to_medium_delay: 14400,
            // ~7 days
            medium_to_cold_delay: 100800,
        }
    }
}

impl TierConfig {
    /// create with custom delays
    pub fn new(hot_to_medium_delay: u32, medium_to_cold_delay: u32) -> Self {
        Self {
            hot_to_medium_delay,
            medium_to_cold_delay,
        }
    }

    /// create with delays in hours (assuming 6 second blocks)
    pub fn from_hours(hot_to_medium_hours: u32, medium_to_cold_hours: u32) -> Self {
        Self {
            hot_to_medium_delay: hot_to_medium_hours * 600,
            medium_to_cold_delay: medium_to_cold_hours * 600,
        }
    }
}

#[derive(Debug)]
pub enum ProxyError {
    Subxt(String),
    InvalidAddress(String),
    NotConnected,
    SigningFailed(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subxt(s) => write!(f, "subxt: {}", s),
            Self::InvalidAddress(s) => write!(f, "invalid address: {}", s),
            Self::NotConnected => write!(f, "not connected"),
            Self::SigningFailed(s) => write!(f, "signing failed: {}", s),
        }
    }
}

impl std::error::Error for ProxyError {}

/// pure proxy manager for asset hub
pub struct ProxyManager {
    client: Option<OnlineClient<PolkadotConfig>>,
    rpc_url: String,
}

impl ProxyManager {
    /// create new proxy manager
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: None,
            rpc_url: rpc_url.to_string(),
        }
    }

    /// connect to the network
    pub async fn connect(&mut self) -> Result<(), ProxyError> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&self.rpc_url)
            .await
            .map_err(|e| ProxyError::Subxt(e.to_string()))?;
        self.client = Some(client);
        Ok(())
    }

    /// create a pure (keyless) proxy account
    /// returns the address of the new pure proxy
    pub async fn create_pure_proxy(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        proxy_type: ProxyType,
        delay: u32,
        index: u16,
    ) -> Result<PureProxyResult, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        // get the keypair for signing
        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        // build the create_pure call dynamically
        let call = subxt::dynamic::tx(
            "Proxy",
            "create_pure",
            vec![
                ("proxy_type", subxt::dynamic::Value::u128(proxy_type.as_u8() as u128)),
                ("delay", subxt::dynamic::Value::u128(delay as u128)),
                ("index", subxt::dynamic::Value::u128(index as u128)),
            ],
        );

        // create signer from secret key
        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        // submit and watch
        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        let extrinsic_hash = tx_in_block.extrinsic_hash();

        // wait for success and get events
        let events = tx_in_block
            .wait_for_success()
            .await
            .map_err(|e| ProxyError::Subxt(format!("events: {}", e)))?;

        // parse events to find PureCreated
        let pure_address = self.extract_pure_created_address(&events).await?;

        Ok(PureProxyResult {
            pure_address,
            block_hash: format!("{:?}", block_hash),
            extrinsic_hash: format!("{:?}", extrinsic_hash),
            spawner: wallet.derive_address(user_id, derivation_index),
            proxy_type,
            delay,
        })
    }

    /// add a proxy to an existing account (pure or regular)
    pub async fn add_proxy(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        delegate: &str,
        config: ProxyConfig,
    ) -> Result<String, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        // decode delegate address to account id
        let delegate_bytes = crate::wallet::polkadot::decode_ss58(delegate)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        let call = subxt::dynamic::tx(
            "Proxy",
            "add_proxy",
            vec![
                ("delegate", subxt::dynamic::Value::from_bytes(delegate_bytes)),
                ("proxy_type", subxt::dynamic::Value::u128(config.proxy_type.as_u8() as u128)),
                ("delay", subxt::dynamic::Value::u128(config.delay_blocks as u128)),
            ],
        );

        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(format!("{:?}", block_hash))
    }

    /// remove a proxy from an account
    pub async fn remove_proxy(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        delegate: &str,
        proxy_type: ProxyType,
        delay: u32,
    ) -> Result<String, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        let delegate_bytes = crate::wallet::polkadot::decode_ss58(delegate)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        let call = subxt::dynamic::tx(
            "Proxy",
            "remove_proxy",
            vec![
                ("delegate", subxt::dynamic::Value::from_bytes(delegate_bytes)),
                ("proxy_type", subxt::dynamic::Value::u128(proxy_type.as_u8() as u128)),
                ("delay", subxt::dynamic::Value::u128(delay as u128)),
            ],
        );

        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(format!("{:?}", block_hash))
    }

    /// execute a proxied asset transfer via proxy
    pub async fn proxy_transfer(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        real_account: &str,
        asset_id: u32,
        destination: &str,
        amount: u128,
    ) -> Result<String, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        let real_bytes = crate::wallet::polkadot::decode_ss58(real_account)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        let dest_bytes = crate::wallet::polkadot::decode_ss58(destination)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        // build the inner transfer call
        let transfer_call = subxt::dynamic::Value::unnamed_variant(
            "Assets",
            vec![
                subxt::dynamic::Value::unnamed_variant(
                    "transfer_keep_alive",
                    vec![
                        subxt::dynamic::Value::u128(asset_id as u128),
                        subxt::dynamic::Value::unnamed_variant("Id", vec![
                            subxt::dynamic::Value::from_bytes(dest_bytes),
                        ]),
                        subxt::dynamic::Value::u128(amount),
                    ],
                ),
            ],
        );

        // wrap the call in proxy.proxy
        let proxy_call = subxt::dynamic::tx(
            "Proxy",
            "proxy",
            vec![
                ("real", subxt::dynamic::Value::from_bytes(real_bytes)),
                ("force_proxy_type", subxt::dynamic::Value::unnamed_variant("None", vec![])),
                ("call", transfer_call),
            ],
        );

        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&proxy_call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(format!("{:?}", block_hash))
    }

    /// announce a proxied call (for delayed execution)
    pub async fn announce(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        real_account: &str,
        call_hash: [u8; 32],
    ) -> Result<String, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        let real_bytes = crate::wallet::polkadot::decode_ss58(real_account)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        let call = subxt::dynamic::tx(
            "Proxy",
            "announce",
            vec![
                ("real", subxt::dynamic::Value::from_bytes(real_bytes)),
                ("call_hash", subxt::dynamic::Value::from_bytes(call_hash)),
            ],
        );

        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(format!("{:?}", block_hash))
    }

    /// execute a previously announced asset transfer after delay
    pub async fn proxy_announced_transfer(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        delegate: &str,
        real_account: &str,
        asset_id: u32,
        destination: &str,
        amount: u128,
    ) -> Result<String, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);

        let delegate_bytes = crate::wallet::polkadot::decode_ss58(delegate)
            .map_err(|e| ProxyError::InvalidAddress(e))?;
        let real_bytes = crate::wallet::polkadot::decode_ss58(real_account)
            .map_err(|e| ProxyError::InvalidAddress(e))?;
        let dest_bytes = crate::wallet::polkadot::decode_ss58(destination)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        // build the inner transfer call
        let transfer_call = subxt::dynamic::Value::unnamed_variant(
            "Assets",
            vec![
                subxt::dynamic::Value::unnamed_variant(
                    "transfer_keep_alive",
                    vec![
                        subxt::dynamic::Value::u128(asset_id as u128),
                        subxt::dynamic::Value::unnamed_variant("Id", vec![
                            subxt::dynamic::Value::from_bytes(dest_bytes),
                        ]),
                        subxt::dynamic::Value::u128(amount),
                    ],
                ),
            ],
        );

        let proxy_call = subxt::dynamic::tx(
            "Proxy",
            "proxy_announced",
            vec![
                ("delegate", subxt::dynamic::Value::from_bytes(delegate_bytes)),
                ("real", subxt::dynamic::Value::from_bytes(real_bytes)),
                ("force_proxy_type", subxt::dynamic::Value::unnamed_variant("None", vec![])),
                ("call", transfer_call),
            ],
        );

        let pair = sr25519_pair_from_secret(&secret)?;
        let signer = subxt::tx::PairSigner::new(pair);

        let tx_in_block = client
            .tx()
            .sign_and_submit_then_watch_default(&proxy_call, &signer)
            .await
            .map_err(|e| ProxyError::Subxt(format!("submit: {}", e)))?
            .wait_for_finalized()
            .await
            .map_err(|e| ProxyError::Subxt(format!("finalize: {}", e)))?;

        let block_hash = tx_in_block.block_hash();
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(format!("{:?}", block_hash))
    }

    /// extract the pure proxy address from PureCreated event
    async fn extract_pure_created_address(
        &self,
        result: &subxt::blocks::ExtrinsicEvents<PolkadotConfig>,
    ) -> Result<String, ProxyError> {
        use subxt::ext::scale_value::At;

        for event in result.iter() {
            let event = event.map_err(|e| ProxyError::Subxt(format!("event: {}", e)))?;

            if event.pallet_name() == "Proxy" && event.variant_name() == "PureCreated" {
                let fields = event.field_values()
                    .map_err(|e| ProxyError::Subxt(format!("fields: {}", e)))?;

                // extract the "pure" field which is the new account
                if let Some(pure) = fields.at("pure") {
                    let addr_str = format!("{}", pure);
                    // the address is formatted, need to extract the actual address
                    return Ok(addr_str);
                }
            }
        }

        Err(ProxyError::Subxt("PureCreated event not found".into()))
    }
}

/// result of creating a pure proxy
#[derive(Debug, Clone)]
pub struct PureProxyResult {
    /// address of the new pure proxy account
    pub pure_address: String,
    /// block hash where it was created
    pub block_hash: String,
    /// extrinsic hash
    pub extrinsic_hash: String,
    /// address that spawned this proxy
    pub spawner: String,
    /// proxy type configured
    pub proxy_type: ProxyType,
    /// delay in blocks
    pub delay: u32,
}

/// convert schnorrkel secret to sp_core sr25519 pair
fn sr25519_pair_from_secret(secret: &schnorrkel::SecretKey) -> Result<sr25519::Pair, ProxyError> {
    let secret_bytes = secret.to_bytes();
    sr25519::Pair::from_seed_slice(&secret_bytes[..32])
        .map_err(|e| ProxyError::SigningFailed(format!("{:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_config_from_hours() {
        let config = TierConfig::from_hours(24, 168); // 24h, 7 days
        assert_eq!(config.hot_to_medium_delay, 14400);
        assert_eq!(config.medium_to_cold_delay, 100800);
    }

    #[test]
    fn test_proxy_type_values() {
        assert_eq!(ProxyType::Any.as_u8(), 0);
        assert_eq!(ProxyType::Assets.as_u8(), 3);
    }
}
