//! sweep logic for automatic fund transfers
//!
//! handles sweeping funds from deposit addresses to tiered wallets

use subxt::{OnlineClient, PolkadotConfig};
use subxt::ext::sp_core::sr25519;

use crate::wallet::polkadot::PolkadotWallet;
use crate::proxy::ProxyError;

/// asset sweep configuration
#[derive(Debug, Clone)]
pub struct SweepConfig {
    /// minimum amount to trigger sweep (in smallest unit)
    pub min_amount: u128,
    /// asset id to sweep (1337 = USDC, 1984 = USDT)
    pub asset_id: u32,
    /// keep this much in source for fees
    pub keep_for_fees: u128,
    /// destination address for sweep
    pub destination: String,
}

impl SweepConfig {
    /// create sweep config for USDC
    pub fn usdc(destination: String) -> Self {
        Self {
            min_amount: 1_000_000, // 1 USDC (6 decimals)
            asset_id: 1337,
            keep_for_fees: 0,
            destination,
        }
    }

    /// create sweep config for USDT
    pub fn usdt(destination: String) -> Self {
        Self {
            min_amount: 1_000_000, // 1 USDT
            asset_id: 1984,
            keep_for_fees: 0,
            destination,
        }
    }
}

/// sweeper for automatic fund transfers
pub struct Sweeper {
    client: Option<OnlineClient<PolkadotConfig>>,
    rpc_url: String,
}

impl Sweeper {
    /// create new sweeper
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

    /// sweep assets from a derived address to destination
    pub async fn sweep_assets(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        config: &SweepConfig,
        amount: u128,
    ) -> Result<SweepResult, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);
        let source_address = wallet.derive_address(user_id, derivation_index);

        // check if amount meets minimum
        if amount < config.min_amount {
            return Ok(SweepResult {
                success: false,
                tx_hash: None,
                amount_swept: 0,
                source: source_address,
                destination: config.destination.clone(),
                reason: Some(format!("amount {} below minimum {}", amount, config.min_amount)),
            });
        }

        let sweep_amount = amount.saturating_sub(config.keep_for_fees);
        if sweep_amount == 0 {
            return Ok(SweepResult {
                success: false,
                tx_hash: None,
                amount_swept: 0,
                source: source_address,
                destination: config.destination.clone(),
                reason: Some("nothing to sweep after fees".into()),
            });
        }

        // decode destination address
        let dest_bytes = crate::wallet::polkadot::decode_ss58(&config.destination)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        // build assets.transfer_keep_alive call
        let call = subxt::dynamic::tx(
            "Assets",
            "transfer_keep_alive",
            vec![
                ("id", subxt::dynamic::Value::u128(config.asset_id as u128)),
                ("target", subxt::dynamic::Value::unnamed_variant("Id", vec![
                    subxt::dynamic::Value::from_bytes(dest_bytes),
                ])),
                ("amount", subxt::dynamic::Value::u128(sweep_amount)),
            ],
        );

        // sign and submit
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

        let tx_hash = format!("{:?}", tx_in_block.block_hash());
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        tracing::info!(
            "swept {} from {} to {} in {}",
            sweep_amount,
            source_address,
            config.destination,
            tx_hash
        );

        Ok(SweepResult {
            success: true,
            tx_hash: Some(tx_hash),
            amount_swept: sweep_amount,
            source: source_address,
            destination: config.destination.clone(),
            reason: None,
        })
    }

    /// sweep native DOT (for fees or if accepting DOT)
    pub async fn sweep_native(
        &self,
        wallet: &PolkadotWallet,
        user_id: &str,
        derivation_index: u32,
        destination: &str,
        amount: u128,
        keep_for_fees: u128,
    ) -> Result<SweepResult, ProxyError> {
        let client = self.client.as_ref().ok_or(ProxyError::NotConnected)?;

        let (secret, _public) = wallet.derive_keypair(user_id, derivation_index);
        let source_address = wallet.derive_address(user_id, derivation_index);

        let sweep_amount = amount.saturating_sub(keep_for_fees);
        if sweep_amount == 0 {
            return Ok(SweepResult {
                success: false,
                tx_hash: None,
                amount_swept: 0,
                source: source_address,
                destination: destination.to_string(),
                reason: Some("nothing to sweep".into()),
            });
        }

        let dest_bytes = crate::wallet::polkadot::decode_ss58(destination)
            .map_err(|e| ProxyError::InvalidAddress(e))?;

        // use transfer_keep_alive for native token
        let call = subxt::dynamic::tx(
            "Balances",
            "transfer_keep_alive",
            vec![
                ("dest", subxt::dynamic::Value::unnamed_variant("Id", vec![
                    subxt::dynamic::Value::from_bytes(dest_bytes),
                ])),
                ("value", subxt::dynamic::Value::u128(sweep_amount)),
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

        let tx_hash = format!("{:?}", tx_in_block.block_hash());
        tx_in_block.wait_for_success().await
            .map_err(|e| ProxyError::Subxt(format!("failed: {}", e)))?;

        Ok(SweepResult {
            success: true,
            tx_hash: Some(tx_hash),
            amount_swept: sweep_amount,
            source: source_address,
            destination: destination.to_string(),
            reason: None,
        })
    }

}

/// result of a sweep operation
#[derive(Debug, Clone)]
pub struct SweepResult {
    /// whether the sweep succeeded
    pub success: bool,
    /// transaction hash if successful
    pub tx_hash: Option<String>,
    /// amount that was swept
    pub amount_swept: u128,
    /// source address
    pub source: String,
    /// destination address
    pub destination: String,
    /// reason if failed
    pub reason: Option<String>,
}

/// convert schnorrkel secret to sp_core sr25519 pair
fn sr25519_pair_from_secret(secret: &schnorrkel::SecretKey) -> Result<sr25519::Pair, ProxyError> {
    use subxt::ext::sp_core::Pair;
    let secret_bytes = secret.to_bytes();
    sr25519::Pair::from_seed_slice(&secret_bytes[..32])
        .map_err(|e| ProxyError::SigningFailed(format!("{:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweep_config_usdc() {
        let config = SweepConfig::usdc("1234...".into());
        assert_eq!(config.asset_id, 1337);
        assert_eq!(config.min_amount, 1_000_000);
    }
}
