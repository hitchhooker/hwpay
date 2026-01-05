//! Test penumbra wallet and listener
//!
//! Run with: cargo run --example penumbra_test --features penumbra

use hwpay::wallet::penumbra::PenumbraWallet;
use hwpay::listener::penumbra::{PenumbraListener, PenumbraListenerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // generate a test wallet from seed
    let seed = [42u8; 32];
    let wallet = PenumbraWallet::from_seed(&seed)?;

    println!("=== Penumbra Test Wallet ===");
    println!("Full Viewing Key: {}", wallet.full_viewing_key_encoded());
    println!();

    // derive some addresses - now returns (address, index) tuple
    // the index is what you store in DB to map deposits back to users
    let mut indices = Vec::new();
    for i in 0..3 {
        let (addr, idx) = wallet.derive_address("test_user", i);
        println!("Derivation {}: index={} addr={}", i, idx, addr);
        indices.push(idx);
    }
    println!();

    // check if pclientd is running
    let config = PenumbraListenerConfig {
        view_service_url: "http://localhost:8081".to_string(),
    };

    let listener = PenumbraListener::new(config);

    // register addresses to watch using the actual indices from derive_address
    // in production, load these from your database
    listener.watch(indices[0], "test_user", 0).await;
    listener.watch(indices[1], "test_user", 1).await;

    println!("=== Starting Listener ===");
    println!("Connecting to pclientd at http://localhost:8081...");
    println!();

    // try to get balance for index 0 (using actual computed index)
    match listener.get_balance(indices[0]).await {
        Ok(balances) => {
            println!("Balances for address index 0:");
            if balances.is_empty() {
                println!("  (no balances)");
            }
            for (asset, amount) in balances {
                println!("  {}: {}", asset, amount);
            }
        }
        Err(e) => {
            println!("Failed to get balance: {}", e);
            println!();
            println!("Make sure pclientd is running:");
            println!("  1. Initialize: pclientd init --grpc-url https://grpc.penumbra.zone --fvk <fvk>");
            println!("  2. Start: pclientd start");
        }
    }

    Ok(())
}
