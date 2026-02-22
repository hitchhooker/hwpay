//! send test assets on paseo asset hub

use subxt::{OnlineClient, PolkadotConfig};
use subxt::ext::sp_core::{sr25519, Pair};

const PASEO_ASSETHUB_RPC: &str = "wss://asset-hub-paseo.rotko.net";

// alice's well-known dev seed
const ALICE_SEED: &str = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("usage: send_test_asset <destination_address> <amount>");
        eprintln!("  amount is in smallest units (1000000 = 1.0 for 6 decimal assets)");
        eprintln!("  example: send_test_asset 14ieGWthxohjDtrbdN7dM2V6o2REdVDCpZvx4nCNaQw3fbD3 1000000");
        std::process::exit(1);
    }

    let destination = &args[1];
    let amount: u128 = args[2].parse()?;

    // asset ID - use 0 for native token, or specify test asset ID
    let asset_id: Option<u32> = args.get(3).map(|s| s.parse().unwrap_or(0));

    println!("connecting to {}", PASEO_ASSETHUB_RPC);
    let client = OnlineClient::<PolkadotConfig>::from_url(PASEO_ASSETHUB_RPC).await?;

    // create alice's keypair
    let seed_bytes = hex::decode(ALICE_SEED.trim_start_matches("0x"))?;
    let pair = sr25519::Pair::from_seed_slice(&seed_bytes)?;
    let signer = subxt::tx::PairSigner::new(pair.clone());

    // decode destination
    let dest_bytes = hwpay::wallet::polkadot::decode_ss58(destination)?;

    println!("alice: {}", pair.public());
    println!("destination: {}", destination);
    println!("amount: {}", amount);

    let tx_hash = if let Some(id) = asset_id {
        // send asset (USDC/USDT)
        println!("sending asset id {} ...", id);

        let call = subxt::dynamic::tx(
            "Assets",
            "transfer_keep_alive",
            vec![
                ("id", subxt::dynamic::Value::u128(id as u128)),
                ("target", subxt::dynamic::Value::unnamed_variant("Id", vec![
                    subxt::dynamic::Value::from_bytes(dest_bytes),
                ])),
                ("amount", subxt::dynamic::Value::u128(amount)),
            ],
        );

        let result = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await?
            .wait_for_finalized_success()
            .await?;

        format!("{:?}", result.extrinsic_hash())
    } else {
        // send native token
        println!("sending native token...");

        let call = subxt::dynamic::tx(
            "Balances",
            "transfer_keep_alive",
            vec![
                ("dest", subxt::dynamic::Value::unnamed_variant("Id", vec![
                    subxt::dynamic::Value::from_bytes(dest_bytes),
                ])),
                ("value", subxt::dynamic::Value::u128(amount)),
            ],
        );

        let result = client
            .tx()
            .sign_and_submit_then_watch_default(&call, &signer)
            .await?
            .wait_for_finalized_success()
            .await?;

        format!("{:?}", result.extrinsic_hash())
    };

    println!("transaction finalized: {}", tx_hash);
    println!("success!");

    Ok(())
}
