//! generate deposit addresses for testing

use hwpay::PolkadotWallet;

fn main() {
    // test seed (32 bytes of 0x01) - same as DEPOSIT_WALLET_SEED env
    let seed = [0x01u8; 32];
    let wallet = PolkadotWallet::from_seed(&seed).unwrap();

    // generate deposit address for test user
    let addr = wallet.derive_address("test-user-1", 0);
    println!("deposit address for 'test-user-1' index 0: {}", addr);

    // also show a few more
    for i in 1..3 {
        let addr = wallet.derive_address("test-user-1", i);
        println!("deposit address for 'test-user-1' index {}: {}", i, addr);
    }
}
