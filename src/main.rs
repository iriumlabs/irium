// See src/lib.rs — main.rs re-includes the same mod tree so it needs
// the same allow set. Keep these in sync with the lib.rs attributes.
#![allow(clippy::all)]
#![allow(warnings)]

mod activation;
mod auxpow;
mod anchors;
mod block;
mod btc_spv;
mod btc_tx_parse;
mod chain;
mod constants;
mod genesis;
#[allow(dead_code)]
mod ltc_spv;
// Pulled in so chain.rs's `#[cfg(test)] mod tests` can reference
// `crate::mempool::evict_invalid_mempool_entries` and `MempoolManager`
// when `cargo test --all` builds tests for this thin secondary binary.
// Not used by main() itself.
#[allow(dead_code)]
mod mempool;
mod pow;
#[allow(dead_code)]
mod scrypt_pow;
mod tx;

use crate::activation::{
    network_kind_from_env, resolved_htlcv1_activation_height, resolved_lwma_activation_height,
    resolved_lwma_v2_activation_height,
};
use crate::chain::{block_from_locked, ChainParams, ChainState, LwmaParams};
use crate::genesis::load_locked_genesis;
use crate::pow::Target;

fn main() {
    let locked = match load_locked_genesis() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to load locked genesis: {e}");
            std::process::exit(1);
        }
    };

    let block = match block_from_locked(&locked) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to build genesis block from locked config: {e}");
            std::process::exit(1);
        }
    };
    let pow_limit = Target { bits: 0x1d00_ffff };
    let network = network_kind_from_env();
    let params = ChainParams {
        genesis_block: block,
        pow_limit,
        htlcv1_activation_height: resolved_htlcv1_activation_height(network),
        mpsov1_activation_height: None,
        lwma: LwmaParams::new(resolved_lwma_activation_height(network), pow_limit),
        lwma_v2: resolved_lwma_v2_activation_height(network)
            .map(|h| LwmaParams::new_v2(Some(h), pow_limit)),
        auxpow_activation_height: crate::activation::resolved_auxpow_activation_height(network),
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
    };

    let state = ChainState::new(params);

    println!("Irium Rust node initialized:");
    println!("  chain height: {}", state.height);
    println!("  genesis hash: {}", locked.header.hash);
}
