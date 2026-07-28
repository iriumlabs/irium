//! One process-wide lock for every test that reads or writes process environment.
//!
//! Rust runs a target's tests as threads in ONE process, so `set_var` is global: any test
//! that mutates env can break any test that reads it, whether or not they know about each
//! other. This suite had SIX independent locks (poawx_mining_harness, network, p2p's
//! `orphan_test_lock`, bin/iriumd ×2, bin/irium-miner), which is the same as having none —
//! tests holding different locks never exclude one another.
//!
//! The symptom was 12 of ~1000 lib tests failing per run with a set that CHANGED between
//! runs. One run lost `p2p::attaches_out_of_order_orphan_headers`, the next lost
//! `poawx_puzzle::mainnet_ignores_the_env_override` instead — and that one printed the
//! smoking gun: `IRIUM_POAWX_PUZZLE_BITS=17 disagrees with
//! IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS=1`, two tests writing the same consensus knob at the
//! same instant. Others raced `IRIUM_NETWORK` and failed with `assignment v2: wrong
//! network` or `no nonce satisfied target`.
//!
//! A suite that reddens at random teaches everyone to ignore red, which is how a real
//! regression gets shipped. Every env-touching test in a target takes THIS lock and no
//! other.
//!
//! Lives in its own module because `src/main.rs` re-declares the whole module tree, so the
//! guard has to resolve from both crate roots.

/// Serialises env-touching tests. Poisoning is ignored deliberately: one test panicking
/// while holding the lock must not cascade into failures for every test after it.
#[cfg(test)]
pub(crate) fn guard() -> std::sync::MutexGuard<'static, ()> {
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ENV.lock().unwrap_or_else(|e| e.into_inner())
}
