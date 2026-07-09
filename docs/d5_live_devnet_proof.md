# D5 LIVE isolated-devnet direct-payout proof (proposer-VRF off)

The in-process proof (docs/d5_direct_payout_proof.md) established the semantics
against the node's real connect_block. This document records the LIVE end-to-end
run: the actual pool binary produces a delegated block over stratum and the actual
node accepts it via submit_block_extended, paying the miner directly on-chain.

Harness: pool/irium-stratum/tools/devnet_directpay_demo.sh (isolated storage +
ports; mainnet :38300 and rig :38500 untouched; torn down at end).

## Topology (all four real binaries, built from this branch)

- iriumd (node): devnet, isolated IRIUM_DATA_DIR/BLOCKS_DIR/STATE_DIR, gates ON
  EXCEPT proposer-VRF (IRIUM_POAWX_PROPOSER_VRF_* unset => proposer_vrf_enforced
  == false), delegation active. Isolation asserted from the node log
  ("Using blocks dir: .../devnet-directpay/blocks") - never ~/.irium.
- irium-stratum (pool): IRIUM_STRATUM_POAWX=1, NATIVE_REWARDABLE_ENABLED=1,
  IRIUM_POAWX_STAGE_D_PRODUCTION=1, delegation server on loopback, isolated key/
  store paths.
- irium-wallet: signs the miner's v2 delegation (poawx-register) with an isolated
  key (IRIUM_POAWX_DELEGATION_SECRET_HEX), never a mainnet/wallet key.
- irium-miner: stratum client mining the pool's jobs.

## What was proven LIVE

1. D1 live: the pool loaded its custodial proposer secret and advertised the
   derived pubkey - pool log: "custodial proposer pubkey advertised (Stage D,
   network_id=2)"; /poawx/pool-identity returns proposer_pubkey.
2. Delegation signup live: irium-wallet poawx-register signed a v2 delegation
   binding the advertised proposer pubkey + pool pubkey + miner payout, POSTed it,
   and the pool stored it - "delegation registered (miner_pkh ..., worker rig1,
   ... status active)".
3. Pool produces the mode-1 multi-role coinbase live: session adapter
   native_rewardable_reserved; producer trace "build_mode1 OK ...
   delegation_present=true", "session_receipts BUILT count=1
   phase20_ext_present=true". The notify coinbase carries 4 role P2PKH outputs +
   the irx1 OP_RETURN commitment.
4. Node ACCEPTS the pool-produced block: node log "[submit_block_extended]
   accepted height=3 ... source=pool_stratum_native_rewardable". 3 blocks
   accepted; tip advanced.
5. Miner paid directly on-chain: accepted block height=3 has
   miner_address = the miner's address, poawx_receipts[0].delegation present
   (deleg_ver=02), and the miner payout pkh appears in the coinbase. The pool
   delegate pubkey is distinct from the miner (no central wallet).
6. Proposer-VRF genuinely off: the accepted receipt carries NO proposer_assignment
   (PRP1 section absent) and the node accepted it anyway - exactly the pool's
   no-ECVRF-prover mode.

## Notes / honest scope

- Single-miner synthetic role source (IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS=1,
  testnet/devnet-only): all role solver pkhs resolve to the one miner, so the
  miner receives PRIMARY + roles. Distinct per-role participants would require the
  live role-collection path (separate work). The direct-payout claim (miner paid
  on-chain by a pool-produced, node-accepted delegated block, proposer-VRF off) is
  fully demonstrated.
- The gate set enables every PoAW-X gate that does not require the pool to hold an
  ECVRF prover; proposer-VRF (and the full custodial-proposer VRF mode, D4) stays
  off/deferred per the ECVRF-prover decision (docs/d4_spike_finding.md).
- Isolated + torn down; nothing merged, deployed, or activated; live pool/mainnet
  untouched.
