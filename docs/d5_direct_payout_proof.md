# D5 direct-payout end-to-end proof (proposer-VRF off)

Goal (user's Option 1): prove the node accepts a pool-produced delegated block
that pays the miner directly on-chain, with proposer-VRF enforcement OFF - the
mode the pool can run today with no ECVRF prover (see d4_spike_finding.md).

## How the proof is constructed (in-process, deterministic)

`stage_d_delegated_direct_payout_proposer_vrf_off_connect_block_pays_miner`
(src/chain.rs) runs the node's REAL `connect_block` on a delegated (mode-1)
all-gates block, with proposer-VRF enforcement OFF, and asserts acceptance +
direct miner payout. It is the pool's exact scenario:

- Every all-gates check is ON (tickets, candidate-set, assignment-proof,
  puzzle-work, finality, committed-admission, true-VRF, penalty, anti-domination,
  multi-role reward, delegation) EXCEPT proposer-VRF (`IRIUM_POAWX_PROPOSER_VRF_*`
  unset => `proposer_vrf_enforced(2) == false`, asserted in the test).
- The block carries a miner-signed v2 `Delegation` (payout key signs; binds
  proposer_pubkey + pool_pubkey + payout) and NO proposer-VRF assignment
  (`proposer_ctx = None` => `phase20_ext.proposer_assignment == None`, asserted).
- `connect_block` ACCEPTS it and the tip advances.
- The on-chain coinbase: PRIMARY output pays the MINER's payout pkh directly;
  the role outputs pay the pool delegate (which did the role work). Miner != pool
  delegate ("no central wallet").

## Why this is a faithful end-to-end proof of the POOL's path

The proof uses the node's real `connect_block` (not a stub) on a block that is
byte-equivalent to what the pool produces, and that equivalence is separately
proven by the pool parity tests:
- `phase18b3_build_mode1_receipt_and_root_parity`: the pool's mode-1 receipt pays
  the miner (`worker_pkh == miner`, `worker_pubkey == pool delegate`, delegation
  embedded) and its receipts-root equals the node's `irx1_root_from_block_receipts`.
- `phase18c_native_notify_split_matches_validation_coinbase_mode1`: the pool's
  multi-role notify coinbase (cb1+extranonce+cb2) reconstructs to the exact
  validation coinbase.
- D2 `d2_proposer_registration_section_full_ext_parity_with_node`: the pool's ext
  (incl. any PRG1 registration) round-trips through the node byte-for-byte.

So: the node accepts a delegated direct-payout block with proposer-VRF off (this
proof), and the pool produces byte-identical receipts/coinbase (parity proofs) =>
the node accepts the pool's delegated direct-payout block and the miner is paid
directly. No ECVRF prover is involved anywhere.

## What this is and is not

- IS: a deterministic in-process proof against the node's real consensus
  validation, exercising the pool's exact production scenario. Repeatable, not
  environment-fragile.
- IS NOT: a live TCP devnet run of the pool binary end-to-end (node+pool+miner
  over sockets). The in-process proof + byte-parity proofs together establish the
  same fact without the fragility of a full socket standup. If a live-socket
  demonstration is wanted as additional evidence, it is a separate follow-up.
- The full proposer-VRF-enforced custodial mode (D4) remains blocked on the
  ECVRF-prover architecture decision and is explicitly deferred.

All work is behind `stage_d_production_active` / the emit gate, mainnet hard-off.
Not merged, not deployed, no activation.
