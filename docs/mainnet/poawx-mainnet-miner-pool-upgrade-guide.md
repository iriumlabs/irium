# PoAW-X Mainnet Miner / Pool Upgrade Guide (DRAFT — no activation scheduled)

For miners and pool/stratum operators. **No activation scheduled; mainnet is PoW-only until an announced,
approved activation.** Not audited / not production-ready / not mainnet-ready.

## Impact summary

- **Before `A` (activation height):** mining is unchanged — standard Irium PoW; no PoAW-X sections.
- **`A ..= A+W` (warm-up):** miners must begin producing PoAW-X blocks: candidate set/admission, true-VRF
  assignment, puzzle proofs, finality proof, role rewards (55/22/13/10), DMC1 dominance commitment, ADM1
  adaptive commitment, RMF1 reward manifest, and **register tickets (TKT1)** for the next epoch.
- **From `E = A+W+1`:** every rewarded role must reference an **active on-chain ticket** (registered in an
  earlier block). Blocks missing required sections or with ineligible role tickets are rejected.

## What pool/miner software must add

1. Build PoAW-X blocks via the consensus builder path (the reference is
   `poawx_mining_harness::build_devnet_all_gates_block_with` with all sections enabled). NOTE: the
   reference harness uses deterministic devnet keys — production miners must use **real role identities
   and keys** and register tickets for those identities.
2. **Ticket lifecycle:** register a miner work ticket (TKT1, with sybil work meeting the configured bits)
   in block H for the role identity that will be rewarded at H+1; emit the matching `role_ticket_proofs`.
3. Emit RMF1 = the canonical reward manifest for the actual recipients (the node rejects any mismatch).
4. Do **not** pay a penalized/suspended finality signer (the node rejects it).

## Pool operator actions (when announced)

1. Upgrade stratum/pool to the activation release before `A`; test on devnet first.
2. Provision role identities + ticket registration ahead of `E` (warm-up exists precisely for this).
3. Keep RPC/stratum non-public; no change to that posture.
4. Monitor share/block acceptance + reject reasons across `A` and `E`.

## Do not
- Do not use the harness's devnet keys on mainnet.
- Do not skip the warm-up ticket registration — roles will be ineligible at `E`.

## Current status
No activation height exists; preparatory only. The reference live harness (`--phase31-34`) demonstrates
section emission on devnet.
