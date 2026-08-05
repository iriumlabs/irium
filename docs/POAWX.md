# PoAW-X — Irium Proposer Consensus

PoAW-X (Proof-of-Adaptive-Work, eXtended) is Irium's block-proposer consensus layer. It adds
verifiable, hardware-neutral block proposal on top of Irium's existing SHA-256d proof of work.

> **Reward model changed at block 66,400.** From that height the full block reward is paid to a
> single VRF-selected proposer, not split across four roles. See
> [Reward distribution](#reward-distribution-proposer-takes-all-from-block-66400) below. The
> claim that PoAW-X leaves the underlying PoW and LWMA-144 difficulty untouched held only between
> blocks 50,000 and 61,414 — see PoW demotion and the difficulty freeze in *Current status*.

## Activation: mainnet block 50,000

PoAW-X activates on Irium **mainnet at block height 50,000**.

- **Before block 50,000:** blocks follow the existing SHA-256d PoW rules, unchanged.
- **At and after block 50,000:** every block must additionally satisfy the PoAW-X consensus rules
  described below.

The activation height is fixed in consensus code (`MAINNET_POAWX_ACTIVATION_HEIGHT = 50_000`); it
is **not** an operator setting and cannot be enabled or disabled by configuration.

> **Operators and miners must upgrade to iriumd v1.9.119 (or later) before block 50,000.** A node
> still running an older binary will reject post-activation blocks and fall off the canonical chain.

## Activation: mainnet block 66,400 — single-payee reward (HARD FORK)

At **mainnet block height 66,400** the reward model changed. This was a **hard fork**: the pre- and
post-66,400 coinbase rules are mutually exclusive, so a node must run a binary carrying the gate in
order to follow the chain past 66,399.

- **Before block 66,400:** the legacy multi-role coinbase rules apply, byte-identically. Persisted
  history still re-validates on restart.
- **At and after block 66,400:** the coinbase must pay the **full block subsidy to exactly one
  payee** — the block's VRF-selected proposer. A legacy multi-payee coinbase is rejected.

Fixed in consensus code as `MAINNET_SINGLE_PAYEE_REWARD_ACTIVATION_HEIGHT = Some(66_400)`; on
mainnet the environment override is ignored.

> ⚠️ **A node without this gate stops following the chain at block 66,399.** It rejects every block
> from 66,400 onward with a `shared-reward: expected N role outputs, found 1` error while still
> reporting itself as connected with peers. The symptom is a frozen height, not an obvious failure.
>
> **No tagged release contains this gate yet.** The latest published node release, **v1.9.191**, is
> commit `99859111` and predates it. Until a release is cut, follow the chain by building from
> `main` at commit `d57d22a5` or later:
>
> ```bash
> git pull && cargo build --release --bin iriumd
> ```
>
> Verify your build carries the gate before relying on it:
>
> ```bash
> strings target/release/iriumd | grep -c IRIUM_POAWX_SINGLE_PAYEE_REWARD_ACTIVATION_HEIGHT
> # 1 = gate present; 0 = your build will freeze at 66,399
> ```

## Current status (updated 2026-08-05)

The consensus **gates** listed below are active on mainnet from block 50,000 and are enforced by
every node: proposer selection validation, proposer registration, anti-domination, assigned puzzle
work, the finality committee, and candidate admission. Blocks that do not satisfy them are rejected.

What changed since the previous revision of this section:

- **The 55/22/13/10 split no longer pays out.** From block 66,400 the full 50 IRM subsidy goes to a
  single VRF-selected proposer. Verified by decoding mainnet coinbases across the boundary: block
  66,399 carries four P2PKH role outputs (2.75 / 1.10 / 0.65 / 0.50 IRM), block 66,400 carries one
  (50.00000000 IRM). The four-role split described in earlier revisions is now **historical**.
  - **The role and candidate-set machinery has *not* been removed.** Role workers still run and
    still enrol on both mainnet hosts, and the admission gates outside the reward path are
    unchanged. What stopped is *payment*: the reward path no longer consults the role manifest, so
    role claims no longer determine who is paid. Retiring the machinery itself is a separate,
    activation-gated change that has been designed but **not built**.
- **PoW demotion is active on mainnet** from block 61,414 (`MAINNET_COMBINED_ACTIVATION_HEIGHT`).
  Earlier revisions of this section said it was not active. A proposer that is eligible for the
  current height is validated against a reduced (floor) target; every other block must still meet the
  full network target.
- **Ticket-proof and pool-admission enforcement are active** from block 62,236
  (`MAINNET_FAIR_DISTRIBUTION_ACTIVATION_HEIGHT`).
- **The difficulty freeze is active** from block 64,291
  (`MAINNET_DIFFICULTY_DEMOTION_FREEZE_ACTIVATION_HEIGHT`). While demotion is active LWMA has no
  feedback — an eligible proposer only beats the floor, so block times say nothing about the
  network target, and LWMA ratchets forever. Unfrozen, the declared difficulty ran from 1.72e6 at
  block 61,413 to ~9.7e56 by 64,290. The target is now held at the value in force immediately
  before demotion began (block 61,413: difficulty 1,721,700, bits `1a09be94`). This matters
  because a NON-eligible miner must still meet the full target, so the runaway was progressively
  locking out the independent miners the network needs.
  ⚠️ An earlier arming of this freeze at block 63,824 never took effect: the gate was
  const-controlled but its baseline lookup read an env var that mainnet ignores, so it silently
  returned `None`. Fixed and re-armed in v1.9.149.

Limitations that remain, stated plainly:

- **Block proposal is not yet meaningfully open to third parties.** Non-exclusive proposer
  eligibility is active from block 59,900, so a non-incumbent key *can* become eligible and propose.
  But an **ineligible** miner's block is judged against the full network target rather than the
  demoted floor, which in practice is an enormous disadvantage — so proposal today remains
  concentrated among keys that already hold eligibility. Becoming eligible still depends on an
  existing producer including your registration.
- **Block production is still operator-run.** Both producing keys on mainnet belong to the
  operator. Under the single-payee model the whole subsidy now follows whichever key the VRF
  selects, so reward concentration tracks proposal concentration directly — there is no longer a
  role split to spread it. Treat proposer selection as a working, verifiable mechanism, not as
  evidence of decentralisation.
- **Fraud-proof enforcement is deliberately off on mainnet.** Fraud-proof sections are carried but
  not enforced; the validator is disabled rather than half-armed, which is intentional.

We continue to treat the proposal-concentration limitation as a defect to fix, not as intended
behaviour. This section will be updated when that changes.

## What PoAW-X adds

1. **VRF proposer selection** — each block has a verifiably-selected proposer chosen by a Verifiable
   Random Function, not just whoever finds the proof of work first.
2. **Single-payee reward** — the full block reward goes to the block's VRF-selected proposer.
   (Before block 66,400 this was a 55/22/13/10 split across four contribution roles.)
3. **Anti-domination** — per-identity weighting over a rolling 2016-block window discourages any
   single identity from dominating proposal (the weighting is enforced; note that block proposal on
   mainnet is currently concentrated in a single producer, see Current status).
4. **Distributed finality** — a registered committee provides 2/3-threshold finality votes (the
   finality gate is enforced; a broad multi-party committee is not yet operating in production).
5. **Consensus security gates** — hidden role-precommit, sybil tickets, committed admission,
   deterministic receipts, equivocation and lane-validation checks.

## Reward distribution: proposer takes all (from block 66,400)

From block **66,400**, each block's coinbase pays the **entire 50 IRM subsidy to one payee** — the
block's VRF-selected proposer (`worker_pkh`). There is no role split. The coinbase carries a single
P2PKH output alongside the `irx1` `OP_RETURN` commitment; a coinbase that splits the reward, pays a
different key, underpays, or hides value in a non-P2PKH output is rejected. Third-party fees are not
supported in this model (`fee_bps` must be 0).

**What did *not* change — this is the important part.** The single-payee gate changes only *how the
reward is distributed once a proposer is selected*. It does not touch **how a proposer is selected**:

- **Selection is still hardware-neutral.** Since the PoW-demotion activation at block 61,414, an
  eligible proposer's block is validated against a constant anti-spam floor rather than the full
  network target. A commodity CPU, a GPU and an ASIC all clear that floor trivially, so none of them
  buys a better chance of being selected. Adding hashrate does not raise your odds.
- **Selection is still fair VRF sortition.** The proposer for each height is drawn by an ECVRF
  (RFC-9381) proof bound to a per-height seed. Each eligible key wins roughly `1/n` of blocks at
  random, regardless of what hardware it runs on.
- Proposer registration, the eligibility freeze, anti-domination, fork-choice and finality are all
  unaffected by this gate.

So the network is no less hardware-neutral and no less random than before 66,400. What changed is
that the winner now receives the whole reward instead of 55% of it.

### Historical: the 55/22/13/10 role split (blocks 62,236 – 66,399)

Before block 66,400 the reward was divided across four contribution roles and materialized as four
P2PKH coinbase outputs:

| Role | Share | Paid on 50 IRM |
|------|-------|----------------|
| Proposer (primary) | 55% | 27.5 IRM |
| Compute | 22% | 11.0 IRM |
| Verify | 13% | 6.5 IRM |
| Support | 10% | 5.0 IRM |

This rule still governs the validation of blocks below 66,400, which is why historical chain data
continues to re-validate on restart. It no longer applies to new blocks.

**The role machinery still exists.** Role workers, role receipts and the candidate-set admission
gates remain in the codebase and continue to run — they simply no longer determine payment, because
the reward path stopped consulting the role manifest at 66,400. Nothing has been deleted. Retiring
that machinery is a separate, activation-gated change that is designed but not built.

## VRF proposer system

- **Sortition.** For each height, an eligible proposer is selected by an ECVRF (RFC-9381) proof bound
  to a per-height seed. The proof (`AssignmentProofV2`) is verifiable by every node, so the selected
  proposer cannot be forged.
- **Registration.** To be eligible, a proposer registers a VRF public key on-chain. Registration
  carries a sybil-resistant proof of work and is **frozen** at a depth below the tip, so the
  per-height seed (revealed only at the previous block) cannot be used to register a winning key
  after the fact.
- **Seed.** The selection seed is derived from prior block data and finality signatures, so it is
  unpredictable before the parent block and deterministic afterward.

## Running a node

1. Install **iriumd v1.9.119** (or later) — see [QUICKSTART.md](../QUICKSTART.md) and
   [README.md](../README.md).
2. Run it as you would any Irium node. From block 50,000 it validates PoAW-X automatically — **no
   environment variables are required on mainnet**; the activation height and all consensus rules are
   built in.
3. Make sure you are upgraded **before** block 50,000.

## Important — one-time re-validation on first start with v1.9.119

The first time **v1.9.119** starts on a node that already has chain history, it performs a **one-time re-validation** of its stored chain. While this runs (usually a few minutes), your node may briefly show a **lower block height and then climb back** to the network tip. **This is normal and expected.**

- It happens **once**, on the first start after upgrading — later restarts are fast.
- **No data is lost.** Balances and wallets are unaffected; the node rejoins consensus automatically once it catches up.
- Larger or older nodes take longer to re-validate. **Let it finish — do not stop the node while it is catching up.**
- This does not change PoAW-X activation, which remains height-gated at block 50,000.

*(A later release will remove this one-time step so upgrades resume instantly.)*

## Mining

From block 50,000, **mining requires a full `iriumd` node** — a pool/stratum connection alone is no
longer sufficient to produce valid blocks, because each block must carry a verifiable proposer
assignment and role receipts that only a full node can build and validate.

- Run your full node (`iriumd`).
- Run the bundled miner against it with the PoAW-X flag:

  ```
  irium-miner --poawx
  ```

  The miner requests the current role assignment from your node, performs the role work, and submits
  role receipts; your node assembles and validates the block. See [MINING.md](MINING.md) for
  hardware-specific miner setup.

Pool operators must run a full node and move their workers to the full-node flow before block 50,000.

## Consensus security gates

At and after block 50,000, every block is validated against the full PoAW-X gate set (all of which
were validated in a 2016-block adversarial soak before activation):

- **Proposer VRF** — the block's proposer assignment proof must verify against the registered VRF key
  and per-height seed.
- **Hidden role-precommit** — each block commits the next block's role-claim leaves; claims must
  reveal pre-committed leaves matching the parent's `precommit_root`.
- **Sybil tickets** — role claims must carry tickets meeting the minimum sybil-work threshold.
- **Committed admission** — the committed admission root must match.
- **Reward payout** — from block 66,400 the coinbase must pay the full subsidy to the VRF-selected
  proposer and nothing to anyone else. Between 62,236 and 66,399 it had to pay the 55/22/13/10 split
  to the correct role addresses instead.
- **Anti-domination** — per-identity weighting over the rolling 2016-block window.
- **Finality committee** — 2/3-threshold finality votes from distinct registered committee keys.
- **Audit hardening** — deterministic receipts root, equivocation and parent-hash checks, signature
  coverage, lane-byte validation, strict leaf decoding.

A block that fails any required gate at or after activation is rejected.

## RPC endpoints

PoAW-X adds the following node RPC endpoints (see [API.md](API.md) for full request/response detail):

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/poawx/assignment` | Current proposer/role assignment for the tip |
| POST | `/poawx/receipt` | Submit a solved role receipt (miner to node) |
| POST | `/poawx/registration` | Submit/gossip a proposer registration |
| POST | `/poawx/finality-vote` | Submit/gossip a finality-committee vote |
| GET  | `/poawx/finality-votes?target_height=N` | Finality votes near a height |
| GET  | `/rpc/poawx_dominance` | Anti-domination weight snapshot |

## See also

- [WHITEPAPER.md](WHITEPAPER.md) — Section 4 Consensus Mechanism (PoAW-X specification)
- [MINING.md](MINING.md) — miner setup
- [API.md](API.md) — RPC reference
