import type { TxOutput } from '../api'

// ─── Coinbase reward-distribution decode helper ──────────────────────────────
//
// The API/indexer already decodes every coinbase output into a typed
// { vout, value, script_type, address } shape (see TxOutput) — including the
// P2PKH recipient ADDRESS, encoded with the same base58check version byte the
// rest of the explorer uses. This helper does NOT re-decode scripts; it simply
// labels the already-decoded outputs with their PoAW-X reward role so the
// BlockPage can render an honest reward-distribution table.
//
// Role model (PoAW-X): the first four P2PKH coinbase outputs are, in vout
// order, the PRIMARY (55%), COMPUTE (22%), VERIFY (13%) and SUPPORT (10%)
// shares of the block reward. Any further P2PKH outputs, and the non-payout
// outputs (irx1 commitment, phase-20 data blobs), are labelled honestly rather
// than forced into a role. If a future change makes the four roles pay
// DISTINCT addresses, each row already carries its own address and renders
// correctly with zero further changes.

export interface RewardRow {
  vout: number
  /** Human role label, e.g. "Primary", "Data", "Output 6". */
  role: string
  /** Reward-share percentage for the four role outputs; null otherwise. */
  pct: string | null
  scriptType: string
  /** Recipient address (P2PKH outputs) or null for data/commitment outputs. */
  address: string | null
  /** Payout value in satoshis (1 IRM = 100_000_000 sats). */
  value: number
}

const ROLES: Array<[string, string]> = [
  ['Primary', '55%'],
  ['Compute', '22%'],
  ['Verify', '13%'],
  ['Support', '10%'],
]

/**
 * Map decoded coinbase outputs to labelled reward-distribution rows.
 * Handles any output count (6 or 7 today; more in future) — it never assumes
 * exactly four outputs, and only the first four P2PKH outputs get role labels.
 */
export function rewardDistribution(outputs: TxOutput[]): RewardRow[] {
  const ordered = [...outputs].sort((a, b) => a.vout - b.vout)
  let p2pkhSeen = 0
  return ordered.map((o): RewardRow => {
    let role: string
    let pct: string | null = null
    if (o.script_type === 'p2pkh') {
      if (p2pkhSeen < ROLES.length) {
        role = ROLES[p2pkhSeen][0]
        pct = ROLES[p2pkhSeen][1]
      } else {
        role = `Output ${o.vout}`
      }
      p2pkhSeen++
    } else if (o.script_type === 'op_return') {
      role = 'Commitment (irx1)'
    } else if (o.script_type === 'irium_data') {
      role = 'Data'
    } else {
      role = `Output ${o.vout}`
    }
    return {
      vout: o.vout,
      role,
      pct,
      scriptType: o.script_type,
      address: o.address,
      value: o.value,
    }
  })
}
