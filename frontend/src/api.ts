
const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`)
  return r.json()
}

export interface ExplorerStatus { synced_height: number; synced_block_hash: string }
export interface BlockSummary {
  height: number; hash: string; timestamp: string;
  tx_count: number; miner_address: string | null; total_reward: number
}
export interface BlockDetail extends BlockSummary {
  prev_hash: string; merkle_root: string; difficulty: string; nonce: string; txids: string[]
}
export interface TxInput { prev_txid: string; prev_vout: number; script_sig_hex: string; is_coinbase: boolean }
export interface TxOutput { vout: number; value: number; script_type: string; address: string | null; spent_by_txid: string | null }
export interface TxDetail {
  txid: string; block_height: number; block_hash: string; tx_index: number;
  is_coinbase: boolean; input_count: number; output_count: number; total_out: number; fee: number;
  inputs: TxInput[]; outputs: TxOutput[]
}
export interface AddressStats { address: string; balance: number; total_received: number; total_sent: number; tx_count: number }
export interface AddressTx { txid: string; block_height: number; total_out: number }
export interface HtlcInfo {
  txid: string; vout: number; block_height: number; htlc_type: string; value: number;
  recipient_addr: string; refund_addr: string; secret_hash: string;
  timeout_height: number; state: string; spend_txid: string | null
}
export interface AgreementInfo { agreement_hash: string; anchor_type: string; txid: string; block_height: number; milestone_id: string | null }
export interface MinerStats { address: string; blocks_mined: number; total_reward: number; last_block_height: number | null }
export interface SearchResponse { result_type: string; value: string }

/**
 * Shape of GET /pool/stats as the explorer backend actually serves it (verified against the
 * live endpoint 2026-07-29). Every field is optional because this page must render before the
 * request resolves, and because the pool can be stopped.
 *
 * Note there is no `asic` object and no `total_miners` — an earlier draft of Home.tsx expected
 * both. `chain_active_miners_window` is the real "how many miners are producing" figure.
 * `pool_hashrate` is served but currently returns a physically impossible magnitude, so it is
 * deliberately NOT surfaced as a hashrate until the backend value is trustworthy.
 */
export interface PoolStats {
  pool_hashrate?: number
  chain_active_miners_window?: number
  chain_active_miners_window_blocks?: number
  network_height?: number
  difficulty?: number
  backend_connected?: boolean
  payout_model?: string
}

export const api = {
  status: () => get<ExplorerStatus>('/status'),
  blocks: (limit = 20, offset = 0) => get<BlockSummary[]>(`/blocks?limit=${limit}&offset=${offset}`),
  blockByHeight: (h: number) => get<BlockDetail>(`/blocks/height/${h}`),
  blockByHash: (hash: string) => get<BlockDetail>(`/blocks/hash/${hash}`),
  tx: (txid: string) => get<TxDetail>(`/tx/${txid}`),
  address: (addr: string) => get<AddressStats>(`/address/${addr}`),
  addressTxs: (addr: string, limit = 50) => get<AddressTx[]>(`/address/${addr}/txs?limit=${limit}`),
  addressHtlcs: (addr: string) => get<HtlcInfo[]>(`/address/${addr}/htlcs`),
  agreement: (hash: string) => get<AgreementInfo>(`/agreement/${hash}`),
  // Verified live against the explorer backend on 2026-07-29: /agreements, /htlcs and /miners
  // all return 200 with payloads matching the interfaces above.
  //
  // /pool/stats is the exception — it is served on the public API host but NOT by the backend
  // the dev proxy targets, so it 404s in local dev and its tile falls back to "—". That is a
  // backend deployment gap, not a client bug; the path is the documented one.
  poolStats: () => get<PoolStats>('/pool/stats'),
  miners: (limit = 50) => get<MinerStats[]>(`/miners?limit=${limit}`),
  agreements: (limit = 50) => get<AgreementInfo[]>(`/agreements?limit=${limit}`),
  htlcs: (limit = 50) => get<HtlcInfo[]>(`/htlcs?limit=${limit}`),
  search: (q: string) => get<SearchResponse | null>(`/search?q=${encodeURIComponent(q)}`),
}
