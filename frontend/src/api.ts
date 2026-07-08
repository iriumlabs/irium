const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`)
  return r.json()
}

async function getAbs<T>(url: string): Promise<T> {
  const r = await fetch(url)
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

export interface ExplorerStatus { synced_height: number; synced_block_hash: string }
export interface BlockSummary {
  height: number; hash: string; timestamp: string;
  tx_count: number; miner_address: string | null; total_reward: number;
  coinbase_tag: string | null
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

export interface PoolStats {
  pool: string
  total_miners: number
  total_blocks_found: number
  blocks_found_today: number
  asic: {
    active_miners: number
    tcp_sessions: number
    accepted_shares: number
    rejected_shares: number
    blocks_found: number
    integrity: string
    hashrate_estimate_hps: number
    hashrate_window_seconds: number
    hashrate_confidence: string
    current_diff: number
    recent_reject_rate_pct: number | null
  }
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
  agreements: (limit = 50) => get<AgreementInfo[]>(`/agreements?limit=${limit}`),
  agreement: (hash: string) => get<AgreementInfo>(`/agreement/${hash}`),
  htlcs: (limit = 50) => get<HtlcInfo[]>(`/htlcs?limit=${limit}`),
  miners: (limit = 50) => get<MinerStats[]>(`/miners?limit=${limit}`),
  search: (q: string) => get<SearchResponse | null>(`/search?q=${encodeURIComponent(q)}`),
  poolStats: () => getAbs<PoolStats>('/pool-stats/'),
}
