import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { api } from '../api'
import Breadcrumb from '../components/Breadcrumb'
import StatCard from '../components/StatCard'
import StatRow from '../components/StatRow'
import HashLink from '../components/HashLink'
import CopyButton from '../components/CopyButton'
import { satToIrm, fmtTime } from '../lib/fmt'
import { rewardDistribution } from '../lib/coinbase'

export default function BlockPage() {
  const { id } = useParams<{ id: string }>()
  const isHeight = /^\d+$/.test(id ?? '')
  const { data: block, isLoading, error } = useQuery({
    queryKey: ['block', id],
    queryFn: () => isHeight ? api.blockByHeight(Number(id)) : api.blockByHash(id!),
    enabled: !!id,
  })

  // Coinbase is always the first transaction. Fetch it so we can render the
  // reward-distribution breakdown; the API already decodes each output's
  // address, so we only label the outputs with their PoAW-X reward role.
  const coinbaseTxid = block?.txids?.[0]
  const { data: coinbaseTx } = useQuery({
    queryKey: ['tx', coinbaseTxid],
    queryFn: () => api.tx(coinbaseTxid!),
    enabled: !!coinbaseTxid,
  })
  const rewards = coinbaseTx?.is_coinbase ? rewardDistribution(coinbaseTx.outputs) : []

  if (isLoading) return <div className="text-zinc-500 text-sm py-10 text-center">Loading block...</div>
  if (error || !block) return <div className="text-rose-400 text-sm py-10 text-center">Block not found</div>

  return (
    <div className="space-y-6">
      <Breadcrumb items={[{ label: 'Home', to: '/' }, { label: 'Blocks', to: '/blocks' }, { label: `#${block.height.toLocaleString()}` }]} />

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 mono">Block #{block.height.toLocaleString()}</h1>
          <div className="flex items-center gap-2 mt-1.5">
            <span className="mono text-xs text-zinc-600 break-all">{block.hash}</span>
            <CopyButton value={block.hash} size={12} />
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {block.height > 0 && (
            <Link to={`/block/height/${block.height - 1}`}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs text-zinc-400 hover:text-zinc-200 transition-colors mono">
              <ChevronLeft size={13} /> #{(block.height - 1).toLocaleString()}
            </Link>
          )}
          <Link to={`/block/height/${block.height + 1}`}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs text-zinc-400 hover:text-zinc-200 transition-colors mono">
            #{(block.height + 1).toLocaleString()} <ChevronRight size={13} />
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Height" value={block.height.toLocaleString()} />
        <StatCard label="Transactions" value={String(block.tx_count)} />
        <StatCard label="Reward" value={`${satToIrm(block.total_reward)} IRM`} />
        <StatCard label="Nonce" value={String(block.nonce)} />
      </div>

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Block Details</h2>
        </div>
        <div className="px-5 py-1">
          <StatRow label="Timestamp" value={fmtTime(block.timestamp)} />
          <StatRow label="Miner" value={
            block.miner_address
              ? <HashLink hash={block.miner_address} to={`/address/${block.miner_address}`} start={10} end={8} />
              : '—'
          } />
          <StatRow label="Difficulty" value={<span className="mono text-zinc-300">{block.difficulty}</span>} />
          <StatRow label="Merkle Root" value={
            <span className="inline-flex items-center gap-1.5 group">
              <span className="mono text-xs text-indigo-400">{block.merkle_root.slice(0,12)}...{block.merkle_root.slice(-8)}</span>
              <span className="opacity-0 group-hover:opacity-100 transition-opacity">
                <CopyButton value={block.merkle_root} size={12} />
              </span>
            </span>
          } />
          <StatRow label="Prev Block" value={
            <HashLink hash={block.prev_hash} to={`/block/hash/${block.prev_hash}`} start={10} end={8} />
          } />
          {block.coinbase_tag != null && (
            <StatRow label="Coinbase Tag" value={
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-violet-500/15 text-violet-400 border border-violet-500/20">
                {block.coinbase_tag}
              </span>
            } />
          )}
        </div>
      </div>

      {rewards.length > 0 && (
        <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between">
            <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Reward Distribution</h2>
            <span className="text-xs text-zinc-600 mono">{satToIrm(coinbaseTx!.total_out)} IRM total</span>
          </div>
          <div className="px-5 py-1">
            {rewards.map(r => (
              <div key={r.vout} className="flex items-center gap-3 py-2.5 border-b border-zinc-800/40 last:border-0">
                <div className="flex items-center gap-2 w-40 shrink-0">
                  <span className="text-sm text-zinc-300">{r.role}</span>
                  {r.pct && (
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-indigo-500/15 text-indigo-400 border border-indigo-500/20">
                      {r.pct}
                    </span>
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  {r.address
                    ? <HashLink hash={r.address} to={`/address/${r.address}`} start={8} end={6} />
                    : <span className="text-xs text-zinc-600 italic">{r.scriptType === 'op_return' ? 'irx1 commitment (no payout)' : 'data (no payout)'}</span>}
                </div>
                <span className={`mono text-sm font-medium shrink-0 ${r.value === 0 ? 'text-zinc-600' : 'text-emerald-400'}`}>
                  {satToIrm(r.value)} IRM
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Transactions ({block.tx_count})</h2>
        </div>
        <div className="px-5 py-3 space-y-2">
          {block.txids.map(txid => (
            <div key={txid} className="flex items-center gap-2 py-1.5 border-b border-zinc-800/40 last:border-0">
              <HashLink hash={txid} to={`/tx/${txid}`} start={12} end={10} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
