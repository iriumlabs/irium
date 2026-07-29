
import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router'
import { api } from '../api'
import Card from '../components/Card'
import StatRow from '../components/StatRow'
import HashLink from '../components/HashLink'
import { satToIrm, fmtTime } from '../lib/fmt'

export default function BlockPage() {
  const { id } = useParams<{ id: string }>()
  const isHeight = /^\d+$/.test(id ?? '')

  const { data: block, isLoading, error } = useQuery({
    queryKey: ['block', id],
    queryFn: () => isHeight ? api.blockByHeight(Number(id)) : api.blockByHash(id!),
    enabled: !!id,
  })

  if (isLoading) return <div className="text-zinc-500">Loading block...</div>
  if (error || !block) return <div className="text-red-400">Block not found</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Block <span className="mono">#{block.height.toLocaleString()}</span></h1>
        <p className="mono text-xs text-zinc-500 mt-1">{block.hash}</p>
      </div>

      <Card title="Block Details">
        <StatRow label="Height" value={block.height.toLocaleString()} />
        <StatRow label="Timestamp" value={fmtTime(block.timestamp)} />
        <StatRow label="Transactions" value={block.tx_count} />
        <StatRow label="Miner" value={block.miner_address ?
          <HashLink to={`/address/${block.miner_address}`} hash={block.miner_address} full /> : '—'} />
        <StatRow label="Reward" value={`${satToIrm(block.total_reward)} IRM`} />
        <StatRow label="Difficulty" value={block.difficulty} />
        <StatRow label="Nonce" value={block.nonce} />
        <StatRow label="Merkle Root" value={<span className="text-xs">{block.merkle_root}</span>} />
        <StatRow label="Prev Hash" value={
          <HashLink to={`/block/hash/${block.prev_hash}`} hash={block.prev_hash} />
        } />
      </Card>

      <Card title="Transactions">
        <div className="space-y-1">
          {block.txids.map(txid => (
            <div key={txid}>
              <HashLink to={`/tx/${txid}`} hash={txid} full />
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
