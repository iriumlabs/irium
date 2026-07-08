import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { api } from '../api'
import Breadcrumb from '../components/Breadcrumb'
import StatRow from '../components/StatRow'
import HashLink from '../components/HashLink'
import Badge from '../components/Badge'
import CopyButton from '../components/CopyButton'

export default function AgreementDetailPage() {
  const { hash } = useParams<{ hash: string }>()
  const { data: a, isLoading, error } = useQuery({
    queryKey: ['agreement', hash],
    queryFn: () => api.agreement(hash!),
    enabled: !!hash,
  })

  if (isLoading) return <div className="text-zinc-500 text-sm py-10 text-center">Loading agreement...</div>
  if (error || !a) return <div className="text-rose-400 text-sm py-10 text-center">Agreement not found</div>

  return (
    <div className="space-y-6">
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: 'Agreements', to: '/agreements' },
        { label: 'Detail' },
      ]} />

      <div>
        <h1 className="text-xl font-bold text-zinc-100 mb-2">Settlement Agreement</h1>
        <div className="flex items-center gap-2">
          <span className="mono text-xs text-zinc-500 break-all">{a.agreement_hash}</span>
          <CopyButton value={a.agreement_hash} size={12} />
        </div>
      </div>

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Agreement Details</h2>
        </div>
        <div className="px-5 py-1">
          <StatRow label="Anchor Type" value={<Badge type={a.anchor_type} />} />
          <StatRow label="Anchor Tx" value={<HashLink hash={a.txid} to={`/tx/${a.txid}`} start={12} end={10} />} />
          <StatRow label="Block" value={<HashLink hash={String(a.block_height)} to={`/block/height/${a.block_height}`} full copyable={false} />} />
          {a.milestone_id && (
            <StatRow label="Milestone ID" value={<span className="mono text-xs text-zinc-300">{a.milestone_id}</span>} />
          )}
        </div>
      </div>
    </div>
  )
}
