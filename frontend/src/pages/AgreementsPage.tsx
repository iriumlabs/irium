import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { FileText } from 'lucide-react'
import { api } from '../api'
import Badge from '../components/Badge'
import EmptyState from '../components/EmptyState'
import HashLink from '../components/HashLink'

export default function AgreementsPage() {
  const { data: agreements, isLoading } = useQuery({
    queryKey: ['agreements'],
    queryFn: () => api.agreements(100),
  })

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Settlement Agreements</h1>
        <p className="text-sm text-zinc-600 mt-1">OP_RETURN-anchored agreements indexed from the Irium chain</p>
      </div>

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        {isLoading ? (
          <div className="px-5 py-10 text-sm text-zinc-600 text-center">Loading...</div>
        ) : !agreements || agreements.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No settlement agreements on chain yet"
            description="Agreements appear when settlement-anchor transactions are broadcast to the Irium network"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Agreement Hash</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Type</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Anchor Tx</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Block</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {agreements.map(a => (
                  <tr key={a.agreement_hash} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-5 py-3">
                      <Link to={`/agreement/${a.agreement_hash}`} className="mono text-sm text-sky-400 hover:text-sky-300">
                        {a.agreement_hash.slice(0, 12)}...{a.agreement_hash.slice(-8)}
                      </Link>
                    </td>
                    <td className="px-5 py-3"><Badge type={a.anchor_type} /></td>
                    <td className="px-5 py-3">
                      <HashLink hash={a.txid} to={`/tx/${a.txid}`} start={8} end={6} />
                    </td>
                    <td className="px-5 py-3 text-right">
                      <Link to={`/block/height/${a.block_height}`} className="mono text-sm text-sky-400 hover:text-sky-300">
                        #{a.block_height.toLocaleString()}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
