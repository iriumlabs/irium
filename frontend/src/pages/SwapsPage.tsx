import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ArrowLeftRight } from 'lucide-react'
import { api } from '../api'
import Badge from '../components/Badge'
import EmptyState from '../components/EmptyState'
import HashLink from '../components/HashLink'
import { satToIrm } from '../lib/fmt'

export default function SwapsPage() {
  const { data: htlcs, isLoading } = useQuery({
    queryKey: ['htlcs'],
    queryFn: () => api.htlcs(100),
  })

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Atomic Swaps</h1>
        <p className="text-sm text-zinc-600 mt-1">HTLC outputs for BTC/LTC atomic swaps and Irium settlement contracts</p>
      </div>

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        {isLoading ? (
          <div className="px-5 py-10 text-sm text-zinc-600 text-center">Loading...</div>
        ) : !htlcs || htlcs.length === 0 ? (
          <EmptyState
            icon={ArrowLeftRight}
            title="No HTLC outputs on chain yet"
            description="Atomic swap outputs appear when HTLC transactions are confirmed on the Irium network"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Transaction</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Type</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Value</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">State</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Block</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Timeout</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {htlcs.map(h => (
                  <tr key={`${h.txid}:${h.vout}`} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-1.5">
                        <HashLink hash={h.txid} to={`/tx/${h.txid}`} start={8} end={6} />
                        <span className="mono text-xs text-zinc-600">:{h.vout}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3"><Badge type={h.htlc_type} /></td>
                    <td className="px-5 py-3 mono text-sm text-emerald-400 text-right">{satToIrm(h.value)} IRM</td>
                    <td className="px-5 py-3"><Badge type={h.state} /></td>
                    <td className="px-5 py-3 text-right">
                      <Link to={`/block/height/${h.block_height}`} className="mono text-sm text-sky-400 hover:text-sky-300">
                        #{h.block_height.toLocaleString()}
                      </Link>
                    </td>
                    <td className="px-5 py-3 mono text-xs text-zinc-600 text-right">
                      #{h.timeout_height.toLocaleString()}
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
