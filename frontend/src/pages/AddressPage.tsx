
import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router'
import { api } from '../api'
import Card from '../components/Card'
import HashLink from '../components/HashLink'
import { satToIrm } from '../lib/fmt'

export default function AddressPage() {
  const { address } = useParams<{ address: string }>()
  const { data: stats, isLoading } = useQuery({ queryKey: ['addr', address], queryFn: () => api.address(address!) })
  const { data: txs } = useQuery({ queryKey: ['addr-txs', address], queryFn: () => api.addressTxs(address!) })
  const { data: htlcs } = useQuery({ queryKey: ['addr-htlcs', address], queryFn: () => api.addressHtlcs(address!) })

  if (isLoading) return <div className="text-zinc-500">Loading...</div>
  if (!stats) return <div className="text-red-400">Address not found</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Address</h1>
        <p className="mono text-sm text-zinc-300 mt-1">{stats.address}</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Balance', value: `${satToIrm(stats.balance)} IRM`, color: 'text-green-400' },
          { label: 'Received', value: `${satToIrm(stats.total_received)} IRM`, color: 'text-zinc-200' },
          { label: 'Sent', value: `${satToIrm(stats.total_sent)} IRM`, color: 'text-zinc-200' },
          { label: 'Transactions', value: stats.tx_count.toLocaleString(), color: 'text-zinc-200' },
        ].map(({ label, value, color }) => (
          <Card key={label}>
            <div className="text-xs text-zinc-500 mb-1">{label}</div>
            <div className={`mono font-semibold ${color}`}>{value}</div>
          </Card>
        ))}
      </div>

      {txs && txs.length > 0 && (
        <Card title="Transactions">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-zinc-500 text-xs uppercase border-b border-zinc-800">
                <th className="pb-2 text-left">TxID</th>
                <th className="pb-2 text-right">Block</th>
              </tr>
            </thead>
            <tbody>
              {txs.map(t => (
                <tr key={t.txid} className="border-b border-zinc-800/50">
                  <td className="py-2"><HashLink to={`/tx/${t.txid}`} hash={t.txid} /></td>
                  <td className="py-2 mono text-right text-zinc-400">
                    <HashLink to={`/block/height/${t.block_height}`} hash={String(t.block_height)} full />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {htlcs && htlcs.length > 0 && (
        <Card title="HTLC Outputs">
          <div className="space-y-3">
            {htlcs.map(h => (
              <div key={`${h.txid}:${h.vout}`} className="bg-zinc-800/50 rounded-lg p-3 text-sm">
                <div className="flex justify-between">
                  <HashLink to={`/tx/${h.txid}`} hash={h.txid} />
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    h.state === 'claimed' ? 'bg-green-900/50 text-green-300' :
                    h.state === 'refunded' ? 'bg-red-900/50 text-red-300' :
                    'bg-zinc-700 text-zinc-300'
                  }`}>{h.state}</span>
                </div>
                <div className="mt-1 text-xs text-zinc-400">
                  <span className="mono text-zinc-200">{satToIrm(h.value)} IRM</span>
                  <span className="mx-2">•</span>
                  <span>{h.htlc_type}</span>
                  <span className="mx-2">•</span>
                  <span>timeout #{h.timeout_height.toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
