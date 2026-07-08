import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { Wallet, ArrowDownLeft, ArrowUpRight, Activity } from 'lucide-react'
import { api } from '../api'
import Breadcrumb from '../components/Breadcrumb'
import StatCard from '../components/StatCard'
import HashLink from '../components/HashLink'
import CopyButton from '../components/CopyButton'
import Badge from '../components/Badge'
import { satToIrm } from '../lib/fmt'

export default function AddressPage() {
  const { address } = useParams<{ address: string }>()
  const { data: stats, isLoading } = useQuery({
    queryKey: ['address', address],
    queryFn: () => api.address(address!),
    enabled: !!address,
  })
  const { data: txs } = useQuery({
    queryKey: ['addr-txs', address],
    queryFn: () => api.addressTxs(address!, 50),
    enabled: !!address,
  })
  const { data: htlcs } = useQuery({
    queryKey: ['addr-htlcs', address],
    queryFn: () => api.addressHtlcs(address!),
    enabled: !!address,
  })

  if (isLoading) return <div className="text-zinc-500 text-sm py-10 text-center">Loading address...</div>
  if (!stats) return <div className="text-rose-400 text-sm py-10 text-center">Address not found</div>

  return (
    <div className="space-y-6">
      <Breadcrumb items={[{ label: 'Home', to: '/' }, { label: 'Address' }]} />

      <div>
        <h1 className="text-xl font-bold text-zinc-100 mb-2">Address</h1>
        <div className="flex items-center gap-2">
          <span className="mono text-sm text-zinc-400 break-all">{stats.address}</span>
          <CopyButton value={stats.address} />
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Balance" value={`${satToIrm(stats.balance)} IRM`} sub="unspent" icon={<Wallet size={16} />} />
        <StatCard label="Received" value={`${satToIrm(stats.total_received)} IRM`} sub="total in" icon={<ArrowDownLeft size={16} />} />
        <StatCard label="Sent" value={`${satToIrm(stats.total_sent)} IRM`} sub="total out" icon={<ArrowUpRight size={16} />} />
        <StatCard label="Transactions" value={stats.tx_count.toLocaleString()} sub="on-chain" icon={<Activity size={16} />} />
      </div>

      {/* Transaction history */}
      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">Transaction History</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Transaction</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Block</th>
                <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Total Out</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {txs?.map(tx => (
                <tr key={tx.txid} className="hover:bg-zinc-800/40 transition-colors">
                  <td className="px-5 py-2.5">
                    <HashLink hash={tx.txid} to={`/tx/${tx.txid}`} start={10} end={8} />
                  </td>
                  <td className="px-5 py-2.5">
                    <Link to={`/block/height/${tx.block_height}`} className="mono text-sm text-sky-400 hover:text-sky-300">
                      #{tx.block_height.toLocaleString()}
                    </Link>
                  </td>
                  <td className="px-5 py-2.5 mono text-sm text-zinc-300 text-right">
                    {satToIrm(tx.total_out)} IRM
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(!txs || txs.length === 0) && (
            <div className="px-5 py-10 text-sm text-zinc-600 text-center">No transactions</div>
          )}
        </div>
      </div>

      {/* HTLCs if any */}
      {htlcs && htlcs.length > 0 && (
        <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-zinc-800">
            <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">HTLC Outputs ({htlcs.length})</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Transaction</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Type</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">State</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {htlcs.map(h => (
                  <tr key={`${h.txid}:${h.vout}`} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-5 py-2.5">
                      <HashLink hash={h.txid} to={`/tx/${h.txid}`} start={8} end={6} />
                      <span className="mono text-xs text-zinc-600 ml-1">:{h.vout}</span>
                    </td>
                    <td className="px-5 py-2.5"><Badge type={h.htlc_type} /></td>
                    <td className="px-5 py-2.5"><Badge type={h.state} /></td>
                    <td className="px-5 py-2.5 mono text-sm text-emerald-400 text-right">{satToIrm(h.value)} IRM</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
