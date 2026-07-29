
import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router'
import { api } from '../api'
import Card from '../components/Card'
import StatRow from '../components/StatRow'
import HashLink from '../components/HashLink'
import { satToIrm } from '../lib/fmt'

export default function TxPage() {
  const { txid } = useParams<{ txid: string }>()
  const { data: tx, isLoading, error } = useQuery({
    queryKey: ['tx', txid],
    queryFn: () => api.tx(txid!),
    enabled: !!txid,
  })

  if (isLoading) return <div className="text-zinc-500">Loading transaction...</div>
  if (error || !tx) return <div className="text-red-400">Transaction not found</div>

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Transaction</h1>
        <p className="mono text-xs text-zinc-400 mt-1 break-all">{tx.txid}</p>
      </div>

      <Card title="Summary">
        <StatRow label="Block" value={<HashLink to={`/block/height/${tx.block_height}`} hash={String(tx.block_height)} full />} />
        <StatRow label="Index" value={tx.tx_index} />
        <StatRow label="Coinbase" value={tx.is_coinbase ? 'Yes' : 'No'} />
        <StatRow label="Inputs" value={tx.input_count} />
        <StatRow label="Outputs" value={tx.output_count} />
        <StatRow label="Total Out" value={`${satToIrm(tx.total_out)} IRM`} />
        <StatRow label="Fee" value={`${satToIrm(tx.fee)} IRM`} />
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Inputs">
          <div className="space-y-3">
            {tx.inputs.map((inp, i) => (
              <div key={i} className="bg-zinc-800/50 rounded-lg p-3 text-sm">
                {inp.is_coinbase ? (
                  <span className="text-yellow-400 font-medium">Coinbase</span>
                ) : (
                  <>
                    <div className="text-zinc-400 text-xs">From</div>
                    <HashLink to={`/tx/${inp.prev_txid}`} hash={inp.prev_txid} />
                    <span className="text-zinc-500 mono text-xs ml-1">:{inp.prev_vout}</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </Card>

        <Card title="Outputs">
          <div className="space-y-3">
            {tx.outputs.map(out => (
              <div key={out.vout} className="bg-zinc-800/50 rounded-lg p-3 text-sm">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-xs text-zinc-500 mono">vout:{out.vout}</span>
                    <span className={`ml-2 text-xs px-1.5 py-0.5 rounded ${
                      out.script_type === 'htlc' ? 'bg-purple-900/50 text-purple-300' :
                      out.script_type === 'op_return' ? 'bg-zinc-700 text-zinc-400' :
                      'bg-zinc-800 text-zinc-400'
                    }`}>{out.script_type}</span>
                  </div>
                  <span className="mono text-green-400 text-sm">{satToIrm(out.value)} IRM</span>
                </div>
                {out.address && (
                  <div className="mt-1">
                    <Link to={`/address/${out.address}`} className="mono text-xs text-sky-400 hover:text-sky-300">
                      {out.address}
                    </Link>
                  </div>
                )}
                {out.spent_by_txid && (
                  <div className="mt-1 text-xs text-zinc-500">
                    Spent: <HashLink to={`/tx/${out.spent_by_txid}`} hash={out.spent_by_txid} />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}
