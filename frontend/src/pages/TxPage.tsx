import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { Zap } from 'lucide-react'
import { api, type TxInput, type TxOutput } from '../api'
import Breadcrumb from '../components/Breadcrumb'
import Badge from '../components/Badge'
import HashLink from '../components/HashLink'
import CopyButton from '../components/CopyButton'
import { satToIrm } from '../lib/fmt'

function InputCard({ input }: { input: TxInput }) {
  if (input.is_coinbase) {
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg bg-amber-500/5 border border-amber-500/20">
        <Zap size={15} className="text-amber-400 shrink-0" />
        <div>
          <div className="text-sm font-medium text-amber-400">Coinbase Generation</div>
          <div className="mono text-xs text-zinc-600 mt-0.5">New block reward</div>
        </div>
      </div>
    )
  }
  return (
    <div className="p-4 rounded-lg bg-zinc-800/40 border border-zinc-700/40">
      <div className="text-xs text-zinc-600 mb-1">Prev Output</div>
      <div className="flex items-center gap-2 flex-wrap">
        <HashLink hash={input.prev_txid} to={`/tx/${input.prev_txid}`} start={10} end={8} />
        <span className="mono text-xs text-zinc-600">:{input.prev_vout}</span>
      </div>
    </div>
  )
}

function OutputCard({ output }: { output: TxOutput }) {
  const isData = output.script_type === 'irium_data' || output.script_type === 'op_return'
  return (
    <div className={`p-4 rounded-lg border ${isData ? 'bg-zinc-800/20 border-zinc-700/30' : 'bg-zinc-800/40 border-zinc-700/40'}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="mono text-xs text-zinc-600">#{output.vout}</span>
          <Badge type={output.script_type} />
        </div>
        <span className={`mono text-sm font-medium ${output.value === 0 ? 'text-zinc-600' : 'text-emerald-400'}`}>
          {satToIrm(output.value)} IRM
        </span>
      </div>
      {output.address
        ? <HashLink hash={output.address} to={`/address/${output.address}`} start={8} end={6} />
        : <span className="text-xs text-zinc-600 italic">{isData ? 'OP_RETURN data' : 'no address'}</span>}
    </div>
  )
}

export default function TxPage() {
  const { txid } = useParams<{ txid: string }>()
  const { data: tx, isLoading, error } = useQuery({
    queryKey: ['tx', txid],
    queryFn: () => api.tx(txid!),
    enabled: !!txid,
  })

  if (isLoading) return <div className="text-zinc-500 text-sm py-10 text-center">Loading transaction...</div>
  if (error || !tx) return <div className="text-rose-400 text-sm py-10 text-center">Transaction not found</div>

  return (
    <div className="space-y-6">
      <Breadcrumb items={[
        { label: 'Home', to: '/' },
        { label: `Block #${tx.block_height.toLocaleString()}`, to: `/block/height/${tx.block_height}` },
        { label: 'Transaction' },
      ]} />

      <div>
        <div className="flex items-center gap-3 flex-wrap mb-2">
          <h1 className="text-xl font-bold text-zinc-100">Transaction</h1>
          {tx.is_coinbase && <Badge type="coinbase" />}
        </div>
        <div className="flex items-center gap-2 mb-3">
          <span className="mono text-xs text-zinc-500 break-all">{tx.txid}</span>
          <CopyButton value={tx.txid} size={12} />
        </div>
        <div className="flex items-center gap-3 flex-wrap text-xs text-zinc-500">
          <span>Block <span className="mono text-sky-400">{tx.block_height.toLocaleString()}</span></span>
          <span className="text-zinc-700">·</span>
          <span>Index <span className="mono text-zinc-400">{tx.tx_index}</span></span>
          <span className="text-zinc-700">·</span>
          <span>Fee <span className="mono text-zinc-400">{satToIrm(tx.fee)} IRM</span></span>
          <span className="text-zinc-700">·</span>
          <span>Total Out <span className="mono text-emerald-400">{satToIrm(tx.total_out)} IRM</span></span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">
            Inputs ({tx.input_count})
          </h2>
          <div className="space-y-2">
            {tx.inputs.map((inp, i) => <InputCard key={i} input={inp} />)}
          </div>
        </div>
        <div>
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">
            Outputs ({tx.output_count})
          </h2>
          <div className="space-y-2">
            {tx.outputs.map(out => <OutputCard key={out.vout} output={out} />)}
          </div>
        </div>
      </div>
    </div>
  )
}
