const S: Record<string, string> = {
  coinbase:          'bg-amber-500/15 text-amber-400 border-amber-500/20',
  p2pkh:             'bg-sky-500/15 text-sky-400 border-sky-500/20',
  p2sh:              'bg-sky-500/15 text-sky-400 border-sky-500/20',
  irium_data:        'bg-zinc-700/50 text-zinc-500 border-zinc-700/40',
  op_return:         'bg-zinc-700/50 text-zinc-500 border-zinc-700/40',
  irium_v1:          'bg-violet-500/15 text-violet-400 border-violet-500/20',
  btc_swap_v1:       'bg-orange-500/15 text-orange-400 border-orange-500/20',
  ltc_swap_v1:       'bg-zinc-500/15 text-zinc-400 border-zinc-600/30',
  pending:           'bg-amber-500/15 text-amber-400 border-amber-500/20',
  claimed:           'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  refunded:          'bg-rose-500/15 text-rose-400 border-rose-500/20',
  expired:           'bg-zinc-700/50 text-zinc-500 border-zinc-700/40',
  fund:              'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  release:           'bg-sky-500/15 text-sky-400 border-sky-500/20',
  refund:            'bg-rose-500/15 text-rose-400 border-rose-500/20',
  milestone_release: 'bg-violet-500/15 text-violet-400 border-violet-500/20',
}

export default function Badge({ type }: { type: string }) {
  const s = S[type] ?? 'bg-zinc-700/50 text-zinc-400 border-zinc-700/40'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${s} whitespace-nowrap`}>
      {type.replace(/_/g, ' ')}
    </span>
  )
}
