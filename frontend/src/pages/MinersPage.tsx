import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../api'
import HashLink from '../components/HashLink'
import { satToIrm } from '../lib/fmt'

function rankStyle(i: number): string {
  if (i === 0) return 'text-amber-400 font-bold'
  if (i === 1) return 'text-zinc-400 font-semibold'
  if (i === 2) return 'text-orange-500/80 font-semibold'
  return 'text-zinc-700'
}

export default function MinersPage() {
  const { data: miners, isLoading } = useQuery({
    queryKey: ['miners'],
    queryFn: () => api.miners(200),
  })

  const max = miners?.[0]?.blocks_mined ?? 1

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold text-zinc-100">Mining Leaderboard</h1>

      <div className="bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden">
        {isLoading ? (
          <div className="px-5 py-10 text-sm text-zinc-600 text-center">Loading...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide w-12">#</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Address</th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-zinc-600 uppercase tracking-wide">Blocks</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Total Reward</th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-zinc-600 uppercase tracking-wide">Last Block</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {miners?.map((m, i) => (
                  <tr key={m.address} className="hover:bg-zinc-800/40 transition-colors">
                    <td className="px-5 py-3">
                      <span className={`mono text-sm ${rankStyle(i)}`}>{i + 1}</span>
                    </td>
                    <td className="px-5 py-3">
                      <HashLink hash={m.address} to={`/address/${m.address}`} start={8} end={6} />
                    </td>
                    <td className="px-5 py-3">
                      <div className="mono text-sm text-zinc-200">{m.blocks_mined.toLocaleString()}</div>
                      <div className="mt-1.5 h-1 w-28 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-violet-600/70 rounded-full"
                          style={{ width: `${Math.round((m.blocks_mined / max) * 100)}%` }}
                        />
                      </div>
                    </td>
                    <td className="px-5 py-3 mono text-sm text-emerald-400 text-right">
                      {satToIrm(m.total_reward)} IRM
                    </td>
                    <td className="px-5 py-3 text-right">
                      {m.last_block_height != null
                        ? <Link to={`/block/height/${m.last_block_height}`} className="mono text-sm text-sky-400 hover:text-sky-300">
                            #{m.last_block_height.toLocaleString()}
                          </Link>
                        : <span className="text-zinc-700">—</span>}
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
