
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { api } from '../api'
import Card from '../components/Card'
import { satToIrm } from '../lib/fmt'

export default function MinersPage() {
  const { data: miners, isLoading } = useQuery({
    queryKey: ['miners'], queryFn: () => api.miners(100), refetchInterval: 30000
  })

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Mining Leaderboard</h1>
      <Card>
        {isLoading ? (
          <div className="text-zinc-500">Loading...</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-zinc-500 text-xs uppercase border-b border-zinc-800">
                <th className="pb-2 text-left">#</th>
                <th className="pb-2 text-left">Address</th>
                <th className="pb-2 text-right">Blocks</th>
                <th className="pb-2 text-right">Total Reward</th>
                <th className="pb-2 text-right">Last Block</th>
              </tr>
            </thead>
            <tbody>
              {miners?.map((m, i) => (
                <tr key={m.address} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                  <td className="py-2 text-zinc-500 mono">{i + 1}</td>
                  <td className="py-2">
                    <Link to={`/address/${m.address}`} className="mono text-xs text-sky-400 hover:text-sky-300">
                      {m.address}
                    </Link>
                  </td>
                  <td className="py-2 mono text-right text-zinc-200">{m.blocks_mined.toLocaleString()}</td>
                  <td className="py-2 mono text-right text-green-400">{satToIrm(m.total_reward)} IRM</td>
                  <td className="py-2 mono text-right text-zinc-400">
                    {m.last_block_height ? (
                      <Link to={`/block/height/${m.last_block_height}`} className="text-zinc-400 hover:text-zinc-200">
                        #{m.last_block_height.toLocaleString()}
                      </Link>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
