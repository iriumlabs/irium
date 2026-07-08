import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Loader2 } from 'lucide-react'
import { api } from '../api'

export default function SearchBar() {
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  const handle = async (e: React.FormEvent) => {
    e.preventDefault()
    const query = q.trim()
    if (!query) return
    setLoading(true)
    try {
      const r = await api.search(query)
      if (r) {
        if (r.result_type === 'block_height') nav(`/block/height/${r.value}`)
        else if (r.result_type === 'block_hash') nav(`/block/hash/${r.value}`)
        else if (r.result_type === 'tx') nav(`/tx/${r.value}`)
        else if (r.result_type === 'address') nav(`/address/${r.value}`)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handle} className="relative w-full">
      <span className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
        {loading
          ? <Loader2 size={14} className="text-zinc-500 animate-spin" />
          : <Search size={14} className="text-zinc-500" />}
      </span>
      <input
        value={q}
        onChange={e => setQ(e.target.value)}
        placeholder="Search block, txid, or address..."
        className="w-full bg-zinc-800/80 border border-zinc-700/60 rounded-lg pl-8 pr-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-violet-600/60 focus:bg-zinc-800 transition-colors"
      />
    </form>
  )
}
