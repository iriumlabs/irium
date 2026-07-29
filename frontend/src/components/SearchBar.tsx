
import type { FormEvent } from 'react'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { api } from '../api'

export default function SearchBar() {
  const [q, setQ] = useState('')
  const nav = useNavigate()

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = q.trim()
    if (!trimmed) return
    try {
      const result = await api.search(trimmed)
      if (!result) return
      if (result.result_type === 'block') nav(`/block/height/${result.value}`)
      else if (result.result_type === 'tx') nav(`/tx/${result.value}`)
      else if (result.result_type === 'address') nav(`/address/${result.value}`)
    } catch { /* ignore */ }
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-2">
      <input
        value={q}
        onChange={e => setQ(e.target.value)}
        placeholder="Block height, hash, txid, or address..."
        className="flex-1 bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm
                   text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-zinc-500 mono"
      />
      <button type="submit" className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded-md text-sm transition-colors">
        Search
      </button>
    </form>
  )
}
