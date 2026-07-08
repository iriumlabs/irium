import React from 'react'

export default function StatRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between py-3 border-b border-zinc-800/60 last:border-0 gap-6">
      <span className="text-sm text-zinc-500 shrink-0 w-36">{label}</span>
      <span className="text-sm text-zinc-200 text-right break-all min-w-0">{value}</span>
    </div>
  )
}
