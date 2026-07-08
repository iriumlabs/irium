import React from 'react'

interface Props {
  title?: string
  children: React.ReactNode
  className?: string
  action?: React.ReactNode
}

export default function Card({ title, children, className = '', action }: Props) {
  return (
    <div className={`bg-zinc-900 rounded-xl ring-1 ring-zinc-800 overflow-hidden ${className}`}>
      {title && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-zinc-800">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest">{title}</h2>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  )
}
