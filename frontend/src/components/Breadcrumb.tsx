import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

interface Item { label: string; to?: string }

export default function Breadcrumb({ items }: { items: Item[] }) {
  return (
    <nav className="flex items-center gap-1 text-xs text-zinc-600 mb-6 flex-wrap">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight size={12} className="text-zinc-700 shrink-0" />}
          {item.to
            ? <Link to={item.to} className="hover:text-zinc-400 transition-colors">{item.label}</Link>
            : <span className="text-zinc-500">{item.label}</span>
          }
        </span>
      ))}
    </nav>
  )
}
