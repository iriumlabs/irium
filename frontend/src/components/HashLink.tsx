import { Link } from 'react-router-dom'
import CopyButton from './CopyButton'

interface Props {
  hash: string
  to?: string
  full?: boolean
  start?: number
  end?: number
  copyable?: boolean
  className?: string
}

function trunc(h: string, s: number, e: number) {
  return h.length <= s + e + 3 ? h : `${h.slice(0, s)}...${h.slice(-e)}`
}

export default function HashLink({ hash, to, full, start = 8, end = 8, copyable = true, className = '' }: Props) {
  const display = full ? hash : trunc(hash, start, end)
  return (
    <span className="inline-flex items-center gap-1.5 group min-w-0">
      {to
        ? <Link to={to} className={`mono text-sm text-sky-400 hover:text-sky-300 transition-colors truncate ${className}`}>{display}</Link>
        : <span className={`mono text-sm text-indigo-400 truncate ${className}`}>{display}</span>
      }
      {copyable && (
        <span className="opacity-0 group-hover:opacity-100 transition-opacity">
          <CopyButton value={hash} />
        </span>
      )}
    </span>
  )
}
