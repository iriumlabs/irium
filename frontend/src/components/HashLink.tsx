
import { Link } from 'react-router'
import { shortHash } from '../lib/fmt'

interface Props { to: string; hash: string; full?: boolean; start?: number; end?: number }

export default function HashLink({ to, hash, full, start, end }: Props) {
  return (
    <Link to={to} className="mono text-sky-400 hover:text-sky-300 transition-colors text-sm">
      {full ? hash : shortHash(hash, start, end)}
    </Link>
  )
}
