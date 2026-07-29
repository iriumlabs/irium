export function satToIrm(sats: number): string {
  return (sats / 1e8).toFixed(2)
}

export function fmtIrm(sats: number): string {
  return (sats / 1e8).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

export function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  // Timestamp drift: if block time is in the future, show absolute date
  if (diff < 0) {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
      hour12: false,
    })
  }
  const sec = Math.floor(diff / 1000)
  if (sec < 5) return 'just now'
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  return `${Math.floor(hr / 24)}d ago`
}

export function fmtTime(ts: string): string {
  return new Date(ts).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  })
}

export function fmtDifficulty(d: string): string {
  return d.length > 12 ? d.slice(0, 10) + '…' : d
}

export function fmtHashrate(hps: number): string {
  if (!hps || hps === 0) return '0 H/s'
  if (hps >= 1e18) return `${(hps / 1e18).toFixed(2)} EH/s`
  if (hps >= 1e15) return `${(hps / 1e15).toFixed(2)} PH/s`
  if (hps >= 1e12) return `${(hps / 1e12).toFixed(2)} TH/s`
  if (hps >= 1e9)  return `${(hps / 1e9).toFixed(2)} GH/s`
  if (hps >= 1e6)  return `${(hps / 1e6).toFixed(2)} MH/s`
  if (hps >= 1e3)  return `${(hps / 1e3).toFixed(2)} kH/s`
  return `${Math.round(hps)} H/s`
}

// genesis: 2026-01-05T03:32:10Z
const GENESIS_MS = new Date('2026-01-05T03:32:10Z').getTime()

export function fmtAvgBlockTime(height: number): string {
  if (!height || height < 10) return '—'
  const elapsed = (Date.now() - GENESIS_MS) / 1000
  if (elapsed <= 0) return '—'
  const avg = Math.round(elapsed / height)
  if (avg < 60) return `${avg}s`
  const m = Math.floor(avg / 60)
  const s = avg % 60
  return s > 0 ? `${m}m ${s}s` : `${m} min`
}

/**
 * Abbreviate a hash/address as `<start>…<end>`, e.g. `00000ebfec…8d9400`.
 *
 * Returns the value unchanged when it is not longer than the two ends plus the ellipsis,
 * so short strings are never padded or made longer by "shortening" them.
 */
export function shortHash(hash: string, start = 10, end = 8): string {
  if (!hash) return ''
  const s = Math.max(0, start)
  const e = Math.max(0, end)
  if (hash.length <= s + e + 1) return hash
  return `${hash.slice(0, s)}…${hash.slice(hash.length - e)}`
}
