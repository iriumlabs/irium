import { useState, useCallback } from 'react'
import { Copy, Check } from 'lucide-react'

export default function CopyButton({ value, size = 13 }: { value: string; size?: number }) {
  const [copied, setCopied] = useState(false)
  const handle = useCallback((e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation()
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [value])
  return (
    <button
      onClick={handle}
      className="inline-flex items-center justify-center text-zinc-600 hover:text-zinc-300 transition-colors cursor-pointer shrink-0"
      title="Copy to clipboard"
    >
      {copied
        ? <Check size={size} className="text-emerald-400" />
        : <Copy size={size} />}
    </button>
  )
}
