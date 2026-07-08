import { type LucideIcon } from 'lucide-react'

export default function EmptyState({
  icon: Icon,
  title,
  description,
}: {
  icon: LucideIcon
  title: string
  description?: string
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-8 text-center">
      <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center mb-4">
        <Icon size={22} className="text-zinc-600" />
      </div>
      <p className="text-sm font-medium text-zinc-500">{title}</p>
      {description && <p className="mt-1.5 text-xs text-zinc-700 max-w-xs">{description}</p>}
    </div>
  )
}
