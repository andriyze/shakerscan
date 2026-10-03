export function huntActionStatusClass(status: string): string {
  if (status === 'completed') return 'bg-emerald-500/10 text-emerald-300'
  if (status === 'partial') return 'bg-amber-500/10 text-amber-300'
  if (status === 'blocked' || status === 'cancelled') return 'bg-gray-700 text-gray-300'
  if (status === 'failed') return 'bg-red-500/10 text-red-300'
  return 'bg-blue-500/10 text-blue-300'
}

export function formatHuntDuration(startedAt?: string, completedAt?: string | null): string | null {
  if (!startedAt) return null
  const start = Date.parse(startedAt)
  const end = completedAt ? Date.parse(completedAt) : Date.now()
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null
  const seconds = Math.max(0, Math.round((end - start) / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const remainder = seconds % 60
  if (minutes < 60) return `${minutes}m ${remainder}s`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${minutes % 60}m`
}
