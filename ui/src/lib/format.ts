// Shared date/time formatting helpers.

// "2d ago", "in 5h", "just now". Falls back to em dash for missing/invalid input.
export function formatRelativeTime(input: string | Date | null | undefined): string {
  if (!input) return '—'
  const date = typeof input === 'string' ? new Date(input) : input
  if (isNaN(date.getTime())) return '—'
  const diffMs = date.getTime() - Date.now()
  const abs = Math.abs(diffMs)
  if (abs < 10_000) return diffMs <= 0 ? 'just now' : 'in a few seconds'
  const units: Array<[number, string]> = [
    [86_400_000, 'd'],
    [3_600_000, 'h'],
    [60_000, 'm'],
    [1_000, 's'],
  ]
  for (const [ms, label] of units) {
    if (abs >= ms) {
      const value = Math.floor(abs / ms)
      return diffMs < 0 ? `${value}${label} ago` : `in ${value}${label}`
    }
  }
  return 'just now'
}

// Converts an "HH:MM" UTC time-of-day to the equivalent local time label.
// Returns null when the input is unparsable or local time equals UTC.
export function utcTimeToLocalLabel(timeOfDay: string): string | null {
  const match = /^(\d{1,2}):(\d{2})$/.exec(timeOfDay.trim())
  if (!match) return null
  const hours = Number(match[1])
  const minutes = Number(match[2])
  if (hours > 23 || minutes > 59) return null
  const date = new Date()
  date.setUTCHours(hours, minutes, 0, 0)
  if (date.getTimezoneOffset() === 0) return null
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
