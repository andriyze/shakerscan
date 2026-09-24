// How recently a finding was actually observed, and how to say so without
// claiming more than the data supports.
//
// A finding's lifecycle status answers "has someone triaged this". It does not
// answer "is this still there". Those are different questions, and the findings
// list only ever showed the first one: a critical last observed in May and one
// found a minute ago rendered identically, so a fresh scan's single real result
// sat indistinguishable among dozens of historical rows.
//
// What the data can support is when it was last *seen*. What it cannot support
// is "fixed": absence from a later scan may only mean that scan never reached
// the route -- different budget, auth state, family selection, or a crashed
// action all produce the same silence. So nothing here ever says fixed, and the
// stale state is deliberately uncertainty rather than good news.

export const STALE_AFTER_DAYS = 14

export type FindingFreshnessState = 'current' | 'stale' | 'resolved' | 'unknown'

export type FindingFreshness = {
  state: FindingFreshnessState
  /** Short badge text, or null when the finding is unremarkably current. */
  badge: string | null
  /** Always-visible sentence: when it was first and last observed. */
  detail: string
  tone: 'neutral' | 'amber' | 'emerald'
  ageDays: number | null
}

type FreshnessInput = {
  status?: string | null
  first_seen_at?: string | null
  last_seen_at?: string | null
  resolved_at?: string | null
  resurfaced_count?: number | null
}

function parsed(value: unknown): Date | null {
  if (typeof value !== 'string' || !value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function relativeAge(from: Date, now: Date): string {
  const seconds = Math.max(0, Math.round((now.getTime() - from.getTime()) / 1000))
  if (seconds < 90) return 'just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 36) return `${hours}h ago`
  const days = Math.round(hours / 24)
  if (days < 45) return `${days}d ago`
  const months = Math.round(days / 30)
  if (months < 18) return `${months}mo ago`
  return `${Math.round(days / 365)}y ago`
}

export function findingFreshness(
  finding: FreshnessInput,
  now: Date = new Date(),
  staleAfterDays: number = STALE_AFTER_DAYS,
): FindingFreshness {
  const lastSeen = parsed(finding.last_seen_at)
  const firstSeen = parsed(finding.first_seen_at)
  const status = String(finding.status || '').toLowerCase()
  const resurfaced = Number(finding.resurfaced_count || 0)

  const ageDays = lastSeen
    ? Math.max(0, (now.getTime() - lastSeen.getTime()) / 86_400_000)
    : null

  const seenText = lastSeen
    ? `Last seen ${relativeAge(lastSeen, now)}`
    : 'Never observed by a scan'
  const firstText = firstSeen && lastSeen
    && Math.abs(firstSeen.getTime() - lastSeen.getTime()) > 60_000
    ? ` · first seen ${relativeAge(firstSeen, now)}`
    : ''
  const returnedText = resurfaced > 0
    ? ` · returned ${resurfaced}× after being resolved`
    : ''
  const detail = `${seenText}${firstText}${returnedText}`

  if (status === 'resolved') {
    const resolved = parsed(finding.resolved_at)
    return {
      state: 'resolved',
      badge: resolved ? `resolved ${relativeAge(resolved, now)}` : 'resolved',
      detail,
      tone: 'emerald',
      ageDays,
    }
  }
  if (ageDays === null) {
    return { state: 'unknown', badge: 'never observed', detail, tone: 'amber', ageDays }
  }
  if (ageDays > staleAfterDays) {
    return {
      state: 'stale',
      // Deliberately not "fixed" or "gone": a later scan may simply never have
      // reached this route, and that is not evidence of anything.
      badge: 'not seen recently',
      detail,
      tone: 'amber',
      ageDays,
    }
  }
  return { state: 'current', badge: null, detail, tone: 'neutral', ageDays }
}
