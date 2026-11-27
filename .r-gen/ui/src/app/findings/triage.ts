import type { FindingStatus } from '@/lib/constants'

// Verdict buttons wear the same colors as the row status badges
// (FINDING_STATUS_BADGE_STYLES) so the decision and its result share one
// vocabulary. Class strings stay literal for Tailwind's JIT.
export const TRIAGE_VERDICTS: ReadonlyArray<{
  status: FindingStatus
  label: string
  /** Past-tense phrase for the toast, so the button and its outcome use one name. */
  done: string
  classes: string
}> = [
  {
    status: 'resolved',
    label: 'Mark resolved',
    done: 'marked resolved',
    classes: 'bg-green-500/15 text-green-300 ring-green-500/30 hover:bg-green-500/25',
  },
  {
    status: 'false_positive',
    label: 'False positive',
    done: 'marked false positive',
    classes: 'bg-gray-500/15 text-gray-200 ring-gray-500/30 hover:bg-gray-500/25',
  },
  {
    status: 'accepted_risk',
    label: 'Accept risk',
    done: 'marked accepted risk',
    classes: 'bg-purple-500/15 text-purple-300 ring-purple-500/30 hover:bg-purple-500/25',
  },
  {
    status: 'active',
    label: 'Reactivate',
    done: 'reactivated',
    classes: 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/30 hover:bg-yellow-500/25',
  },
]

/** Toast copy after a bulk triage; `notFound` comes from the API when some ids no longer exist. */
export function triageOutcomeMessage(updated: number, status: FindingStatus, notFound = 0): string {
  const verdict = TRIAGE_VERDICTS.find((entry) => entry.status === status)
  const base = `${updated} finding${updated === 1 ? '' : 's'} ${verdict?.done ?? 'updated'}`
  if (notFound <= 0) return base
  return `${base} · ${notFound} no longer exist${notFound === 1 ? 's' : ''}`
}

/** Secondary filters live behind the Filters button; this count is its badge. */
export function countActiveSecondaryFilters(values: Array<string | number | boolean | undefined | null>): number {
  return values.filter((value) => value !== undefined && value !== null && value !== '' && value !== 0 && value !== false).length
}
