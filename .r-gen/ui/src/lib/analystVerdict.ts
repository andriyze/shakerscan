// The analyst verdict and the finding status are separate fields. A verdict changes the status
// only where the two would otherwise contradict each other, and the change is always stated:
// the option names it before the choice and the confirmation names it after.

export type AnalystVerdict = 'true_positive' | 'false_positive' | 'duplicate' | 'accepted_risk' | 'retest_needed'

export const FINDING_STATUS_LABELS: Record<string, string> = {
  active: 'Active',
  resolved: 'Resolved',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
}

export const ANALYST_VERDICTS: ReadonlyArray<{ value: AnalystVerdict; label: string }> = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'duplicate', label: 'Duplicate' },
  { value: 'accepted_risk', label: 'Accepted risk' },
  { value: 'retest_needed', label: 'Retest needed' },
]

export function statusLabel(status: string): string {
  return FINDING_STATUS_LABELS[status] || status.replaceAll('_', ' ')
}

/** The status a verdict leaves the finding in; null clears the verdict and keeps the status. */
export function statusForVerdict(current: string, verdict: AnalystVerdict | null): string {
  if (verdict === 'false_positive' || verdict === 'duplicate') return 'false_positive'
  if (verdict === 'accepted_risk') return 'accepted_risk'
  // A real (or still open) issue cannot stay dismissed as a false positive; any other status,
  // resolved included, is the analyst's and is kept.
  if ((verdict === 'true_positive' || verdict === 'retest_needed') && current === 'false_positive') return 'active'
  return current
}

/**
 * The status a verdict edit sends: only a change the verdict makes. A verdict that leaves the
 * status alone sends none, so the server keeps the stored status rather than the one this page
 * last saw (a retest or another session may have changed it since).
 */
export function verdictRequestStatus(current: string, verdict: AnalystVerdict | null): string | undefined {
  const next = statusForVerdict(current, verdict)
  return next === current ? undefined : next
}

/** Option text that names the status change a verdict would make, if any. */
export function verdictOptionLabel(current: string, verdict: { value: AnalystVerdict; label: string }): string {
  const next = statusForVerdict(current, verdict.value)
  return next === current ? verdict.label : `${verdict.label} (status becomes ${statusLabel(next)})`
}

/**
 * The confirmation after a verdict was stored, from what the server reported back. `shownStatus`
 * is the status the page displayed: a stored status that differs from it without this request
 * changing it was changed elsewhere, and the confirmation says so rather than staying silent.
 */
export function verdictChangeMessage(result: {
  analyst_verdict?: string | null
  status?: string | null
  previous_status?: string | null
}, shownStatus?: string | null): string {
  const verdict = ANALYST_VERDICTS.find((item) => item.value === result.analyst_verdict)
  const head = verdict ? `Analyst verdict set to ${verdict.label.toLowerCase()}` : 'Analyst verdict cleared'
  if (result.status && result.previous_status && result.status !== result.previous_status) {
    return `${head}; status changed from ${statusLabel(result.previous_status)} to ${statusLabel(result.status)}`
  }
  if (result.status && shownStatus && result.status !== shownStatus) {
    return `${head}; status is ${statusLabel(result.status)}, changed since this page loaded`
  }
  return head
}
