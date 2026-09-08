/** Presentation only. None of these labels changes server proof or assessment. */
export function assessmentText(value?: string): string {
  const labels: Record<string, string> = {
    potential_violation: 'Potential violation — entitlement review required',
    entitlement_unknown: 'Access observed — entitlement is unknown',
    shared_access_as_declared: 'Observed access matches the declared sharing rule',
    access_denied: 'Access denied for this tested object and principal pair',
    inconclusive: 'Inconclusive — no boundary conclusion',
    not_examined: 'Not examined',
  }
  const key = value || 'not_examined'
  return Object.hasOwn(labels, key) ? labels[key] : `Server assessment: ${value}`
}

export function candidateHistoryText(relation?: string): string {
  if (relation === 'historical_only') {
    return 'Earlier lead retained. The latest attempt did not reproduce that lead; review both results.'
  }
  if (relation === 'current_attempt') {
    return 'The latest attempt is linked to a retained lead. This association is not proof of a vulnerability.'
  }
  if (relation === 'none') return 'No candidate association has been recorded for this investigation.'
  return 'Consult the saved candidate and attempt history; historical/current linkage is unavailable.'
}

export function isReviewId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
}
