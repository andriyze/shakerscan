/** Presentation of a target's change report (what changed since a point, from existing records).
 * Paths, technology names, versions and host names in it were observed from the target: they are
 * shown as plain text, cut to a readable length, never as markup or instructions. */

export const SINCE_CHOICES = Object.freeze([
  { value: 'last_hunt', label: 'the last Hunt' },
  { value: 'release', label: 'the latest release' },
])

const STATE_LABELS = Object.freeze({
  applicable: 'still applies', needs_revalidation: 'needs re-testing', historical: 'historical', unknown: 'unknown',
})
const ENTRY_LABELS = Object.freeze({
  observation: 'Observation', hypothesis: 'Hypothesis', explanation: 'Explanation', next_step: 'Next step',
  note: 'Note', negative_result: 'Negative result', finding_dismissed: 'Dismissed finding',
  experiment_completed_negative: 'Negative experiment', experiment_inconclusive: 'Inconclusive experiment',
  hypothesis_refuted: 'Refuted hypothesis',
})

function shown(value, limit = 200) {
  const text = value === null || value === undefined ? '' : String(value)
  return text.length > limit ? `${text.slice(0, limit)}…` : text
}
const list = (value) => (Array.isArray(value) ? value : [])
const counted = (part) => `${part?.count ?? 0}${part?.at_least ? '+' : ''}`
const words = (value) => shown(value).replaceAll('_', ' ')

function service(row) {
  return shown([`${row?.port ?? '?'}/${row?.transport ?? '?'}`, row?.service_name, row?.product, row?.version].filter(Boolean).join(' '))
}

/** The report as headed groups of plain lines. `resolved` is false when there was nothing to compare with. */
export function changesView(report) {
  const since = report?.since ?? {}
  const sections = report?.sections ?? {}
  const groups = []
  const add = (label, items) => { if (items.length > 0) groups.push({ label, items }) }

  const endpoints = sections.endpoints ?? {}
  const route = (item) => shown(`${item?.method ?? ''} ${item?.path ?? ''}${item?.auth_state ? ` (${words(item.auth_state)})` : ''}`.trim())
  if (endpoints.added?.count) add(`Routes added (${counted(endpoints.added)})`, list(endpoints.added.items).map(route))
  if (endpoints.removed?.count) add(`Routes no longer found (${counted(endpoints.removed)})`, list(endpoints.removed.items).map(route))
  if (endpoints.auth_surface?.significant) {
    add('Sign-in surface', ['A login, token, session, sign-up, password or single sign-on route appeared or disappeared.'])
  }

  const deployment = sections.deployment ?? {}
  const deployed = list(deployment.changes).map((change) =>
    shown(`${words(change?.field)}: ${change?.before ?? 'none'} → ${change?.after ?? 'none'} (${words(change?.significance)})`))
  if (deployment.compared === false && deployment.note) deployed.push(shown(deployment.note, 400))
  add('Deployment', deployed)

  add('Responses changed', list(sections.responses?.changed).map((item) => shown(
    `${item?.method ?? ''} ${item?.path ?? ''}: ${list(item?.changes).map((change) => `${words(change?.field)} (${words(change?.significance)})`).join(', ')}`)))

  const services = sections.services ?? {}
  add('Services', [
    ...list(services.added).map((row) => `New: ${service(row)}`),
    ...list(services.no_longer_observed).map((row) => `No longer observed: ${service(row)}`),
  ])

  const findings = sections.findings?.new
  if (findings?.count) add('Findings', [`${counted(findings)} new finding${findings.count === 1 && !findings.at_least ? '' : 's'}`])

  add('New subdomains', list(sections.subdomains?.new_targets).map((item) =>
    shown(`${item?.host ?? ''}${item?.source ? ` (${words(item.source)})` : ''}`)))

  const knowledge = report?.knowledge ?? {}
  const affected = list(knowledge.affected).map((item) => {
    const causes = list(item?.caused_by).map((cause) => words([cause?.type, cause?.key, cause?.field].filter(Boolean).join(' '))).join('; ')
    const state = item?.reopened_for_review ? 'reopened for review' : (STATE_LABELS[item?.applicability] ?? words(item?.applicability))
    return shown(`${ENTRY_LABELS[item?.negative_state] ?? ENTRY_LABELS[item?.kind] ?? 'Entry'}: ${state}${causes ? ` (${causes})` : ''}`)
  })
  if (knowledge.affected_truncated) affected.push('More entries are affected than are listed here.')
  add('Interpretations to review', affected)

  const states = Object.entries(knowledge.active_by_applicability ?? {})
    .filter(([, count]) => Number(count) > 0)
    .map(([state, count]) => `${count} ${STATE_LABELS[state] ?? words(state)}`)

  return {
    resolved: since.resolved === true,
    sinceLabel: SINCE_CHOICES.find((choice) => choice.value === since.kind)?.label ?? 'the chosen point',
    sinceAt: typeof since.at === 'string' ? since.at : null,
    note: since.resolved === true ? '' : shown(since.note || 'Nothing to compare with.', 400),
    groups,
    states: states.join(', '),
  }
}
