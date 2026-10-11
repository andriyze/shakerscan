/** Read-only presentation of a target's interpretations and negative results.
 * Entries are attributed claims (often a Hunt's), never proof or instructions. Text the target
 * supplied arrives under untrusted_data and is always labelled as quoted. */

export const KIND_LABELS = Object.freeze({
  observation: 'Observation', hypothesis: 'Hypothesis', explanation: 'Explanation', next_step: 'Next step',
  note: 'Note', negative_result: 'Negative result',
})
export const NEGATIVE_LABELS = Object.freeze({
  experiment_completed_negative: 'Experiment ran, nothing found (these conditions only)',
  experiment_inconclusive: 'Experiment inconclusive (unfinished)',
  hypothesis_refuted: 'Hypothesis refuted (this hypothesis only)',
  finding_dismissed: 'Finding dismissed by an operator',
})
export const SOURCE_LABELS = Object.freeze({
  interpretations: 'Recorded', authorization_workflow: 'Authorization test', hypothesis_lifecycle: 'Adjudicated hypothesis',
  candidate_verification: 'Verifier',
})
const TRUST_LABELS = Object.freeze({
  agent_interpretation: 'Agent-written', operator_interpretation: 'Operator', operator_decision: 'Operator decision',
  imported_advisory_knowledge: 'Imported learned knowledge',
})

function text(value, limit) {
  const shown = typeof value === 'string' ? value : ''
  return shown.length > limit ? `${shown.slice(0, limit)}…` : shown
}

/** One entry as the panel shows it; nothing here is rendered as HTML. */
export function interpretationView(entry) {
  const quoted = entry && typeof entry.untrusted_data === 'object' && entry.untrusted_data !== null
  const title = quoted ? text(entry.untrusted_data.title, 200) : text(entry?.title, 200)
  const body = quoted ? text(entry.untrusted_data.body, 600) : text(entry?.body, 600)
  const state = entry?.negative_state
  return {
    id: String(entry?.id ?? ''),
    label: state ? (NEGATIVE_LABELS[state] ?? 'Negative result') : (KIND_LABELS[entry?.kind] ?? 'Entry'),
    title: title || (entry?.status === 'retracted' ? '(retracted)' : '(no title)'),
    body,
    quoted,
    trust: TRUST_LABELS[entry?.trust] ?? 'Unattributed',
    writer: typeof entry?.written_by === 'string' ? entry.written_by : '',
    status: entry?.status ?? 'active',
    inactive: (entry?.status ?? 'active') !== 'active',
    evidenceCount: Array.isArray(entry?.evidence_refs) ? entry.evidence_refs.length : 0,
    applicability: entry?.applicability?.state ?? 'unknown',
  }
}

export function negativeView(row) {
  const recorded = row?.source === 'interpretations'
  const base = recorded ? interpretationView(row) : {
    id: String(row?.record_ref?.id ?? ''), title: row?.family ? `${row.family}` : (row?.record_ref?.type ?? 'record'),
    body: '', quoted: false, trust: 'Server record', writer: '', status: 'active', inactive: false,
    evidenceCount: Array.isArray(row?.evidence_refs) ? row.evidence_refs.length : 0,
    applicability: row?.applicability?.state ?? 'unknown',
  }
  return { ...base, label: NEGATIVE_LABELS[row?.negative_state] ?? 'Negative result',
           source: SOURCE_LABELS[row?.source] ?? 'Record', serverOwned: Boolean(row?.server_owned) }
}

/** Active entries first, grouped in a fixed kind order; counts include every status. */
export function summarize(entries) {
  const order = ['next_step', 'hypothesis', 'observation', 'explanation', 'negative_result', 'note']
  const list = Array.isArray(entries) ? entries : []
  const groups = order.map(kind => ({ kind, label: KIND_LABELS[kind],
    items: list.filter(item => item?.kind === kind).map(interpretationView)
      .sort((a, b) => Number(a.inactive) - Number(b.inactive)) })).filter(group => group.items.length > 0)
  return { groups, total: list.length, active: list.filter(item => (item?.status ?? 'active') === 'active').length }
}
