// Pure presentation logic for one Hunt run: tabs, decisions waiting on the operator,
// budget use against limits, requests grouped under the action that sent them.

export const RUN_TABS = ['results', 'requests', 'timeline', 'details', 'ssh']

const LIVE = new Set(['active', 'awaiting_planner'])

export function huntIsLive(hunt) {
  return LIVE.has(String(hunt?.status || '')) && !hunt?.completed_at
}

/** A finished run opens on its results; a live one on its requests. A #hash picks a tab. */
export function defaultRunTab(hunt, hash = '') {
  const requested = String(hash || '').replace(/^#/, '')
  if (RUN_TABS.includes(requested)) return requested
  return huntIsLive(hunt) ? 'requests' : 'results'
}

// Budget limits are named max_*; settled usage uses the counter's own name.
const USAGE_KEY = {
  max_capability_calls: 'agent_actions',
  max_http_requests: 'http_requests',
  max_state_changing_requests: 'state_changing_requests',
  max_active_actions: 'active_actions',
  max_browser_actions: 'browser_actions',
  max_candidates: 'candidates',
  max_verifications: 'verifications',
  max_oob_interactions: 'oob_interactions',
  max_hosts: 'hosts_attempted',
  max_tcp_ports: 'tcp_ports_attempted',
  max_udp_ports: 'udp_ports_attempted',
  max_device_fragility_points: 'device_fragility_points',
}

/**
 * Each budget dimension with its settled use. A zero limit is a disabled dimension, listed
 * separately so it does not read as "0 of 0 used".
 */
export function budgetUsage(hunt, labels = {}, nowMs = Date.now()) {
  const limits = hunt?.budget || {}
  const used = hunt?.budget_used || {}
  const rows = []
  const disabled = []
  for (const [name, rawLimit] of Object.entries(limits)) {
    const limit = Number(rawLimit)
    if (!Number.isFinite(limit)) continue
    const label = String(labels[name] || name.replace(/^max_/, '').replaceAll('_', ' ')).replace(/^Maximum /, '')
    if (limit <= 0) { disabled.push(label); continue }
    let value
    if (name === 'max_duration_seconds') {
      const start = Date.parse(hunt?.created_at || '')
      const end = hunt?.completed_at ? Date.parse(hunt.completed_at) : nowMs
      value = Number.isFinite(start) && Number.isFinite(end) && end >= start ? Math.round((end - start) / 1000) : 0
    } else {
      value = Number(used[USAGE_KEY[name] ?? name.replace(/^max_/, '')] || 0)
    }
    rows.push({ name, label, used: value, limit, ratio: Math.min(1, value / limit) })
  }
  rows.sort((a, b) => b.ratio - a.ratio || a.label.localeCompare(b.label))
  return { rows, disabled: disabled.sort() }
}

/** The budget limit a stop reason such as `budget_exhausted:hosts_attempted` ran out of. */
export function exhaustedDimension(hunt) {
  const counter = String(hunt?.stop_reason || '').match(/^budget_exhausted:([a-z_]+)/)?.[1]
  if (!counter) return null
  if (counter in USAGE_KEY) return counter
  const limit = Object.entries(USAGE_KEY).find(([, used]) => used === counter)?.[0]
  return limit || (`max_${counter}` in (hunt?.budget || {}) ? `max_${counter}` : null)
}

/** Decisions only the operator can make, in the order they block progress. */
export function pendingDecisions(hunt, shellPlans = []) {
  const decisions = []
  for (const plan of shellPlans) {
    if (plan?.status === 'proposed') decisions.push({ kind: 'ssh_plan', id: plan.plan_id })
  }
  if (hunt?.status === 'budget_exhausted' && !hunt?.completed_at) {
    decisions.push({ kind: 'budget', id: 'budget', reason: String(hunt?.stop_reason || '').replace(/^budget_exhausted:?/, '').replaceAll('_', ' ') })
  }
  // Permission requests a refused action is waiting on. Read-only here: a person approves them in
  // a terminal (`shakerscan approve <id>`); the page never needs to.
  if (!hunt?.completed_at) {
    for (const request of hunt?.pending_permission_requests || []) {
      if (!request?.id) continue
      decisions.push({
        kind: 'permission', id: String(request.id), title: String(request.title || request.kind || 'Permission request'),
        command: String(request.approve_command || `shakerscan approve ${request.id}`),
      })
    }
  }
  return decisions
}

/** Requests keyed by the action that sent them; requests with no recorded action stay separate. */
export function requestsByAction(rows) {
  const byAction = new Map()
  const unlinked = []
  for (const row of rows || []) {
    const actionId = row?.hunt_action_id
    if (!actionId) { unlinked.push(row); continue }
    if (!byAction.has(actionId)) byAction.set(actionId, [])
    byAction.get(actionId).push(row)
  }
  return { byAction, unlinked }
}

/** What to paste into the terminal so a coding agent picks this Hunt up. */
export function agentHandoff(hunt) {
  const id = String(hunt?.hunt_id || '')
  return {
    command: 'shakerscan agent',
    prompt: `Drive ShakerScan Hunt ${id}. Read it with \`shakerscan hunt get ${id}\`, then work toward its objective using only the capabilities it allows, and finish with a debrief.`,
  }
}

/**
 * From the Hunt record export: what each action was called with and why it failed, keyed by
 * action ID. The record is the server's masked decision trace, never model chain-of-thought.
 */
export function actionOutcomes(record) {
  const byAction = new Map()
  for (const entry of record?.decision_trace || []) {
    if (!entry?.action_id) continue
    const outcome = entry.outcome || {}
    const errors = [outcome.error, ...(Array.isArray(outcome.parser_errors) ? outcome.parser_errors : []), outcome.reason, outcome.detail]
      .filter(value => typeof value === 'string' && value.trim())
    byAction.set(entry.action_id, {
      input: entry.decision?.input && typeof entry.decision.input === 'object' ? entry.decision.input : null,
      errors: [...new Set(errors.map(value => value.trim()))],
    })
  }
  return byAction
}

/** Call arguments as short key/value pairs; nested values are compact JSON, long values clipped. */
export function callArguments(input, maxValue = 160) {
  if (!input || typeof input !== 'object') return []
  return Object.entries(input)
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([key, value]) => {
      const text = typeof value === 'string' ? value : JSON.stringify(value)
      return { key, value: text.length > maxValue ? `${text.slice(0, maxValue - 1)}…` : text, full: text }
    })
}

// Stop reasons a person should read as a sentence, not a code.
const STOP_REASON_TEXT = {
  permission_authority_unrepaired:
    'Stopped on upgrade: this Hunt\'s granted permissions could not be rebuilt after a revocation, so it was ' +
    'cancelled rather than left running on permissions nobody granted. Start a new Hunt to continue.',
}

const STOP_REASON_LABEL = {
  permission_authority_unrepaired: 'cancelled on upgrade: permissions could not be rebuilt',
}

export function huntStopReasonText(reason) {
  const code = String(reason || '')
  return STOP_REASON_TEXT[code] || code.replaceAll('_', ' ')
}

// The short form, for a list row.
export function huntStopReasonLabel(reason) {
  const code = String(reason || '')
  return STOP_REASON_LABEL[code] || code.replaceAll('_', ' ')
}
