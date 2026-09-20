const MATERIAL_SEVERITIES = new Set(['critical', 'high', 'medium'])

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function finiteNumber(value, fallback = 0) {
  if (value === null || value === undefined || value === '') return fallback
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) ? number : fallback
}

export function scanFindingIdentity(finding) {
  const item = record(finding)
  return [
    String(item.title || '').trim().toLowerCase(),
    String(item.url || '').trim().replace(/\/+$/, '').toLowerCase(),
    String(item.tool || '').trim().toLowerCase(),
  ].join('|')
}

export function scanPhasePresentation(scan) {
  const status = String(record(scan).status || 'pending').toLowerCase()
  const rawPhase = String(record(scan).current_phase || '').trim().toLowerCase()
  const progress = Math.max(0, Math.min(100, finiteNumber(record(scan).progress)))

  if (status === 'pending' || status === 'queued') {
    return {
      label: 'Waiting for a worker',
      description: 'The scan is queued. Testing will begin as soon as a compatible worker is available.',
      progress,
    }
  }

  const phases = [
    {
      terms: ['final', 'report', 'complete'],
      label: 'Preparing the report',
      description: 'Consolidating evidence, coverage, findings, and the final decision record.',
    },
    {
      terms: ['validat', 'verif', 'proof', 'attack_chain'],
      label: 'Validating evidence',
      description: 'Checking candidate findings against deterministic proof requirements.',
    },
    {
      terms: ['active', 'test', 'template', 'nuclei', 'phase_'],
      label: 'Testing the attack surface',
      description: 'Running the checks permitted by this scan’s policy and resource budget.',
    },
    {
      terms: ['discover', 'crawl', 'recon', 'probe', 'baseline', 'pre_scan', 'init'],
      label: 'Mapping the application',
      description: 'Discovering reachable pages, APIs, technologies, and baseline security posture.',
    },
  ]
  const match = phases.find((phase) => phase.terms.some((term) => rawPhase.includes(term)))
  return match ? {
    label: match.label,
    description: match.description,
    progress,
  } : {
    label: rawPhase ? rawPhase.replaceAll('_', ' ') : 'Scan in progress',
    description: 'The worker is executing the current scan plan. Activity appears below as it is recorded.',
    progress,
  }
}

export function scanLogEntry(rawLine) {
  const raw = String(rawLine || '').trim()
  // A parallel parent's feed is assembled from its children, each line prefixed with the child
  // that produced it. That prefix is not the log source; keep it as the entry's origin so the
  // operator can still tell discovery from shard work.
  const childMatch = raw.match(/^\[(Discovery|Shard \d+)\]\s*/)
  const child = childMatch ? childMatch[1] : ''
  const body = childMatch ? raw.slice(childMatch[0].length) : raw
  const sourceMatch = body.match(/^\[([^\]]+)\]\s*/)
  const source = sourceMatch ? sourceMatch[1] : ''
  let message = sourceMatch ? body.slice(sourceMatch[0].length) : body
  let kind = 'detail'
  let label = source ? source.replaceAll('_', ' ') : 'activity'
  let meta = ''

  const progress = raw.match(/\[progress\]\s+phase=([^\s]+)\s+pct=(\d+)\s+message=(.*)$/i)
  if (progress) {
    kind = 'milestone'
    label = 'milestone'
    message = progress[3].trim() || progress[1].replaceAll('_', ' ')
    meta = `${progress[2]}% · ${progress[1].replaceAll('_', ' ')}`
  } else if (structuredLogFailure(raw, source)) {
    kind = 'error'
    label = 'error'
  } else if (structuredLogWarning(raw, source)) {
    kind = 'warning'
    label = 'attention'
  } else if (/\b(finding|vulnerab|verified|candidate|exploit)\b/i.test(raw)) {
    kind = 'finding'
    label = 'finding'
  } else if (/\b(starting|started|complete|completed|discovered|found \d+|phase)\b/i.test(raw)) {
    kind = 'milestone'
    label = 'milestone'
  }

  if (child) meta = meta ? `${child} · ${meta}` : child
  return { raw, source, child, message, kind, label, meta }
}

function structuredValue(raw, key) {
  const match = raw.match(new RegExp(`(?:^|[\\s·])${key}=([^\\s·]+)`, 'i'))
  return match ? match[1].replace(/^['"]|['"]$/g, '').toLowerCase() : ''
}

function structuredLogFailure(raw, source) {
  const normalizedSource = String(source || '').toLowerCase()
  if (['error', 'fatal', 'exception', 'traceback'].includes(normalizedSource)) return true
  const outcome = structuredValue(raw, '(?:outcome|status|result)')
  if (['error', 'failed', 'failure', 'fatal', 'exception'].includes(outcome)) return true
  const error = structuredValue(raw, 'error')
  // A structured action outcome is authoritative. Skipped/partial/degraded
  // actions often retain an adapter error class explaining why no execution
  // occurred; that is attention-worthy, not an execution failure.
  if (
    error
    && !['none', 'null', 'false', 'no', '0', 'nil', 'success', 'ok', '-'].includes(error)
    && !['warning', 'partial', 'degraded', 'timeout', 'timed_out', 'skipped'].includes(outcome)
  ) return true
  if (['success', 'ok', 'complete', 'completed', 'warning', 'partial', 'degraded', 'timeout', 'timed_out', 'skipped'].includes(outcome)) return false
  if (error && !['none', 'null', 'false', 'no', '0', 'nil', 'success', 'ok', '-'].includes(error)) return true
  const withoutBenignFields = raw
    .replace(/(?:^|[\s·])(?:error|reason)=(?:none|null|false|no|0|nil|success|ok|-)(?=$|[\s·])/gi, ' ')
    .replace(/(?:^|[\s·])(?:outcome|status|result)=(?:success|ok|complete|completed)(?=$|[\s·])/gi, ' ')
  return /(?:^|[\s:])(error|failed|failure|traceback|exception|fatal)(?:$|[\s:])/i.test(withoutBenignFields)
}

function structuredLogWarning(raw, source) {
  const normalizedSource = String(source || '').toLowerCase()
  if (['warn', 'warning'].includes(normalizedSource)) return true
  const outcome = structuredValue(raw, '(?:outcome|status|result)')
  if (['warning', 'partial', 'degraded', 'timeout', 'timed_out', 'skipped'].includes(outcome)) return true
  return /\b(warn(?:ing)?|timed?\s*out|partial|degraded|budget reached|skipping)\b/i.test(raw)
}

// Coverage reasons arrive as the finalizer's stable codes. Each label says what happened to the
// planned work in the operator's terms; the raw code (underscores and all) is the fallback only
// for a code this table does not know.
const COVERAGE_REASON_LABELS = {
  timed_out: 'A planned step ran out of its time allowance before it finished',
  cancelled: 'The run was cancelled before all planned work finished',
  budget_exhausted: 'The run exhausted its budget before all planned work finished',
  insufficient_plan_budget: 'Planned steps were skipped because the admitted budget did not reach them',
  not_applicable: 'A planned proof step had no candidate left to prove',
  dependency_failed: 'A planned step was skipped because the step it depended on did not complete',
  policy_disabled: 'A planned step was disabled by the scan policy',
  worker_lost: 'A worker was lost before all planned work finished',
  authentication_uncertain: 'Credential authority could not be confirmed',
}

// Why no application response was observed. The finalizer records the cause as a coverage
// reason; the HTTP status is the fallback. Saying "authentication challenge" for a bound
// origin that only redirects elsewhere sent operators to look for a login that does not exist.
export function notExaminedExplanation(report) {
  const reasons = new Set((Array.isArray(record(report.coverage).reasons) ? record(report.coverage).reasons : [])
    .concat(Array.isArray(record(record(report.coverage).grade_reliability).reasons) ? record(record(report.coverage).grade_reliability).reasons : [])
    .map((reason) => String(reason || '')))
  if (reasons.has('bound_origin_redirects_off_origin')) {
    return 'The bound origin answered every request with a redirect to another origin, so no application response was observed here. Scan the origin that serves the application (for example its www host) to examine it.'
  }
  const status = Number(record(report.http).status)
  if ([401, 403, 407].includes(status)) {
    return 'The scanner reached an authentication challenge that did not expose application content.'
  }
  return 'The responses observed on the bound origin did not expose application content.'
}

const ACTIVE_FAMILIES = new Set(['xss', 'sqli', 'nuclei_active', 'bola', 'sensitive_exposure', 'nosqli', 'authz_surface'])
const ACTIVE_FAMILY_LABELS = {
  xss: 'XSS', sqli: 'SQLi', nuclei_active: 'active templates', bola: 'BOLA',
  sensitive_exposure: 'exposure', nosqli: 'NoSQLi', authz_surface: 'authz',
}

// The one thing to do next, derived from what limited this run. A page that lists every gap
// but never says what to do about it leaves the operator to reverse-engineer the fix.
export function nextStepsFor({ targetUrl, testingWarning, coverageReasons, http, authenticated, authenticationRequested, notExamined }) {
  const steps = []
  const target = String(targetUrl || '')
  const encodedTarget = encodeURIComponent(target)
  if (coverageReasons.includes('bound_origin_redirects_off_origin')) {
    const destination = String(http.redirect_origin || http.redirect_location || http.location || '')
    let origin = ''
    try {
      origin = destination ? new URL(destination, target || undefined).origin : ''
    } catch {
      origin = ''
    }
    steps.push({
      key: 'serving-origin',
      label: origin ? `Scan ${origin.replace(/^https?:\/\//, '')} instead` : 'Scan the origin that serves the application',
      href: `/scan/new?target=${encodeURIComponent(origin || target)}`,
    })
  }
  if (testingWarning) {
    steps.push({
      key: 'standard-active',
      label: 'Re-run with the standard active preset',
      href: `/scan/new?target=${encodedTarget}&preset=standard_active`,
    })
  }
  if (!notExamined && !authenticated && !authenticationRequested) {
    steps.push({
      key: 'credentials',
      label: 'Add credentials to examine the authenticated surface',
      href: '/credentials',
    })
  }
  return steps
}

// What earlier scans found that this run did not observe. Only active rows count, and a row
// counts as observed here when this scan wrote it, last saw it, or reported the same finding.
// Subtracting list lengths counted resolved and false-positive rows as "unresolved".
export function carriedOverSummary(scan, targetFindings, historyState = 'ready') {
  const scanRecord = record(scan)
  const scanId = String(scanRecord.id || '')
  if (historyState !== 'ready') {
    return { state: historyState, count: 0, material: 0, highest: null }
  }
  const reported = Array.isArray(record(scanRecord.result).findings) ? record(scanRecord.result).findings : []
  const reportedKeys = new Set(reported.map(scanFindingIdentity))
  const carried = (Array.isArray(targetFindings) ? targetFindings : []).filter((finding) => {
    const item = record(finding)
    if (String(item.status || 'active') !== 'active') return false
    if (String(item.scan_id || '') === scanId || String(item.last_seen_scan_id || '') === scanId) return false
    return !reportedKeys.has(scanFindingIdentity(item))
  })
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const highest = order.find((severity) => carried.some((finding) => String(record(finding).severity || '').toLowerCase() === severity)) || null
  const material = carried.filter((finding) => ['critical', 'high', 'medium'].includes(String(record(finding).severity || '').toLowerCase())).length
  return { state: 'ready', count: carried.length, material, highest }
}

// The release line states provenance only when the decision supplies it: a blocker the gate
// marked as carried from the target's unresolved set, and not written by this scan, came from
// an earlier scan. Proof state says nothing about when a finding was observed.
export function releaseLine(decision, scanId, confirmedCount) {
  const item = record(decision)
  const verdict = String(item.decision || item.deploy_decision || '').toLowerCase()
  if (!verdict) return null
  const blockers = Array.isArray(item.blocking_findings) ? item.blocking_findings : []
  const earlier = blockers.filter((blocker) => (
    record(blocker).from_target_active === true && String(record(blocker).scan_id || '') !== String(scanId || '')
  ))
  const rationale = String(item.rationale || item.reason || '').trim()
  if (verdict === 'block' || verdict === 'blocked') {
    if (blockers.length > 0 && earlier.length === blockers.length && confirmedCount === 0) {
      return { verdict, tone: 'block', text: `Release is blocked by ${blockers.length} unresolved finding${blockers.length === 1 ? '' : 's'} from earlier scans that this run did not re-examine.` }
    }
    return { verdict, tone: 'block', text: blockers.length > 0
      ? `Release is blocked by ${blockers.length} unresolved finding${blockers.length === 1 ? '' : 's'} on this target.`
      : 'Release is blocked by unresolved findings on this target.' }
  }
  if (verdict === 'allow') {
    return { verdict, tone: 'allow', text: 'Release policy allows this target on the findings currently unresolved.' }
  }
  return { verdict, tone: 'review', text: rationale
    ? `${rationale}${blockers.length > 0 ? ` ${blockers.length} unresolved finding${blockers.length === 1 ? '' : 's'} on this target.` : ''}`
    : `Release decision: ${verdict.replace(/_/g, ' ')}.` }
}

export function scanResultPresentation(scan, assurance) {
  const scanRecord = record(scan)
  const report = record(scanRecord.result)
  const result = record(report.result)
  const findings = Array.isArray(report.findings) ? report.findings : []
  const material = findings.filter((finding) => MATERIAL_SEVERITIES.has(String(finding?.severity || '').toLowerCase()))
  const confirmed = material.filter((finding) => (
    finding?.verified === true && String(finding?.proof_state || '') === 'verified'
  ))
  const candidates = material.filter((finding) => !confirmed.includes(finding))
  const assuranceBand = String(assurance?.band || result.assurance_band || 'none')
  const assuranceLabel = String(assurance?.label || 'Coverage unavailable')
  const weakExamination = ['none', 'weak', 'limited'].includes(assuranceBand)
  const notExamined = result.risk_assessment_state === 'not_examined' || result.application_observed === false

  let headline = 'No material vulnerability confirmed in this run'
  let explanation = findings.length
    ? `${findings.length} lower-severity or informational observation${findings.length === 1 ? ' was' : 's were'} recorded.`
    : 'This run did not produce a confirmed medium, high, or critical finding.'
  let tone = 'caution'
  if (notExamined) {
    headline = 'Application was not examined'
    explanation = notExaminedExplanation(report)
    tone = 'warning'
  } else if (confirmed.length) {
    headline = `${confirmed.length} confirmed material ${confirmed.length === 1 ? 'issue requires' : 'issues require'} action`
    explanation = 'Deterministic evidence confirmed at least one medium, high, or critical finding in this run.'
    tone = 'danger'
  } else if (candidates.length) {
    headline = `${candidates.length} potential material ${candidates.length === 1 ? 'issue needs' : 'issues need'} verification`
    explanation = 'These candidates are not confirmed vulnerabilities until their proof requirements succeed.'
    tone = 'warning'
  }

  const options = record(scanRecord.options)
  const plan = record(options.scan_execution_plan)
  const policy = record(plan.policy)
  const resolvedFamilies = Array.isArray(plan.resolved_families) ? plan.resolved_families : []
  const budgetProfile = String(plan.budget_profile || options.budget_profile || 'unknown')
  const activeTesting = policy.active_testing === true
  // What "active" bought. Permission alone ran nothing: a run allowed active testing under the
  // passive preset and the tile said "Active allowed" over a report with no active family in it.
  const activeFamilies = resolvedFamilies.filter((family) => ACTIVE_FAMILIES.has(String(family)))
  const activeFamiliesLabel = activeFamilies.map((family) => ACTIVE_FAMILY_LABELS[family] || String(family).replaceAll('_', ' ')).join(', ')
  const testingSummary = !activeTesting
    ? 'Passive only'
    : activeFamilies.length
      ? `Active · ${activeFamiliesLabel}`
      : 'Active allowed · none selected'
  const testingWarning = activeTesting && !activeFamilies.length
    ? 'Active testing was allowed but the passive preset ran no active family. Re-run with the standard active preset to test XSS and SQLi.'
    : null
  const smartCoverage = record(report.smart_coverage)
  const authStates = Array.isArray(smartCoverage.auth_states_tested) ? smartCoverage.auth_states_tested : []
  const authenticated = authStates.some((state) => String(state).toLowerCase() !== 'anonymous')
  // This historical flag records a credential lane, not an accepted identity or
  // a continuous session-health observation.
  const identityAssurance = record(report.authentication_assurance)
  const authenticationGap = identityAssurance.reason_code === 'authentication_gap'
  const interruptedActions = Math.max(0, Math.trunc(finiteNumber(identityAssurance.interrupted_action_count, 0)))
  const authenticationRequested = authenticationGap || identityAssurance.authentication_requested === true || authenticated
    || (Array.isArray(options.credential_profile_refs) && options.credential_profile_refs.length > 0)
    || (Array.isArray(options.managed_credential_profiles) && options.managed_credential_profiles.length > 0)
  const authenticationAssurance = authenticationGap ? 'Credential authority unavailable' : authenticationRequested ? 'Identity unverified' : 'Anonymous only'
  const budgetUsed = record(record(report.scan_metadata).budget_used)
  const missingHeaders = Array.isArray(record(report.http).missing_security_headers)
    ? record(report.http).missing_security_headers
    : []
  const scorePolicy = String(result.score_policy || '')
  const posturePenalty = finiteNumber(result.posture_penalty, null)
  const policyVersion = Number(scorePolicy.match(/^risk_and_assurance\/v(\d+)$/)?.[1] || 0)
  const coverage = record(report.coverage)
  const coverageReasons = Array.isArray(coverage.reasons) ? coverage.reasons : []
  const coverageWarnings = coverageReasons.map((reason) => (
    String(reason || '').replaceAll('_', ' ')
  )).filter(Boolean)
  // Families the operator selected that never reached a complete state. Naming them is what
  // turns "a selected check family is incomplete" into something a reader can act on.
  const incompleteFamilies = Array.isArray(coverage.selected_family_gaps)
    ? coverage.selected_family_gaps.map((family) => String(family || '').replaceAll('_', ' ')).filter(Boolean)
    : []
  const assuranceGaps = Array.isArray(assurance?.gaps) ? assurance.gaps : []
  // A strong examination score describes the work that ran. When the run stopped before its
  // plan completed, or the scorer itself marked the grade unreliable, the conclusion is only as
  // wide as the completed work, and the supporting sentence must say so instead of endorsing it.
  const coverageIncomplete = coverageWarnings.length > 0
    || incompleteFamilies.length > 0
    || assuranceGaps.length > 0
    || result.grade_reliable === false
    || authenticationRequested
  const confidenceTone = weakExamination ? 'weak' : coverageIncomplete ? 'qualified' : 'supporting'
  const confidence = authenticationGap
    ? `${assuranceLabel}. Credential authority could not be confirmed; ${interruptedActions || 'some'} planned action${interruptedActions === 1 ? ' was' : 's were'} interrupted or blocked. Review the identity and approval before starting new work. Independently verified findings remain supported.`
    : authenticationRequested
    ? `${assuranceLabel}. Credentials do not establish accepted identity; no session-health timeline proves authenticated coverage. Independently verified findings remain supported.`
    : weakExamination
    ? `${assuranceLabel} — this is not a clean bill of health.`
    : coverageIncomplete
      ? `${assuranceLabel} for the work that ran, but the run did not finish everything it planned; the conclusion is limited to what completed.`
      : `${assuranceLabel} supports this run-level conclusion.`
  const coverageGapReasons = coverageReasons.map((reason) => COVERAGE_REASON_LABELS[String(reason)] || String(reason || '').replaceAll('_', ' ')).filter(Boolean)
  const nextSteps = nextStepsFor({
    targetUrl: String(scanRecord.target_url || scanRecord.target || ''),
    testingWarning,
    coverageReasons: coverageReasons.map((reason) => String(reason || '')),
    http: record(report.http),
    authenticated,
    authenticationRequested,
    notExamined,
  })

  return {
    headline,
    nextSteps,
    explanation,
    tone,
    confidence,
    confidenceTone,
    coverageIncomplete,
    coverageGapReasons,
    incompleteFamilies,
    observedCount: findings.length,
    observedRiskScore: notExamined ? null : finiteNumber(result.risk_score ?? result.score ?? scanRecord.score, null),
    observedRiskGrade: notExamined ? '' : String(result.risk_grade || result.grade || scanRecord.grade || '').replace(/\*+$/, ''),
    budgetProfile,
    activeTesting,
    authenticated,
    authenticationRequested,
    authenticationAssurance,
    resolvedFamilies,
    activeFamilies,
    testingSummary,
    testingWarning,
    requestCount: finiteNumber(budgetUsed.http_requests, null),
    missingHeaders,
    posturePenalty,
    scorePolicy,
    // v3 was briefly reused for both pre- and post-posture calculations.
    // The emitted penalty disambiguates those rows; v4+ has stable provenance.
    postureIncluded: posturePenalty !== null || policyVersion >= 4,
    notExamined,
    confirmedCount: confirmed.length,
    candidateCount: candidates.length,
    coverageWarnings,
  }
}
