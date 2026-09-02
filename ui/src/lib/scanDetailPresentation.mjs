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
  const sourceMatch = raw.match(/^\[([^\]]+)\]\s*/)
  const source = sourceMatch ? sourceMatch[1] : ''
  let message = sourceMatch ? raw.slice(sourceMatch[0].length) : raw
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

  return { raw, source, message, kind, label, meta }
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
  const notExamined = result.risk_assessment_state === 'not_examined'

  let headline = 'No material vulnerability confirmed in this run'
  let explanation = findings.length
    ? `${findings.length} lower-severity or informational observation${findings.length === 1 ? ' was' : 's were'} recorded.`
    : 'This run did not produce a confirmed medium, high, or critical finding.'
  let tone = 'caution'
  if (notExamined) {
    headline = 'Application was not examined'
    explanation = 'The scanner reached an authentication challenge or another response that did not expose application content.'
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
  const smartCoverage = record(report.smart_coverage)
  const authStates = Array.isArray(smartCoverage.auth_states_tested) ? smartCoverage.auth_states_tested : []
  const authenticated = authStates.some((state) => String(state).toLowerCase() !== 'anonymous')
  const budgetUsed = record(record(report.scan_metadata).budget_used)
  const missingHeaders = Array.isArray(record(report.http).missing_security_headers)
    ? record(report.http).missing_security_headers
    : []
  const scorePolicy = String(result.score_policy || '')
  const posturePenalty = finiteNumber(result.posture_penalty, null)
  const policyVersion = Number(scorePolicy.match(/^risk_and_assurance\/v(\d+)$/)?.[1] || 0)
  const coverageReasons = Array.isArray(record(report.coverage).reasons)
    ? record(report.coverage).reasons
    : []
  const coverageWarnings = coverageReasons.map((reason) => (
    String(reason || '').replaceAll('_', ' ')
  )).filter(Boolean)

  return {
    headline,
    explanation,
    tone,
    confidence: weakExamination
      ? `${assuranceLabel} — this is not a clean bill of health.`
      : `${assuranceLabel} supports this run-level conclusion.`,
    observedRiskScore: finiteNumber(result.risk_score ?? result.score ?? scanRecord.score, null),
    observedRiskGrade: String(result.risk_grade || result.grade || scanRecord.grade || '').replace(/\*+$/, ''),
    budgetProfile,
    activeTesting,
    authenticated,
    resolvedFamilies,
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
