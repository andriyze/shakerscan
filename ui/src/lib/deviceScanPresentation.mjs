function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function finiteScore(value) {
  if (value === null || value === undefined || value === '') return null
  const score = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(score) ? score : null
}

export const DEVICE_POSTURE_FRESHNESS_DAYS = 7

/**
 * Keep a stored device score visible without presenting incomplete posture as a
 * final pass. The scanner may retain a provisional score while its deployment
 * decision correctly stays needs_review.
 */
export function deviceScorePresentation(scan) {
  const scanRecord = record(scan)
  const scanResult = record(scanRecord.result)
  const resultSummary = record(scanResult.result)
  const posture = record(scanResult.device_posture)
  const isDevice = (
    scanRecord.scan_type === 'device_posture'
    || scanRecord.run_kind === 'device_posture'
    || Object.keys(posture).length > 0
  )
  // Device rows keep their posture score in the scan columns. Web scan detail reports,
  // however, may carry a current-policy read projection for an immutable legacy result;
  // that projection must win over the stale row-level score.
  const gradeValue = isDevice
    ? (scanRecord.grade ?? resultSummary.grade)
    : (resultSummary.risk_grade ?? resultSummary.grade ?? scanRecord.grade)
  const storedGrade = gradeValue === null || gradeValue === undefined || gradeValue === ''
    ? null
    : String(gradeValue)
  const grade = storedGrade?.replace(/\*+$/, '') || null
  const score = finiteScore(isDevice
    ? (scanRecord.score ?? resultSummary.score)
    : (resultSummary.risk_score ?? resultSummary.score ?? scanRecord.score))

  if (!isDevice) {
    if (resultSummary.risk_assessment_state === 'not_examined' || resultSummary.application_observed === false
      || scanRecord.risk_assessment_state === 'not_examined' || scanRecord.application_observed === false) {
      const reasons = new Set((Array.isArray(record(scanResult.coverage).reasons) ? record(scanResult.coverage).reasons : [])
        .map((reason) => String(reason || '')))
      return {
        isDevice: false,
        status: 'not_examined',
        grade: null,
        score: null,
        note: reasons.has('bound_origin_redirects_off_origin')
          ? 'The bound origin only redirected to another origin, so no application response was observed and no clean risk grade is available.'
          : 'No application response was observed on the bound origin, so no clean risk grade is available.',
      }
    }
    const coverage = record(scanResult.coverage)
    const executionCoverage = record(record(scanRecord.execution_explanation).coverage)
    const reliability = record(
      Object.keys(record(coverage.grade_reliability)).length
        ? coverage.grade_reliability
        : executionCoverage.grade_reliability,
    )
    const coverageStatus = String(coverage.status || executionCoverage.status || '').toLowerCase()
    const provisional = (
      storedGrade?.endsWith('*')
      || resultSummary.grade_reliable === false
      || reliability.reliable === false
      || ['partial', 'failed', 'cancelled', 'in_progress'].includes(coverageStatus)
    )
    if (provisional) {
      return {
        isDevice: false,
        status: 'provisional',
        grade,
        score,
        note: 'Observed-finding score only; incomplete or unresolved coverage means this is not a pass verdict.',
      }
    }
    return { isDevice: false, status: 'final', grade, score, note: null }
  }

  const reachability = record(posture.reachability)
  const completeness = record(posture.completeness)
  const decision = String(record(posture.decision).decision || '').toLowerCase()
  const reachabilityStatus = String(reachability.status || '').toLowerCase()
  if (reachabilityStatus && reachabilityStatus !== 'online') {
    return {
      isDevice: true,
      status: 'unavailable',
      grade: null,
      score: null,
      note: 'No score is available because device reachability was not confirmed.',
    }
  }

  if (completeness.complete !== true || decision === 'needs_review') {
    return {
      isDevice: true,
      status: grade !== null || score !== null ? 'provisional' : 'unavailable',
      grade,
      score,
      note: grade !== null || score !== null
        ? 'Coverage is incomplete; this score is provisional and is not a pass verdict.'
        : 'No reliable posture score is available until required inventory checks complete.',
    }
  }

  return { isDevice: true, status: 'final', grade, score, note: null }
}


/** Preserve a stored score in device list/detail summaries without turning an
 * explicitly incomplete latest posture into an apparent pass. */
export function deviceTargetScorePresentation(target, { nowMs = Date.now() } = {}) {
  const targetRecord = record(target)
  const gradeValue = targetRecord.last_grade
  const grade = gradeValue === null || gradeValue === undefined || gradeValue === ''
    ? null
    : String(gradeValue)
  const score = finiteScore(targetRecord.last_score)
  if (grade === null && score === null) {
    return { status: 'unavailable', grade: null, score: null, note: 'No posture score is available.' }
  }
  const reachability = record(targetRecord.last_reachability)
  const reachabilityStatus = String(reachability.status || '').toLowerCase()
  if (reachabilityStatus !== 'online') {
    return {
      status: 'unavailable',
      grade: null,
      score: null,
      note: reachabilityStatus
        ? `The latest reachability result is ${reachabilityStatus}; a retained posture score is not current proof.`
        : 'No current positive reachability receipt is available, so the retained posture score is withheld.',
    }
  }
  const observedAt = Date.parse(String(reachability.checked_at || targetRecord.last_scanned_at || ''))
  const staleAfterMs = DEVICE_POSTURE_FRESHNESS_DAYS * 24 * 60 * 60 * 1000
  if (!Number.isFinite(observedAt) || Math.max(0, nowMs - observedAt) > staleAfterMs) {
    return {
      status: 'provisional',
      grade,
      score,
      note: `The latest positive device evidence is older than ${DEVICE_POSTURE_FRESHNESS_DAYS} days; refresh it before relying on this posture.`,
    }
  }
  const decision = String(targetRecord.last_posture_decision || '').toLowerCase()
  if (targetRecord.last_posture_complete === false || decision === 'needs_review') {
    return {
      status: 'provisional',
      grade,
      score,
      note: 'The latest device posture is incomplete; this score is provisional and is not a pass verdict.',
    }
  }
  return { status: 'final', grade, score, note: null }
}


/** Convert the content-free device activity feed into readable report logs. */
export function deviceActivityLogLines(activity) {
  const events = Array.isArray(record(activity).events) ? activity.events : []
  return events.flatMap((rawEvent) => {
    const event = record(rawEvent)
    const message = String(event.message || '').trim()
    if (!message) return []
    const progress = finiteScore(event.progress)
    const phase = String(event.phase || '').trim().replace(/_/g, ' ')
    const context = [
      progress !== null ? `${progress}%` : '',
      phase && phase.toLowerCase() !== message.toLowerCase() ? phase : '',
    ].filter(Boolean).join(' · ')
    return [`[device] ${context ? `${context} · ` : ''}${message}`]
  })
}


/**
 * Distinguish the latest reachability observation from retained inventory.
 * A current timeout or closed-port result does not erase services that an
 * earlier completed scan positively confirmed.
 * @param {{ serviceAccessible?: boolean | null, selectedScan?: boolean, retainedServiceCount?: number }} options
 * @returns {string}
 */
export function deviceReachabilityServiceSummary({ serviceAccessible, selectedScan = false, retainedServiceCount = 0 } = {}) {
  if (serviceAccessible === true) return 'at least one service responded'
  if (serviceAccessible !== false) return 'service accessibility still being assessed'
  if (selectedScan) return 'this scan found no currently responding TCP service with complete visibility'
  const retained = Number.isInteger(retainedServiceCount) && retainedServiceCount > 0
    ? retainedServiceCount
    : 0
  if (retained > 0) {
    return `latest check found no currently responding TCP service; ${retained} previously confirmed service${retained === 1 ? '' : 's'} retained below`
  }
  return 'latest check found no currently responding TCP service with complete visibility'
}

const TCP_SCOPE_LABELS = {
  all_tcp: 'All 65,535 TCP ports',
  all_65535: 'All 65,535 TCP ports',
  top_100_plus_priority: 'Top 100 + device priority TCP ports',
  top_100: 'Top 100 TCP ports',
}

function count(value) {
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : null
}

function rows(value) {
  return Array.isArray(value) ? value.map(record) : []
}

function transportOf(row) {
  return String(row.transport || 'tcp').toLowerCase()
}

function sumStateCounts(receipts) {
  const totals = {}
  for (const receipt of receipts) {
    for (const [state, value] of Object.entries(record(receipt.port_state_counts))) {
      const number = count(value)
      if (number !== null) totals[state] = (totals[state] || 0) + number
    }
  }
  return totals
}

/**
 * What a device scan examined, read from what the scanner recorded. Open ports are listed
 * individually elsewhere; here TCP and UDP are summarised by scope and port state. Closed and
 * filtered are reported separately only when the scan actually classified them — otherwise the
 * remainder is "not open", never presented as closed.
 */
export function devicePortCoverage(scan) {
  const posture = record(record(record(scan).result).device_posture)
  const completeness = record(posture.completeness)
  const receipts = rows(completeness.tool_receipts)
  if (!Object.keys(completeness).length && !receipts.length) return null
  const services = rows(posture.services).filter((row) => String(row.state || 'open') === 'open')
  const observations = rows(posture.inconclusive_observations)

  const tcpOpen = services.filter((row) => transportOf(row) === 'tcp').length
  const required = count(completeness.tcp_required_port_count)
  const examined = count(completeness.tcp_completed_required_port_count) ?? required
  const classified = completeness.tcp_closed_filtered_classification_complete === true
  const filtered = count(completeness.tcp_filtered_ports_count) ?? 0
  const notOpen = examined === null ? null : Math.max(0, examined - tcpOpen)
  const scope = completeness.tcp_scope ? String(completeness.tcp_scope) : null
  const tcp = {
    scope,
    scopeLabel: scope ? (TCP_SCOPE_LABELS[scope] || scope.replace(/_/g, ' ')) : 'TCP ports',
    examined,
    required,
    open: tcpOpen,
    notOpen,
    classified,
    closed: classified && notOpen !== null ? Math.max(0, notOpen - filtered) : null,
    filtered: classified ? filtered : null,
    complete: completeness.tcp_discovery_complete === true,
  }

  const udpReceipts = receipts.filter((receipt) => receipt.stage === 'udp_service_discovery')
  let udp = null
  if (udpReceipts.length) {
    const states = sumStateCounts(udpReceipts)
    const open = services.filter((row) => transportOf(row) === 'udp').length
    const noResponse = Math.max(
      count(states['open|filtered']) ?? 0,
      observations.filter((row) => transportOf(row) === 'udp').length,
    )
    udp = {
      examined: Object.values(states).reduce((total, value) => total + value, 0) || null,
      open,
      closed: count(states.closed) ?? 0,
      noResponse,
      filtered: count(states.filtered) ?? 0,
      complete: udpReceipts.every((receipt) => receipt.complete === true),
    }
  }

  const fingerprintReceipts = receipts.filter((receipt) => String(receipt.stage || '').startsWith('tcp_service_fingerprint_'))
  let fingerprint = null
  if (fingerprintReceipts.length) {
    const states = sumStateCounts(fingerprintReceipts)
    const tcpServices = services.filter((row) => transportOf(row) === 'tcp')
    fingerprint = {
      ports: Object.values(states).reduce((total, value) => total + value, 0),
      identified: tcpServices.filter((row) => row.product || (row.service_name && !['unknown', 'tcpwrapped'].includes(String(row.service_name)))).length,
      withVersion: tcpServices.filter((row) => row.version).length,
      truncated: count(completeness.tcp_fingerprint_truncated_count) ?? 0,
      complete: completeness.tcp_fingerprinting_complete === true,
    }
  }
  return { tcp, udp, fingerprint }
}

/** The recorded identification of one open port: product and version, extra detail, TLS and CPE. */
export function deviceServiceDetails(service) {
  const row = record(service)
  const productVersion = [row.product, row.version].filter(Boolean).map(String).join(' ')
  return {
    productVersion: productVersion || null,
    extraInfo: row.extra_info ? String(row.extra_info) : null,
    tls: String(row.tunnel || '').toLowerCase() === 'ssl' || row.encrypted === true || String(row.service_name || '') === 'https',
    cpe: row.cpe ? String(row.cpe) : null,
    unidentified: !productVersion && ['unknown', 'tcpwrapped', ''].includes(String(row.service_name || '')),
  }
}
