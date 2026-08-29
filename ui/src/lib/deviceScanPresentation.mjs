function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function finiteScore(value) {
  const score = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(score) ? score : null
}

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
export function deviceTargetScorePresentation(target) {
  const targetRecord = record(target)
  const gradeValue = targetRecord.last_grade
  const grade = gradeValue === null || gradeValue === undefined || gradeValue === ''
    ? null
    : String(gradeValue)
  const score = finiteScore(targetRecord.last_score)
  if (grade === null && score === null) {
    return { status: 'unavailable', grade: null, score: null, note: 'No posture score is available.' }
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
