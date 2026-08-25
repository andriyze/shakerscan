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
  const gradeValue = scanRecord.grade ?? resultSummary.grade
  const grade = gradeValue === null || gradeValue === undefined || gradeValue === ''
    ? null
    : String(gradeValue)
  const score = finiteScore(scanRecord.score ?? resultSummary.score)

  if (!isDevice) {
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
