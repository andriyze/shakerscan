// One line that relates the totals a Scan page shows: the tab's count, the proven and unverified
// split, the critical-or-high count the release decision speaks of, and the "confirmed material"
// number of the headline. It counts the run's stored findings with the grouping the Findings tab
// draws, so it introduces no number of its own.
import { scanFindingCounts } from './scanDetailPresentation.mjs'

const RELEASE_SEVERITIES = new Set(['critical', 'high'])

/** The findings a run reported: the stored report's rows, else the rows attached to the scan. */
export function scanReportedFindings(scan) {
  const report = scan?.result?.findings
  if (Array.isArray(report)) return report
  return Array.isArray(scan?.findings) ? scan.findings : []
}

/** The counts behind the line, or null for a run without findings. */
export function scanCountSummary(scan) {
  const findings = scanReportedFindings(scan)
  if (findings.length === 0) return null
  const counts = scanFindingCounts(findings)
  const criticalOrHigh = findings
    .filter((finding) => RELEASE_SEVERITIES.has(String(finding?.severity || '').toLowerCase())).length
  return { ...counts, criticalOrHigh }
}

/** "44 findings in this run: 28 proven, 16 awaiting verification. Critical or high: 38. Proven at medium or higher: 22." */
export function scanCountLine(scan) {
  const summary = scanCountSummary(scan)
  if (!summary) return null
  const parts = [`${summary.proven} proven`]
  if (summary.verify) parts.push(`${summary.verify} awaiting verification`)
  if (summary.informational) parts.push(`${summary.informational} informational`)
  return `${summary.total} finding${summary.total === 1 ? '' : 's'} in this run: ${parts.join(', ')}. `
    + `Critical or high: ${summary.criticalOrHigh}. Proven at medium or higher: ${summary.provenMaterial}.`
}
