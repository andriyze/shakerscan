// Assurance is the second scoring axis: how much of the application a scan actually
// examined, independent of how bad the findings were. It exists because a single number
// could not tell "we tested thoroughly and it is clean" apart from "we barely looked",
// and those call for opposite actions.

const BANDS = [
  { min: 85, band: 'strong', label: 'Strong coverage' },
  { min: 70, band: 'adequate', label: 'Adequate coverage' },
  { min: 50, band: 'limited', label: 'Limited coverage' },
  { min: 1, band: 'weak', label: 'Weak coverage' },
  { min: 0, band: 'none', label: 'Nothing examined' },
]

const GAP_LABELS = {
  no_examination_recorded: 'no examination recorded',
  required_actions_complete: 'required work did not finish',
  selected_families_complete: 'a selected check family is incomplete',
  candidates_attempted: 'planned candidates were not attempted',
  active_verification_attempted: 'active verification never ran',
  authenticated_coverage: 'only anonymous traffic',
  placement_available: 'a worker placement was unavailable',
  examination_breadth: 'the examination was narrow',
}

export function assuranceBand(score) {
  if (typeof score !== 'number' || Number.isNaN(score)) return null
  return BANDS.find((entry) => score >= entry.min) || BANDS[BANDS.length - 1]
}

export function assuranceClass(band) {
  switch (band) {
    case 'strong': return 'text-emerald-400'
    case 'adequate': return 'text-blue-300'
    case 'limited': return 'text-amber-300'
    case 'weak': return 'text-orange-400'
    case 'none': return 'text-red-400'
    default: return 'text-gray-400'
  }
}

export function assuranceGapLabels(gaps) {
  if (!Array.isArray(gaps)) return []
  return gaps.map((gap) => GAP_LABELS[gap] || String(gap).replaceAll('_', ' '))
}

// Detail reports may project an immutable legacy result through the current policy, so the
// report body wins when present. List rows still fall back to the stored column.
export function scanAssurance(scan) {
  if (!scan || typeof scan !== 'object') return null
  const result = (scan.result && typeof scan.result === 'object') ? scan.result : {}
  const inner = (result.result && typeof result.result === 'object') ? result.result : result
  const score = typeof inner.assurance_score === 'number'
    ? inner.assurance_score
    : (typeof scan.assurance_score === 'number' ? scan.assurance_score : null)
  if (score === null) return null
  const band = assuranceBand(score)
  return {
    score,
    band: band ? band.band : 'none',
    label: band ? band.label : 'Nothing examined',
    gaps: assuranceGapLabels(inner.assurance_gaps),
  }
}
