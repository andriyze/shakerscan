import type { AsmCoverage, AsmCoverageRollup } from './api'

export type CoverageSummary = AsmCoverage | AsmCoverageRollup

export function asmCoverageDenominator(
  coverage: CoverageSummary | null | undefined,
): { value: number; label: string } {
  if (!coverage) return { value: 0, label: 'testable' }
  if (coverage.metric_contract) {
    return {
      value: coverage.metric_contract.inventory.route_variants,
      label: 'testable route variants',
    }
  }
  const value = coverage.denominator
    ?? coverage.testable
    ?? Math.max(coverage.total - ('gone' in coverage ? coverage.gone : 0), 0)
  const label = coverage.denominator_label
    || (coverage.denominator !== undefined || coverage.testable !== undefined
      ? 'testable'
      : 'total - gone')
  return { value, label }
}

export function currentCompletedVariantCount(coverage: CoverageSummary): number {
  return Math.max(0, Number(coverage.tested) || 0)
}

export function resolvedCoverage(coverage: CoverageSummary | null | undefined): number {
  if (!coverage) return 0
  const denominator = asmCoverageDenominator(coverage).value
  const completed = currentCompletedVariantCount(coverage)
  return denominator > 0 ? Math.max(0, Math.min(1, completed / denominator)) : 0
}
