export interface ScanCountSummary {
  total: number
  proven: number
  provenMaterial: number
  verify: number
  informational: number
  criticalOrHigh: number
}
export function scanReportedFindings(scan: unknown): any[]
export function scanCountSummary(scan: unknown): ScanCountSummary | null
export function scanCountLine(scan: unknown): string | null
