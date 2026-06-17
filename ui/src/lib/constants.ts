// Shared constants for ShakerScan UI

export type ScanType = 'quick' | 'standard' | 'deep' | 'full' | 'smart' | 'aggressive'
export type BudgetProfile = 'fast' | 'balanced' | 'thorough' | 'exhaustive'
export type ParallelStrategy = 'auto' | 'scope' | 'family' | 'coverage' | 'coverage_family'

export interface ScanTypeOption {
  value: ScanType
  label: string
  description: string
  duration?: string
  requiresPermission?: boolean
  options: Record<string, boolean | string>
}

export const SCAN_TYPES: ScanTypeOption[] = [
  {
    value: 'quick',
    label: 'Quick',
    description: 'DNS, TLS, headers',
    duration: '1-2 min',
    options: { scan_type: 'quick', quick: true, public: true }
  },
  {
    value: 'standard',
    label: 'Standard',
    description: '+ Nuclei, cookies, CORS',
    duration: '5-10 min',
    options: { scan_type: 'standard', quick: false, public: false }
  },
  {
    value: 'deep',
    label: 'Deep',
    description: '+ Full Nuclei, ports',
    duration: '30-60 min',
    options: { scan_type: 'deep', quick: false, thorough: true }
  },
  {
    value: 'full',
    label: 'Full',
    description: '+ Active XSS/SQLi',
    duration: '1-2 hrs',
    requiresPermission: true,
    options: { scan_type: 'full', quick: false, thorough: true, active: true }
  },
  {
    value: 'aggressive',
    label: 'Aggressive',
    description: 'Maximum coverage',
    duration: '2+ hrs',
    requiresPermission: true,
    options: { scan_type: 'aggressive' }
  },
  {
    value: 'smart',
    label: 'Smart',
    description: 'Adaptive intelligent scan',
    duration: 'Budget-dependent',
    requiresPermission: true,
    options: { scan_type: 'smart' }
  },
]

export const BUDGET_PROFILES: Array<{
  value: BudgetProfile
  label: string
  description: string
}> = [
  { value: 'fast', label: 'Fast', description: 'Small coverage budget for quick feedback' },
  { value: 'balanced', label: 'Balanced', description: 'Default depth and runtime limits' },
  { value: 'thorough', label: 'Thorough', description: 'Higher coverage for staging and release checks' },
  { value: 'exhaustive', label: 'Exhaustive', description: 'Maximum coverage; can run for hours' },
]

export const PARALLEL_STRATEGIES: Array<{
  value: ParallelStrategy
  label: string
  description: string
}> = [
  { value: 'auto', label: 'Auto', description: 'Use endpoint sharding when endpoints are provided; otherwise use active-family sharding.' },
  { value: 'scope', label: 'Endpoint scope', description: 'Split known API endpoints across workers. Best for real speed-up.' },
  { value: 'family', label: 'Check family', description: 'Run broad, SQLi-focused, and XSS-focused shards in parallel for active scans.' },
  { value: 'coverage', label: 'Full coverage', description: 'Discover once, then partition every discovered endpoint across shards to test the whole target. Heaviest; scale workers to match.' },
]

export const PARALLEL_ACTIVE_SCAN_TYPES: ScanType[] = ['smart', 'full', 'aggressive']

export function supportsParallelFamily(scanType: ScanType): boolean {
  return PARALLEL_ACTIVE_SCAN_TYPES.includes(scanType)
}

export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const
export type SeverityLevel = typeof SEVERITY_LEVELS[number]

export const SCAN_STATUSES = ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'] as const
export type ScanStatus = typeof SCAN_STATUSES[number]

export const FINDING_STATUSES = ['active', 'resolved', 'false_positive', 'accepted_risk'] as const
export type FindingStatus = typeof FINDING_STATUSES[number]

export const SORT_OPTIONS = [
  { value: 'severity', label: 'Severity' },
  { value: 'first_seen', label: 'First Seen' },
  { value: 'last_seen', label: 'Last Seen' },
  { value: 'cvss', label: 'CVSS Score' },
] as const
export type SortOption = typeof SORT_OPTIONS[number]['value']

export type SortOrder = 'asc' | 'desc'

export const DISCOVERY_SOURCES = ['manual', 'subfinder', 'gungnir-monitor', 'import', 'model-intake'] as const
export type DiscoverySource = typeof DISCOVERY_SOURCES[number]

export const GRADES = ['A', 'B', 'C', 'D', 'F'] as const
export type Grade = typeof GRADES[number]

export const TARGET_SORT_OPTIONS = [
  { value: 'root_domain', label: 'Domain Name' },
  { value: 'last_scanned_at', label: 'Last Scanned' },
  { value: 'active_findings_count', label: 'Findings Count' },
  { value: 'last_score', label: 'Score' },
  { value: 'created_at', label: 'Date Added' },
] as const
export type TargetSortOption = typeof TARGET_SORT_OPTIONS[number]['value']

export const LAST_SEEN_OPTIONS = [
  { value: 7, label: 'Last 7 days' },
  { value: 30, label: 'Last 30 days' },
  { value: 60, label: 'Last 60 days' },
  { value: 90, label: 'Last 90 days' },
] as const

export const CLEANUP_AGE_OPTIONS = [
  { value: 30, label: '30+ days' },
  { value: 60, label: '60+ days' },
  { value: 90, label: '90+ days' },
  { value: 180, label: '180+ days' },
] as const

// ---------------------------------------------------------------------------
// Shared style maps — single source of truth for severity/status/grade colors.
// Class strings must stay literal so Tailwind's JIT can see them.
// ---------------------------------------------------------------------------

export const SEVERITY_BADGE_STYLES: Record<SeverityLevel, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
  info: 'bg-gray-500/20 text-gray-400',
}

export const SEVERITY_TEXT_COLORS: Record<SeverityLevel, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-gray-500',
}

export const SCAN_STATUS_BADGE_STYLES: Record<ScanStatus, string> = {
  pending: 'bg-gray-500/20 text-gray-400',
  queued: 'bg-gray-500/20 text-gray-400',
  running: 'bg-blue-500/20 text-blue-400',
  completed: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-500/20 text-red-400',
  cancelled: 'bg-orange-500/20 text-orange-400',
}

export const FINDING_STATUS_BADGE_STYLES: Record<FindingStatus, string> = {
  active: 'bg-yellow-500/20 text-yellow-400',
  resolved: 'bg-green-500/20 text-green-400',
  false_positive: 'bg-gray-500/20 text-gray-400',
  accepted_risk: 'bg-purple-500/20 text-purple-400',
}

// Retest / verification verdicts (see api/retest_contract.py SUPPORTED_RETEST_VERDICTS).
export const RETEST_VERDICT_BADGE_STYLES: Record<string, string> = {
  exploited: 'bg-red-500/20 text-red-400',
  likely_vulnerable: 'bg-orange-500/20 text-orange-400',
  blocked_by_security: 'bg-amber-500/20 text-amber-300',
  out_of_scope_internal: 'bg-gray-500/20 text-gray-400',
  inconclusive: 'bg-amber-500/20 text-amber-300',
  false_positive: 'bg-gray-500/20 text-gray-400',
  likely_fixed: 'bg-green-500/20 text-green-400',
  error: 'bg-gray-500/20 text-gray-400',
}

export const RETEST_VERDICT_LABELS: Record<string, string> = {
  exploited: 'Still vulnerable',
  likely_vulnerable: 'Likely vulnerable',
  blocked_by_security: 'Blocked by security',
  out_of_scope_internal: 'Out of scope (internal)',
  inconclusive: 'Inconclusive',
  false_positive: 'False positive',
  likely_fixed: 'Likely fixed',
  error: 'Retest error',
}

export type FindingSourceType = 'AI' | 'DAST' | 'Model Intake'

export const SOURCE_TYPE_BADGE_STYLES: Record<FindingSourceType, string> = {
  AI: 'bg-purple-500/20 text-purple-300',
  DAST: 'bg-blue-500/20 text-blue-300',
  'Model Intake': 'bg-cyan-500/20 text-cyan-300',
}

export const GRADE_TEXT_COLORS: Record<string, string> = {
  'A+': 'text-green-500',
  A: 'text-green-500',
  B: 'text-lime-500',
  C: 'text-yellow-500',
  D: 'text-orange-500',
  F: 'text-red-500',
}

export function normalizeGradeKey(grade?: string | null): string {
  const raw = String(grade || '').trim().toUpperCase()
  if (!raw) return ''
  if (raw.startsWith('A+')) return 'A+'
  return raw.match(/^[A-F]/)?.[0] || ''
}

export function gradeTextColorClass(grade?: string | null): string {
  const key = normalizeGradeKey(grade)
  return GRADE_TEXT_COLORS[key] ?? 'text-gray-500'
}

// Helper to get scan type options for API calls
export function getScanOptions(scanType: ScanType): Record<string, boolean | string> {
  const type = SCAN_TYPES.find(t => t.value === scanType)
  return type ? { ...type.options } : {}
}

// Get scan type description with duration
export function getScanTypeDescription(scanType: ScanType): string {
  const type = SCAN_TYPES.find(t => t.value === scanType)
  if (!type) return ''
  return type.duration ? `${type.duration} - ${type.description}` : type.description
}
