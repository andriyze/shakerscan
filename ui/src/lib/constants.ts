// Shared constants for Shaker Scan UI

export type ScanType = 'quick' | 'standard' | 'deep' | 'full' | 'smart' | 'aggressive'

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
    options: { quick: true, public: true }
  },
  {
    value: 'standard',
    label: 'Standard',
    description: '+ Nuclei, cookies, CORS',
    duration: '5-10 min',
    options: { quick: false, public: false }
  },
  {
    value: 'deep',
    label: 'Deep',
    description: '+ Full Nuclei, ports',
    duration: '30-60 min',
    options: { quick: false, thorough: true }
  },
  {
    value: 'full',
    label: 'Full',
    description: '+ Active XSS/SQLi',
    duration: '1-2 hrs',
    requiresPermission: true,
    options: { quick: false, thorough: true, active: true }
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
    requiresPermission: true,
    options: { scan_type: 'smart' }
  },
]

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

export const DISCOVERY_SOURCES = ['manual', 'subfinder', 'gungnir-monitor', 'import'] as const
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

export const AGE_FILTER_OPTIONS = [
  { value: 30, label: '30+ days' },
  { value: 60, label: '60+ days' },
  { value: 90, label: '90+ days' },
  { value: 180, label: '180+ days' },
] as const

// Helper to get scan type options for API calls
export function getScanOptions(scanType: ScanType): Record<string, boolean | string> {
  const type = SCAN_TYPES.find(t => t.value === scanType)
  return type?.options || {}
}

// Get scan type description with duration
export function getScanTypeDescription(scanType: ScanType): string {
  const type = SCAN_TYPES.find(t => t.value === scanType)
  if (!type) return ''
  return type.duration ? `${type.duration} - ${type.description}` : type.description
}
