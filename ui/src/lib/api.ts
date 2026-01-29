const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

async function getApiErrorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const data = await res.json()
    if (typeof data?.detail === 'string') return data.detail
    if (typeof data?.message === 'string') return data.message
  } catch {
    // Ignore JSON parse errors and use fallback.
  }
  return fallback
}

export interface DashboardMetrics {
  total_targets: number
  total_scans: number
  running_scans: number
  active_findings: number
  critical_findings: number
  high_findings: number
  avg_score: number
}

export interface Scan {
  id: string
  target_url: string
  target_name?: string
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  scan_type: string
  progress?: number
  current_phase?: string
  score?: number
  grade?: string
  findings_count: number
  created_at: string
  completed_at?: string
  duration_seconds?: number
  error_message?: string
}

export interface Target {
  id: string
  url: string
  name?: string
  root_domain: string
  is_root: boolean
  discovery_source: string
  is_active: boolean
  last_score?: number
  last_grade?: string
  last_scanned_at?: string
  total_scans: number
  active_findings_count: number
  created_at: string
}

export interface GroupedDomain {
  root_domain: string
  root_target: Target | null
  subdomains: Target[]
  subdomain_count: number
  total_count: number
}

export interface Finding {
  id: string
  title: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_score?: number
  status: 'active' | 'resolved' | 'false_positive' | 'accepted_risk'
  tool?: string
  fingerprint?: string
  cwe?: string
  cwe_name?: string
  owasp?: string
  url?: string
  target_url?: string
  target_name?: string
  scan_id?: string
  target_id?: string
  evidence?: string | Record<string, unknown>
  request?: string
  response?: string
  ai_verdict?: string
  ai_confidence?: number
  ai_rationale?: string
  ai_recommendations?: string[] | Record<string, unknown> | null
  notes?: string
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resurfaced_count?: number
  created_at?: string
  updated_at?: string
}

export interface QueueStats {
  pending: number
  queued: number
  running: number
  completed: number
  failed: number
}

export interface WorkerInfo {
  name: string
  status: string
  health?: string
}

export interface WorkerStats {
  count: number
  workers: WorkerInfo[]
  max_allowed: number
  error?: string
}

// Dashboard
export async function getDashboard() {
  const res = await fetch(`${API_URL}/dashboard`)
  if (!res.ok) throw new Error('Failed to fetch dashboard')
  return res.json()
}

// Scans
export async function getScans(params?: {
  status?: string
  limit?: number
  offset?: number
  root_domain?: string
  target?: string
}): Promise<{ scans: Scan[]; total: number; limit: number; offset: number }> {
  const searchParams = new URLSearchParams()
  if (params?.status) searchParams.set('status', params.status)
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  if (params?.offset) searchParams.set('offset', params.offset.toString())
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.target) searchParams.set('target', params.target)

  const res = await fetch(`${API_URL}/scans?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch scans')
  return res.json()
}

export async function getScan(id: string) {
  const res = await fetch(`${API_URL}/scans/${id}`)
  if (!res.ok) throw new Error('Failed to fetch scan')
  return res.json()
}

export async function getScanLogs(id: string, limit: number = 200) {
  const res = await fetch(`${API_URL}/scans/${id}/logs?limit=${limit}`)
  if (!res.ok) throw new Error('Failed to fetch scan logs')
  return res.json()
}

export async function submitScan(target: string, options: Record<string, boolean | string> = {}) {
  const res = await fetch(`${API_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, options })
  })
  if (!res.ok) throw new Error('Failed to submit scan')
  return res.json()
}

export async function cancelScan(id: string) {
  const res = await fetch(`${API_URL}/scans/${id}/cancel`, {
    method: 'POST'
  })
  if (!res.ok) throw new Error('Failed to cancel scan')
  return res.json()
}

// Targets
export async function getTargets(params?: { includeInactive?: boolean }) {
  const searchParams = new URLSearchParams()
  if (params?.includeInactive) searchParams.set('include_inactive', 'true')

  const res = await fetch(`${API_URL}/targets?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch targets')
  return res.json()
}

export async function getTargetsGrouped(params?: {
  includeInactive?: boolean
  search?: string
  discovery_source?: string
  grade?: string
  has_findings?: boolean
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}): Promise<{
  domains: GroupedDomain[]
  total_root_domains: number
  total_targets: number
}> {
  const searchParams = new URLSearchParams()
  if (params?.includeInactive) searchParams.set('include_inactive', 'true')
  if (params?.search) searchParams.set('search', params.search)
  if (params?.discovery_source) searchParams.set('discovery_source', params.discovery_source)
  if (params?.grade) searchParams.set('grade', params.grade)
  if (params?.has_findings !== undefined) searchParams.set('has_findings', String(params.has_findings))
  if (params?.sort_by) searchParams.set('sort_by', params.sort_by)
  if (params?.sort_order) searchParams.set('sort_order', params.sort_order)

  const res = await fetch(`${API_URL}/targets/grouped?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch grouped targets')
  return res.json()
}

export async function createTarget(url: string, name?: string) {
  const res = await fetch(`${API_URL}/targets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, name })
  })
  if (!res.ok) throw new Error('Failed to create target')
  return res.json()
}

export async function scanTarget(targetId: string, options: Record<string, boolean | string> = {}) {
  const res = await fetch(`${API_URL}/targets/${targetId}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options)
  })
  if (!res.ok) throw new Error('Failed to start scan')
  return res.json()
}

// Findings
export async function getFindings(params?: {
  severity?: string
  status?: string
  limit?: number
  offset?: number
  root_domain?: string
  scan_id?: string
  target_id?: string
  search?: string
  sort_by?: 'severity' | 'first_seen' | 'last_seen' | 'cvss'
  sort_order?: 'asc' | 'desc'
}): Promise<{ findings: Finding[]; total: number; limit: number; offset: number }> {
  const searchParams = new URLSearchParams()
  if (params?.severity) searchParams.set('severity', params.severity)
  if (params?.status) searchParams.set('status', params.status)
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  if (params?.offset) searchParams.set('offset', params.offset.toString())
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.scan_id) searchParams.set('scan_id', params.scan_id)
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  if (params?.search) searchParams.set('search', params.search)
  if (params?.sort_by) searchParams.set('sort_by', params.sort_by)
  if (params?.sort_order) searchParams.set('sort_order', params.sort_order)

  const res = await fetch(`${API_URL}/findings?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch findings')
  return res.json()
}

// Domains
export async function getDomains(): Promise<{ domains: string[] }> {
  const res = await fetch(`${API_URL}/domains`)
  if (!res.ok) throw new Error('Failed to fetch domains')
  return res.json()
}

export async function getFinding(id: string): Promise<Finding> {
  const res = await fetch(`${API_URL}/findings/${id}`)
  if (!res.ok) throw new Error('Failed to fetch finding')
  return res.json()
}

export async function updateFinding(id: string, status: string, notes?: string, scanId?: string) {
  const url = scanId
    ? `${API_URL}/findings/${id}?scan_id=${scanId}`
    : `${API_URL}/findings/${id}`
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, notes })
  })
  if (!res.ok) throw new Error('Failed to update finding')
  return res.json()
}

// Queue
export async function getQueueStats(): Promise<QueueStats> {
  const res = await fetch(`${API_URL}/queue/stats`)
  if (!res.ok) throw new Error('Failed to fetch queue stats')
  return res.json()
}

// Health
export async function getHealth() {
  const res = await fetch(`${API_URL}/health`)
  if (!res.ok) throw new Error('API not healthy')
  return res.json()
}

// Workers
export async function getWorkers(): Promise<WorkerStats> {
  const res = await fetch(`${API_URL}/workers`)
  if (!res.ok) throw new Error('Failed to fetch workers')
  return res.json()
}

export async function scaleWorkers(count: number): Promise<{ status: string; target_count: number; message: string }> {
  const res = await fetch(`${API_URL}/workers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ count })
  })
  if (!res.ok) throw new Error('Failed to scale workers')
  return res.json()
}

// Gungnir CT Monitor
export interface GungnirStatus {
  running: boolean
  domains_monitored: number
  subdomains_found: number
  session_found: number
  last_discovery: string | null
  started_at: string | null
  uptime_seconds: number
}

export async function getGungnirStatus(): Promise<GungnirStatus> {
  const res = await fetch(`${API_URL}/gungnir/status`)
  if (!res.ok) throw new Error('Failed to fetch gungnir status')
  return res.json()
}

export async function startGungnir(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_URL}/gungnir/start`, {
    method: 'POST'
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to start gungnir'))
  }
  return res.json()
}

export async function stopGungnir(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_URL}/gungnir/stop`, {
    method: 'POST'
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to stop gungnir'))
  }
  return res.json()
}

// Discovery
export async function discoverSubdomains(rootDomain: string): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_URL}/discovery?root_domain=${encodeURIComponent(rootDomain)}`, {
    method: 'POST'
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to start subdomain discovery'))
  }
  return res.json()
}

// Utilities
export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-500'
    case 'high': return 'text-orange-500'
    case 'medium': return 'text-yellow-500'
    case 'low': return 'text-blue-500'
    default: return 'text-gray-500'
  }
}

export function getSeverityBg(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400'
    case 'high': return 'bg-orange-500/20 text-orange-400'
    case 'medium': return 'bg-yellow-500/20 text-yellow-400'
    case 'low': return 'bg-blue-500/20 text-blue-400'
    default: return 'bg-gray-500/20 text-gray-400'
  }
}

export function getGradeColor(grade: string): string {
  switch (grade?.toUpperCase()) {
    case 'A': case 'A+': return 'text-green-500'
    case 'B': return 'text-lime-500'
    case 'C': return 'text-yellow-500'
    case 'D': return 'text-orange-500'
    case 'F': return 'text-red-500'
    default: return 'text-gray-500'
  }
}

export function formatDate(date: string): string {
  return new Date(date).toLocaleString()
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}
