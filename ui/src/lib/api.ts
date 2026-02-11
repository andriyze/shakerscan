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
  started_at?: string | null
  completed_at?: string
  duration_seconds?: number
  error_message?: string
  options?: Record<string, unknown> | null
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
  ai_classification_source?: 'provider' | 'heuristic_fallback' | 'heuristic_only' | string
  notes?: string
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resurfaced_count?: number
  last_verification_status?: string
  last_verification_verdict?: string
  last_verification_confidence?: number
  last_verified_at?: string
  verification_count?: number
  created_at?: string
  updated_at?: string
}

export interface RetestRecord {
  id: string
  finding_id: string
  job_id?: string
  requested_by?: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  result_status?: 'still_vulnerable' | 'likely_fixed' | 'inconclusive' | 'error' | 'likely_vulnerable'
  verdict?: 'exploited' | 'likely_vulnerable' | 'blocked_by_security' | 'out_of_scope_internal' | 'false_positive' | 'likely_fixed' | 'inconclusive' | 'error'
  verdict_reason?: string
  verification_mode?: 'deterministic' | 'ai_driven'
  finding_type: string
  target_url: string
  original_url?: string
  param?: string
  payload?: string
  method?: string
  request_body?: string
  replay_commands?: string[] | null
  proof?: Record<string, unknown> | null
  artifacts?: Record<string, unknown> | null
  auth_context?: Record<string, unknown> | null
  ai_plan?: Record<string, unknown> | null
  ai_reasoning?: string | null
  confidence?: number | null
  message?: string
  error_message?: string
  created_at?: string
  started_at?: string | null
  completed_at?: string | null
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

export interface AISettings {
  ai_url: string
  ai_model: string
  ai_model_fallback: string
  ai_mask_host: string
  ai_scan_classification_enabled: boolean
  ai_classify_min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ai_api_key_configured: boolean
  ai_api_key_masked?: string
  ai_verify_enabled: boolean
  ai_verify_min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  auto_retest_on_scan_complete: boolean
  auto_retest_min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  auto_retest_max_per_scan: number
  verification_min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ai_escalation_min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  proof_required_for_smart: boolean
}

export interface AISettingsUpdate {
  ai_url?: string
  ai_api_key?: string
  ai_model?: string
  ai_model_fallback?: string
  ai_mask_host?: string
  ai_scan_classification_enabled?: boolean
  ai_classify_min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ai_verify_enabled?: boolean
  ai_verify_min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  auto_retest_on_scan_complete?: boolean
  auto_retest_min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  auto_retest_max_per_scan?: number
  verification_min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  ai_escalation_min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  proof_required_for_smart?: boolean
  persist_to_env?: boolean
}

export interface AIProbeResponse {
  status: 'ok' | 'failed'
  scope: 'scan' | 'verify'
  probe: {
    ok: boolean
    error?: string | null
    latency_ms?: number | null
    provider_meta?: Record<string, unknown>
    response?: Record<string, unknown> | null
  }
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
  seen_within_days?: number
  verification_verdict?: 'exploited' | 'likely_vulnerable' | 'blocked_by_security' | 'out_of_scope_internal' | 'false_positive' | 'likely_fixed' | 'inconclusive' | 'error'
  verification_mode?: 'deterministic' | 'ai_driven'
  verified_only?: boolean
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
  if (params?.seen_within_days) searchParams.set('seen_within_days', params.seen_within_days.toString())
  if (params?.verification_verdict) searchParams.set('verification_verdict', params.verification_verdict)
  if (params?.verification_mode) searchParams.set('verification_mode', params.verification_mode)
  if (params?.verified_only) searchParams.set('verified_only', 'true')
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

export async function retestFinding(
  id: string,
  params: {
    finding_type?: string
    target?: string
    original_url?: string
    param?: string
    payload?: string
    method?: string
    request_body?: string
    requested_by?: string
  } = {},
  mode?: 'ai' | 'deterministic'
): Promise<{
  retest_id: string
  job_id: string
  status: string
  mode?: string
  finding_id: string
  finding_type: string
  target_url: string
  replay_commands?: string[]
}> {
  const query = mode ? `?mode=${mode}` : ''
  const res = await fetch(`${API_URL}/findings/${id}/retest${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to queue retest'))
  }
  return res.json()
}

export async function getFindingRetests(id: string, limit: number = 20): Promise<{
  finding_id: string
  retests: RetestRecord[]
  count: number
}> {
  const res = await fetch(`${API_URL}/retests/finding/${id}?limit=${limit}`)
  if (!res.ok) throw new Error('Failed to fetch retest history')
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

export async function deleteFinding(id: string): Promise<{ id: string; status: string }> {
  const res = await fetch(`${API_URL}/findings/${id}`, {
    method: 'DELETE'
  })
  if (!res.ok) throw new Error('Failed to delete finding')
  return res.json()
}

export async function cleanupFindings(params: {
  older_than_days: number
  status?: string
  root_domain?: string
  dry_run: boolean
}): Promise<{ would_delete?: number; deleted?: number; dry_run: boolean }> {
  const res = await fetch(`${API_URL}/findings/cleanup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
  if (!res.ok) throw new Error('Failed to cleanup findings')
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

export async function getAISettings(): Promise<AISettings> {
  const res = await fetch(`${API_URL}/settings/ai`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to fetch AI settings'))
  }
  return res.json()
}

export async function updateAISettings(data: AISettingsUpdate): Promise<{
  status: string
  persisted_to_env: boolean
  persist_message?: string
  settings: AISettings
}> {
  const res = await fetch(`${API_URL}/settings/ai`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to update AI settings'))
  }
  return res.json()
}

export async function testAISettings(data: {
  scope: 'scan' | 'verify'
  ai_url?: string
  ai_api_key?: string
  ai_model?: string
  ai_fallback_model?: string
}): Promise<AIProbeResponse> {
  const res = await fetch(`${API_URL}/settings/ai/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to test AI settings'))
  }
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

// Schedules
export interface Schedule {
  id: string
  target_id: string
  target_url: string
  target_name?: string
  name?: string
  frequency: 'daily' | 'weekly'
  day_of_week?: number
  time_of_day: string
  timezone: string
  jitter_minutes: number
  scan_type: string
  scan_options?: Record<string, unknown>
  is_active: boolean
  last_run_at?: string
  next_run_at?: string
  created_at: string
  updated_at: string
}

export interface ScheduleCreate {
  target_id: string
  name?: string
  frequency: string
  day_of_week?: number
  time_of_day: string
  timezone?: string
  scan_type: string
  scan_options?: Record<string, unknown>
  jitter_minutes?: number
}

export async function getSchedules(params?: {
  target_id?: string
  is_active?: boolean
}): Promise<{ schedules: Schedule[]; total: number }> {
  const searchParams = new URLSearchParams()
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  if (params?.is_active !== undefined) searchParams.set('is_active', String(params.is_active))

  const res = await fetch(`${API_URL}/schedules?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch schedules')
  return res.json()
}

export async function createSchedule(data: ScheduleCreate): Promise<{ id: string; target_url: string; next_run_at: string; status: string }> {
  const res = await fetch(`${API_URL}/schedules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to create schedule'))
  }
  return res.json()
}

export async function updateSchedule(id: string, data: Partial<Schedule>): Promise<{ id: string; status: string }> {
  const res = await fetch(`${API_URL}/schedules/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to update schedule'))
  }
  return res.json()
}

export async function deleteSchedule(id: string): Promise<{ id: string; status: string }> {
  const res = await fetch(`${API_URL}/schedules/${id}`, {
    method: 'DELETE'
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to delete schedule'))
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

// Interactive Sessions
export interface InteractiveSessionUserState {
  is_authenticated: boolean
  auth_method: string | null
  cookies_count: number
}

export interface InteractiveDiscoveredEndpoint {
  path: string
  method: string
  status: number | null
}

export interface InteractiveSessionState {
  session_id: string
  target_url: string
  current_url: string | null
  created_at: string
  last_activity: string
  users: Record<string, InteractiveSessionUserState>
  discovered_endpoints_count: number
  discovered_endpoints: InteractiveDiscoveredEndpoint[]
  discovered_ids: Record<string, string[]>
  network_log_count: number
}

export interface InteractiveSessionStartResponse {
  success: boolean
  session_id: string
  target: string
  current_url: string
  message?: string
}

export interface InteractiveSessionSummary {
  session_id: string
  target_url: string
  created_at: string
  last_activity: string
  is_expired: boolean
}

export interface InteractiveSessionsListResponse {
  sessions: InteractiveSessionSummary[]
  count: number
}

export interface InteractiveActionRequest {
  action: string
  user?: string
  data?: Record<string, unknown>
}

export interface InteractiveEndpointTestRequest {
  endpoint: string
  method?: string
  as_user?: string
  body?: Record<string, unknown>
  allow_out_of_scope?: boolean
}

export interface InteractiveEndpointTestResult {
  success: boolean
  endpoint: string
  method: string
  as_user?: string
  status?: number
  status_text?: string
  headers?: Record<string, string>
  body?: string
  json?: Record<string, unknown> | null
  accessible?: boolean
  error?: string
}

export interface InteractiveSessionFindingCreateRequest {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description?: string
  category?: string
  cwe?: string
  cvss_score?: number
  url?: string
  evidence?: string
  request?: string
  response?: string
  remediation?: string
  notes?: string
}

export interface InteractiveSessionFindingCreateResponse {
  id: string
  fingerprint: string
  target_id: string
  target: string
  session_id: string
  status: string
  message: string
}

export interface InteractiveScreenshotResponse {
  success: boolean
  format: 'base64'
  data: string
  url: string
  user: string
  saved_path?: string
}

export async function startInteractiveSession(target: string): Promise<InteractiveSessionStartResponse> {
  const res = await fetch(`${API_URL}/session/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to start interactive session'))
  }
  return res.json()
}

export async function listInteractiveSessions(): Promise<InteractiveSessionsListResponse> {
  const res = await fetch(`${API_URL}/sessions`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to list interactive sessions'))
  }
  return res.json()
}

export async function getInteractiveSession(sessionId: string): Promise<InteractiveSessionState> {
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to fetch interactive session'))
  }
  return res.json()
}

export async function runInteractiveAction(
  sessionId: string,
  request: InteractiveActionRequest
): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Interactive action failed'))
  }
  return res.json()
}

export async function captureInteractiveScreenshot(
  sessionId: string,
  params?: { full_page?: boolean; user?: string }
): Promise<InteractiveScreenshotResponse> {
  const searchParams = new URLSearchParams()
  if (params?.full_page !== undefined) searchParams.set('full_page', String(params.full_page))
  if (params?.user) searchParams.set('user', params.user)
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}/screenshot${query ? `?${query}` : ''}`, {
    method: 'POST',
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to capture screenshot'))
  }
  return res.json()
}

export async function testInteractiveEndpoint(
  sessionId: string,
  request: InteractiveEndpointTestRequest
): Promise<InteractiveEndpointTestResult> {
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}/test-endpoint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Endpoint test failed'))
  }
  return res.json()
}

export async function createInteractiveSessionFinding(
  sessionId: string,
  request: InteractiveSessionFindingCreateRequest
): Promise<InteractiveSessionFindingCreateResponse> {
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}/findings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to create finding from interactive session'))
  }
  return res.json()
}

export async function endInteractiveSession(sessionId: string): Promise<{ status: string; session_id: string; message: string }> {
  const res = await fetch(`${API_URL}/session/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to end interactive session'))
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
