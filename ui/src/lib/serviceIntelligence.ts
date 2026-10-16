import { API_URL, getApiErrorMessage } from './apiConfig'
import { fetchHeavyRead } from './busyRetry.mjs'

export interface ServiceEvidence {
  ref: string
  scan_id: string | null
  hunt_id?: string | null
  action_id: string | null
  sha256: string | null
  observed_at: string | null
  vantage: string | null
  status: string
}
export interface ServiceCandidate {
  id: string
  title: string
  severity: string
  advisory_url: string
  match_type: string
  confidence: string
  applicability: 'candidate'
  version_evaluation: string
  local_validation: string
  identity_stale: boolean
  prerequisites: string[]
  exploit_references: Array<{ url: string; source: string; kind: string; review_status: string }>
  // Exploitation context from the pinned snapshot (2.10): CVSS base score, CISA KEV membership,
  // EPSS likelihood, and checks the image's own templates carry. Absent on an older engine.
  cvss_score?: number | null
  known_exploited?: { date_added: string | null; ransomware: boolean } | null
  epss?: { score: number; percentile: number | null } | null
  checks?: Array<{ kind: string; id: string }>
  // 2.11: whether the named check ran in a verify Scan and what it found. Absent on an older engine.
  verification?: ServiceVerification
}
export interface ServiceVerification {
  status: 'no_check' | 'available' | 'unavailable' | 'pending' | 'check_matched' | 'check_not_matched' | 'inconclusive'
  template_ids: string[]
  request?: Record<string, unknown> | null
  unavailable_reason?: string | null
  scan_id?: string
  checked_at?: string | null
  finding_id?: string
  finding_status?: string | null
  proof_state?: string | null
  reason?: string
}
export interface ListenerGroup {
  key: string
  transport: 'tcp' | 'udp'
  port: number
  service: string
  product: string | null
  version: string | null
  service_ids: string[]
  primary_service_id: string
  max_severity: 'critical' | 'high' | 'medium' | 'low' | null
  known_exploited: number
  candidate_count: number
  finding_count: number
  checks_available: number
  check_matched: number
  identity_stale: boolean
  last_seen_at: string | null
  quiet: boolean
}
export interface ServiceActivity {
  id: string
  title: string
  reason: string
  status: string
  capability: string | null
  risk_tier: string | null
  required_approval: string | null
  execution_available: false
  prerequisites: string[]
}
export interface ServiceRecord {
  id: string
  target_id: string
  target_kind: 'web' | 'device'
  address: string | null
  transport: 'tcp' | 'udp'
  port: number
  application_origin: string | null
  service: string
  product: string | null
  version: string | null
  cpes: string[]
  identity_basis: string
  detection_method: string | null
  detection_confidence: number | null
  tunnel: string | null
  encrypted: boolean | null
  state: string
  presence: string
  freshness: string
  identity_stale: boolean
  binding_status: string
  first_seen_at: string | null
  last_seen_at: string | null
  identity_observed_at: string | null
  observation_status: string
  evidence: ServiceEvidence[]
  evidence_truncated: boolean
  history: Array<{ service: string; product: string | null; version: string | null; state: string; observed_at: string | null; evidence_ref: string }>
  findings: Array<{ id: string; title: string; severity: string; status: string; proof_state: string | null; last_verification_verdict: string | null }>
  cve_candidates: ServiceCandidate[]
  candidates_truncated: boolean
  intelligence_status: string
  activities: ServiceActivity[]
  hunt_href: string | null
}
export interface ServiceTarget {
  id: string
  kind: 'web' | 'device'
  label: string
  locator: string | null
  root_domain: string | null
  services: ServiceRecord[]
  source_count: number
  sources_truncated: boolean
  findings_truncated: boolean
  unlinked_findings_count: number
  warnings: string[]
  listener_groups?: ListenerGroup[]
  severity_counts?: Record<'critical' | 'high' | 'medium' | 'low' | 'none' | 'quiet', number>
}
export interface ServicePage {
  schema_version: string
  targets: ServiceTarget[]
  total_targets: number
  limit: number
  offset: number
  has_more: boolean
  intelligence: {
    status: string
    generated_at: string | null
    snapshot_sha256: string | null
    record_count: number
    coverage: string
    source?: 'builtin' | 'external_bundle' | 'operator_pinned'
    bundle?: { status: string; bundle_version: number | null; generated_at: string | null; key_id: string | null }
    limitations: string[]
  }
  limitations: string[]
}

export async function getServiceIntelligence(options: {
  rootDomain?: string
  targetKind?: 'all' | 'web' | 'device'
  targetId?: string
  search?: string
  limit?: number
  offset?: number
  signal?: AbortSignal
} = {}): Promise<ServicePage> {
  const params = new URLSearchParams()
  if (options.rootDomain) params.set('root_domain', options.rootDomain)
  if (options.targetKind && options.targetKind !== 'all') params.set('target_kind', options.targetKind)
  if (options.targetId) params.set('target_id', options.targetId)
  if (options.search) params.set('search', options.search)
  params.set('limit', String(options.limit ?? 10))
  params.set('offset', String(options.offset ?? 0))
  const response = await fetchHeavyRead(`${API_URL}/exposure/services?${params}`, { signal: options.signal, cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load service evidence'))
  return response.json()
}

// Verify a candidate: the server supplies the exact Scan request (the target's origin, the active
// template family and the named checks); this submits it as an ordinary Scan.
export async function submitVerifyScan(request: Record<string, unknown>): Promise<{ scan_id?: string; id?: string }> {
  const response = await fetch(`${API_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to start the verify Scan'))
  return response.json()
}
