import {
  SEVERITY_BADGE_STYLES,
  SEVERITY_TEXT_COLORS,
  type SeverityLevel,
  gradeTextColorClass,
} from './constants'

export function getApiUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL
  }

  if (typeof window !== 'undefined') {
    const host = window.location.hostname
    const pageProtocol = window.location.protocol // "http:" or "https:"
    if (host && !['localhost', '127.0.0.1', '::1'].includes(host)) {
      // Match the page protocol so we don't downgrade to HTTP behind a TLS
      // reverse proxy (which would cause mixed-content blocking) and so we
      // don't try to hit 8080 when the proxy already exposes the API on 443.
      if (pageProtocol === 'https:') {
        // eslint-disable-next-line no-console
        console.warn(
          '[shakerscan] NEXT_PUBLIC_API_URL is not set on an HTTPS deploy. ' +
            'Falling back to same-origin API; set NEXT_PUBLIC_API_URL when the ' +
            'API is behind a different host or port.'
        )
        return `${window.location.origin}`
      }
      return `http://${host}:8080`
    }
  }

  return 'http://localhost:8080'
}

export const API_URL = getApiUrl()

async function getApiErrorMessage(res: Response, fallback: string): Promise<string> {
  try {
    const data = await res.json()
    const detail = data?.detail
    if (typeof detail === 'string') return detail
    // FastAPI validation errors: detail is an array of { msg, loc }.
    if (Array.isArray(detail)) {
      const msgs = detail.map((d) => (typeof d?.msg === 'string' ? d.msg : null)).filter(Boolean)
      if (msgs.length) return msgs.join('; ')
    }
    // Structured errors raised as { detail: { error, message, ... } }.
    if (detail && typeof detail === 'object' && typeof detail.message === 'string') return detail.message
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

export interface DashboardActionSample {
  label?: string | null
  detail?: string | null
  href?: string | null
}

export interface DashboardActionItem {
  id: string
  priority: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  category: string
  title: string
  detail: string
  href?: string | null
  action_label?: string | null
  count?: number | null
  samples?: DashboardActionSample[]
  metadata?: Record<string, unknown>
}

export interface DashboardResponse {
  metrics: DashboardMetrics
  recent_scans: Scan[]
  recent_findings: Finding[]
  action_center?: DashboardActionItem[]
}

export interface Scan {
  id: string
  target_url: string
  target_name?: string
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  scan_type: string
  run_kind?: string
  ai_target_id?: string | null
  ai_target_type?: string | null
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
  scan_role?: 'standalone' | 'parent' | 'shard' | string | null
  parent_scan_id?: string | null
  shard_index?: number | null
  shard_count?: number | null
  shard_rollup?: {
    total: number
    completed: number
    failed: number
    running: number
    pending: number
    terminal: number
    average_progress?: number
    contribution?: {
      assigned_endpoints?: number
      attempted_endpoints?: number
      active_worklist_total?: number
      active_endpoints_selected?: number
      active_endpoint_budget?: number
      active_max_seconds?: number
      duration_seconds?: number
      active_budget_utilization?: number
      attempt_statuses?: Record<string, number>
      by_auth_state?: Record<string, Record<string, number>>
      by_check_family?: Record<string, Record<string, number>>
      shards_with_contribution?: number
      telemetry_shards?: number
    }
  }
  shards?: Array<{
    id: string
    scan_role?: string | null
    shard_index?: number | null
    status: string
    score?: number | null
    grade?: string | null
    findings_count?: number | null
    current_phase?: string | null
    progress?: number | null
    duration_seconds?: number | null
    contribution?: {
      assigned_endpoints?: number
      attempted_endpoints?: number
      attempt_statuses?: Record<string, number>
      active_worklist_total?: number
      active_endpoints_selected?: number
      active_endpoint_budget?: number
      active_max_seconds?: number
      budget_profile?: string
      check_family?: string
      auth_state?: string
      per_endpoint_telemetry?: boolean
    }
  }>
}

export interface ModelIntakeScanRequest {
  artifact_url: string
  name?: string
  metadata_url?: string
  metadata_json?: Record<string, unknown>
  expected_sha256?: string
  signature_url?: string
  signature_public_key?: string
  signature_public_key_url?: string
  signature_value?: string
  signature_rsa_padding?: string
  signature_hash?: string
  signature_payload?: string
  signature_trusted_keys?: string | string[]
  signature_trusted_key_sha256?: string | string[]
  model_card_url?: string
  deployment_approved?: boolean
  require_deployment_approval?: boolean
  require_signature?: boolean
  require_signature_verification?: boolean
  require_hash?: boolean
  require_model_governance?: boolean
  policy_profile?: string
  max_download_bytes?: number
  timeout_seconds?: number
}

export interface ModelIntakeScanResponse {
  scan_id: string
  job_id: string
  status: string
  target: string
  scan_type: 'model_intake'
  run_kind: 'model_intake'
  ui_url: string
}

export type ModelIntakePlatform = 'auto' | 'huggingface' | 'http' | 's3' | 'gcs' | 'azure' | 'oci' | 'mlflow'

export interface ModelIntakeResolveRequest {
  platform: ModelIntakePlatform
  ref: string
  revision?: string
  filename?: string
  metadata_json?: Record<string, unknown>
  timeout_seconds?: number
}

export interface ModelIntakeResolvedFile {
  path: string
  extension?: string
  format_posture?: string
  risk?: 'lower' | 'higher' | string
  size_bytes?: number | null
  sha256?: string | null
  blob_id?: string | null
  score?: number
}

export interface ModelIntakeResolveResponse {
  platform: string
  normalized_ref: string
  repository?: string | null
  revision?: string | null
  selected_file?: ModelIntakeResolvedFile | null
  candidate_files: ModelIntakeResolvedFile[]
  metadata_json: Record<string, unknown>
  warnings: string[]
  scan_payload: ModelIntakeScanRequest | null
}

export interface AITestReadinessControl {
  id: string
  label: string
  applies_to?: 'all' | 'rag' | 'agent' | string
  keys: string[]
}

export interface AITestTargetTemplate {
  key: string
  name: string
  target_type: AITargetType
  endpoint_url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  headers_template: Record<string, unknown>
  request_template: Record<string, unknown>
  response_path?: string | null
  streaming_mode: 'json' | 'sse'
  rate_limit_rps?: number | null
  token_budget?: number | null
  request_budget?: number | null
  metadata_json: Record<string, unknown>
  recommended_scan?: {
    probe_pack: AIProbePack
    scan_profile: AIScanProfile
    environment: AIEnvironment
  }
}

export interface ModelIntakePreset {
  key: string
  name: string
  artifact_url: string
  metadata_url?: string
  metadata_json?: Record<string, unknown>
  expected_sha256?: string
  signature_url?: string
  signature_public_key?: string
  signature_public_key_url?: string
  signature_value?: string
  signature_rsa_padding?: string
  signature_hash?: string
  signature_payload?: string
  signature_trusted_keys?: string | string[]
  signature_trusted_key_sha256?: string | string[]
  model_card_url?: string
  deployment_approved?: boolean
  require_deployment_approval?: boolean
  require_signature?: boolean
  require_signature_verification?: boolean
  require_hash?: boolean
  require_model_governance?: boolean
  policy_profile?: string
  max_download_bytes?: number
  timeout_seconds?: number
  should_pass?: boolean
  expected_findings?: string[]
  expected_min_severity?: string
}

export interface AITestScenario {
  id: 'secure-rag-agent' | 'model-intake-pipeline' | string
  category: 'ai_gate' | 'model_intake' | string
  title: string
  summary: string
  target_templates?: AITestTargetTemplate[]
  request_presets?: ModelIntakePreset[]
  readiness_controls: AITestReadinessControl[]
  test_plan?: Array<Record<string, unknown>>
  acceptance_signals?: string[]
  honey_contract?: {
    registry_url?: string
    required_routes?: string[]
  }
}

export interface AITestScenariosResponse {
  schema_version: string
  scenarios: AITestScenario[]
}

// Compact ASM coverage rollup attached to grouped targets/domains.
export interface AsmCoverageRollup {
  total: number
  tested: number
  untested: number
  testable?: number
  denominator?: number
  denominator_label?: string
  coverage: number
  coverage_basis?: 'attempt_ledger' | 'endpoint_status' | string
  coverage_reconciles?: boolean
  attempted?: number
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
  asm_coverage?: AsmCoverageRollup | null
}

export interface GroupedDomain {
  root_domain: string
  root_target: Target | null
  subdomains: Target[]
  subdomain_count: number
  total_count: number
  asm_coverage?: AsmCoverageRollup | null
}

// Full per-target ASM coverage breakdown (GET /targets/{id}/asm/coverage).
export interface AsmCoverage {
  total: number
  tested: number
  untested: number
  testable?: number
  denominator?: number
  denominator_label?: string
  in_progress: number
  stale: number
  gone: number
  expired_leases?: number
  auth_blocked?: number
  partial?: number
  rate_limited?: number
  error?: number
  attempted?: number
  coverage: number
  coverage_basis?: 'attempt_ledger' | 'endpoint_status' | string
  coverage_reconciles?: boolean
  status_coverage?: Record<string, number | string>
  attempt_coverage?: Record<string, number | string>
  detail?: {
    status_coverage?: Record<string, number | string>
    attempt_coverage?: Record<string, number | string>
  }
}

export interface AsmEndpoint {
  id: string
  method: string
  path: string
  param_shape?: string
  param_location?: 'query' | 'form' | 'json' | 'none'
  replay_spec?: string | null
  content_type?: string | null
  source?: string
  auth_state?: string
  priority_score: number
  test_status: 'untested' | 'in_progress' | 'tested' | 'stale' | 'gone'
  last_attempt_status?: string | null
  last_verdict?: string | null
  first_seen_at?: string
  last_seen_at?: string
  last_tested_at?: string | null
}

export interface AsmRecommendation {
  next_action: 'recon' | 'test' | 'wait'
  label: string
  reason: string
  blockers: Array<{ kind: string; count: number; message: string; scan_id?: string; scan_ids?: string[] }>
}

export interface AsmSchedulerDecision {
  action?: 'recon' | 'test' | 'none' | string
  reason?: string
  blocked_by?: string | null
  next_eligible_at?: string | null
  daily_cap_remaining?: number | null
  rate_cap_remaining?: number | null
  claimable?: number | null
  tested_today?: number | null
  source?: string
  recorded_at?: string
  active_scan_id?: string
  active_scan_ids?: string[]
}

export interface AsmSchedulerState {
  decision?: AsmSchedulerDecision | null
  last_decision?: AsmSchedulerDecision | null
  active_scan_ids?: string[]
  claimable?: number
  tested_today?: number
  daily_cap_remaining?: number | null
  rate_cap_remaining?: number | null
  domain_rate_cap?: number
  domain_rate_used?: number
  domain_rate_reserved?: number
}

export interface AsmFamilyCoverage { completed: number; attempts: number }
export interface AsmRecommendedCampaign {
  campaign: string
  label?: string
  reason: string
  priority: 'high' | 'medium' | 'low' | string
}
export interface AsmGaps {
  coverage: AsmCoverage
  claimable: number
  active_scans: number
  recommendation: AsmRecommendation
  scheduler_state?: AsmSchedulerState
  recommended_campaigns?: AsmRecommendedCampaign[]
  by_auth_state: Record<string, Record<string, number>>
  by_param_location: Record<string, number>
  family_coverage?: Record<string, AsmFamilyCoverage>
  confidence_distribution?: Record<string, { total: number; high_critical: number }>
  stuck_verification?: number
  last_attempt_status: Record<string, number>
  attempt_ledger_status?: Record<string, number>
  sample_gaps: AsmEndpoint[]
}

export interface AsmActivity {
  id: string
  job_id?: string | null
  scan_role: 'asm_batch' | 'asm_recon' | string
  scan_type?: string
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  current_phase?: string | null
  progress?: number | null
  findings_count?: number | null
  score?: number | null
  grade?: string | null
  error_message?: string | null
  created_at: string
  started_at?: string | null
  completed_at?: string | null
  duration_seconds?: number | null
  campaign_id?: string | null
  campaign_mode?: string | null
  campaign_requested_by?: string | null
  campaign_status?: string | null
  campaign_check_families?: string[] | null
  attempt_status_counts?: Record<string, number>
}

export interface AsmActivityResponse {
  activity: AsmActivity[]
  scheduler_state?: AsmSchedulerState
}

export interface AsmActionResponse {
  action: 'recon' | 'test' | 'wait'
  scan_id?: string
  job_id?: string
  campaign_id?: string
  status: string
  batch_size?: number
  check_family?: string
  endpoint_filter?: string | null
  reason?: string
  recommendation?: AsmRecommendation
  scheduler_state?: AsmSchedulerState
}

export interface AsmCheckFamily {
  name: string
  phase: string
  family: string
  label: string
  default_profiles: string[]
  is_active: boolean
  requires_auth_states: boolean
  requires_credentials: boolean
  risk_level: string
  allowed_presets: string[]
  telemetry_schema?: string | null
  runnable: boolean
  description: string
}

export interface AsmCheckFamiliesResponse {
  families: AsmCheckFamily[]
  asm_focus_allowed: string[]
  default: string
}

export interface PrecisionPolicy {
  original_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  original_confidence?: number
  severity_downgraded?: boolean
  confidence_capped?: boolean
  confidence_cap_reason?: string
}

export interface FindingTriage {
  precision_policy?: PrecisionPolicy
  verification_reason?: string
  suspected?: boolean
  needs_verification?: boolean
  verified?: boolean
  confidence?: number
  confidence_tier?: string
}

export function extractFindingTriage(finding: Finding | undefined | null): FindingTriage | null {
  if (!finding) return null
  const evidence = finding.evidence
  if (!evidence || typeof evidence !== 'object') return null
  const triage = (evidence as Record<string, unknown>).triage
  if (!triage || typeof triage !== 'object') return null
  return triage as FindingTriage
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
  ai_target_id?: string | null
  ai_target_url?: string
  ai_target_name?: string
  source?: 'scan' | 'manual' | 'ai_session' | 'ai_gate' | 'model_intake' | 'asm' | string
  evidence?: string | Record<string, unknown>
  request?: string
  response?: string
  ai_verdict?: string
  ai_confidence?: number
  ai_rationale?: string
  ai_recommendations?: string[] | Record<string, unknown> | null
  ai_classification_source?: 'provider' | 'heuristic_fallback' | 'heuristic_only' | string
  analyst_verdict?: 'needs_review' | 'true_positive' | 'false_positive' | 'duplicate' | 'accepted_risk' | 'retest_needed' | string
  analyst_verdict_at?: string
  analyst_verdict_notes?: string
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
  // Single proof-state (docs §7): derived server-side so list and detail agree.
  is_verified?: boolean
  is_suspected?: boolean
  proof_state?: 'verified' | 'suspected' | 'unverified'
  created_at?: string
  updated_at?: string
  // Retest capability hints (populated by GET /findings/{id})
  retest_supported?: boolean
  retest_type?: string | null
  retest_modes?: string[]
  retest_unsupported_reason?: string
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
  retry_class?: string | null
  retryable?: boolean
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
  build_current?: boolean | null
}

export interface WorkerStats {
  count: number
  workers: WorkerInfo[]
  max_allowed: number
  stale_workers?: string[]
  expected_scanner_version?: string
  error?: string
}

export interface SystemResources {
  available: boolean
  cpus?: number
  mem_total_bytes?: number
  operating_system?: string
  os_type?: string
  server_version?: string
  is_desktop_vm?: boolean
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
  auto_fp_on_retest: boolean
  auto_fp_min_confidence: number
  demo_mode_enabled: boolean
  demo_honey_public_url: string
  demo_honey_scanner_url: string
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
  auto_fp_on_retest?: boolean
  auto_fp_min_confidence?: number
  demo_mode_enabled?: boolean
  demo_honey_public_url?: string
  demo_honey_scanner_url?: string
  persist_to_env?: boolean
}

export interface ScanExecutionSettings {
  auto_sharding_enabled: boolean
  auto_sharding_strategy: 'auto' | 'scope' | 'family' | 'coverage' | 'coverage_family'
  auto_sharding_max_shards: number
  auto_sharding_min_workers: number
  eligible_scan_types: string[]
  running_workers?: number | null
}

export interface ScanExecutionSettingsUpdate {
  auto_sharding_enabled?: boolean
  auto_sharding_strategy?: 'auto' | 'scope' | 'family' | 'coverage' | 'coverage_family'
  auto_sharding_max_shards?: number
  auto_sharding_min_workers?: number
}

export interface AsmAutomationConfig {
  batch_size: number
  stale_days: number
  min_interval_minutes: number
  daily_endpoint_cap: number
  recon_interval_hours: number
  exploit_depth: boolean
  window_start_hour: number | null
  window_end_hour: number | null
  window_days: number[] | null
  max_requests_per_hour_per_domain: number
}

export interface AutomationSettings {
  scan_execution: ScanExecutionSettings
  default_continuous_asm: {
    enabled_for_new_web_targets: boolean
    config: AsmAutomationConfig
    active_depth_confirmation_required: boolean
    high_risk_families_require_explicit_request: boolean
    applies_to: string
  }
  safety_boundaries: {
    global_exploit_depth: boolean
    lab_depth_requires_explicit_action: boolean
    planned_high_risk_families_fail_closed: boolean
  }
}

export interface AutomationSettingsUpdate extends ScanExecutionSettingsUpdate {
  default_asm_enabled?: boolean
  default_asm_config?: Partial<AsmAutomationConfig>
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

export type AITargetType = 'api_chat' | 'widget' | 'rag' | 'agent_trace' | 'mcp_trace'
export type AIAuthKind =
  | 'none'
  | 'bearer'
  | 'api_key_header'
  | 'custom_header'
  | 'basic_auth'
  | 'cookie'
  | 'multi_header'
  | 'query_param'
export type AIProbePack =
  | 'shaker-ai-smoke'
  | 'shaker-owasp-llm'
  | 'shaker-agent-abuse'
  | 'shaker-mcp-security'
  | 'shaker-rag-lite'
export type AIScanProfile = 'smoke' | 'trace' | 'standard' | 'deep'
export type AIEnvironment = 'preview' | 'staging' | 'production' | 'development'

export interface AITargetCredential {
  auth_kind: AIAuthKind
  header_name?: string | null
  secret_configured?: boolean
  secret_preview?: string | null
  metadata_json?: Record<string, unknown> | null
}

export interface AITarget {
  id: string
  name: string
  target_type: AITargetType
  endpoint_url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  headers_template: Record<string, string>
  request_template: Record<string, unknown>
  response_path?: string | null
  streaming_mode: 'json' | 'sse'
  rate_limit_rps?: number | null
  token_budget?: number | null
  request_budget?: number | null
  production_mode: boolean
  last_scanned_at?: string | null
  last_scan_id?: string | null
  metadata_json?: Record<string, unknown> | null
  is_active: boolean
  created_at: string
  updated_at: string
  credential: AITargetCredential
}

export type AIPrincipalRole = 'attacker' | 'victim' | 'admin' | 'service' | 'observer'

export interface AITargetPrincipal {
  id: string
  ai_target_id: string
  label: string
  role: AIPrincipalRole
  tenant_id?: string | null
  metadata_json?: Record<string, unknown> | null
  is_active: boolean
  created_at: string
  updated_at: string
  credential: AITargetCredential
}

export interface AITargetPrincipalPayload {
  label: string
  role: AIPrincipalRole
  tenant_id?: string | null
  metadata_json?: Record<string, unknown>
  is_active?: boolean
  credential: {
    auth_kind: AIAuthKind
    header_name?: string | null
    secret?: string | null
    metadata_json?: Record<string, unknown> | null
  }
}

export interface AITargetPayload {
  name?: string
  target_type: AITargetType
  endpoint_url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  headers_template: Record<string, unknown>
  request_template: Record<string, unknown>
  response_path?: string | null
  streaming_mode: 'json' | 'sse'
  rate_limit_rps?: number | null
  token_budget?: number | null
  request_budget?: number | null
  production_mode?: boolean
  metadata_json?: Record<string, unknown>
  credential: {
    auth_kind: AIAuthKind
    header_name?: string | null
    secret?: string | null
    metadata_json?: Record<string, unknown> | null
  }
}

export type ExposureNodeType =
  | 'domain'
  | 'web_target'
  | 'model_artifact'
  | 'model_supply_chain'
  | 'endpoint'
  | 'api_surface'
  | 'auth_role'
  | 'third_party_js'
  | 'cloud_hint'
  | 'ai_target'
  | 'mcp_tool'
  | 'scan'
  | 'finding'
  | 'finding_group'
  | 'vendor'
  | 'attack_chain'

export interface ExposureMetrics {
  asset_count: number
  web_targets: number
  model_artifacts?: number
  ai_surfaces: number
  active_critical: number
  active_high: number
  attack_chains: number
  public_assets?: number
  internal_assets?: number
  unscanned_assets?: number
  stale_assets?: number
  incomplete_scans?: number
  needs_action?: number
  prod_ai_surfaces?: number
  high_blast_ai_surfaces?: number
}

export interface ExposureSearchNode {
  id: string
  type: ExposureNodeType
  label: string
  severity?: string | null
}

export type ExposureAssetKind = 'web' | 'ai' | 'model'

export interface ExposureAsset {
  id: string
  node_id: string
  kind: ExposureAssetKind
  label: string
  url?: string | null
  root_domain?: string | null
  origin?: string | null
  exposure_class?: 'public' | 'internal' | 'supply_chain' | 'unknown' | string | null
  owner?: string | null
  environment?: string | null
  target_type?: string | null
  production_mode?: boolean
  blast_radius_score?: number | null
  blast_radius_tier?: string | null
  blast_radius_factors?: string[]
  data_classification?: string | null
  risk_tier?: string | null
  missing_runtime_controls?: string[]
  grade?: string | null
  score?: number | null
  active_total: number
  active_critical: number
  active_high: number
  active_verified?: number
  active_needs_verification?: number
  total_scans?: number
  last_scanned_at?: string | null
  latest_scan_id?: string | null
  latest_scan_status?: string | null
  latest_scan_type?: string | null
  latest_scan_href?: string | null
  scan_complete?: boolean | null
  scan_limited?: boolean
  coverage_status?: string | null
  coverage_posture?: 'fresh' | 'limited' | 'failed' | 'stale' | 'unscanned' | string | null
  skipped_modules_count?: number
  capped_lists_count?: number
  scan_age_days?: number | null
  action_reasons?: string[]
  needs_action?: boolean
  action_priority?: 'P1' | 'P2' | 'P3' | null
  action_score?: number
  recommended_actions?: Array<{ label: string; kind: 'scan' | 'findings' | 'latest_scan' | 'map' | 'none' | string }>
  first_seen_at?: string | null
  is_new: boolean
  risk_score: number
  findings_href: string
}

export interface ExposureAssetMetrics {
  asset_count: number
  active_critical: number
  active_high: number
  active_verified?: number
  active_needs_verification?: number
  ai_surfaces: number
  web_targets?: number
  model_artifacts?: number
  public_assets?: number
  internal_assets?: number
  unscanned_assets?: number
  stale_assets?: number
  incomplete_scans?: number
  failed_scans?: number
  fresh_scans?: number
  verified_assets?: number
  unverified_high_assets?: number
  unowned_assets?: number
  needs_action?: number
  p1_count?: number
  p2_count?: number
  p3_count?: number
  prod_ai_surfaces?: number
  high_blast_ai_surfaces?: number
}

export interface ExposureAssetsResponse {
  assets: ExposureAsset[]
  count: number
  total?: number
  offset?: number
  new_count: number
  metrics: ExposureAssetMetrics
}

export interface ExposureAttackStep {
  step_number?: number | null
  description?: string | null
  impact?: string | null
  finding_type?: string | null
  finding_id?: string | null
  finding_title?: string | null
  evidence?: unknown
}

export interface ExposureAttackPath {
  id: string
  name: string
  chain_type?: string | null
  severity?: string | null
  status?: string | null
  confidence?: number | null
  completeness?: number | null
  business_impact?: string | null
  description?: string | null
  remediation?: string | string[] | null
  missing_required?: string[]
  steps: ExposureAttackStep[]
  asset_label?: string | null
  asset_node_id?: string | null
  scan_id: string
  scan_href: string
  findings_href?: string | null
}

export interface ExposureAttackPathsResponse {
  attack_paths: ExposureAttackPath[]
  count: number
}

export interface ExposureNode {
  id: string
  type: ExposureNodeType
  label: string
  subtitle?: string | null
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | string | null
  status?: string | null
  href?: string | null
  meta: Record<string, unknown>
}

export interface ExposureEdge {
  source: string
  target: string
  type: string
  label: string
  severity?: string | null
  meta: Record<string, unknown>
}

export interface ExposureGraph {
  nodes: ExposureNode[]
  edges: ExposureEdge[]
  summary: {
    node_count: number
    edge_count: number
    node_type_counts: Record<string, number>
    severity_counts: Record<string, number>
    hotspots: ExposureNode[]
    rendered_node_count?: number
    rendered_edge_count?: number
    truncated?: boolean
    focus?: string | null
    include_endpoints?: boolean
    metrics?: ExposureMetrics
  }
}

// Dashboard
export async function getDashboard(): Promise<DashboardResponse> {
  const res = await fetch(`${API_URL}/dashboard`)
  if (!res.ok) throw new Error('Failed to fetch dashboard')
  return res.json()
}

export async function getExposureGraph(params?: {
  root_domain?: string
  includeInactive?: boolean
  includeResolved?: boolean
  limitFindings?: number
  limitScans?: number
  focus?: string | null
  depth?: number
  includeEndpoints?: boolean
}): Promise<ExposureGraph> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.includeInactive) searchParams.set('include_inactive', 'true')
  if (params?.includeResolved) searchParams.set('include_resolved', 'true')
  if (params?.limitFindings) searchParams.set('limit_findings', String(params.limitFindings))
  if (params?.limitScans) searchParams.set('limit_scans', String(params.limitScans))
  if (params?.focus) searchParams.set('focus', params.focus)
  if (params?.depth) searchParams.set('depth', String(params.depth))
  if (params?.includeEndpoints) searchParams.set('include_endpoints', 'true')

  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/exposure/graph${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch exposure graph'))
  return res.json()
}

export async function getExposureNodes(params?: {
  root_domain?: string
  includeResolved?: boolean
}): Promise<{ nodes: ExposureSearchNode[]; count: number }> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.includeResolved) searchParams.set('include_resolved', 'true')
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/exposure/nodes${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch exposure nodes'))
  return res.json()
}

export async function getExposureAssets(params?: {
  root_domain?: string
  kind?: ExposureAssetKind
}): Promise<ExposureAssetsResponse> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.kind) searchParams.set('kind', params.kind)
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/exposure/assets${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch exposure assets'))
  return res.json()
}

export interface ExposureChangeExample {
  label: string
  detail?: string | null
  when?: string | null
}

export interface ExposureChangeCategory {
  key: string
  label: string
  count: number
  href?: string | null
  examples: ExposureChangeExample[]
}

export interface ExposureChangesResponse {
  since: string
  total_changes: number
  categories: ExposureChangeCategory[]
}

// Re-run the most recent model intake scan for a model target (same policy
// profile, metadata, and requirement options it was last evaluated with).
export async function rescanModelIntakeTarget(targetId: string): Promise<{
  scan_id: string
  job_id: string
  status: string
  ui_url?: string
}> {
  const res = await fetch(`${API_URL}/model-intake/targets/${targetId}/rescan`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to queue model intake re-check'))
  return res.json()
}

// Ownership/accountability fields stored in targets.metadata_json. The API
// merges keys into the existing metadata; send "" to clear a key.
export async function updateTargetMetadata(
  targetId: string,
  metadata: Record<string, string>
): Promise<{ id: string; status: string }> {
  const res = await fetch(`${API_URL}/targets/${targetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ metadata_json: metadata }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to update target metadata'))
  return res.json()
}

export async function getExposureChanges(params?: {
  root_domain?: string
  since?: string
  days?: number
}): Promise<ExposureChangesResponse> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.since) searchParams.set('since', params.since)
  if (params?.days) searchParams.set('days', String(params.days))
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/exposure/changes${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch exposure changes'))
  return res.json()
}

export async function getExposureAttackPaths(params?: {
  root_domain?: string
}): Promise<ExposureAttackPathsResponse> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/exposure/attack-paths${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch attack paths'))
  return res.json()
}

// Scans
export async function getScans(params?: {
  status?: string
  limit?: number
  offset?: number
  root_domain?: string
  target?: string
  created_within_days?: number
  include_shards?: boolean
  include_internal?: boolean
}): Promise<{ scans: Scan[]; total: number; limit: number; offset: number }> {
  const searchParams = new URLSearchParams()
  if (params?.status) searchParams.set('status', params.status)
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  if (params?.offset) searchParams.set('offset', params.offset.toString())
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.target) searchParams.set('target', params.target)
  if (params?.created_within_days) searchParams.set('created_within_days', params.created_within_days.toString())
  if (params?.include_shards) searchParams.set('include_shards', 'true')
  if (params?.include_internal) searchParams.set('include_internal', 'true')

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

export async function submitScan(target: string, options: Record<string, unknown> = {}) {
  const res = await fetch(`${API_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, options })
  })
  if (!res.ok) throw new Error('Failed to submit scan')
  return res.json()
}

export async function submitModelIntakeScan(data: ModelIntakeScanRequest): Promise<ModelIntakeScanResponse> {
  const res = await fetch(`${API_URL}/model-intake/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to submit model intake scan'))
  }
  return res.json()
}

export async function resolveModelIntakeReference(data: ModelIntakeResolveRequest): Promise<ModelIntakeResolveResponse> {
  const res = await fetch(`${API_URL}/model-intake/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to resolve model reference'))
  }
  return res.json()
}

export async function getAITestScenarios(params?: { includeDemo?: boolean }): Promise<AITestScenariosResponse> {
  const searchParams = new URLSearchParams()
  if (params?.includeDemo) searchParams.set('include_demo', 'true')
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/ai/test-scenarios${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch AI test scenarios'))
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

// Continuous ASM — persistent attack-surface inventory (docs/parallel-scan-architecture.md §16)
export async function getAsmCoverage(targetId: string): Promise<AsmCoverage> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/coverage`)
  if (!res.ok) throw new Error('Failed to fetch ASM coverage')
  return res.json()
}

export async function getAsmEndpoints(
  targetId: string,
  params?: { status?: string; limit?: number; offset?: number }
): Promise<{ endpoints: AsmEndpoint[]; coverage: AsmCoverage }> {
  const searchParams = new URLSearchParams()
  if (params?.status) searchParams.set('status', params.status)
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  if (params?.offset) searchParams.set('offset', params.offset.toString())

  const res = await fetch(`${API_URL}/targets/${targetId}/asm/endpoints?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch ASM endpoints')
  return res.json()
}

export async function getAsmCheckFamilies(): Promise<AsmCheckFamiliesResponse> {
  const res = await fetch(`${API_URL}/asm/check-families`)
  if (!res.ok) throw new Error('Failed to fetch ASM check families')
  return res.json()
}

export async function testAsmTarget(
  targetId: string,
  opts?: { batch_size?: number; stale_days?: number; exploit_depth?: boolean; check_family?: string; endpoint_filter?: string }
): Promise<{
  scan_id: string
  job_id: string
  status: string
  batch_size: number
  check_family?: string
  endpoint_filter?: string | null
  inventory_total: number
  untested: number
}> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(opts || {}),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => null)
    throw new Error(detail?.detail || 'Failed to queue ASM test batch')
  }
  return res.json()
}

export async function reconAsmTarget(
  targetId: string,
  opts?: { budget_profile?: string }
): Promise<AsmActionResponse> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(opts || {}),
  })
  if (!res.ok) {
    const msg = await getApiErrorMessage(res, 'Failed to queue ASM recon')
    throw new Error(msg)
  }
  return res.json()
}

export async function improveAsmTarget(
  targetId: string,
  opts?: { batch_size?: number; stale_days?: number; exploit_depth?: boolean; check_family?: string; endpoint_filter?: string }
): Promise<AsmActionResponse> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/improve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(opts || {}),
  })
  if (!res.ok) {
    const msg = await getApiErrorMessage(res, 'Failed to improve ASM coverage')
    throw new Error(msg)
  }
  return res.json()
}

// Continuous ASM policy (docs §16 Phase 3/4)
export interface AsmConfig {
  batch_size: number
  stale_days: number
  min_interval_minutes: number
  daily_endpoint_cap: number
  recon_interval_hours: number
  exploit_depth: boolean
  window_start_hour: number | null
  window_end_hour: number | null
  window_days: number[] | null
  max_requests_per_hour_per_domain: number
}

export interface AsmPolicy {
  enabled: boolean
  config: AsmConfig
  last_test_at: string | null
  last_recon_at: string | null
  scheduler_state?: AsmSchedulerState
}

export async function getAsmPolicy(targetId: string): Promise<AsmPolicy> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/policy`)
  if (!res.ok) throw new Error('Failed to fetch ASM policy')
  return res.json()
}

export async function updateAsmPolicy(
  targetId: string,
  body: { enabled?: boolean; config?: Partial<AsmConfig> }
): Promise<AsmPolicy> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => null)
    throw new Error(detail?.detail || 'Failed to update ASM policy')
  }
  return res.json()
}

export async function getAsmDiff(
  targetId: string,
  params?: { days?: number; limit?: number }
): Promise<{ days: number; total_new: number; endpoints: AsmEndpoint[] }> {
  const searchParams = new URLSearchParams()
  if (params?.days) searchParams.set('days', params.days.toString())
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/diff?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch ASM diff')
  return res.json()
}

export async function getAsmGaps(targetId: string): Promise<AsmGaps> {
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/gaps`)
  if (!res.ok) throw new Error('Failed to fetch ASM gaps')
  return res.json()
}

export async function getAsmActivity(
  targetId: string,
  params?: { limit?: number }
): Promise<AsmActivityResponse> {
  const searchParams = new URLSearchParams()
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  const res = await fetch(`${API_URL}/targets/${targetId}/asm/activity?${searchParams}`)
  if (!res.ok) throw new Error('Failed to fetch ASM activity')
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

export async function scanTarget(targetId: string, options: Record<string, unknown> = {}) {
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
  source_type?: 'dast' | 'ai' | 'ai_gate' | 'ai_session' | 'model_intake' | 'asm' | 'manual'
  limit?: number
  offset?: number
  root_domain?: string
  scan_id?: string
  target_id?: string
  ai_target_id?: string
  search?: string
  seen_within_days?: number
  first_seen_within_days?: number
  resolved_within_days?: number
  verification_verdict?: 'exploited' | 'likely_vulnerable' | 'blocked_by_security' | 'out_of_scope_internal' | 'false_positive' | 'likely_fixed' | 'inconclusive' | 'error'
  verification_mode?: 'deterministic' | 'ai_driven'
  verified_only?: boolean
  sort_by?: 'severity' | 'first_seen' | 'last_seen' | 'cvss'
  sort_order?: 'asc' | 'desc'
}): Promise<{ findings: Finding[]; total: number; limit: number; offset: number }> {
  const searchParams = new URLSearchParams()
  if (params?.severity) searchParams.set('severity', params.severity)
  if (params?.status) searchParams.set('status', params.status)
  if (params?.source_type) searchParams.set('source_type', params.source_type)
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  if (params?.offset) searchParams.set('offset', params.offset.toString())
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.scan_id) searchParams.set('scan_id', params.scan_id)
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  if (params?.ai_target_id) searchParams.set('ai_target_id', params.ai_target_id)
  if (params?.search) searchParams.set('search', params.search)
  if (params?.seen_within_days) searchParams.set('seen_within_days', params.seen_within_days.toString())
  if (params?.first_seen_within_days) searchParams.set('first_seen_within_days', params.first_seen_within_days.toString())
  if (params?.resolved_within_days) searchParams.set('resolved_within_days', params.resolved_within_days.toString())
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

export interface EvidenceObject {
  id: string
  scan_id?: string
  finding_id?: string
  object_type: string
  content_sha256?: string
  size_bytes?: number
  storage_uri?: string
  redaction_profile?: string
  retention_class?: string
  content?: unknown
  created_at?: string
}

// Durable, first-class evidence objects (hash / redaction profile / retention class /
// storage URI) for a finding — distinct from the embedded `finding.evidence` blob.
export async function getFindingEvidence(
  id: string
): Promise<{ finding_id: string; evidence_objects: EvidenceObject[] }> {
  const res = await fetch(`${API_URL}/findings/${id}/evidence`)
  if (!res.ok) throw new Error('Failed to fetch finding evidence objects')
  return res.json()
}

export interface ApplicationGraphNode {
  id: string
  node_type: string
  node_key: string
  label?: string
  attributes?: Record<string, unknown>
  scan_id?: string
  first_seen_at?: string
  last_seen_at?: string
}

export interface ApplicationGraphEdge {
  id: string
  src_key: string
  dst_key: string
  edge_type: string
  attributes?: Record<string, unknown>
  scan_id?: string
  first_seen_at?: string
  last_seen_at?: string
}

export interface ApplicationGraph {
  target_id: string
  nodes: ApplicationGraphNode[]
  edges: ApplicationGraphEdge[]
  summary: {
    node_count: number
    edge_count: number
    by_node_type: Record<string, number>
    by_edge_type: Record<string, number>
  }
}

// First-class application graph for a target: routes, objects, and
// producer/consumer/auth-boundary edges persisted from scans.
export async function getApplicationGraph(targetId: string): Promise<ApplicationGraph> {
  const res = await fetch(`${API_URL}/targets/${targetId}/graph`)
  if (!res.ok) throw new Error('Failed to fetch application graph')
  return res.json()
}

export interface DeploymentBlockingFinding {
  id?: string
  fingerprint?: string
  title?: string
  severity?: string
  tool?: string
  url?: string
  // True when the finding is an unresolved active critical/high on the target from a
  // prior scan (not necessarily re-detected by this scan) — surfaced so the gate's
  // "block" decision is explainable.
  from_target_active?: boolean
}

export interface DeploymentDecision {
  decision?: string
  deploy_decision?: string
  policy_profile?: string
  policy_name?: string
  rationale?: string
  reason?: string
  blocking_findings?: DeploymentBlockingFinding[]
  exceptions_applied?: unknown[]
  expires_at?: string
  [key: string]: unknown
}

export async function getScanDeploymentDecision(scanId: string): Promise<DeploymentDecision> {
  const res = await fetch(`${API_URL}/scans/${scanId}/deployment-decision`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch deployment decision'))
  return res.json()
}

export interface PolicyProfile {
  id: string
  name: string
  product_area: string
  environment: string
  minimum_block_severity: string
  expires_days: number
  strict_model_intake: boolean
  allow_active_exceptions: boolean
  owner?: string | null
  version?: string | null
  is_active: boolean
  created_at?: string
  updated_at?: string
}

export interface PolicyProfilePayload {
  name: string
  product_area: string
  environment: string
  minimum_block_severity: string
  expires_days: number
  strict_model_intake: boolean
  allow_active_exceptions: boolean
  owner?: string | null
  version?: string | null
  is_active: boolean
}

export async function getPolicyProfiles(): Promise<{ policy_profiles: PolicyProfile[] }> {
  const res = await fetch(`${API_URL}/policy-profiles`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch policy profiles'))
  return res.json()
}

export async function createPolicyProfile(data: PolicyProfilePayload): Promise<PolicyProfile> {
  const res = await fetch(`${API_URL}/policy-profiles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create policy profile'))
  return res.json()
}

export async function updatePolicyProfile(id: string, data: PolicyProfilePayload): Promise<PolicyProfile> {
  const res = await fetch(`${API_URL}/policy-profiles/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to update policy profile'))
  return res.json()
}

export async function deletePolicyProfile(id: string): Promise<{ deleted: boolean; id: string }> {
  const res = await fetch(`${API_URL}/policy-profiles/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to delete policy profile'))
  return res.json()
}

export interface FindingException {
  id: string
  finding_id?: string | null
  fingerprint?: string | null
  policy_id?: string | null
  target_id?: string | null
  scope?: string | null
  owner?: string | null
  approver?: string | null
  reason?: string | null
  compensating_controls?: string | null
  status: string
  expires_at?: string | null
  created_at?: string
  updated_at?: string
}

export interface FindingExceptionPayload {
  finding_id?: string | null
  fingerprint?: string | null
  policy_id?: string | null
  target_id?: string | null
  scope?: string | null
  owner?: string | null
  approver?: string | null
  reason?: string | null
  compensating_controls?: string | null
  status: string
  expires_at?: string | null
}

export async function getFindingExceptions(params?: {
  target_id?: string
  status?: string
  queue_filter?: 'expired' | 'expiring' | 'missing_owner' | 'missing_approver' | 'missing_controls' | 'policy_scoped' | 'target_scoped'
  expiring_within_days?: number
  limit?: number
}): Promise<{ finding_exceptions: FindingException[] }> {
  const searchParams = new URLSearchParams()
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  if (params?.status) searchParams.set('status', params.status)
  if (params?.queue_filter) searchParams.set('queue_filter', params.queue_filter)
  if (params?.expiring_within_days) searchParams.set('expiring_within_days', params.expiring_within_days.toString())
  if (params?.limit) searchParams.set('limit', params.limit.toString())
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/finding-exceptions${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch finding exceptions'))
  return res.json()
}

export async function createFindingException(data: FindingExceptionPayload): Promise<FindingException> {
  const res = await fetch(`${API_URL}/finding-exceptions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create finding exception'))
  return res.json()
}

export async function updateFindingException(id: string, data: FindingExceptionPayload): Promise<FindingException> {
  const res = await fetch(`${API_URL}/finding-exceptions/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to update finding exception'))
  return res.json()
}

export async function deleteFindingException(id: string): Promise<{ deleted: boolean; id: string }> {
  const res = await fetch(`${API_URL}/finding-exceptions/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to delete finding exception'))
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

export async function retestAiFinding(
  id: string,
  params: {
    mode?: 'same_probe' | 'same_family' | 'strict_replay'
    requested_by?: string
    confirm_production?: boolean
  } = {}
): Promise<{
  retest_id: string
  job_id: string
  scan_id: string
  status: string
  mode?: string
  finding_id: string
  finding_type: string
  target_url: string
  probe_id?: string
  probe_family?: string
  ui_url?: string
}> {
  const res = await fetch(`${API_URL}/ai/findings/${id}/retest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to queue AI Gate replay'))
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

export async function updateFinding(
  id: string,
  status: string,
  notes?: string,
  scanId?: string,
  analystVerdict?: string
) {
  const url = scanId
    ? `${API_URL}/findings/${id}?scan_id=${scanId}`
    : `${API_URL}/findings/${id}`
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, notes, analyst_verdict: analystVerdict })
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

export async function getScanExecutionSettings(): Promise<ScanExecutionSettings> {
  const res = await fetch(`${API_URL}/settings/scan-execution`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to fetch scan execution settings'))
  }
  return res.json()
}

export async function updateScanExecutionSettings(data: ScanExecutionSettingsUpdate): Promise<{
  status: string
  settings: ScanExecutionSettings
}> {
  const res = await fetch(`${API_URL}/settings/scan-execution`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to update scan execution settings'))
  }
  return res.json()
}

export async function getAutomationSettings(): Promise<AutomationSettings> {
  const res = await fetch(`${API_URL}/settings/automation`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to fetch automation settings'))
  }
  return res.json()
}

export async function updateAutomationSettings(data: AutomationSettingsUpdate): Promise<{
  status: string
  settings: AutomationSettings
}> {
  const res = await fetch(`${API_URL}/settings/automation`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to update automation settings'))
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

export async function getAITargets(params?: {
  includeInactive?: boolean
  includeDemo?: boolean
  limit?: number
  offset?: number
}): Promise<{ targets: AITarget[]; total: number; limit: number; offset: number }> {
  const searchParams = new URLSearchParams()
  if (params?.includeInactive) searchParams.set('include_inactive', 'true')
  if (params?.includeDemo) searchParams.set('include_demo', 'true')
  if (params?.limit) searchParams.set('limit', String(params.limit))
  if (params?.offset) searchParams.set('offset', String(params.offset))
  const res = await fetch(`${API_URL}/ai/targets?${searchParams}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch AI targets'))
  return res.json()
}

export interface AIDemoRunResponse {
  run_id: string
  honey_registry_url: string
  queued: Array<{
    scenario_id: string
    name: string
    surface: string
    safe_fixture: boolean
    expected_findings: string[]
    target_id: string
    scan_id: string
    ui_url: string
    probe_pack: AIProbePack
    scan_profile: AIScanProfile
  }>
  failed?: Array<{
    scenario_id: string
    name?: string
    target_id?: string | null
    error: string
  }>
}

export async function runAIDemo(data?: {
  scenario_ids?: string[]
  scan_profile?: AIScanProfile
  request_budget?: number
}): Promise<AIDemoRunResponse> {
  const res = await fetch(`${API_URL}/ai/demo/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {}),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to queue AI demo'))
  return res.json()
}

export async function createAITarget(data: AITargetPayload): Promise<{ target: AITarget }> {
  const res = await fetch(`${API_URL}/ai/targets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create AI target'))
  return res.json()
}

export async function updateAITarget(
  id: string,
  data: Partial<AITargetPayload> & { is_active?: boolean }
): Promise<{ target: AITarget }> {
  const res = await fetch(`${API_URL}/ai/targets/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to update AI target'))
  return res.json()
}

export async function deleteAITarget(id: string): Promise<{ status: string; target_id: string }> {
  const res = await fetch(`${API_URL}/ai/targets/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to delete AI target'))
  return res.json()
}

export async function getAITargetPrincipals(id: string): Promise<{ target_id: string; principals: AITargetPrincipal[] }> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/principals`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch AI target principals'))
  return res.json()
}

export async function createAITargetPrincipal(
  id: string,
  data: AITargetPrincipalPayload
): Promise<{ principal: AITargetPrincipal }> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/principals`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create AI target principal'))
  return res.json()
}

export async function deleteAITargetPrincipal(
  targetId: string,
  principalId: string
): Promise<{ status: string; target_id: string; principal_id: string }> {
  const res = await fetch(`${API_URL}/ai/targets/${targetId}/principals/${principalId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to delete AI target principal'))
  return res.json()
}

export interface AITargetConnectivityResult {
  target_id: string
  target_name?: string
  target_type?: string
  ok: boolean
  supported?: boolean
  stage?: string
  error?: string
  status_code?: number
  latency_ms?: number
  content_type?: string
  response_path?: string | null
  response_path_ok?: boolean
  request?: {
    method?: string
    url?: string
    headers?: Record<string, string>
    body?: unknown
  }
  response?: {
    excerpt?: string
    extracted_text?: string
  }
}

export async function testAITargetConnectivity(id: string, prompt?: string): Promise<AITargetConnectivityResult> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(prompt ? { prompt } : {}),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to test AI target'))
  return res.json()
}

export interface AIMCPLiveReadinessResult {
  target_id: string
  target_name?: string
  target_type?: string
  ok: boolean
  supported?: boolean
  stage?: string
  error?: string
  summary?: {
    checks: number
    passed: number
    warnings: number
  }
  checks?: Array<{
    id: string
    label: string
    status: 'pass' | 'warn' | string
    evidence?: string
  }>
}

export async function testMCPReadiness(id: string): Promise<AIMCPLiveReadinessResult> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/mcp/live-readiness`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to test MCP readiness'))
  return res.json()
}

export interface AIInventoryCandidate {
  candidate_id: string
  source: string
  scan_id?: string
  target_url?: string
  target_type: AITargetType
  endpoint_url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | string
  confidence: number
  evidence: string[]
  suggested_target: AITargetPayload
}

export interface AIInventoryAsset {
  id: string
  kind: 'saved_ai_target' | 'model_artifact' | string
  name?: string | null
  target_type: AITargetType | 'model_artifact' | string
  endpoint_url?: string | null
  method?: string | null
  owner?: string | null
  risk_tier?: string | null
  data_classification?: string | null
  production_mode?: boolean
  last_scanned_at?: string | null
  tools?: unknown[]
  scopes?: unknown[]
  blast_radius?: {
    score?: number
    tier?: string
    factors?: string[]
    missing_runtime_controls?: string[]
    active_findings?: number
  }
}

export interface AIInventory {
  generated_at: string
  assets: AIInventoryAsset[]
  candidates: AIInventoryCandidate[]
  summary: {
    asset_count: number
    saved_ai_targets: number
    model_artifacts: number
    candidate_count: number
    by_type: Record<string, number>
    highest_blast_radius_score: number
    coverage_gaps: string[]
  }
}

export async function getAIInventory(): Promise<AIInventory> {
  const res = await fetch(`${API_URL}/ai/inventory`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch AI inventory'))
  return res.json()
}

export async function scanAITarget(
  id: string,
  data: {
    probe_pack: AIProbePack
    scan_profile: AIScanProfile
    environment: AIEnvironment
    confirm_production?: boolean
  }
): Promise<{
  scan_id: string
  job_id: string
  status: 'queued'
  target: string
  run_kind: string
  ai_target_id: string
  probe_pack: string
  scan_profile: string
}> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to queue AI Gate scan'))
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

export async function getSystemResources(): Promise<SystemResources> {
  const res = await fetch(`${API_URL}/system/resources`)
  if (!res.ok) throw new Error('Failed to fetch system resources')
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

// Utilities — color maps live in constants.ts as the single source of truth.
export function getSeverityColor(severity: string): string {
  return SEVERITY_TEXT_COLORS[severity as SeverityLevel] ?? SEVERITY_TEXT_COLORS.info
}

export function getSeverityBg(severity: string): string {
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

export function getGradeColor(grade: string): string {
  return gradeTextColorClass(grade)
}

export function formatDate(date: string): string {
  return new Date(date).toLocaleString()
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}
