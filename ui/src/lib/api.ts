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
    // Structured errors raised as { detail: { error, message, reason, ... } }.
    if (detail && typeof detail === 'object') {
      if (typeof detail.message === 'string') return detail.message
      if (typeof detail.reason === 'string') return detail.reason
      if (typeof detail.error === 'string') return detail.error
    }
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

export interface DashboardActionLink {
  label: string
  href: string
  variant?: 'primary' | 'secondary' | string
}

export interface DashboardActionItem {
  id: string
  priority: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  category: string
  title: string
  detail: string
  href?: string | null
  action_label?: string | null
  actions?: DashboardActionLink[]
  count?: number | null
  samples?: DashboardActionSample[]
  metadata?: Record<string, unknown>
}

export interface DashboardProductStatusItem {
  id: string
  label: string
  status: 'critical' | 'warning' | 'ok' | 'info' | string
  summary: string
  href: string
  primary_count?: number | null
  primary_label?: string | null
  secondary_count?: number | null
  secondary_label?: string | null
  actions?: DashboardActionLink[]
  metadata?: Record<string, unknown>
}

export interface DashboardResponse {
  metrics: DashboardMetrics
  recent_scans: Scan[]
  recent_findings: Finding[]
  action_center?: DashboardActionItem[]
  product_status?: DashboardProductStatusItem[]
}

export interface ArsenalCommand {
  name: string
  family: string
  description: string
  status: string
  risk_tier: string
  method: string
  path: string
  scope_fields: string[]
  parameters_schema?: Record<string, unknown>
  required_confirmations: string[]
  required_capabilities: string[]
  evidence_contract: string[]
  redaction_contract: string[]
  timeout_seconds: number
}

export interface ArsenalCommandsResponse {
  schema_version: string
  maturity: string
  execution_enabled: boolean
  status_labels: string[]
  risk_tiers: string[]
  commands: ArsenalCommand[]
  result_schema: Record<string, unknown>
}

export interface ArsenalContractDefinition {
  status: string
  description: string
  required?: string[]
  fields?: Record<string, unknown>
  invariants?: string[]
  forbidden_fields?: string[]
}

export interface ArsenalContractsResponse {
  schema_version: string
  maturity: string
  execution_enabled: boolean
  secret_policy: {
    default: string
    never_inline: string[]
    allowed_refs: string[]
  }
  contract_names: string[]
  contracts: Record<string, ArsenalContractDefinition>
}

export interface ScopeCheck {
  name: string
  status: string
  message: string
}

export interface ScopeReceiptPreview {
  receipt_id: string
  input_scope: Record<string, unknown>
  normalized_scope: Record<string, unknown>
  verdict: string
  checks: ScopeCheck[]
  blocked_by: string[]
  warnings: string[]
  environment: string
  allowed_hosts: string[]
  allowed_root_domains: string[]
  redirect_destinations: Array<Record<string, unknown>>
}

export interface ScopePreviewResponse {
  scope_receipt: ScopeReceiptPreview
  persisted: boolean
  execution_enabled: boolean
}

export interface ApprovalReceipt {
  id: string
  scope_receipt_id: string
  risk_tier: string
  confirmations: string[]
  approved_by?: string | null
  denial_reason?: string | null
  expires_at?: string | null
  action_name?: string | null
  action_context?: Record<string, unknown> | null
  created_at?: string
}

export interface ApprovalReceiptResponse {
  approval_receipt: ApprovalReceipt
  scope_receipt: ScopeReceiptPreview
  execution_enabled: boolean
}

export interface OperationPlanAction {
  command: string
  parameters?: Record<string, unknown>
  risk_tier?: string
  scope_receipt_id?: string
  approval_receipt_id?: string
  reason?: string
}

export interface OperationPlanRequest {
  objective: string
  planner?: Record<string, unknown>
  context_hash: string
  target_scope?: Record<string, unknown>
  risk_tier: string
  allowed_families?: string[]
  disallowed_families?: string[]
  budget?: Record<string, unknown>
  constraints?: Record<string, unknown>
  missing_inputs?: string[]
  confirmations?: string[]
  actions?: OperationPlanAction[]
  stop_conditions?: string[]
  success_criteria?: string[]
  scope_receipt_id?: string
  approval_receipt_id?: string
  created_by?: string
}

export interface OperationPlan {
  id: string
  objective: string
  planner: Record<string, unknown>
  context_hash: string
  target_scope: Record<string, unknown>
  risk_tier: string
  actions: OperationPlanAction[]
  confirmations: string[]
  missing_inputs: string[]
  stop_conditions: string[]
  success_criteria: string[]
  status: string
  validation_errors: string[]
  validation_warnings: string[]
  scope_receipt_id?: string | null
  approval_receipt_id?: string | null
  campaign_id?: string | null
  plan_json: Record<string, unknown>
  created_by?: string | null
  created_at?: string
  updated_at?: string
  execution_enabled: boolean
}

export interface OperationPlanResponse {
  operation_plan: OperationPlan
  execution_enabled: boolean
  validated: boolean
}

export interface ResearchBudget {
  steps: number
  actions: number
  active_actions: number
  requests: number
  seconds: number
  model_tokens: number
}

export interface ResearchEpisode {
  id: string
  target_id: string
  campaign_id?: string | null
  objective: string
  episode_version: string
  planner: Record<string, unknown>
  mission_profile?: string
  subject?: { type?: string; id?: string; title?: string; family?: string }
  allowed_commands?: string[]
  execution_mode: 'shadow' | 'read_only' | 'gated'
  status: string
  version: number
  max_risk_tier: string
  allowed_families: string[]
  budget_limits: ResearchBudget
  budget_used: ResearchBudget
  remaining_budget: ResearchBudget
  scope_receipt_id?: string | null
  approval_receipt_id?: string | null
  current_observation_id?: string | null
  current_decision_id?: string | null
  step_count: number
  cancel_requested: boolean
  autopilot_enabled: boolean
  autopilot_error?: string | null
  autopilot_consecutive_failures: number
  stop_reason?: string | null
  requested_input?: string | null
  terminal: boolean
  execution_enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface ResearchCommandProjection {
  name: string
  status: string
  risk_tier: string
  description?: string
  parameters_schema: Record<string, unknown>
  required_confirmations: string[]
  proposable: boolean
  currently_executable: boolean
  blocked_by: string[]
}

export interface ResearchObservation {
  id: string
  episode_id: string
  sequence: number
  observation_version: string
  context_hash: string
  observation_pack: {
    objective?: string
    execution_mode?: string
    mission?: Record<string, unknown>
    focus?: Record<string, unknown>
    current_gaps?: Array<Record<string, unknown>>
    hypotheses_summary?: Array<Record<string, unknown>>
    findings_summary?: Array<Record<string, unknown>>
    remaining_budget?: ResearchBudget
    proposable_commands?: ResearchCommandProjection[]
    recent_actions?: Array<Record<string, unknown>>
    previous_observation?: Record<string, unknown>
  }
  previous_command_result_id?: string | null
  created_at?: string
}

export interface ResearchDecision {
  id: string
  sequence: number
  decision_type: string
  action: { command?: string; parameters?: Record<string, unknown> }
  expected_signal?: string | null
  falsifier?: string | null
  reason?: string | null
  confidence: number
  requested_input?: string | null
  stop_reason?: string | null
  status: string
  validation_errors: string[]
  validation_warnings: string[]
  policy_result: Record<string, unknown>
  planner?: Record<string, unknown>
  command_result_id?: string | null
  created_at?: string
}

export interface ResearchEvent {
  id: string
  event_type: string
  status: string
  summary: string
  details: Record<string, unknown>
  created_at?: string
}

export interface ResearchEpisodeDetail {
  episode: ResearchEpisode
  current_observation: ResearchObservation | null
  observations: ResearchObservation[]
  decisions: ResearchDecision[]
  events: ResearchEvent[]
  waiting_on?: Array<{
    kind: 'scan' | 'finding_retest' | string
    id: string
    status: string
    ui_path?: string
  }>
  accepted?: boolean
  dispatched?: boolean
  decision_id?: string
  planner_call?: Record<string, unknown>
}

export interface ResearchEpisodeCreateRequest {
  target_id: string
  objective: string
  execution_mode: 'shadow' | 'read_only' | 'gated'
  max_risk_tier: string
  allowed_families?: string[]
  max_steps: number
  budget_limits?: Partial<ResearchBudget>
  scope_receipt_id?: string
  approval_receipt_id?: string
  created_by?: string
  autopilot?: boolean
}

export interface ResearchEpisodeLaunchRequest {
  subject_type: 'target' | 'finding' | 'asm'
  subject_id: string
  mission_profile: 'target_hunt' | 'verify_finding' | 'close_asm_gaps'
  intensity: 'analyze' | 'hunt' | 'relentless' | 'deep_hunt'
  approval_receipt_id?: string
  planner_mode?: ResearchPlannerMode
  autopilot?: boolean
  force_new?: boolean
  created_by?: string
}

export interface ResearchEpisodeLaunchResponse extends ResearchEpisodeDetail {
  ui_path?: string
  reused: boolean
}

export type ResearchPlannerMode = 'agent' | 'local_codex' | 'configured_ai'

export interface ResearchCampaignLaunchRequest {
  target_id: string
  intensity?: 'analyze' | 'hunt' | 'relentless' | 'deep_hunt'
  approval_receipt_id?: string
  planner_mode?: ResearchPlannerMode
  duration_hours?: number
  max_episodes?: number
  objective?: string
  allowed_families?: string[]
  created_by?: string
}

export interface ResearchCampaignLaunchResponse {
  campaign: Campaign
  episode: ResearchEpisodeLaunchResponse | null
  readiness?: Record<string, unknown>
  preflight?: { action?: string; scan_id?: string | null; status?: string }
  ui_path?: string
}

export interface ResearchReadiness {
  planner_ready: boolean
  configured_planner_ready?: boolean
  default_planner_mode?: ResearchPlannerMode
  planner_modes?: Partial<Record<ResearchPlannerMode, {
    ready: boolean
    durable: boolean
    label: string
  }>>
  execution_enabled: boolean
  campaign_readiness_policy?: Record<string, unknown>
  model?: string | null
  fallback_models: string[]
}

export interface CommandResult {
  id: string
  command: string
  status: string
  dry_run: boolean
  risk_tier: string
  operation_plan_id?: string | null
  scope_receipt_id?: string | null
  approval_receipt_id?: string | null
  campaign_id?: string | null
  scan_id?: string | null
  finding_ids: string[]
  hypothesis_ids: string[]
  evidence_object_ids: string[]
  tool_receipt_ids: string[]
  blocked_by: string[]
  next_action?: string | null
  operator_message: string
  result_json: Record<string, unknown>
  created_by?: string | null
  created_at?: string
}

export interface CampaignAction {
  id: string
  command: string
  action_name: string
  status: string
  dry_run: boolean
  risk_tier: string
  operation_plan_id?: string | null
  command_result_id?: string | null
  scope_receipt_id?: string | null
  approval_receipt_id?: string | null
  campaign_id?: string | null
  target_id?: string | null
  target_url?: string | null
  scan_id?: string | null
  live_scan_status?: string | null
  finding_ids: string[]
  hypothesis_ids: string[]
  evidence_object_ids: string[]
  tool_receipt_ids: string[]
  blocked_by: string[]
  next_action?: string | null
  operator_message?: string | null
  result_json: Record<string, unknown>
  created_by?: string | null
  created_at?: string
}

// Cross-product mission timeline (GET /timeline). Events normalize command
// results, campaign actions, scans, evidence bindings, refuters, and exports;
// `upcoming` carries scheduled work with a `next_eligible_at`.
export interface TimelineEvent {
  event_id: string
  kind: string
  command?: string | null
  action_name?: string | null
  status: string
  risk_tier?: string | null
  dry_run?: boolean | null
  target_id?: string | null
  target_url?: string | null
  scan_id?: string | null
  active_scan_id?: string | null
  operation_plan_id?: string | null
  campaign_id?: string | null
  mission_campaign_id?: string | null
  campaign_action_id?: string | null
  scope_receipt_id?: string | null
  approval_receipt_id?: string | null
  finding_ids?: string[]
  evidence_object_ids?: string[]
  tool_receipt_ids?: string[]
  blocked_by?: string[]
  next_action?: string | null
  next_eligible_at?: string | null
  scan_type?: string | null
  name?: string | null
  schedule_id?: string | null
  operator_message?: string | null
  created_at?: string | null
}

export interface TimelineResponse {
  events: TimelineEvent[]
  upcoming: TimelineEvent[]
  count: number
  statuses: string[]
  execution_enabled: boolean
}

export interface CampaignDeploymentImpact {
  linked_finding_count?: number
  active_finding_count?: number
  by_severity?: Record<string, number>
  by_status?: Record<string, number>
  estimated_default_blockers?: number
  blocks_deployment_estimate?: boolean
  partial?: boolean
}

export interface Campaign {
  id: string
  name?: string | null
  objective: string
  campaign_type: string
  target_id?: string | null
  target_scope: Record<string, unknown>
  risk_tier: string
  policy_profile?: string | null
  planner: Record<string, unknown>
  operation_plan_id?: string | null
  context_hash?: string | null
  status: string
  deployment_impact: CampaignDeploymentImpact
  metadata_json: Record<string, unknown>
  created_by?: string | null
  created_at: string
  updated_at?: string | null
  execution_enabled: boolean
}

export interface CampaignDetailResponse {
  campaign: Campaign
  actions: CampaignAction[]
  action_count: number
  total_action_count: number
  status_rollup: Record<string, number>
  deployment_impact: CampaignDeploymentImpact
  research_yield?: {
    episodes: number
    decisions: number
    model_units: number
    experiments: number
    falsified_experiments: number
    experiment_outcomes?: Record<string, number>
    non_scientific_experiments?: number
    semantic_dimensions_tested: number
    exhausted_dimensions: number
    recon_actions: number
    novelty_suppressions: number
    verified_autonomous_findings: number
    verified_campaign_scan_findings?: number
    verified_campaign_retest_findings?: number
    net_new_verified_findings?: number
    finding_yield_per_experiment: number
    model_units_per_verified_finding?: number | null
    surface?: Record<string, number>
    stop_recommended: boolean
    stop_reason?: string | null
  } | null
  research_readiness?: {
    ready: boolean
    state: string
    blockers?: string[]
    // surface mixes route counts (number), inventory/graph timestamps (string),
    // meaningful_preflight_gain (boolean), and executable_families (string[]).
    surface?: Record<string, unknown>
    preflight_scan?: Record<string, unknown> | null
  } | null
  execution_enabled: boolean
}

// Evidence surfaces (GET/POST /evidence/*). Concrete instances are split out of
// findings; objects are content-addressed blobs; manifests/bundles are
// content-free descriptors for audit/export.
export interface EvidenceInstance {
  id: string
  finding_id?: string | null
  evidence_object_id?: string | null
  scan_id?: string | null
  target_id?: string | null
  concrete_url?: string | null
  object_id?: string | null
  payload_variant?: string | null
  request_response_refs?: string[]
  principal_pair?: Record<string, unknown> | null
  proof_observation?: Record<string, unknown> | null
  campaign_action_id?: string | null
  tool_receipt_id?: string | null
  redaction_profile?: string | null
  hash?: string | null
  retention_policy?: string | null
  proof_state?: string | null
  metadata_json?: Record<string, unknown>
  created_by?: string | null
  created_at?: string | null
}

export interface EvidenceExportManifest {
  schema_version: string
  generated_at: string
  object_count: number
  manifest_hash: string
  retention_policy_days: Record<string, number | null>
  retention_counts: Record<string, number>
  storage_counts: Record<string, number>
  integrity_counts: Record<string, number>
  content_included: boolean
  objects: Array<Record<string, unknown>>
  filters: Record<string, unknown>
}

export interface EvidenceRetentionSweepResult {
  dry_run: boolean
  target_id: string
  candidate_count: number
  deleted_count: number
  delete_local_files?: boolean
  local_files?: { deleted: string[]; missing: string[]; errors: string[] }
  remote_objects?: {
    candidate_count: number
    deleted_count: number
    missing_count: number
    failed_count: number
    preserved_count: number
    delete_supported: boolean
  }
  retention_policy_days?: Record<string, number | null>
  candidates?: Array<Record<string, unknown>>
  execution_enabled: boolean
  operation_id?: string | null
  preview_status?: 'ready' | 'executing' | 'consumed' | 'stale'
  approval_receipt_id?: string | null
  execution_started_at?: string | null
  preview_bound: boolean
  preview_id?: string | null
  preview_hash?: string | null
  preview_issued_at?: string | null
  preview_expires_at?: string | null
  preview_candidate_count?: number
  preview_criteria?: {
    scope: 'target'
    target_id: string
    older_than_days?: number | null
    retention_class?: string | null
    limit: number
    delete_local_files: boolean
  } | null
}

export interface ArsenalExecutionResponse {
  command: string
  dispatched: boolean
  dry_run: boolean
  execution_enabled: boolean
  operation_id?: string | null
  execution_blocked_reason?: string | null
  command_result?: CommandResult | null
  campaign_action?: CampaignAction | null
  result?: Record<string, unknown> | null
  action_state?: Record<string, unknown> | null
}

export interface Hypothesis {
  id: string
  target_id?: string | null
  campaign_id?: string | null
  campaign_action_id?: string | null
  source: string
  family: string
  cwe?: string | null
  title?: string | null
  description?: string | null
  severity_guess?: string | null
  confidence: number
  dedupe_key: string
  status: string
  effective_status?: string
  version: number
  claim_owner?: string | null
  claim_lease_expires_at?: string | null
  claim_state?: { owner?: string | null; lease_expires_at?: string | null; active?: boolean; expired?: boolean; effective_status?: string }
  claimable?: boolean
  smoke_score?: number | null
  evidence_object_ids: string[]
  tool_receipt_ids: string[]
  promoted_finding_ids: string[]
  next_test_action?: Record<string, unknown> | null
  endorsements: Array<Record<string, unknown>>
  refutations: Array<Record<string, unknown>>
  terminal_reason?: string | null
  metadata_json: Record<string, unknown>
  can_promote_finding: boolean
  can_reconcile_proof?: boolean
  execution_enabled: boolean
  created_by?: string | null
  created_at?: string
  updated_at?: string
}

export interface HypothesisReportItem {
  id: string
  target_id?: string | null
  campaign_id?: string | null
  source: string
  family: string
  cwe?: string | null
  title?: string | null
  severity_guess?: string | null
  confidence: number
  dedupe_key: string
  status: string
  stored_status?: string
  effective_status?: string
  version: number
  claim_state?: { owner?: string | null; lease_expires_at?: string | null; active?: boolean; expired?: boolean; effective_status?: string }
  smoke_score?: number | null
  next_test_action?: Record<string, unknown> | null
  terminal_reason?: string | null
  endorsement_count: number
  refutation_count: number
  updated_at?: string
  execution_enabled: boolean
  can_promote_finding: boolean
}

export interface HypothesisMissingPrecondition {
  requirement: string
  count: number
  sample_hypothesis_ids: string[]
}

export interface HypothesisGraphContextTarget {
  target_id: string
  hypothesis_count: number
  sample_hypothesis_ids: string[]
  families: Record<string, number>
  node_count: number
  edge_count: number
  route_nodes: number
  object_nodes: number
  principal_nodes: number
  auth_boundary_edges: number
  producer_consumer_edges: number
  by_node_type: Record<string, number>
  by_edge_type: Record<string, number>
  sample_route_keys: string[]
  sample_object_keys: string[]
  sample_principal_keys: string[]
}

export interface HypothesisGraphContext {
  summary: {
    hypothesis_target_count: number
    target_count: number
    node_count: number
    edge_count: number
    auth_boundary_edge_count: number
    producer_consumer_edge_count: number
    missing_graph_target_count: number
  }
  targets: HypothesisGraphContextTarget[]
  missing_graph_target_ids: string[]
  truncated: boolean
}

export interface HypothesisSituationReport {
  summary: {
    generated_at: string
    considered_count: number
    status_counts: Record<string, number>
    source_counts: Record<string, number>
    family_counts: Record<string, number>
    requester?: string | null
    limit: number
  }
  hottest_unclaimed: HypothesisReportItem[]
  requester_claims: HypothesisReportItem[]
  avoid_resurfacing: HypothesisReportItem[]
  live_blockers: HypothesisReportItem[]
  missing_preconditions: HypothesisMissingPrecondition[]
  execution_enabled: boolean
  findings_created: number
  board_truncated: boolean
  graph_context?: HypothesisGraphContext
}

export interface SourceIngestResult {
  hypotheses: Hypothesis[]
  created_or_endorsed: number
  skipped: Array<Record<string, unknown>>
  skipped_count: number
  source_label: string
  execution_enabled: boolean
  findings_created: number
  queued_scans: number
  runtime_proof_required: boolean
}

export interface RefuterCandidate {
  subject_type: string
  subject_id?: string | null
  finding_id?: string | null
  target_id?: string | null
  title?: string | null
  severity?: string | null
  source?: string | null
  tool?: string | null
  proof_state?: string | null
  trigger_type: string
  trigger_reasons: string[]
  already_reviewed: boolean
  recommended_review?: Record<string, unknown>
  automation_plan?: {
    status: string
    execution_enabled: boolean
    recommended_basis?: string | null
    record_only_until_executed: boolean
    minimal_reproducer?: {
      available: boolean
      has_url: boolean
      has_request: boolean
      url_sample?: string | null
    }
    steps: Array<{
      id: string
      label: string
      mode: string
      command: string
      verdict_basis_after_execution?: string
      requires?: string[]
      counterevidence_goal?: string
    }>
  }
}

export interface RefuterWorkSummary {
  summary: {
    candidate_count: number
    unreviewed_count: number
    already_reviewed_count: number
    trigger_counts: Record<string, number>
    trigger_type_counts: Record<string, number>
    integrity_signal_count: number
    limit: number
  }
  candidates: RefuterCandidate[]
  integrity_signals: Array<{
    subject_type: 'target' | 'benchmark' | string
    subject_id?: string | null
    target_id?: string | null
    trigger_type: string
    trigger_reasons: string[]
    review_hint?: string
    already_reviewed?: boolean
  }>
  execution_enabled: boolean
  findings_updated: number
  hypotheses_updated: number
}

export interface RefuterReview {
  id: string
  subject_type: string
  subject_id?: string | null
  target_id?: string | null
  finding_id?: string | null
  hypothesis_id?: string | null
  campaign_id?: string | null
  trigger_reason: string
  refuter_signal: string
  refuter_verdict?: string | null
  verdict_basis: string
  status: string
  evidence_object_ids?: string[]
  tool_receipt_ids?: string[]
  counterevidence?: Record<string, unknown>
  notes?: string | null
  metadata_json: Record<string, unknown>
  created_by?: string | null
  created_at?: string
}

export interface RefuterQueueResult {
  created: number
  created_integrity_signals: number
  created_finding_reviews: number
  skipped_already_reviewed: number
  unreviewed_count: number
  refuter_reviews: RefuterReview[]
  summary: RefuterWorkSummary['summary']
  execution_enabled: boolean
  findings_updated: number
  hypotheses_updated: number
}

export interface RefuterActionResult {
  command?: string
  dispatched?: boolean
  dry_run?: boolean
  execution_enabled?: boolean
  execution_blocked_reason?: string
  operation_id?: string
  command_result?: Record<string, unknown>
  result?: Record<string, unknown>
  action_state?: Record<string, unknown>
  refuter_review?: RefuterReview
  status?: string
}

export interface RefuterReviewsResponse {
  refuter_reviews: RefuterReview[]
  count: number
  execution_enabled: boolean
}

export interface LocalAgentPlanRequest {
  agent: string
  context_pack_id: string
  objective: string
  created_by?: string
}

export interface LocalAgentPlanResponse extends OperationPlanResponse {
  local_agent_spawned: boolean
  planner_execution_enabled: boolean
  agent: {
    agent: string
    status: string
    auth_detected: boolean
    binary_path?: string | null
  }
  context_pack_id: string
  planner_notes: string[]
}

export interface LocalAgentTestRequest {
  agent: string
  timeout_seconds?: number
  max_output_bytes?: number
}

export interface LocalAgentTestResponse {
  agent: string
  display_name: string
  ok: boolean
  status: string
  reason?: string | null
  binary_path?: string | null
  auth_detected: boolean
  auth_detection_method: string
  auth_artifact_contents_read: boolean
  planner_execution_enabled: boolean
  local_agent_spawned: boolean
  prompt_sent: boolean
  prompt_bytes_sent: number
  target_state_mutated: boolean
  scanner_work_queued: boolean
  process_spawned: boolean
  timeout_seconds: number
  max_output_bytes: number
  output?: string
  output_truncated: boolean
  output_bytes_captured: number
  version?: string | null
  return_code?: number | null
  timed_out: boolean
  error?: string | null
  command_kind: string
  argv_redacted: string[]
  environment_policy: {
    provider_api_keys_stripped: boolean
    sensitive_values_returned: boolean
    environment_variable_names_returned: boolean
    stripped_variable_count: number
  }
}

export interface AgentContextPackRequest {
  context_version?: string
  target_id?: string
  context_hash: string
  target_summary?: Record<string, unknown>
  current_surface?: Record<string, unknown>
  current_gaps?: Array<Record<string, unknown>>
  hypotheses_summary?: Array<Record<string, unknown>>
  findings_summary?: Array<Record<string, unknown>>
  allowed_commands?: string[]
  disallowed_commands?: Array<Record<string, unknown>>
  known_preconditions?: Record<string, unknown>
  redaction_profile?: string
  created_by?: string
}

export interface AgentContextPackFromTargetRequest {
  target_id: string
  created_by?: string
  include_findings?: boolean
  include_endpoints?: boolean
  include_gaps?: boolean
  finding_limit?: number
  endpoint_limit?: number
}

export interface AgentContextPack {
  id: string
  context_version: string
  target_id?: string | null
  context_hash: string
  target_summary: Record<string, unknown>
  current_surface: Record<string, unknown>
  current_gaps: Array<Record<string, unknown>>
  hypotheses_summary: Array<Record<string, unknown>>
  findings_summary: Array<Record<string, unknown>>
  allowed_commands: string[]
  disallowed_commands: Array<Record<string, unknown>>
  known_preconditions: Record<string, unknown>
  redaction_profile: string
  context_pack: Record<string, unknown>
  validation_errors: string[]
  validation_warnings: string[]
  status: string
  created_by?: string | null
  created_at?: string
  execution_enabled: boolean
}

export interface AgentContextPackResponse {
  context_pack: AgentContextPack
  execution_enabled: boolean
  validated: boolean
  generated_from?: Record<string, unknown>
}

export interface AgentDecisionTraceStep {
  kind: string
  command?: string | null
  status?: string
  reason?: string | null
  refs?: string[]
}

export interface AgentDecisionTraceRequest {
  operation_plan_id?: string
  context_pack_id?: string
  planner?: Record<string, unknown>
  context_hash: string
  command_schema_version?: string
  steps?: AgentDecisionTraceStep[]
  final_rationale?: string
  redaction_profile?: string
  created_by?: string
}

export interface AgentDecisionTrace {
  id: string
  operation_plan_id?: string | null
  context_pack_id?: string | null
  planner: Record<string, unknown>
  context_hash: string
  command_schema_version: string
  steps: AgentDecisionTraceStep[]
  final_rationale?: string | null
  redaction_profile: string
  validation_errors: string[]
  validation_warnings: string[]
  status: string
  created_by?: string | null
  created_at?: string
  execution_enabled: boolean
}

export interface AgentDecisionTraceResponse {
  decision_trace: AgentDecisionTrace
  execution_enabled: boolean
  validated: boolean
}

export interface ArsenalTool {
  tool_name: string
  family: string
  description: string
  risk_tier: string
  status: string
  expected_status: string
  binary_path?: string | null
  detection?: string | null
  version?: string | null
  version_probe_error?: string | null
  version_command: string[]
  evidence_parser?: string | null
  proof_contract?: string | null
  retest_contract?: string | null
  redaction_rules: string[]
  timeout_seconds: number
}

export interface ArsenalToolsResponse {
  schema_version: string
  maturity: string
  probe_versions: boolean
  status_labels: string[]
  tools: ArsenalTool[]
  summary: Record<string, number>
}

export interface LocalAgentCapability {
  agent: string
  display_name: string
  binary_path?: string | null
  binary_detection?: string | null
  version?: string | null
  version_probe_error?: string | null
  auth_detected: boolean
  auth_detection_method: string
  auth_artifacts: string[]
  auth_artifact_contents_read: boolean
  supports_headless_prompt: boolean
  supports_read_only_mode: boolean
  supports_json_mode: boolean
  supports_timeout: boolean
  supports_workdir_isolation: boolean
  supports_network_disable: boolean
  max_prompt_bytes: number
  max_output_bytes: number
  risk_notes: string[]
  planner_execution_enabled: boolean
  status: string
}

export interface LocalAgentsResponse {
  schema_version: string
  maturity: string
  execution_enabled: boolean
  planner_execution_enabled: boolean
  probe_versions: boolean
  auth_policy: {
    detection_only: boolean
    auth_artifact_contents_read: boolean
    strip_provider_api_key_environment_on_future_spawn: boolean
    sensitive_values_returned: boolean
  }
  agents: LocalAgentCapability[]
  summary: Record<string, number>
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
  trust_anchor_ids?: string[]
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
  approval_receipt_id?: string
}

export interface ModelIntakeTrustAnchor {
  id: string
  name: string
  description?: string | null
  public_key_pem?: string | null
  public_key_sha256?: string | null
  policy_profile?: string | null
  owner?: string | null
  is_active: boolean
  created_at?: string
  updated_at?: string
}

export interface ModelIntakeScanResponse {
  scan_id: string
  job_id: string
  status: string
  target: string
  scan_type: 'model_intake'
  run_kind: 'model_intake'
  ui_url: string
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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
  investigator_verified_count?: number
  investigator_suspected_count?: number
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

export interface AsmFamilyCoverage {
  attempted?: number
  attempts: number
  completed: number
  proved?: number
  blocked?: number
  cancelled?: number
  partial?: number
  failed?: number
}
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

export interface AsmTimelineEvent {
  id: string
  kind: 'active_scan' | 'scheduler_decision' | 'next_eligible' | 'scheduled_wave' | 'last_scheduler_decision' | 'activity' | string
  title: string
  status?: string | null
  detail?: string | null
  timestamp?: string | null
  scan_id?: string | null
  campaign_id?: string | null
  schedule_id?: string | null
  href?: string | null
  remediation?: {
    kind: 'open_scan' | 'configure_auth' | 'workers' | 'schedule' | 'review_coverage' | 'improve' | string
    label: string
    href?: string | null
  } | null
}

export interface AsmActivityResponse {
  activity: AsmActivity[]
  scheduler_state?: AsmSchedulerState
  next_schedule?: Record<string, unknown> | null
  active_scans?: Array<Record<string, unknown>>
  timeline?: AsmTimelineEvent[]
  hypothesis_situation?: HypothesisSituationReport
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
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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

// Research provenance stamped on hunt-driven scanner findings (evidence.research):
// the finding came from a scan a deep-hunt decision queued. Absent on organic DAST
// findings and on agent-native claims (those use source='autonomous' instead).
export interface ResearchProvenance {
  driven_by: 'autonomous_research' | string
  campaign_id?: string
  campaign_action_id?: string
}

export function getFindingResearchProvenance(finding: Finding): ResearchProvenance | null {
  let evidence: unknown = finding.evidence
  if (typeof evidence === 'string') {
    try { evidence = JSON.parse(evidence) } catch { return null }
  }
  if (!evidence || typeof evidence !== 'object') return null
  const research = (evidence as Record<string, unknown>).research
  if (!research || typeof research !== 'object') return null
  const r = research as Record<string, unknown>
  if (typeof r.driven_by !== 'string' || !r.driven_by) return null
  return {
    driven_by: r.driven_by,
    campaign_id: typeof r.campaign_id === 'string' ? r.campaign_id : undefined,
    campaign_action_id: typeof r.campaign_action_id === 'string' ? r.campaign_action_id : undefined,
  }
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
    approval_receipts_required_for_state_changing_actions: boolean
  }
  research_agent: {
    default_planner_mode: ResearchPlannerMode
    available_planner_modes: ResearchPlannerMode[]
  }
}

export interface AutomationSettingsUpdate extends ScanExecutionSettingsUpdate {
  default_asm_enabled?: boolean
  default_asm_config?: Partial<AsmAutomationConfig>
  default_research_planner_mode?: ResearchPlannerMode
  approval_receipts_required_for_state_changing_actions?: boolean
}

export interface AIProbeResponse {
  status: 'ok' | 'failed'
  scope: 'scan' | 'verify' | 'research'
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
  investigator_verified_count?: number
  investigator_suspected_count?: number
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
  investigator_verified_assets?: number
  investigator_suspected_assets?: number
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

export async function getArsenalCommands(): Promise<ArsenalCommandsResponse> {
  const res = await fetch(`${API_URL}/arsenal/commands`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch Command Arsenal schema'))
  return res.json()
}

export async function getArsenalContracts(): Promise<ArsenalContractsResponse> {
  const res = await fetch(`${API_URL}/arsenal/contracts`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch mission contracts'))
  return res.json()
}

export async function previewScopeReceipt(payload: {
  url: string
  target_id?: string
  allowed_hosts?: string[]
  allowed_root_domains?: string[]
  environment?: string
  redirect_urls?: string[]
}): Promise<ScopePreviewResponse> {
  const res = await fetch(`${API_URL}/arsenal/scope/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to preview scope receipt'))
  return res.json()
}

export async function createApprovalReceipt(payload: {
  scope_receipt_id: string
  risk_tier: string
  confirmations?: string[]
  approved_by?: string
  denial_reason?: string
  expires_at?: string
  action_name?: string
  action_context?: Record<string, unknown>
}): Promise<ApprovalReceiptResponse> {
  const res = await fetch(`${API_URL}/arsenal/approvals`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create approval receipt'))
  return res.json()
}

export async function createOperationPlan(payload: OperationPlanRequest): Promise<OperationPlanResponse> {
  const res = await fetch(`${API_URL}/arsenal/plans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to validate operation plan'))
  return res.json()
}

export async function getOperationPlans(limit: number = 20): Promise<{ operation_plans: OperationPlan[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/plans?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load operation plans'))
  return res.json()
}

export async function getCommandResults(limit: number = 20): Promise<{ command_results: CommandResult[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/command-results?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load command result audit records'))
  return res.json()
}

export async function getCampaignActions(limit: number = 20): Promise<{ campaign_actions: CampaignAction[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/campaign-actions?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load campaign action records'))
  return res.json()
}

// Cross-product mission timeline (read-only event feed).
export async function getMissionTimeline(params?: {
  limit?: number
  target_id?: string
  include_campaign_actions?: boolean
  include_scans?: boolean
  include_schedules?: boolean
  include_evidence?: boolean
  include_refuters?: boolean
  include_exports?: boolean
}): Promise<TimelineResponse> {
  const searchParams = new URLSearchParams()
  if (params?.limit) searchParams.set('limit', String(params.limit))
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  const toggleKeys = [
    'include_campaign_actions', 'include_scans', 'include_schedules',
    'include_evidence', 'include_refuters', 'include_exports',
  ] as const
  for (const key of toggleKeys) {
    const value = params?.[key]
    if (value !== undefined) searchParams.set(key, value ? 'true' : 'false')
  }
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/timeline${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load mission timeline'))
  return res.json()
}

// Mission campaigns.
export async function getCampaigns(params?: {
  limit?: number
  target_id?: string
  status?: string
}): Promise<{ campaigns: Campaign[]; execution_enabled: boolean; count: number }> {
  const searchParams = new URLSearchParams()
  if (params?.limit) searchParams.set('limit', String(params.limit))
  if (params?.target_id) searchParams.set('target_id', params.target_id)
  if (params?.status) searchParams.set('status', params.status)
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/arsenal/campaigns${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load campaigns'))
  return res.json()
}

export async function getCampaign(id: string, actionLimit: number = 50): Promise<CampaignDetailResponse> {
  const res = await fetch(`${API_URL}/arsenal/campaigns/${encodeURIComponent(id)}?action_limit=${actionLimit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load campaign'))
  return res.json()
}

export async function createCampaign(payload: {
  objective: string
  campaign_type: string
  name?: string
  target_id?: string
  target_scope?: Record<string, unknown>
  risk_tier?: string
  policy_profile?: string
  status?: string
  metadata_json?: Record<string, unknown>
  created_by?: string
}): Promise<{ campaign: Campaign }> {
  const res = await fetch(`${API_URL}/arsenal/campaigns`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create campaign'))
  return res.json()
}

export async function linkCampaignAction(
  id: string,
  payload: { command_result_id?: string; campaign_action_id?: string }
): Promise<{ campaign_id: string; linked_action: CampaignAction; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/campaigns/${encodeURIComponent(id)}/actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to link campaign action'))
  return res.json()
}

// Evidence browsing / export / retention.
export async function getEvidenceInstances(params?: {
  finding_id?: string
  tool_receipt_id?: string
  limit?: number
}): Promise<{ evidence_instances: EvidenceInstance[]; count: number; execution_enabled: boolean }> {
  const searchParams = new URLSearchParams()
  if (params?.finding_id) searchParams.set('finding_id', params.finding_id)
  if (params?.tool_receipt_id) searchParams.set('tool_receipt_id', params.tool_receipt_id)
  if (params?.limit) searchParams.set('limit', String(params.limit))
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/evidence/instances${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load evidence instances'))
  return res.json()
}

export async function getEvidenceObject(id: string): Promise<EvidenceObject> {
  const res = await fetch(`${API_URL}/evidence/${encodeURIComponent(id)}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load evidence object'))
  return res.json()
}

function evidenceQuery(params?: {
  finding_id?: string
  scan_id?: string
  retention_class?: string
  limit?: number
}): URLSearchParams {
  const searchParams = new URLSearchParams()
  if (params?.finding_id) searchParams.set('finding_id', params.finding_id)
  if (params?.scan_id) searchParams.set('scan_id', params.scan_id)
  if (params?.retention_class) searchParams.set('retention_class', params.retention_class)
  if (params?.limit) searchParams.set('limit', String(params.limit))
  return searchParams
}

export async function getEvidenceExportManifest(params?: {
  finding_id?: string
  scan_id?: string
  retention_class?: string
  limit?: number
}): Promise<EvidenceExportManifest> {
  const query = evidenceQuery(params).toString()
  const res = await fetch(`${API_URL}/evidence/export-manifest${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load evidence export manifest'))
  return res.json()
}

// `format=zip` returns bytes, so the caller downloads via this URL (anchor /
// window.open) rather than parsing JSON.
export function evidenceExportBundleUrl(params?: {
  finding_id?: string
  scan_id?: string
  retention_class?: string
  limit?: number
}): string {
  const query = evidenceQuery(params)
  query.set('format', 'zip')
  query.set('record_event', 'true')
  return `${API_URL}/evidence/export-bundle?${query.toString()}`
}

export type EvidenceRetentionPreviewRequest = {
  dry_run?: true
  target_id: string
  older_than_days?: number
  retention_class?: string
  limit?: number
  delete_local_files?: boolean
  approval_receipt_id?: never
  preview_id?: never
}

export type EvidenceRetentionExecutionRequest = {
  dry_run: false
  preview_id: string
  approval_receipt_id: string
  target_id?: never
  older_than_days?: never
  retention_class?: never
  limit?: never
  delete_local_files?: never
}

export async function sweepEvidenceRetention(
  payload: EvidenceRetentionPreviewRequest | EvidenceRetentionExecutionRequest
): Promise<EvidenceRetentionSweepResult> {
  const res = await fetch(`${API_URL}/evidence/retention/sweep`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to run evidence retention sweep'))
  return res.json()
}

export async function getEvidenceRetentionExecutions(params?: {
  target_id?: string
  limit?: number
}): Promise<{ executions: EvidenceRetentionSweepResult[]; count: number; execution_enabled: boolean }> {
  const query = new URLSearchParams()
  if (params?.target_id) query.set('target_id', params.target_id)
  if (params?.limit) query.set('limit', String(params.limit))
  const suffix = query.toString() ? `?${query.toString()}` : ''
  const res = await fetch(`${API_URL}/evidence/retention/executions${suffix}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load unfinished retention cleanup'))
  return res.json()
}

export async function executeAuthzReplay(
  campaignActionId: string,
  payload: {
    session_id: string
    execute: boolean
    confirmations?: string[]
    approval_receipt_id?: string
    created_by?: string
  }
): Promise<ArsenalExecutionResponse> {
  const res = await fetch(`${API_URL}/arsenal/campaign-actions/${encodeURIComponent(campaignActionId)}/authz-replay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to execute authorization replay'))
  return res.json()
}

export async function promoteAuthzReplay(
  campaignActionId: string,
  payload: {
    execute: boolean
    confirmations?: string[]
    approval_receipt_id?: string
    created_by?: string
  }
): Promise<ArsenalExecutionResponse> {
  const res = await fetch(`${API_URL}/arsenal/campaign-actions/${encodeURIComponent(campaignActionId)}/authz-promote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to promote authorization replay'))
  return res.json()
}

export async function getHypotheses(limit: number = 20): Promise<{ hypotheses: Hypothesis[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load hypotheses'))
  return res.json()
}

// --- Adaptive workbench (Waves 4-6): scheduling + lifecycle transitions ---

export interface ScheduledLead {
  hypothesis_id: string
  priority: number | null
  excluded: boolean
  exclude_reason: string | null
  breakdown: Record<string, number>
  request_cost?: number
  deferred_reason?: string
  hypothesis?: Hypothesis
}

export interface HypothesisScheduleResponse {
  version: string
  scheduled: ScheduledLead[]
  deferred: ScheduledLead[]
  excluded: ScheduledLead[]
  counts: { scheduled: number; deferred: number; excluded: number }
  execution_enabled: boolean
}

export async function scheduleHypotheses(params?: {
  targetId?: string
  authAvailable?: boolean
  remainingRequests?: number
  limit?: number
}): Promise<HypothesisScheduleResponse> {
  const q = new URLSearchParams()
  if (params?.targetId) q.set('target_id', params.targetId)
  if (params?.authAvailable) q.set('auth_available', 'true')
  if (params?.remainingRequests != null) q.set('remaining_requests', String(params.remainingRequests))
  if (params?.limit != null) q.set('limit', String(params.limit))
  const res = await fetch(`${API_URL}/arsenal/hypotheses/schedule${q.toString() ? `?${q.toString()}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to schedule hypotheses'))
  return res.json()
}

export async function transitionHypothesis(
  hypothesisId: string,
  payload: {
    to: string
    expected_version: number
    reason?: string
    refuted_by?: Record<string, unknown>
    blockers?: string[]
    created_by?: string
  }
): Promise<{ hypothesis: Hypothesis; transitioned: boolean; from: string; to: string; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/${encodeURIComponent(hypothesisId)}/transition`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Transition rejected'))
  return res.json()
}

// --- Family proof handoffs (Wave 5) ---

export interface FamilyProofContract {
  cwe: string
  requires: string[]
  refute_if?: string[]
}

export interface FamilyProofContracts {
  version: string
  families: string[]
  contracts: Record<string, FamilyProofContract>
  aliases: Record<string, string>
  verdicts: string[]
}

export async function getFamilyProofContracts(): Promise<FamilyProofContracts> {
  const res = await fetch(`${API_URL}/arsenal/family-proof/contracts`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load family proof contracts'))
  return res.json()
}

// --- Bounded HTTP differential experiment builder (Wave 2 + 8) ---

export interface ArsenalExecuteResult {
  command: string
  dispatched: boolean
  dry_run: boolean
  execution_blocked_reason?: string
  result?: Record<string, unknown>
  operation_id?: string | null
  action_state?: Record<string, unknown>
  command_result?: Record<string, unknown>
  execution_enabled: boolean
}

export async function executeArsenalCommand(payload: {
  command: string
  parameters: Record<string, unknown>
  execute?: boolean
  confirmations?: string[]
  approval_receipt_id?: string
  created_by?: string
}): Promise<ArsenalExecuteResult> {
  const res = await fetch(`${API_URL}/arsenal/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Arsenal execution failed'))
  return res.json()
}

export async function reconcileHypothesisProof(
  hypothesisId: string,
  payload: {
    expected_version: number
    campaign_action_id?: string
    approval_receipt_id: string
    created_by?: string
  }
): Promise<{
  status: string
  promoted: boolean
  hypothesis: Hypothesis
  proof_reconciliation: Record<string, unknown>
  command_result: CommandResult
  operation_id: string
  findings_created: number
  execution_enabled: boolean
}> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/${encodeURIComponent(hypothesisId)}/reconcile-proof`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to reconcile hypothesis proof'))
  return res.json()
}

export async function generateSourceIngestHypotheses(payload: {
  target_id?: string
  source_label?: string
  created_by?: string
  hints: Array<{
    kind?: string
    method?: string
    path?: string
    route?: string
    risk_hints?: string[]
    parameters?: string[]
    body_paths?: string[]
    object_keys?: string[]
    tenant_keys?: string[]
    roles?: string[]
    auth_required?: boolean
    confidence?: number
  }>
}): Promise<SourceIngestResult> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/source-ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate source-informed hypotheses'))
  return res.json()
}

// Compare-and-set lease claim. 409 `hypothesis_not_claimable` on conflict —
// getApiErrorMessage unwraps the structured detail message for display.
export async function claimHypothesis(
  hypothesisId: string,
  payload: { owner: string; expected_version: number; lease_seconds?: number }
): Promise<{ hypothesis: Hypothesis; claimed: boolean; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/${encodeURIComponent(hypothesisId)}/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to claim hypothesis'))
  return res.json()
}

export async function appendHypothesisSignal(
  hypothesisId: string,
  payload: {
    signal_type: 'endorsement' | 'refutation'
    source: string
    reason?: string
    evidence_object_ids?: string[]
    tool_receipt_ids?: string[]
    confidence_delta?: number
    status_hint?: 'support' | 'question' | 'weaken' | 'refute'
    metadata_json?: Record<string, unknown>
    created_by?: string
  }
): Promise<{ hypothesis: Hypothesis; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/${encodeURIComponent(hypothesisId)}/signals`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to record hypothesis signal'))
  return res.json()
}

export async function planHypothesisCampaign(
  hypothesisId: string,
  payload: { campaign_id?: string; campaign_name?: string; operator_message?: string; created_by?: string }
): Promise<{ campaign?: Campaign; campaign_id?: string; linked_action?: CampaignAction; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/${encodeURIComponent(hypothesisId)}/plan-campaign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to plan campaign from hypothesis'))
  return res.json()
}

export async function generateHypothesesFromPlan(payload: {
  operation_plan_id: string
  created_by?: string
  max_actions?: number
}): Promise<{ created: number; hypotheses: Hypothesis[]; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/from-plan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate hypotheses from plan'))
  return res.json()
}

export interface BenchmarkFollowupItem {
  expectation_id: string
  family: string
  benchmark?: string
  route?: string
  proof_required?: string
  min_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status?: string
  reason?: string
}

export async function generateHypothesesFromBenchmark(payload: {
  benchmark: string
  followups: BenchmarkFollowupItem[]
  target_id?: string
  scorecard_id?: string
  scorecard_scan_id?: string
  created_by?: string
}): Promise<{ created: number; hypotheses: Hypothesis[]; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/arsenal/hypotheses/from-benchmark`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate hypotheses from benchmark'))
  return res.json()
}

export async function getHypothesisSituationReport(
  limit: number = 5,
  requester: string = 'operator',
): Promise<HypothesisSituationReport> {
  const params = new URLSearchParams({ limit: String(limit) })
  if (requester) params.set('requester', requester)
  const res = await fetch(`${API_URL}/arsenal/hypotheses/situation-report?${params.toString()}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load hypothesis situation report'))
  return res.json()
}

export async function getRefuterWorkSummary(limit: number = 5, findingWindow: number = 200): Promise<RefuterWorkSummary> {
  const params = new URLSearchParams({ limit: String(limit), finding_window: String(findingWindow) })
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews/summary?${params.toString()}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load refuter review summary'))
  return res.json()
}

export async function getRefuterReviews(limit: number = 20): Promise<RefuterReviewsResponse> {
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load refuter reviews'))
  return res.json()
}

export async function recordRefuterReview(payload: {
  subject_type: string
  subject_id?: string
  target_id?: string
  finding_id?: string
  hypothesis_id?: string
  campaign_id?: string
  trigger_reason: string
  refuter_signal?: 'support' | 'question' | 'weaken' | 'refute'
  refuter_verdict?: 'supported' | 'weakened' | 'refuted' | 'inconclusive'
  verdict_basis?: 'signal_only' | 'deterministic_replay' | 'cryptographic' | 'parser_protocol' | 'human_approved_review'
  evidence_object_ids?: string[]
  tool_receipt_ids?: string[]
  counterevidence?: Record<string, unknown>
  notes?: string
  metadata_json?: Record<string, unknown>
  created_by?: string
}): Promise<{ refuter_review: RefuterReview; execution_enabled: boolean; findings_updated: number; hypotheses_updated: number }> {
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to record refuter counterevidence'))
  return res.json()
}

export async function queueRefuterReviewsFromSummary(payload: {
  limit?: number
  finding_window?: number
  include_integrity_signals?: boolean
  created_by?: string
} = {}): Promise<RefuterQueueResult> {
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews/queue-from-summary`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to queue refuter review work'))
  return res.json()
}

export async function executeRefuterReviewPlan(refuterReviewId: string, payload: {
  execute?: boolean
  confirmations?: string[]
  approval_receipt_id?: string
  step_id?: string
  requested_by?: string
  confirm_production?: boolean
} = {}): Promise<RefuterActionResult> {
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews/${encodeURIComponent(refuterReviewId)}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to execute refuter plan'))
  return res.json()
}

export async function deriveRefuterReviewVerdict(refuterReviewId: string, payload: {
  execute?: boolean
  confirmations?: string[]
  approval_receipt_id?: string
  verification_id?: string
  created_by?: string
} = {}): Promise<RefuterActionResult> {
  const res = await fetch(`${API_URL}/arsenal/refuter-reviews/${encodeURIComponent(refuterReviewId)}/derive-verdict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to derive refuter verdict'))
  return res.json()
}

export async function createAgentContextPack(payload: AgentContextPackRequest): Promise<AgentContextPackResponse> {
  const res = await fetch(`${API_URL}/arsenal/context-packs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to record context pack'))
  return res.json()
}

export async function getAgentContextPacks(limit: number = 20): Promise<{ context_packs: AgentContextPack[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/context-packs?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load context packs'))
  return res.json()
}

export async function generateAgentContextPackFromTarget(payload: AgentContextPackFromTargetRequest): Promise<AgentContextPackResponse> {
  const res = await fetch(`${API_URL}/arsenal/context-packs/from-target`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate context pack'))
  return res.json()
}

export async function createAgentDecisionTrace(payload: AgentDecisionTraceRequest): Promise<AgentDecisionTraceResponse> {
  const res = await fetch(`${API_URL}/arsenal/decision-traces`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to record decision trace'))
  return res.json()
}

export async function getAgentDecisionTraces(limit: number = 20): Promise<{ decision_traces: AgentDecisionTrace[]; execution_enabled: boolean; count: number }> {
  const res = await fetch(`${API_URL}/arsenal/decision-traces?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load decision traces'))
  return res.json()
}

export async function getResearchEpisodes(params?: {
  target_id?: string
  campaign_id?: string
  status?: string
  limit?: number
}): Promise<{ episodes: ResearchEpisode[]; count: number }> {
  const search = new URLSearchParams()
  if (params?.target_id) search.set('target_id', params.target_id)
  if (params?.campaign_id) search.set('campaign_id', params.campaign_id)
  if (params?.status) search.set('status', params.status)
  search.set('limit', String(params?.limit || 50))
  const res = await fetch(`${API_URL}/research/episodes?${search}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load research episodes'))
  return res.json()
}

export async function getResearchEpisode(episodeId: string): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes/${encodeURIComponent(episodeId)}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load research episode'))
  return res.json()
}

export async function createResearchEpisode(payload: ResearchEpisodeCreateRequest): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create research episode'))
  return res.json()
}

export async function launchResearchEpisode(payload: ResearchEpisodeLaunchRequest): Promise<ResearchEpisodeLaunchResponse> {
  const res = await fetch(`${API_URL}/research/launch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to launch autonomous investigation'))
  return res.json()
}

export async function launchResearchCampaign(payload: ResearchCampaignLaunchRequest): Promise<ResearchCampaignLaunchResponse> {
  const res = await fetch(`${API_URL}/research/campaigns/launch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to launch autonomous research campaign'))
  return res.json()
}

export async function controlResearchCampaign(campaignId: string, action: 'pause' | 'resume' | 'cancel'): Promise<{ campaign: Campaign; affected_episode_ids: string[]; cancelled_episode_ids: string[] }> {
  const res = await fetch(`${API_URL}/research/campaigns/${encodeURIComponent(campaignId)}/control`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, created_by: 'research_agent_ui' }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, `Failed to ${action} research campaign`))
  return res.json()
}

export async function getResearchReadiness(): Promise<ResearchReadiness> {
  const res = await fetch(`${API_URL}/research/readiness`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to check autonomous investigation readiness'))
  return res.json()
}

// ---------------------------------------------------------------------------
// Deep Hunt — keyless, free-form AI investigation (/agent/hunt/*).
// The current coding-agent session plans each turn; ShakerScan owns scope,
// active-tool authorization, budgets, evidence, and deterministic promotion.
// ---------------------------------------------------------------------------

export type AgentHuntStatus = 'awaiting_planner' | 'planning' | 'completed' | 'cancelled' | 'failed'

export interface AgentHuntTranscriptMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface AgentHuntResult {
  target_id: string
  objective: string
  iterations: number
  stop_reason: string
  tool_calls_made: number
  request_units_used: number
  active_actions_used: number
  model_tokens_used: number
  elapsed_seconds: number
  http_evidence_count: number
  abstained: boolean
  net_new_count: number
  verified_count: number
  persisted: Array<{ id: string; persisted: string; net_new: boolean; title: string; url: string | null }>
}

export interface AgentHuntSession {
  run_id: string | null
  target_id: string | null
  objective: string
  status: AgentHuntStatus
  awaiting_planner: boolean
  iterations: number
  max_iterations: number
  stop_reason: string | null
  mode: 'read_only' | 'deep_hunt'
  tool_surface: { allow_write: boolean; allow_active: boolean; note: string }
  transcript: AgentHuntTranscriptMessage[]
  next_action: string
  result: AgentHuntResult | null
}

export interface AgentHuntRunSummary {
  id: string
  target_id: string
  objective: string
  status: AgentHuntStatus
  stop_reason: string | null
  max_iterations: number
  iterations: string | null
  created_by: string | null
  created_at: string
  updated_at: string
}

export interface AgentVerifiedFinding {
  id: string
  title: string
  severity: string
  tool: string
  url: string
  last_verification_verdict: string
  first_seen_at: string
}

export interface AgentSuspectedFinding {
  id: string
  title: string
  severity: string
  tool: string
  url: string
  first_seen_at: string
  predicate: string | null
  family: string | null
  net_new_vs_known: boolean | null
  trust_tier: string
}

export interface AgentTwoTierFindings {
  target_id: string
  verified: AgentVerifiedFinding[]
  suspected: AgentSuspectedFinding[]
}

export interface AgentVerifyResult {
  finding_id: string
  verified: boolean
  verified_finding_id: string | null
  upgraded_in_place?: boolean
  hypothesis_id?: string
  superseded_suspected?: boolean
  family_proof?: { verdict: string | null; promotable: boolean | null; novelty_gate: unknown }
  error?: string
}

export async function startAgentHuntSession(
  targetId: string,
  payload: {
    objective?: string
    max_iterations?: number
    token_budget?: number
    mode?: 'read_only' | 'deep_hunt'
    approval_receipt_id?: string
  },
): Promise<AgentHuntSession> {
  const res = await fetch(`${API_URL}/agent/hunt/${encodeURIComponent(targetId)}/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to start Deep Hunt'))
  return res.json()
}

export async function getAgentHuntSession(runId: string): Promise<AgentHuntSession> {
  const res = await fetch(`${API_URL}/agent/hunt/session/${encodeURIComponent(runId)}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load Deep Hunt'))
  return res.json()
}

export async function replyAgentHuntSession(runId: string, reply: string): Promise<AgentHuntSession> {
  const res = await fetch(`${API_URL}/agent/hunt/session/${encodeURIComponent(runId)}/reply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reply }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to submit planner turn'))
  return res.json()
}

export async function cancelAgentHuntSession(runId: string): Promise<AgentHuntSession> {
  const res = await fetch(`${API_URL}/agent/hunt/session/${encodeURIComponent(runId)}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to cancel Deep Hunt'))
  return res.json()
}

export async function listAgentHuntRuns(params?: {
  target_id?: string
  status?: AgentHuntStatus
  limit?: number
}): Promise<{ runs: AgentHuntRunSummary[]; count: number }> {
  const query = new URLSearchParams()
  if (params?.target_id) query.set('target_id', params.target_id)
  if (params?.status) query.set('status', params.status)
  if (params?.limit) query.set('limit', String(params.limit))
  const qs = query.toString()
  const res = await fetch(`${API_URL}/agent/hunt/runs${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load Deep Hunt runs'))
  return res.json()
}

export async function getAgentTwoTierFindings(targetId: string): Promise<AgentTwoTierFindings> {
  const res = await fetch(`${API_URL}/agent/findings/${encodeURIComponent(targetId)}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load agent findings'))
  return res.json()
}

export async function verifySuspectedAgentFinding(findingId: string, approvalReceiptId: string): Promise<AgentVerifyResult> {
  const res = await fetch(`${API_URL}/agent/findings/${encodeURIComponent(findingId)}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approval_receipt_id: approvalReceiptId }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to verify finding'))
  return res.json()
}

export async function planResearchEpisodeStep(episodeId: string, payload: {
  execute?: boolean
  timeout_seconds?: number
  max_tokens?: number
  created_by?: string
} = {}): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes/${encodeURIComponent(episodeId)}/plan-step`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to run research planner step'))
  return res.json()
}

export async function setResearchEpisodeAutopilot(
  episodeId: string,
  enabled: boolean,
  plannerMode?: ResearchPlannerMode,
): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes/${encodeURIComponent(episodeId)}/autopilot`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled, planner_mode: plannerMode, created_by: 'research_agent_ui' }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, enabled ? 'Failed to resume autopilot' : 'Failed to pause autopilot'))
  return res.json()
}

export async function refreshResearchObservation(episodeId: string): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes/${encodeURIComponent(episodeId)}/observe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ created_by: 'research_agent_ui' }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to refresh research observation'))
  return res.json()
}

export async function cancelResearchEpisode(episodeId: string): Promise<ResearchEpisodeDetail> {
  const res = await fetch(`${API_URL}/research/episodes/${encodeURIComponent(episodeId)}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to cancel research episode'))
  return res.json()
}

export async function getArsenalTools(params?: { probeVersions?: boolean }): Promise<ArsenalToolsResponse> {
  const searchParams = new URLSearchParams()
  if (params?.probeVersions) searchParams.set('probe_versions', 'true')
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/arsenal/tools${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch tool status'))
  return res.json()
}

export async function getLocalAgents(params?: { probeVersions?: boolean }): Promise<LocalAgentsResponse> {
  const searchParams = new URLSearchParams()
  if (params?.probeVersions) searchParams.set('probe_versions', 'true')
  const query = searchParams.toString()
  const res = await fetch(`${API_URL}/agents/local${query ? `?${query}` : ''}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch local agents'))
  return res.json()
}

export async function createLocalAgentDryRunPlan(payload: LocalAgentPlanRequest): Promise<LocalAgentPlanResponse> {
  const res = await fetch(`${API_URL}/agents/local/plan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create local-agent dry-run plan'))
  return res.json()
}

export async function testLocalAgentCapability(payload: LocalAgentTestRequest): Promise<LocalAgentTestResponse> {
  const res = await fetch(`${API_URL}/agents/local/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to test local-agent capability'))
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
  limit?: number
  offset?: number
}): Promise<ExposureAssetsResponse> {
  const searchParams = new URLSearchParams()
  if (params?.root_domain) searchParams.set('root_domain', params.root_domain)
  if (params?.kind) searchParams.set('kind', params.kind)
  if (params?.limit) searchParams.set('limit', String(params.limit))
  if (params?.offset) searchParams.set('offset', String(params.offset))
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

export async function getModelIntakeTrustAnchors(activeOnly: boolean = true): Promise<{ trust_anchors: ModelIntakeTrustAnchor[] }> {
  const res = await fetch(`${API_URL}/model-intake/trust-anchors?active_only=${activeOnly}`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to load Model Intake trust anchors'))
  }
  return res.json()
}

export async function createModelIntakeTrustAnchor(data: {
  name: string
  description?: string
  public_key_pem?: string
  public_key_sha256?: string
  policy_profile?: string
  owner?: string
  is_active?: boolean
}): Promise<ModelIntakeTrustAnchor> {
  const res = await fetch(`${API_URL}/model-intake/trust-anchors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to save Model Intake trust anchor'))
  }
  return res.json()
}

export async function deactivateModelIntakeTrustAnchor(id: string): Promise<{ deactivated: boolean; trust_anchor: ModelIntakeTrustAnchor }> {
  const res = await fetch(`${API_URL}/model-intake/trust-anchors/${id}`, { method: 'DELETE' })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to deactivate Model Intake trust anchor'))
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

// Batch scan submission — queue the same options across many targets.
export async function submitBatch(
  targets: string[],
  options: Record<string, unknown> = {}
): Promise<{
  jobs: unknown[]
  errors: Array<{ target: string; status_code: number; error: unknown }>
  count: number
  queued_count: number
  failed_count: number
  requested_count: number
  status: 'queued' | 'partial' | 'failed'
}> {
  const res = await fetch(`${API_URL}/scans/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targets, options }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to submit batch scan'))
  return res.json()
}

// Merge scheme/trailing-slash duplicate target rows. Defaults to a dry-run preview.
export async function dedupeTargets(dryRun: boolean = true): Promise<{
  dry_run: boolean
  groups_found: number
  targets_merged: number
  groups_executed: number
  plan: Array<Record<string, unknown>>
}> {
  const res = await fetch(`${API_URL}/targets/dedupe?dry_run=${dryRun ? 'true' : 'false'}`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to dedupe targets'))
  return res.json()
}

// Emergency: clear pending scan jobs (optionally retest jobs too).
export async function clearQueue(includeRetests: boolean = false): Promise<{ cleared: number; retest_cleared: number }> {
  const res = await fetch(`${API_URL}/queue/clear?include_retests=${includeRetests ? 'true' : 'false'}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to clear queue'))
  return res.json()
}

// ASM inventory prune: re-probe reachability and retire phantom endpoints. Safe anytime.
export async function pruneAsmInventory(
  targetId: string,
  payload: { max_probe?: number; retire_threshold?: number } = {}
): Promise<{
  action: string
  target_id: string
  sweep: Record<string, unknown>
  inventory_total_before?: number | null
  inventory_testable_after?: number | null
  gone_after?: number | null
  reason: string
}> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/asm/prune`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to prune ASM inventory'))
  return res.json()
}

// AI Operations Router — deterministic NL → safe API plan. Dry-runs unless
// execution is confirmed AND the server flag AI_OPS_ROUTER_EXECUTE_ENABLED is set.
export interface AIOpsPlannedCall {
  method: string
  path: string
  body?: Record<string, unknown>
}

export interface AIOpsRouteResponse {
  intent: string
  dry_run: boolean
  execute_requested: boolean
  execution_allowed: boolean
  execution_blocked_reason?: string | null
  requires_confirmation: boolean
  safety_preset?: string | null
  missing_inputs: string[]
  non_goals?: string[]
  planned_api_call?: AIOpsPlannedCall | null
  planned_api_calls?: AIOpsPlannedCall[]
  explanation?: string | null
  authorization_assumption?: string | null
  blast_radius?: Record<string, unknown>
}

export async function routeAiOps(payload: {
  prompt?: string
  utterance?: string
  target?: string
  target_id?: string
  execute?: boolean
  confirm_execution?: boolean
  confirm_authorized?: boolean
  confirm_high_risk?: boolean
  auth_context?: Record<string, unknown>
}): Promise<AIOpsRouteResponse> {
  const res = await fetch(`${API_URL}/ai/ops/route`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to route AI operation'))
  return res.json()
}

// Targets
export async function getTarget(targetId: string): Promise<Target> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to fetch target'))
  return res.json()
}

export async function getTargets(params?: { includeInactive?: boolean; limit?: number }): Promise<{ targets: Target[]; total: number }> {
  const searchParams = new URLSearchParams()
  if (params?.includeInactive) searchParams.set('include_inactive', 'true')
  if (params?.limit) searchParams.set('limit', String(params.limit))

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
  opts?: { batch_size?: number; stale_days?: number; exploit_depth?: boolean; check_family?: string; endpoint_filter?: string; approval_receipt_id?: string }
): Promise<{
  scan_id: string
  job_id: string
  status: string
  batch_size: number
  check_family?: string
  endpoint_filter?: string | null
  inventory_total: number
  untested: number
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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
  opts?: { budget_profile?: string; approval_receipt_id?: string }
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
  opts?: { batch_size?: number; stale_days?: number; exploit_depth?: boolean; check_family?: string; endpoint_filter?: string; approval_receipt_id?: string }
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
  source_type?: 'dast' | 'ai' | 'ai_gate' | 'ai_session' | 'deep_hunt' | 'autonomous' | 'model_intake' | 'asm' | 'manual'
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
  driven_by?: 'autonomous_research'
  research_campaign_id?: string
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
  if (params?.driven_by) searchParams.set('driven_by', params.driven_by)
  if (params?.research_campaign_id) searchParams.set('research_campaign_id', params.research_campaign_id)
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
  hash?: string
  size_bytes?: number
  storage_uri?: string
  storage_backend?: string
  redaction_profile?: string
  retention_class?: string
  integrity_status?: string
  proof_state?: string
  metadata_json?: Record<string, unknown>
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

export interface GraphHypothesisGenerationResult {
  target_id: string
  candidate_count: number
  created: number
  endorsed: number
  hypotheses: Hypothesis[]
  execution_enabled: boolean
  findings_created: number
}

// First-class application graph for a target: routes, objects, and
// producer/consumer/auth-boundary edges persisted from scans.
export async function getApplicationGraph(targetId: string): Promise<ApplicationGraph> {
  const res = await fetch(`${API_URL}/targets/${targetId}/graph`)
  if (!res.ok) throw new Error('Failed to fetch application graph')
  return res.json()
}

export async function generateApplicationGraphHypotheses(targetId: string): Promise<GraphHypothesisGenerationResult> {
  const res = await fetch(`${API_URL}/targets/${targetId}/graph/hypotheses`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate graph hypotheses'))
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
  applied_exceptions?: unknown[]
  exceptions_applied?: unknown[]
  exception_summary?: {
    total?: number
    applied_count?: number
    profile_disables_exceptions?: boolean
    expired?: number
    expiring_soon?: number
    missing_owner?: number
    missing_approver?: number
    missing_compensating_controls?: number
    missing_expiry?: number
    inactive_or_revoked?: number
    review_required?: number
  }
  required_evidence_missing?: Array<{
    id?: string
    label?: string
    status?: string
    required_trust_anchor_ids?: string[]
    policy_profile?: string
    signature_trusted_root?: boolean | null
    signature_verification_status?: string | null
  }>
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
  required_trust_anchor_ids?: string[]
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
  required_trust_anchor_ids?: string[]
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

export interface FindingExceptionLifecycleSweepResult {
  dry_run: boolean
  target_id?: string | null
  candidate_count: number
  expired_count: number
  candidate_exception_ids: string[]
  execution_enabled: boolean
  operation_id?: string
}

export async function sweepFindingExceptionLifecycle(data: {
  dry_run?: boolean
  target_id?: string
  limit?: number
  approval_receipt_id?: string
}): Promise<FindingExceptionLifecycleSweepResult> {
  const res = await fetch(`${API_URL}/finding-exceptions/lifecycle/sweep`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to sweep exception lifecycle'))
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
    approval_receipt_id?: string
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
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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
    approval_receipt_id?: string
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
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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

export async function replayAiScan(
  id: string,
  params: {
    mode?: 'skipped' | 'errors' | 'family' | 'transcript' | 'all'
    probe_family?: string
    probe_id?: string
    transcript_index?: number
    requested_by?: string
    confirm_production?: boolean
    approval_receipt_id?: string
  } = {}
): Promise<{
  scan_id: string
  job_id: string
  status: string
  source_scan_id: string
  mode?: string
  probe_ids?: string[]
  probe_family?: string | null
  transcript?: Record<string, unknown> | null
  target_url: string
  ui_url?: string
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
}> {
  const res = await fetch(`${API_URL}/ai/scans/${id}/replay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  })
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to queue AI Gate scan replay'))
  }
  return res.json()
}

export interface AiScanCampaignHistoryRun {
  id: string
  ui_url?: string | null
  current: boolean
  status?: string | null
  target_url?: string | null
  created_at?: string | null
  completed_at?: string | null
  score?: number | null
  grade?: string | null
  findings_count: number
  decision?: string | null
  rationale?: string | null
  probe_pack?: string | null
  scan_profile?: string | null
  environment?: string | null
  planned: number
  executed: number
  skipped: number
  errors: number
  with_transcripts: number
  with_findings: number
  coverage_pct: number
  readiness_score: number
  stopped_by_request_budget?: boolean
  transcripts_hash?: string | null
  manifest_hash?: string | null
}

export interface AiReadinessTrendPoint {
  scan_id?: string | null
  completed_at?: string | null
  coverage_pct?: number | null
  readiness_score?: number | null
  findings_count?: number | null
  errors?: number | null
  decision?: string | null
  stopped_by_request_budget: boolean
}

export interface AiScanCampaignHistory {
  scan_id: string
  ai_target_id: string
  target_url?: string | null
  context: {
    probe_pack?: string | null
    scan_profile?: string | null
    environment?: string | null
  }
  runs: AiScanCampaignHistoryRun[]
  previous_run?: AiScanCampaignHistoryRun | null
  deltas?: {
    findings_count: number
    executed: number
    skipped: number
    errors: number
    coverage_pct: number
    decision_changed: boolean
  } | null
  trend_series?: {
    overall: AiReadinessTrendPoint[]
  }
  total_same_target_runs: number
}

export async function getAiScanCampaignHistory(id: string, limit: number = 6): Promise<AiScanCampaignHistory> {
  const res = await fetch(`${API_URL}/ai/scans/${id}/campaign-history?limit=${limit}`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to load AI Gate campaign history'))
  }
  return res.json()
}

export interface AiTargetCampaignHistoryContext {
  probe_pack?: string | null
  scan_profile?: string | null
  environment?: string | null
  runs_count: number
  latest_run?: AiScanCampaignHistoryRun | null
  previous_run?: AiScanCampaignHistoryRun | null
  deltas?: AiScanCampaignHistory['deltas'] | null
  readiness_trend?: AiReadinessTrend | null
  trend_points?: AiReadinessTrendPoint[]
}

export interface AiReadinessTrend {
  state: string
  latest_run_id?: string | null
  previous_run_id?: string | null
  coverage_pct?: number | null
  coverage_delta?: number | null
  findings_count?: number | null
  findings_delta?: number | null
  errors?: number | null
  errors_delta?: number | null
  decision?: string | null
  decision_changed: boolean
  stopped_by_request_budget: boolean
}

export interface AiTargetCampaignHistory {
  ai_target_id: string
  runs: AiScanCampaignHistoryRun[]
  contexts: AiTargetCampaignHistoryContext[]
  latest_run?: AiScanCampaignHistoryRun | null
  readiness_trends?: {
    overall: AiReadinessTrend
    contexts: Array<{
      probe_pack?: string | null
      scan_profile?: string | null
      environment?: string | null
      runs_count: number
      trend: AiReadinessTrend
    }>
  }
  trend_series?: {
    overall: AiReadinessTrendPoint[]
    contexts: Array<{
      probe_pack?: string | null
      scan_profile?: string | null
      environment?: string | null
      runs_count: number
      points: AiReadinessTrendPoint[]
    }>
  }
  summary: {
    total_runs: number
    contexts: number
    blocked_runs: number
    errored_runs: number
    budget_stopped_runs: number
  }
}

export async function getAiTargetCampaignHistory(id: string, limit: number = 12): Promise<AiTargetCampaignHistory> {
  const res = await fetch(`${API_URL}/ai/targets/${id}/campaign-history?limit=${limit}`)
  if (!res.ok) {
    throw new Error(await getApiErrorMessage(res, 'Failed to load AI Gate target campaign history'))
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
  scope: 'scan' | 'verify' | 'research'
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

// Durable AI surface inventory (GET /ai/surfaces) with attempt rollups, and the
// per-surface attempt ledger backfilled from completed AI Gate scans.
export interface AISurface {
  id: string
  ai_target_id: string
  surface_type: string
  endpoint_url: string
  auth_kind?: string | null
  owner?: string | null
  environment?: string | null
  risk_tier?: string | null
  data_classification?: string | null
  tools_count: number
  metadata_json?: string | Record<string, unknown> | null
  last_seen?: string | null
  updated_at?: string | null
  last_tested?: string | null
  created_at?: string | null
  attempt_count: number
  last_attempt_at?: string | null
  total_findings: number
  total_crit_high: number
}

export interface AISurfaceAttempt {
  id: string
  surface_id: string
  scan_id: string
  probe_pack?: string | null
  scan_profile?: string | null
  environment?: string | null
  families: string[]
  status: string
  proof_state?: string | null
  findings_count: number
  critical_high_count: number
  started_at?: string | null
  completed_at?: string | null
  created_at?: string | null
}

export interface AISurfaceSyncResult {
  surfaces_upserted: number
  attempts_written: number
  attempts_skipped_no_surface: number
  scans_scanned: number
  partial: boolean
}

export async function syncAISurfaces(): Promise<AISurfaceSyncResult> {
  const res = await fetch(`${API_URL}/ai/surfaces/sync`, { method: 'POST' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to sync AI surfaces'))
  return res.json()
}

export async function getAISurfaces(): Promise<{ ai_surfaces: AISurface[] }> {
  const res = await fetch(`${API_URL}/ai/surfaces`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load AI surfaces'))
  return res.json()
}

export async function getAISurfaceAttempts(id: string): Promise<{ surface: AISurface; attempts: AISurfaceAttempt[] }> {
  const res = await fetch(`${API_URL}/ai/surfaces/${encodeURIComponent(id)}/attempts`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load AI surface attempts'))
  return res.json()
}

export async function scanAITarget(
  id: string,
  data: {
    probe_pack: AIProbePack
    scan_profile: AIScanProfile
    environment: AIEnvironment
    confirm_production?: boolean
    approval_receipt_id?: string
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
  approval_receipt_id?: string | null
  scope_receipt_id?: string | null
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
  schedule_kind?: 'normal_scan' | 'asm_improve' | 'evidence_retention_sweep'
  scan_type: string
  scan_options?: Record<string, unknown>
  is_active: boolean
  last_run_at?: string
  next_run_at?: string
  schedule_health?: {
    status: 'attention' | 'warning' | 'ok' | string
    reason?: string | null
    failure_kind?: string | null
    recent_failed_count?: number | null
    timeout_failed_count?: number | null
    lookback_days?: number | null
    latest_failed_scan_id?: string | null
    latest_failed_at?: string | null
    latest_error?: string | null
    recommendation?: string | null
    suggested_scan_type?: string | null
  }
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
  schedule_kind?: 'normal_scan' | 'asm_improve'
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
  credential_profile_id?: string | null
  principal_auth_state?: string | null
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

export interface TargetPrincipal {
  id: string
  target_id: string
  label: string
  role: string
  tenant_id?: string | null
  auth_state: string
  credential_profile?: string | null
  credential_configured: boolean
  is_active: boolean
  metadata_json: Record<string, unknown>
}

export interface TargetCredentialProfile {
  id: string
  target_id: string
  name: string
  auth_kind: 'authorization_header' | 'cookie'
  secret_preview?: string | null
  secret_configured: boolean
  storage_encrypted: boolean
  encryption_available: boolean
  expires_at?: string | null
  status: 'active' | 'expired' | 'inactive'
  refresh_required: boolean
  execution_compatible: boolean
  is_active: boolean
  rotated_at?: string | null
  metadata_json: Record<string, unknown>
}

export interface TargetCredentialProfilePayload {
  name: string
  auth_kind: TargetCredentialProfile['auth_kind']
  secret: string
  expires_at?: string
  metadata_json?: Record<string, unknown>
}

export interface TargetPrincipalExpectation {
  id: string
  method: string
  path: string
  param_shape?: string | null
  param_location?: string | null
  principal_id?: string | null
  principal_label?: string | null
  principal_auth_state?: string | null
  principal_role?: string | null
  tenant_id?: string | null
  expected_access: 'allow' | 'deny' | 'requires_role' | 'unknown'
  expected_http_status?: number | null
  expectation_source?: string | null
}

export interface TargetPrincipalExpectationPayload {
  endpoint_id?: string
  method: string
  path: string
  param_shape?: string
  param_location?: string
  principal_id?: string
  principal_role?: string
  tenant_id?: string
  expected_access: TargetPrincipalExpectation['expected_access']
  expected_http_status?: number
  expectation_source?: string
  metadata_json?: Record<string, unknown>
  approval_receipt_id?: string
}

export interface TargetPrincipalMatrixResponse {
  target_id: string
  principals: TargetPrincipal[]
  expectations: TargetPrincipalExpectation[]
  count: number
  execution_enabled: boolean
  findings_created: number
}

export interface TargetInvariantVerificationPlan {
  verifier: string
  proof_family: string
  deterministic_family_supported: boolean
  required_inputs: string[]
  missing_inputs: string[]
  ready_to_execute: boolean
  requires_two_live_executions: boolean
  requires_restoration: boolean
  promotion_authority: boolean
  promotion_gate?: string | null
}

export interface TargetInvariantContract {
  id?: string | null
  contract_kind: 'access_control' | 'field_constraint' | 'workflow_transition' | 'ownership'
  title?: string
  source_text?: string | null
  subject_role?: string | null
  action?: string | null
  resource?: string | null
  method?: string | null
  path?: string | null
  field_name?: string | null
  operator?: string | null
  expected_value?: unknown
  expected_access?: 'allow' | 'deny' | 'requires_role' | null
  conditions: Record<string, unknown>
  status?: 'draft' | 'approved' | 'retired'
  ready_for_approval?: boolean
  approval_errors?: string[]
  planning_authority: boolean
  promotion_authority: boolean
  verification_plan?: TargetInvariantVerificationPlan
}

export interface TargetInvariantListResponse {
  target_id: string
  contracts: TargetInvariantContract[]
  count: number
  approved_count: number
  draft_count: number
}

export interface TargetInvariantCompileResponse {
  target_id: string
  candidates: TargetInvariantContract[]
  candidate_count: number
  matched: boolean
  warnings: string[]
  persisted_drafts: TargetInvariantContract[]
  persisted_count: number
  planning_authority: boolean
  promotion_authority: boolean
}

export interface TargetPrincipalPayload {
  label: string
  role: string
  tenant_id?: string
  auth_state: string
  credential_profile?: string
  is_active?: boolean
  metadata_json?: Record<string, unknown>
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

export async function getTargetPrincipalMatrix(targetId: string, limit: number = 200): Promise<TargetPrincipalMatrixResponse> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principal-matrix?limit=${limit}`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load target principal matrix'))
  return res.json()
}

export async function getTargetInvariants(targetId: string): Promise<TargetInvariantListResponse> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/invariants?include_drafts=true`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load target invariants'))
  return res.json()
}

export async function compileTargetInvariant(
  targetId: string,
  payload: { rule_text: string; method?: string; path?: string; persist_drafts?: boolean; approval_receipt_id?: string },
): Promise<TargetInvariantCompileResponse> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/invariants/compile`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to compile target invariant'))
  return res.json()
}

export async function approveTargetInvariant(
  targetId: string,
  contractId: string,
  approvalReceiptId: string,
): Promise<{ contract: TargetInvariantContract; planning_authority: boolean; promotion_authority: boolean }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/invariants/${encodeURIComponent(contractId)}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      approval_receipt_id: approvalReceiptId,
      approved_by: 'interactive-ui',
      confirm_authoritative: true,
    }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to approve target invariant'))
  return res.json()
}

export async function generateTargetInvariantHypotheses(targetId: string): Promise<{ created: number; hypotheses: Array<Record<string, unknown>> }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/invariants/hypotheses`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ created_by: 'interactive-ui' }),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to generate invariant hypotheses'))
  return res.json()
}

export async function getTargetCredentialProfiles(targetId: string): Promise<{ target_id: string; profiles: TargetCredentialProfile[]; count: number }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/credential-profiles`)
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to load credential profiles'))
  return res.json()
}

export async function createTargetCredentialProfile(targetId: string, payload: TargetCredentialProfilePayload): Promise<{ profile: TargetCredentialProfile }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/credential-profiles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create credential profile'))
  return res.json()
}

export async function rotateTargetCredentialProfile(targetId: string, profileId: string, payload: { secret: string; expires_at?: string; clear_expiry?: boolean }): Promise<{ profile: TargetCredentialProfile }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/credential-profiles/${encodeURIComponent(profileId)}/rotate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to rotate credential profile'))
  return res.json()
}

export async function deactivateTargetCredentialProfile(targetId: string, profileId: string): Promise<{ status: string; profile: TargetCredentialProfile }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/credential-profiles/${encodeURIComponent(profileId)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to deactivate credential profile'))
  return res.json()
}

export async function createTargetPrincipal(targetId: string, payload: TargetPrincipalPayload): Promise<{ principal: TargetPrincipal; execution_enabled: boolean; findings_created: number }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principals`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to create target principal'))
  return res.json()
}

export async function updateTargetPrincipal(targetId: string, principalId: string, payload: Partial<TargetPrincipalPayload>): Promise<{ principal: TargetPrincipal; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principals/${encodeURIComponent(principalId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to update target principal'))
  return res.json()
}

export async function deactivateTargetPrincipal(targetId: string, principalId: string): Promise<{ status: string; target_id: string; principal_id: string; execution_enabled: boolean }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principals/${encodeURIComponent(principalId)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to deactivate target principal'))
  return res.json()
}

export async function createTargetPolicyApproval(targetId: string, targetUrl: string, ttlMinutes: number = 120, riskTier: 'active' | 'credential' = 'active'): Promise<string> {
  const parsed = new URL(targetUrl)
  const scope = await previewScopeReceipt({
    url: targetUrl,
    target_id: targetId,
    allowed_hosts: [parsed.hostname],
    environment: 'production',
  })
  if (scope.scope_receipt.verdict === 'blocked') {
    throw new Error(`Target policy scope is blocked: ${scope.scope_receipt.blocked_by.join(', ')}`)
  }
  const confirmations = ['confirm_authorized']
  if (scope.scope_receipt.verdict === 'needs_approval') confirmations.push('confirm_scope_reviewed')
  const approval = await createApprovalReceipt({
    scope_receipt_id: scope.scope_receipt.receipt_id,
    risk_tier: riskTier,
    confirmations,
    approved_by: 'interactive-ui',
    // Durable hunts may run for seven days. Keep the receipt bounded to that ceiling plus a
    // small launch/supervisor handoff buffer so the final episode does not outlive approval.
    expires_at: new Date(Date.now() + Math.max(5, Math.min(ttlMinutes, 7 * 24 * 60 + 15)) * 60_000).toISOString(),
  })
  return approval.approval_receipt.id
}

export async function upsertTargetPrincipalExpectation(targetId: string, payload: TargetPrincipalExpectationPayload): Promise<{ expectation: TargetPrincipalExpectation; execution_enabled: boolean; findings_created: number; operation_id: string }> {
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principal-matrix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to save principal expectation'))
  return res.json()
}

export async function deleteTargetPrincipalExpectation(targetId: string, expectationId: string, approvalReceiptId: string): Promise<{ status: string; target_id: string; expectation_id: string; execution_enabled: boolean; findings_created: number; operation_id: string }> {
  const query = new URLSearchParams({ approval_receipt_id: approvalReceiptId })
  const res = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/principal-matrix/${encodeURIComponent(expectationId)}?${query}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await getApiErrorMessage(res, 'Failed to delete principal expectation'))
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
