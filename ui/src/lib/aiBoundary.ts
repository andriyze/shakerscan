import { API_URL, getApiErrorMessage } from './apiConfig'

export interface BoundaryPrincipal {
  role: string
  subject: string
  tenant: string
  resource_id: string
}

export interface BoundaryDiscoveryDraft {
  draft_id: string
  origin: string
  kind: 'cross_tenant_read'
  agent_paths: string[]
  fixture_prefill: {
    owner: { resource_id: string }; attacker: { resource_id: string }
    [key: string]: unknown
  }
  missing_facts: string[]
  field_provenance: Record<string, Array<{ capture_id: string; action_id: string }>>
  candidate_request: {
    family: string; locus: Record<string, unknown>; title: string; claim: string
    severity: 'info'; evidence_refs: string[]
  }
}

export interface BoundaryDiscovery {
  status: 'drafts_available' | 'needs_evidence'
  drafts: BoundaryDiscoveryDraft[]
  coverage: {
    captures_read: number; captures_truncated: boolean; structure_unavailable: number
    drafts_truncated: boolean; historical_backfill_performed: false
  }
  execution_enabled: false
}

export interface BoundaryProposal {
  schema_version: 'boundary-proposal/v1'
  status: 'ready' | 'needs_context'
  kind: string
  hypothesis_id: string
  hypothesis_sha256: string
  missing_facts: string[]
  contract_fragment: Record<string, unknown> | null
  provenance: Array<Record<string, string>>
  principal_bindings: { owner: BoundaryPrincipal; attacker: BoundaryPrincipal }
}

export interface BoundaryContext {
  status: 'context_available' | 'needs_context'
  kind: string | null
  context: { missing_fields: string[]; issues: string[] }
  evidence: { resolved: Array<{ id: string; kind: string }>; complete_for_inspected_references: boolean }
  execution_enabled: false
}

export interface BoundaryHandoff {
  status: 'ready' | 'needs_context'
  missing_facts: string[]
  proposal: BoundaryProposal | null
  candidate_context: BoundaryContext
  verification_performed: false
}

export interface BoundaryMaterialization {
  boundary_contract_sha256: string
  boundary_contract: Record<string, unknown>
}

export interface BoundaryRegressionArtifact {
  schema_version: 'ai-boundary-regression/v1'
  ai_target_id: string
  source_scan_id: string
  boundary_contract_sha256: string
  artifact_sha256: string
  verify_request: {
    proposal: BoundaryProposal
    boundary_base: Record<string, unknown>
    environment: 'preview' | 'staging' | 'development'
    scan_profile: 'smoke' | 'trace' | 'standard' | 'deep'
  }
  acceptance: { required_legitimate_controls: string[] }
}

export interface BoundaryRegressionEvaluation {
  status: 'pass' | 'fail' | 'inconclusive'
  reasons: string[]
  missing_legitimate_controls: string[]
  scan_id: string
  boundary_contract_sha256: string
}

async function responseJson<T>(responsePromise: Promise<Response>, fallback: string): Promise<T> {
  const response = await responsePromise
  if (!response.ok) throw new Error(await getApiErrorMessage(response, fallback))
  return response.json() as Promise<T>
}

function candidateUrl(huntId: string, candidateId: string): string {
  return `${API_URL}/hunts/${encodeURIComponent(huntId)}/candidates/${encodeURIComponent(candidateId)}`
}

export async function discoverBoundaryDrafts(huntId: string): Promise<BoundaryDiscovery> {
  return responseJson(fetch(`${API_URL}/hunts/${encodeURIComponent(huntId)}/boundary-discovery`, {
    method: 'POST', cache: 'no-store',
  }), 'Failed to discover boundary drafts')
}

export async function prepareBoundaryCandidate(
  huntId: string, draft: BoundaryDiscoveryDraft,
): Promise<{ candidate: { id: string } }> {
  return responseJson(fetch(`${API_URL}/hunts/${encodeURIComponent(huntId)}/candidates`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(draft.candidate_request),
  }), 'Failed to prepare boundary candidate')
}

export async function inspectBoundaryCandidate(huntId: string, candidateId: string): Promise<BoundaryContext> {
  return responseJson(fetch(`${candidateUrl(huntId, candidateId)}/boundary-context`, { cache: 'no-store' }), 'Failed to inspect Hunt candidate')
}

export async function compileBoundaryCandidate(
  huntId: string, candidateId: string,
  request: { owner: BoundaryPrincipal; attacker: BoundaryPrincipal; expected_rule?: string },
): Promise<BoundaryHandoff> {
  return responseJson(fetch(`${candidateUrl(huntId, candidateId)}/boundary-proposal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
  }), 'Failed to compile Hunt candidate')
}

export async function materializeBoundaryProposal(
  proposal: BoundaryProposal, boundaryBase: Record<string, unknown>,
): Promise<BoundaryMaterialization> {
  return responseJson(fetch(`${API_URL}/ai/boundary/proposals/materialize`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal, boundary_base: boundaryBase }),
  }), 'Failed to materialize boundary proposal')
}

export async function queueBoundaryVerification(
  targetId: string, proposal: BoundaryProposal, boundaryBase: Record<string, unknown>,
  environment: 'preview' | 'staging' | 'development',
  scanProfile: 'smoke' | 'trace' | 'standard' | 'deep',
): Promise<{ scan_id: string; status: string }> {
  return responseJson(fetch(`${API_URL}/ai/targets/${encodeURIComponent(targetId)}/boundary/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal, boundary_base: boundaryBase, environment, scan_profile: scanProfile }),
  }), 'Failed to queue AI Boundary verification')
}

export async function exportBoundaryRegression(
  targetId: string, sourceScanId: string, proposal: BoundaryProposal,
  boundaryBase: Record<string, unknown>,
): Promise<BoundaryRegressionArtifact> {
  return responseJson(fetch(`${API_URL}/ai/targets/${encodeURIComponent(targetId)}/boundary/regressions/export`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_scan_id: sourceScanId, proposal, boundary_base: boundaryBase }),
  }), 'Failed to export AI Boundary regression')
}

export async function evaluateBoundaryRegression(
  targetId: string, artifact: BoundaryRegressionArtifact, scanId: string,
): Promise<BoundaryRegressionEvaluation> {
  return responseJson(fetch(`${API_URL}/ai/targets/${encodeURIComponent(targetId)}/boundary/regressions/evaluate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ artifact, scan_id: scanId }),
  }), 'Failed to evaluate AI Boundary regression')
}
