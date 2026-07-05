export interface AiGateCampaignFamily {
  family: string
  planned: number
  executed: number
  skipped: number
  with_transcript: number
  with_findings: number
  errors: number
}

export interface AiGateCampaignFinding {
  id?: string | null
  title: string
  severity: string
  probe_id?: string | null
  probe_family?: string | null
}

export interface AiGateCampaignReview {
  available: boolean
  target_name?: string | null
  target_type?: string | null
  probe_pack?: string | null
  scan_profile?: string | null
  environment?: string | null
  decision?: string | null
  rationale?: string | null
  planned: number
  executed: number
  skipped: number
  with_transcripts: number
  with_findings: number
  errors: number
  request_budget?: number | null
  stopped_by_rate_limit: boolean
  stopped_by_request_budget: boolean
  planned_hash?: string | null
  executed_hash?: string | null
  transcripts_hash?: string | null
  execution_plan_hash?: string | null
  evidence_manifest_hash?: string | null
  semantic_judge_status?: string | null
  semantic_reviewed_count: number
  judging_gate_status?: string | null
  families: AiGateCampaignFamily[]
  skipped_reasons: Array<{ reason: string; count: number; families: string[] }>
  findings: AiGateCampaignFinding[]
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function num(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function familyLabel(value: string): string {
  return value.replace(/_/g, ' ')
}

function evidenceForFinding(finding: Record<string, unknown>): Record<string, unknown> {
  return asRecord(finding.evidence)
}

export function buildAiGateCampaignReview(result: unknown): AiGateCampaignReview {
  const root = asRecord(result)
  const aiGate = asRecord(root.ai_gate)
  if (!Object.keys(aiGate).length) {
    return {
      available: false,
      planned: 0,
      executed: 0,
      skipped: 0,
      with_transcripts: 0,
      with_findings: 0,
      errors: 0,
      stopped_by_rate_limit: false,
      stopped_by_request_budget: false,
      semantic_reviewed_count: 0,
      families: [],
      skipped_reasons: [],
      findings: [],
    }
  }

  const coverage = asRecord(aiGate.coverage_matrix)
  const summary = asRecord(coverage.summary)
  const evidenceManifest = asRecord(aiGate.evidence_manifest)
  const probeCatalog = asRecord(evidenceManifest.probe_catalog)
  const evidence = asRecord(evidenceManifest.evidence)
  const executionPlan = asRecord(aiGate.execution_plan)
  const semanticJudge = asRecord(executionPlan.semantic_judge)
  const judgingGate = asRecord(executionPlan.judging_quality_gate)
  const usage = asRecord(aiGate.usage)
  const decision = asRecord(aiGate.decision)

  const families = Object.entries(asRecord(coverage.by_family))
    .map(([family, raw]) => {
      const bucket = asRecord(raw)
      const planned = num(bucket.planned)
      const executed = num(bucket.executed)
      return {
        family,
        planned,
        executed,
        skipped: Math.max(0, planned - executed),
        with_transcript: num(bucket.with_transcript),
        with_findings: num(bucket.with_findings),
        errors: num(bucket.errors),
      }
    })
    .sort((a, b) => b.planned - a.planned || familyLabel(a.family).localeCompare(familyLabel(b.family)))

  const skippedByReason = new Map<string, { reason: string; count: number; families: Set<string> }>()
  for (const item of asArray(coverage.skipped)) {
    const skipped = asRecord(item)
    const reason = str(skipped.reason) || 'not_executed'
    const family = str(skipped.family) || 'unknown'
    const bucket = skippedByReason.get(reason) || { reason, count: 0, families: new Set<string>() }
    bucket.count += 1
    bucket.families.add(family)
    skippedByReason.set(reason, bucket)
  }

  const findings = asArray(root.findings)
    .map((raw) => asRecord(raw))
    .filter((finding) => String(finding.source || '') === 'ai_gate' || Boolean(finding.ai_target_id) || Boolean(evidenceForFinding(finding).probe_id))
    .slice(0, 8)
    .map((finding) => {
      const evidence = evidenceForFinding(finding)
      return {
        id: str(finding.id),
        title: str(finding.title) || 'AI Gate finding',
        severity: str(finding.severity) || 'info',
        probe_id: str(evidence.probe_id),
        probe_family: str(evidence.probe_family || evidence.family),
      }
    })

  return {
    available: true,
    target_name: str(aiGate.target_name),
    target_type: str(aiGate.target_type),
    probe_pack: str(aiGate.probe_pack),
    scan_profile: str(aiGate.scan_profile),
    environment: str(decision.environment),
    decision: str(decision.decision),
    rationale: str(decision.rationale),
    planned: num(summary.planned),
    executed: num(summary.executed),
    skipped: num(summary.skipped),
    with_transcripts: num(summary.with_transcripts),
    with_findings: num(summary.with_findings),
    errors: num(summary.errors),
    request_budget: summary.request_budget === undefined ? null : num(summary.request_budget),
    stopped_by_rate_limit: Boolean(summary.stopped_by_rate_limit || usage.stopped_by_rate_limit),
    stopped_by_request_budget: Boolean(usage.stopped_by_request_budget),
    planned_hash: str(probeCatalog.planned_hash),
    executed_hash: str(probeCatalog.executed_hash),
    transcripts_hash: str(evidence.transcripts_hash),
    execution_plan_hash: str(evidence.execution_plan_hash),
    evidence_manifest_hash: str(evidenceManifest.manifest_hash),
    semantic_judge_status: str(semanticJudge.status),
    semantic_reviewed_count: num(semanticJudge.reviewed_probe_count),
    judging_gate_status: str(judgingGate.status),
    families,
    skipped_reasons: Array.from(skippedByReason.values())
      .map((bucket) => ({
        reason: bucket.reason,
        count: bucket.count,
        families: Array.from(bucket.families).sort(),
      }))
      .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason)),
    findings,
  }
}
