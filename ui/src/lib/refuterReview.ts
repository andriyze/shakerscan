export interface RefuterReviewPlanView {
  available: boolean
  steps: Array<{ id: string; label: string; command: string; mode: string }>
  reviewQuestions: string[]
  benignExplanations: string[]
  requiredEvidenceRefs: string[]
  verdictPaths: Array<{ verdict: string; description: string }>
}

export interface RefuterAnnotationInput {
  mode: 'signal' | 'human_verdict'
  signal: 'support' | 'question' | 'weaken' | 'refute'
  verdict?: 'supported' | 'weakened' | 'refuted' | 'inconclusive'
  observedBehavior: string
  notes: string
  evidenceObjectIds: string[]
  toolReceiptIds: string[]
  createdBy: string
}

export interface RefuterReviewIdentity {
  id: string
  subject_type: string
  subject_id?: string | null
  target_id?: string | null
  finding_id?: string | null
  hypothesis_id?: string | null
  campaign_id?: string | null
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && Boolean(item.trim())) : []
}

export function buildRefuterReviewPlanView(metadata: unknown): RefuterReviewPlanView {
  const root = record(metadata)
  const plan = record(root.automation_plan)
  const bundle = record(plan.counterevidence_bundle)
  const steps = (Array.isArray(plan.steps) ? plan.steps : []).map(record).map((step) => ({
    id: String(step.id || ''),
    label: String(step.label || step.id || 'Review step'),
    command: String(step.command || 'refuter_review.record'),
    mode: String(step.mode || 'planned_not_executed'),
  })).filter((step) => step.id)
  const paths = record(bundle.verdict_paths)

  return {
    available: Object.keys(plan).length > 0,
    steps,
    reviewQuestions: strings(bundle.review_questions),
    benignExplanations: strings(bundle.benign_explanations_to_test),
    requiredEvidenceRefs: strings(bundle.required_evidence_refs),
    verdictPaths: Object.entries(paths).map(([verdict, description]) => ({ verdict, description: String(description) })),
  }
}

export function buildRefuterAnnotationPayload(review: RefuterReviewIdentity, input: RefuterAnnotationInput) {
  const verdict = input.mode === 'human_verdict' ? input.verdict : undefined
  const signalByVerdict = {
    supported: 'support',
    weakened: 'weaken',
    refuted: 'refute',
    inconclusive: 'question',
  } as const
  return {
    subject_type: review.subject_type,
    subject_id: review.subject_id || undefined,
    target_id: review.target_id || undefined,
    finding_id: review.finding_id || undefined,
    hypothesis_id: review.hypothesis_id || undefined,
    campaign_id: review.campaign_id || undefined,
    trigger_reason: `Analyst counterevidence for refuter review ${review.id}`,
    refuter_signal: verdict ? signalByVerdict[verdict] : input.signal,
    refuter_verdict: verdict,
    verdict_basis: verdict ? 'human_approved_review' as const : 'signal_only' as const,
    evidence_object_ids: input.evidenceObjectIds,
    tool_receipt_ids: input.toolReceiptIds,
    counterevidence: {
      observed_behavior: input.observedBehavior || 'inconclusive',
      source_refuter_review_id: review.id,
    },
    notes: input.notes || undefined,
    metadata_json: { parent_refuter_review_id: review.id, annotation_mode: input.mode },
    created_by: input.createdBy || 'operator',
  }
}
