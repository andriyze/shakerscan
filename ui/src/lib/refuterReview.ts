export interface RefuterReviewPlanView {
  available: boolean
  steps: Array<{ id: string; label: string; command: string; mode: string }>
  reviewQuestions: string[]
  benignExplanations: string[]
  requiredEvidenceRefs: string[]
  verdictPaths: Array<{ verdict: string; description: string }>
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
