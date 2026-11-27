const BASE_FIELDS = [
  'version', 'name', 'owner', 'attacker', 'identity', 'resource',
  'response_path', 'baseline_prompt', 'attacks', 'repetitions',
] as const

/** Use saved fixture bindings without copying execution fragments or secrets. */
export function boundaryBaseFromTarget(metadata: Record<string, unknown> | null | undefined): Record<string, unknown> | null {
  const contract = metadata?.boundary_contract
  if (!contract || typeof contract !== 'object' || Array.isArray(contract)) return null
  const source = contract as Record<string, unknown>
  const base = Object.fromEntries(BASE_FIELDS.filter((key) => key in source).map((key) => [key, source[key]]))
  return BASE_FIELDS.slice(0, 7).every((key) => key in base) ? base : null
}

export function boundaryCandidateIds(hunt: {
  outcome_summary?: { candidate_ids?: string[] } | null
  actions?: Array<{ result?: { reference_ids?: { candidate_ids?: string[] } } }>
}): string[] {
  const ids = [
    ...(hunt.outcome_summary?.candidate_ids || []),
    ...(hunt.actions || []).flatMap((action) => action.result?.reference_ids?.candidate_ids || []),
  ]
  return [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0))]
}

export function boundaryScanMessage(status: string | null | undefined): string {
  if (status === 'completed') return 'Scan complete. Stored evidence is ready for regression export or evaluation.'
  if (status === 'failed' || status === 'cancelled') return `Scan ${status}. Review its result before continuing.`
  if (status === 'pending' || status === 'queued' || status === 'running') return 'Scan is still queued or running. Refresh its status before continuing.'
  return 'Load a scan to check whether the verification completed.'
}

export function savedArtifactMatchesSource(
  supplied: { artifact_sha256: string; ai_target_id: string; source_scan_id: string },
  rebuilt: { artifact_sha256: string; ai_target_id: string; source_scan_id: string },
): boolean {
  return supplied.artifact_sha256 === rebuilt.artifact_sha256
    && supplied.ai_target_id === rebuilt.ai_target_id
    && supplied.source_scan_id === rebuilt.source_scan_id
}
