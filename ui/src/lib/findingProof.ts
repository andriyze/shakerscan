export function canonicalFindingProofVerified(finding: unknown): boolean {
  if (!finding || typeof finding !== 'object') return false
  const value = finding as { proof_state?: unknown }
  // Findings APIs overwrite this with the server's authoritative projection.
  // Do not recompute proof from a second client-side boolean predicate.
  return value.proof_state === 'verified'
}
