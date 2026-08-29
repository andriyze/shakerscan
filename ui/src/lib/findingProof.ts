export function canonicalFindingProofVerified(finding: unknown): boolean {
  if (!finding || typeof finding !== 'object') return false
  const value = finding as { is_verified?: unknown; proof_state?: unknown }
  return value.is_verified === true && value.proof_state === 'verified'
}
