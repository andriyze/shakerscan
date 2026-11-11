// Why a release decision was made under the policy profile it names.

/**
 * A short reason beside the profile: what selected it. `policy_profile_basis` is "scan" (the run
 * named or recorded it), "target_environment", or "default" (neither did). Null when the
 * decision does not say.
 */
export function releaseProfileReason(decision) {
  const basis = String(decision?.policy_profile_basis || '')
  const environment = String(decision?.target_environment || '').trim()
  if (basis === 'target_environment') return "from the target's environment"
  if (basis === 'scan') return 'set for this run'
  if (basis === 'default') {
    return environment
      ? `default: no profile is defined for the target's environment "${environment}"`
      : 'default: the run names no environment'
  }
  return null
}
