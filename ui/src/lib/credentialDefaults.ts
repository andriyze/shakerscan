// Which credential a new Scan or Hunt starts with for a lane or slot: the target's own credentials
// before ones shared with it, then by name. The form shows the choice and the operator can clear it.

export interface DefaultableCredential {
  id: string
  name: string
  principal_slot: string
  execution_compatible: boolean
  shared?: boolean
}

export function preferredCredentialId<T extends DefaultableCredential>(
  profiles: readonly T[],
  accept: (profile: T) => boolean,
  exclude: readonly string[] = [],
): string {
  const candidates = profiles
    .filter((profile) => profile.execution_compatible && accept(profile) && !exclude.includes(profile.id))
    .sort((a, b) => Number(Boolean(a.shared)) - Number(Boolean(b.shared)) || a.name.localeCompare(b.name))
  return candidates[0]?.id || ''
}

// SSH is selected deliberately for authentication or separately confirmed command plans.
export const DEFAULTED_HUNT_SLOTS = ['primary', 'secondary', 'service'] as const

export function defaultHuntCredentialIds<T extends DefaultableCredential>(
  profiles: readonly T[],
): Record<'primary' | 'secondary' | 'service' | 'ssh', string> {
  const chosen = { primary: '', secondary: '', service: '', ssh: '' }
  for (const slot of DEFAULTED_HUNT_SLOTS) {
    chosen[slot] = preferredCredentialId(profiles, (profile) => profile.principal_slot === slot)
  }
  return chosen
}
