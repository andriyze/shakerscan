/** A device service policy as a person reads it in a choice list. Built-in policies are named by
 * an identifier such as `camera-baseline-v1`; policies a person created keep the name they gave. */
export function devicePolicyLabel(policy) {
  const name = typeof policy?.name === 'string' ? policy.name : ''
  const builtIn = policy?.is_builtin === true && /^[a-z0-9]+(?:-[a-z0-9]+)*-v\d+$/.test(name)
  if (!builtIn) return name || 'Unnamed policy'
  const version = name.slice(name.lastIndexOf('-v') + 2)
  const words = name.slice(0, name.lastIndexOf('-v')).split('-').join(' ')
  return `${words.charAt(0).toUpperCase()}${words.slice(1)} (version ${version})`
}
