// UI presentation only. The deployment gateway must independently enforce every API request.
export type WorkspaceCapabilities = {
  schema: 'shakerscan.workspace-capabilities/v1'
  mode: 'managed'
  features: Record<string, { state: 'enabled' | 'unavailable' | 'excluded' | 'setup_required'; reason?: string }>
  navigation: Record<string, string>
  ui_routes: string[]
  scan_limits?: Record<string, number>
}

export function workspaceScanCeiling(name: string, engineCeiling?: number): number | undefined {
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  const hosted = policy?.schema === 'shakerscan.workspace-capabilities/v1'
    && policy.mode === 'managed' ? policy.scan_limits?.[name] : undefined
  if (typeof hosted !== 'number' || !Number.isSafeInteger(hosted) || hosted < 1) return engineCeiling
  return engineCeiling === undefined ? hosted : Math.min(hosted, engineCeiling)
}

declare global {
  interface Window { __SHAKERSCAN_CAPABILITIES__?: WorkspaceCapabilities }
}

export function featureEnabled(feature: string): boolean {
  if (typeof window === 'undefined') return false
  const policy = window.__SHAKERSCAN_CAPABILITIES__
  if (!policy) return true // Existing standalone deployments retain their full product surface.
  return policy.schema === 'shakerscan.workspace-capabilities/v1'
    && policy.mode === 'managed' && policy.features?.[feature]?.state === 'enabled'
}

export function navigationAllowed(href: string): boolean {
  if (typeof window === 'undefined') return false
  const policy = window.__SHAKERSCAN_CAPABILITIES__
  if (!policy) return true
  if (policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed'
    || !Array.isArray(policy.ui_routes) || !policy.navigation
    || typeof policy.navigation !== 'object') return false
  const path = href.split(/[?#]/, 1)[0]
  const base = Object.keys(policy.navigation || {}).sort((a, b) => b.length - a.length)
    .find(base => path === base || (base !== '/' && path.startsWith(base + '/')))
  if (!base || !featureEnabled(policy.navigation[base])) return false
  return policy.ui_routes.some(pattern => {
    if (typeof pattern !== 'string') return false
    try { return new RegExp('^(?:' + pattern + ')$').test(path) } catch { return false }
  })
}
