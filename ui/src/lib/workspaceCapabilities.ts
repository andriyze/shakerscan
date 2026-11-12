// UI presentation only. The deployment gateway must independently enforce every API request.
import {
  ALL_ALLOWED, actionAllowed, pageAllowed, type SessionAction, type SessionCapabilities,
} from './sessionCapabilities.mjs'
import { NO_EXTENSIONS, parseUiExtensions, type UiExtensions } from './uiExtensions.mjs'

export type WorkspaceCapabilities = {
  schema: 'shakerscan.workspace-capabilities/v1'
  mode: 'managed'
  features: Record<string, { state: 'enabled' | 'unavailable' | 'excluded' | 'setup_required'; reason?: string }>
  navigation: Record<string, string>
  ui_routes: string[]
  scan_limits?: Record<string, number>
  // Label shown under the product name instead of "Open Source Edition" (e.g. an Enterprise
  // gateway names its edition here). Presentation only.
  edition?: string
  // What the deployment adds to this UI (ui-extensions/v1, docs/ui-extensions.md): sidebar
  // entries, hosted pages, slot panels and an account block. Read through workspaceExtensions().
  extensions?: unknown
}

export const DEFAULT_EDITION_LABEL = 'Open Source Edition'

// A deployment gateway (Enterprise) manages this workspace: host commands such as
// `shakerscan model-intake enable` are not the user's to run. Client-only, like the edition label.
export function workspaceIsManaged(): boolean {
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  return Boolean(policy && policy.schema === 'shakerscan.workspace-capabilities/v1' && policy.mode === 'managed')
}

export function workspaceEdition(): string | undefined {
  // Client-only: the server render always says "Open Source Edition" and the client updates the
  // label after mount, so a managed deployment never produces a hydration mismatch.
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy || policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed') return undefined
  const label = typeof policy.edition === 'string' ? policy.edition.trim() : ''
  return label && label.length <= 60 ? label : undefined
}

// The deployment's extensions, validated once per declared block. Client-only like the edition
// label: a standalone UI and the server render have none.
let extensionsSource: unknown
let extensionsParsed: UiExtensions = NO_EXTENSIONS

export function workspaceExtensions(): UiExtensions {
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy || policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed') return NO_EXTENSIONS
  if (policy.extensions !== extensionsSource) {
    extensionsSource = policy.extensions
    extensionsParsed = parseUiExtensions(policy.extensions)
  }
  return extensionsParsed
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
  // The server never receives the client-injected policy, so it must resolve to the same
  // full surface a standalone client does. Forcing false on the server diverged the
  // server markup from the client and produced a hydration mismatch (empty nav on first paint).
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy) return true // Server render and existing standalone deployments retain their full product surface.
  return policy.schema === 'shakerscan.workspace-capabilities/v1'
    && policy.mode === 'managed' && policy.features?.[feature]?.state === 'enabled'
}

export function featureUnavailableReason(feature: string): string | undefined {
  // The managed policy's own explanation for a feature it does not enable, if it gives one.
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy || policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed') return undefined
  const reason = policy.features?.[feature]?.reason
  return typeof reason === 'string' && reason.trim() && reason.length <= 300 ? reason.trim() : undefined
}

export function managedTargetAuthorizationIsAutomatic(): boolean {
  // A managed deployment can record the target's standing authorization itself when active
  // work is submitted; it then reports target_authorization as unavailable because the
  // operator has nothing to click. Manual mode keeps the capability enabled. A standalone
  // deployment has no policy and is never automatic: its own authorization flow applies.
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
  if (!policy || policy.schema !== 'shakerscan.workspace-capabilities/v1' || policy.mode !== 'managed') return false
  return policy.features?.target_authorization?.state === 'unavailable'
}

export function navigationAllowed(href: string): boolean {
  // Server render has no policy and must match the standalone client's full surface (see featureEnabled).
  const policy = typeof window === 'undefined' ? undefined : window.__SHAKERSCAN_CAPABILITIES__
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

// ---- Session capabilities (session-capabilities/v1, docs/session-capabilities.md) ------------
// The policy above (window.__SHAKERSCAN_CAPABILITIES__) is the deployment's workspace surface:
// which features and pages exist at all, published with the page by the runtime config. The
// session answer below is per person: which of the existing controls and pages this signed-in
// person may use, read once per page load from GET /session/capabilities (a gateway answers it by
// role; the engine answers "everything allowed"). A control is offered only when both allow it.
// Both are presentation only; the server decides every request.
let sessionAnswer: SessionCapabilities = ALL_ALLOWED
let sessionRequested = false
const sessionListeners = new Set<() => void>()

export function sessionCapabilities(): SessionCapabilities {
  return sessionAnswer
}

/** Subscribe to the session answer; the first subscriber in a browser starts `load` (once). */
export function subscribeSessionCapabilities(
  listener: () => void, load: () => Promise<SessionCapabilities>,
): () => void {
  sessionListeners.add(listener)
  if (!sessionRequested && typeof window !== 'undefined') {
    sessionRequested = true
    void load().then(answer => {
      sessionAnswer = answer
      sessionListeners.forEach(notify => notify())
    }, () => undefined)
  }
  return () => { sessionListeners.delete(listener) }
}

export function sessionActionAllowed(action: SessionAction): boolean {
  return actionAllowed(sessionAnswer, action)
}

/** A page the signed-in person may open (session answer); navigationAllowed says whether it exists. */
export function sessionPageAllowed(href: string): boolean {
  return pageAllowed(sessionAnswer, href)
}
