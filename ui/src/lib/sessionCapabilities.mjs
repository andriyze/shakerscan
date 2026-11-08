// session-capabilities/v1 (docs/session-capabilities.md): what the person using the UI may do.
// Presentation only: the server that executes a request still decides it. Any failure, absence
// or unknown schema means "everything allowed", which is how the UI behaved before the contract.

export const SCHEMA_VERSION = 'session-capabilities/v1'

export const ALL_ALLOWED = Object.freeze({ default: 'allow', actions: Object.freeze({}), pages: Object.freeze({}), reasons: Object.freeze({}), role: null })

function booleanMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const out = {}
  for (const [key, flag] of Object.entries(value)) if (typeof flag === 'boolean') out[key] = flag
  return out
}

/** Normalize a response body; anything that is not this contract is everything allowed. */
export function parseSessionCapabilities(body) {
  if (!body || typeof body !== 'object' || body.schema_version !== SCHEMA_VERSION) return ALL_ALLOWED
  const reasons = {}
  if (body.reasons && typeof body.reasons === 'object' && !Array.isArray(body.reasons)) {
    for (const [key, text] of Object.entries(body.reasons)) {
      if (typeof text === 'string' && text.trim() && text.length <= 300) reasons[key] = text.trim()
    }
  }
  return {
    default: body.default === 'deny' ? 'deny' : 'allow',
    actions: booleanMap(body.actions),
    pages: booleanMap(body.pages),
    reasons,
    role: typeof body.role === 'string' ? body.role : null,
  }
}

export function actionAllowed(capabilities, action) {
  const caps = capabilities || ALL_ALLOWED
  const flag = caps.actions[action]
  return typeof flag === 'boolean' ? flag : caps.default !== 'deny'
}

/** Pages: the longest matching prefix wins; an unlisted page is allowed (only links are hidden). */
export function pageAllowed(capabilities, href) {
  const caps = capabilities || ALL_ALLOWED
  if (typeof href !== 'string' || !href.startsWith('/')) return true
  const path = href.split(/[?#]/, 1)[0]
  const match = Object.keys(caps.pages)
    .filter(prefix => prefix.startsWith('/') && (path === prefix || prefix === '/'
      || path.startsWith(prefix.endsWith('/') ? prefix : prefix + '/')))
    .sort((a, b) => b.length - a.length)[0]
  return match === undefined ? true : caps.pages[match]
}

export function capabilityReason(capabilities, key) {
  return (capabilities || ALL_ALLOWED).reasons[key]
}

/** Fetch the answer (url: `${API_URL}/session/capabilities`); resolves to everything allowed on any failure or after timeoutMs. */
export async function fetchSessionCapabilities(url, fetchImpl = globalThis.fetch, timeoutMs = 5000) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null
  try {
    const response = await fetchImpl(url, {
      cache: 'no-store', headers: { Accept: 'application/json' }, signal: controller?.signal,
    })
    if (!response || response.status !== 200) return ALL_ALLOWED
    return parseSessionCapabilities(await response.json())
  } catch {
    return ALL_ALLOWED
  } finally {
    if (timer) clearTimeout(timer)
  }
}
