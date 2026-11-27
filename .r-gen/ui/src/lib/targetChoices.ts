import { MAX_SCAN_TARGET_CHARS } from './targetLimits.mjs'

function isUsableWebTarget(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const target = value.trim()
  if (!target || target.length > MAX_SCAN_TARGET_CHARS || /\s/.test(target)) return false
  try {
    const url = new URL(target)
    return Boolean(url.hostname) && ['http:', 'https:'].includes(url.protocol)
  } catch {
    return false
  }
}

export function usableWebTargets<T extends { url?: unknown; is_active?: boolean }>(targets: T[]): T[] {
  return targets.filter((target) => (
    target.is_active !== false
    && isUsableWebTarget(target.url)
  ))
}

export function boundedDisplayText(value: unknown, maxLength = 160): string {
  const limit = Math.max(16, maxLength)
  const display = typeof value === 'string' ? value.trim() : String(value ?? '').trim()
  if (display.length <= limit) return display
  return `${display.slice(0, limit - 1)}…`
}

export function boundedTargetDisplay(
  target: { name?: unknown; url?: unknown },
  options: { maxLength?: number; stripScheme?: boolean } = {},
): string {
  const maxLength = Math.max(16, options.maxLength ?? 160)
  const name = typeof target.name === 'string' ? target.name.trim() : ''
  const rawUrl = typeof target.url === 'string' ? target.url.trim() : ''
  const url = options.stripScheme ? rawUrl.replace(/^https?:\/\//i, '') : rawUrl
  const display = name ? `${name} — ${url}` : url
  return boundedDisplayText(display, maxLength)
}

/** The host (with a non-default port and any path) a person recognizes, not the full URL. */
function readableLocator(rawUrl: string): string {
  try {
    const url = new URL(rawUrl)
    const path = url.pathname && url.pathname !== '/' ? url.pathname.replace(/\/$/, '') : ''
    return `${url.host}${path}`
  } catch {
    return rawUrl.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
  }
}

/**
 * A picker choice for a target: its name first when it has a real one, else the host a person
 * recognizes; the full URL goes underneath. A name that only repeats the URL is not a name.
 */
export function targetChoiceLabel(
  target: { name?: unknown; url?: unknown },
  options: { maxLength?: number } = {},
): { label: string; description?: string } {
  const maxLength = options.maxLength ?? 160
  const rawUrl = typeof target.url === 'string' ? target.url.trim() : ''
  const name = typeof target.name === 'string' ? target.name.trim() : ''
  const repeatsUrl = !name || [rawUrl, rawUrl.replace(/\/$/, ''), readableLocator(rawUrl)]
    .some((form) => form && form.toLowerCase() === name.replace(/\/$/, '').toLowerCase())
    || name.replace(/^https?:\/\//i, '').replace(/\/$/, '').toLowerCase() === readableLocator(rawUrl).toLowerCase()
  if (repeatsUrl) {
    const label = boundedDisplayText(readableLocator(rawUrl) || name, maxLength)
    return { label, description: rawUrl && rawUrl !== label ? boundedDisplayText(rawUrl, maxLength) : undefined }
  }
  return { label: boundedDisplayText(name, maxLength), description: rawUrl ? boundedDisplayText(rawUrl, maxLength) : undefined }
}
