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
