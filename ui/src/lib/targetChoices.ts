export function usableWebTargets<T extends { url?: unknown; is_active?: boolean }>(targets: T[]): T[] {
  return targets.filter((target) => (
    target.is_active !== false
    && typeof target.url === 'string'
    && target.url.trim().length > 0
  ))
}
