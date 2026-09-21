/**
 * Worker Pools presentation helpers.
 *
 * An opt-in pool with no worker at all is simply not started; only a pool that has workers but
 * cannot use them is a readiness fault. The server's `remedy` text, when present, is the line an
 * operator should read; the raw `reason` token is the fallback.
 */

/** @param {{status: string, count: number}} pool @param {boolean} [optIn] */
export function poolBadge(pool, optIn = false) {
  if (pool.status === 'ready') return { text: 'ready', className: 'bg-emerald-500/15 text-emerald-300' }
  if (pool.status === 'disabled') return { text: 'disabled', className: 'bg-gray-700 text-gray-300' }
  if (optIn && Number(pool.count) === 0) return { text: 'not started', className: 'bg-gray-700 text-gray-300' }
  return { text: 'not ready', className: 'bg-amber-500/15 text-amber-300' }
}

/** @param {{reason?: string | null, remedy?: string | null}} pool */
export function poolDetail(pool) {
  if (pool.remedy) return pool.remedy
  return pool.reason ? pool.reason.replaceAll('_', ' ') : 'All reported workers are current and capable.'
}
