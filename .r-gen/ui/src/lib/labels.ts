/**
 * Pure presentation labels shared by pages.
 *
 * These exist so their behaviour can be tested with real inputs instead of by
 * grepping a page for an exact ternary. Source-regex assertions broke whenever
 * copy was reworded even though the guarantee -- correct grammar, and a status
 * that never implies background execution -- still held.
 */

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`)
}

/** "N local worker(s) running", used for the dashboard capacity chip. */
export function workerCountLabel(count: number): string {
  const safe = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0
  return `${safe} local ${pluralize(safe, 'worker')} running`
}

/** Placement preview copy for the New Scan page. */
export function placementPreviewLabel(topology: string, activeWorkerCount: number): string {
  if (topology === 'single') return 'one compatible current worker'
  const usable = Math.max(1, Number.isFinite(activeWorkerCount) ? Math.floor(activeWorkerCount) : 1)
  return `up to ${usable} compatible current ${pluralize(usable, 'worker')}`
}

/**
 * A Hunt run's status as shown to an operator.
 *
 * "active" must never read as "the system is working on it": a Hunt only makes
 * network requests when the operator's coding agent submits a capability call.
 */
export function huntStatusLabel(status: string): string {
  if (status === 'active') return 'agent session open'
  return status.replaceAll('_', ' ')
}

/** Shown beside an open Hunt so "open" is not mistaken for autonomous execution. */
export const HUNT_SESSION_NON_AUTONOMOUS_NOTICE =
  'This agent session is open for planner actions. It does not investigate ' +
  'autonomously and is not running background traffic; network activity occurs ' +
  'only when your coding agent submits a permitted capability call.'


/**
 * Capacity tooltip for the dashboard worker chip.
 *
 * When Fleet is disabled there are no remote workers, so the label must not
 * qualify the count as "local" or mention "remote" -- doing so implies a
 * multi-node deployment that does not exist.
 */
export function workerCapacityLabel(options: {
  fleetEnabled: boolean
  totalAvailable: number
  localAvailable: number
  remoteAvailable: number
}): string {
  const { fleetEnabled, totalAvailable, localAvailable, remoteAvailable } = options
  if (fleetEnabled) {
    return `${totalAvailable} available: ${localAvailable} local, ${remoteAvailable} remote`
  }
  const noun = pluralize(localAvailable, 'worker')
  const verb = localAvailable === 1 ? 'is' : 'are'
  return `${localAvailable} current-build ${noun} ${verb} schedulable`
}
