// The notice a Scan report or a finding retest shows when the work stopped because of the
// target's authorization while it ran. The worker writes the stop as
// scan_metadata.stop_reason ('authorization_withdrawn' or 'authorization_unverified') with
// scan_metadata.authority_stop: the reason, when it was observed, the action that was interrupted
// and the actions that did not run. A retest carries the same authority_stop record
// (GET /retests/finding/{id}: authority_stop and stop_reason).

export interface AuthorizationStopNotice {
  title: string
  detail: string
  observedAt: string | null
  interruptedActions: string[]
  notRunActions: string[]
}

export type StoppedWork = 'Scan' | 'Retest'

const REASONS: Record<string, string> = {
  authorization_revoked: 'The target’s authorization was revoked',
  authorization_expired: 'The testing approval expired',
  scope_invalid: 'The target was deactivated or no longer matched the approved scope',
}

// A retest is checked against the URL it replays as well as the target.
const RETEST_REASONS: Record<string, string> = {
  scope_invalid: 'The target was deactivated or removed, or the approved scope does not cover it or the replayed URL',
}

// What to do before retesting, per cause.
const RETEST_NEXT_STEP: Record<string, string> = {
  authorization_revoked: 'Authorize the target again before retesting.',
  authorization_expired: 'Renew the approval before retesting.',
  scope_invalid: 'Check that the target is active and that its authorization or the approval covers the URL the retest replays.',
}

// The same causes as the end of a sentence that starts "stopped because ...".
const BECAUSE: Record<string, string> = {
  authorization_revoked: 'the target’s authorization was revoked',
  authorization_expired: 'the testing approval expired',
  scope_invalid: 'the target was deactivated or no longer matched the approved scope',
}

const STOP_REASONS = new Set(['authorization_withdrawn', 'authorization_unverified'])

function actionList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map((item) => String(item ?? '').trim()).filter(Boolean)
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function stopNotice(stopReason: unknown, stopValue: unknown, work: StoppedWork): AuthorizationStopNotice | null {
  if (typeof stopReason !== 'string' || !STOP_REASONS.has(stopReason)) return null
  const stop = record(stopValue)
  const notRun = actionList(stop.not_run_actions)
  const interrupted = actionList(stop.interrupted_actions)
  const observedAt = typeof stop.observed_at === 'string' && stop.observed_at ? stop.observed_at : null
  const subject = work === 'Scan' ? 'this Scan' : 'this retest'
  if (stopReason === 'authorization_unverified') {
    return {
      title: `${work} stopped: authorization could not be confirmed`,
      detail: `The target’s authorization could not be confirmed while ${subject} was running (the check did not `
        + 'answer in time), so it stopped. The authorization was not found revoked. '
        + (work === 'Scan' ? 'Coverage is partial.' : 'No verdict was recorded; run the retest again.'),
      observedAt,
      interruptedActions: interrupted,
      notRunActions: notRun,
    }
  }
  const code = String(stop.reason_code ?? '')
  const cause = (work === 'Retest' ? RETEST_REASONS[code] : undefined) ?? REASONS[code]
    ?? 'The target’s authorization was withdrawn'
  // A retest refused before it started sent no traffic.
  const when = work === 'Retest' && stop.before_start === true
    ? 'before this retest started' : `while ${subject} was running`
  const outcome = work === 'Scan'
    ? `Findings recorded before the stop are kept; coverage is partial${notRun.length
      ? ` and ${notRun.length} action${notRun.length === 1 ? '' : 's'} did not run` : ''}.`
    : 'No verdict was recorded: a partial retest neither shows the finding fixed nor still vulnerable. '
      + (RETEST_NEXT_STEP[code] ?? 'Check the target’s authorization before retesting.')
  return {
    title: `${work} stopped: authorization withdrawn`,
    detail: `${cause} ${when}, so it stopped. ${outcome}`,
    observedAt,
    interruptedActions: interrupted,
    notRunActions: notRun,
  }
}

export function authorizationStopNotice(scanMetadata: unknown): AuthorizationStopNotice | null {
  const metadata = record(scanMetadata)
  return stopNotice(metadata.stop_reason, metadata.authority_stop, 'Scan')
}

// A finding retest (one row of GET /retests/finding/{id}) stopped by its authorization.
export function retestAuthorizationStopNotice(retest: unknown): AuthorizationStopNotice | null {
  const row = record(retest)
  const stop = record(row.authority_stop)
  return stopNotice(row.stop_reason ?? stop.stop_reason, stop, 'Retest')
}

// Phase names that say how a run ended rather than where it was.
const TERMINAL_PHASES = new Set(['failed', 'error', 'cancelled', 'canceled', 'completed', 'complete', 'done'])

// The first sentence of a failed Scan's panel. A Scan stopped by its authorization says so
// instead of naming its terminal status as the phase it stopped in ("stopped during the failed
// phase").
export function failedScanHeadline(scan: unknown, noun = 'scan'): string {
  const row = record(scan)
  const metadata = record(record(row.result).scan_metadata)
  const stop = record(metadata.authority_stop)
  const error = String(row.error_message || row.error || metadata.terminated_reason || '')
  const match = /target authorization check returned (\w+)/.exec(error)
  const code = String(stop.reason_code || (match ? match[1] : ''))
  if (metadata.stop_reason === 'authorization_unverified' || code === 'authorization_unverified') {
    return `This ${noun} was stopped because its target’s authorization could not be confirmed while it ran; `
      + 'the authorization was not found revoked.'
  }
  if (metadata.stop_reason === 'authorization_withdrawn' || match) {
    return `This ${noun} was stopped because ${BECAUSE[code] ?? 'the target’s authorization was withdrawn'}.`
  }
  const phase = String(metadata.terminated_at_phase || row.current_phase || '').replace(/_/g, ' ').trim()
  if (phase && !TERMINAL_PHASES.has(phase.toLowerCase())) {
    return `This ${noun} stopped during the ${phase} phase and did not finish.`
  }
  return `This ${noun} stopped before it finished.`
}
