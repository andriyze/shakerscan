// The notice a Scan report shows when the Scan stopped because the target's authorization was
// withdrawn while it ran (scan_metadata.stop_reason === 'authorization_withdrawn'). The worker
// writes scan_metadata.authority_stop with the reason, when it was observed, the action that was
// interrupted and the actions that did not run.

export interface AuthorizationStopNotice {
  title: string
  detail: string
  observedAt: string | null
  interruptedActions: string[]
  notRunActions: string[]
}

const REASONS: Record<string, string> = {
  authorization_revoked: 'The target’s authorization was revoked',
  authorization_expired: 'The testing approval expired',
  scope_invalid: 'The target was deactivated or no longer matched the approved scope',
}

function actionList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map((item) => String(item ?? '').trim()).filter(Boolean)
}

export function authorizationStopNotice(scanMetadata: unknown): AuthorizationStopNotice | null {
  if (!scanMetadata || typeof scanMetadata !== 'object') return null
  const metadata = scanMetadata as Record<string, unknown>
  if (metadata.stop_reason !== 'authorization_withdrawn') return null
  const stop = (metadata.authority_stop && typeof metadata.authority_stop === 'object'
    ? metadata.authority_stop : {}) as Record<string, unknown>
  const reasonCode = String(stop.reason_code ?? '')
  const cause = REASONS[reasonCode] ?? 'The target’s authorization was withdrawn'
  const notRun = actionList(stop.not_run_actions)
  const interrupted = actionList(stop.interrupted_actions)
  return {
    title: 'Scan stopped: authorization withdrawn',
    detail: `${cause} while this Scan was running, so it stopped. Findings recorded before the stop `
      + `are kept; coverage is partial${notRun.length ? ` and ${notRun.length} action${notRun.length === 1 ? '' : 's'} did not run` : ''}.`,
    observedAt: typeof stop.observed_at === 'string' && stop.observed_at ? stop.observed_at : null,
    interruptedActions: interrupted,
    notRunActions: notRun,
  }
}
