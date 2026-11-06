'use client'

import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button, Card } from '@/components/ui'
import { checkTargetLiveness, type TargetLiveness } from '@/lib/targetAssetApi'
import { livenessView } from '@/lib/targetInventoryModel.mjs'
import { boundedDisplayText } from '@/lib/targetChoices'
import { LivenessPill } from './inventory/TargetRow'

const DNS_LABEL: Record<string, string> = { resolves: 'Resolves', no_record: 'No address record', error: 'Resolver error' }
const TCP_LABEL: Record<string, string> = {
  open: 'opened', refused: 'refused', timeout: 'timed out', unreachable: 'no route', error: 'failed', not_tried: 'not tried',
}
const TRIGGER_LABEL: Record<string, string> = { add: 'when added', pre_scan: 'before a Scan', schedule: 'on schedule', manual: 'Check now' }

function yesNo(value: boolean | null | undefined) {
  return value === true ? 'Yes' : value === false ? 'No' : '—'
}

/** The target page's liveness: DNS, reachable, live, ports tried, last check and reason, Check now. */
export function TargetLivenessCard({ targetId, liveness }: { targetId: string; liveness?: TargetLiveness }) {
  const [current, setCurrent] = useState<TargetLiveness | undefined>(liveness)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  useEffect(() => { setCurrent(liveness) }, [liveness])
  const view = livenessView(current)

  async function checkNow() {
    setBusy(true)
    setMessage(null)
    try {
      const result = await checkTargetLiveness(targetId)
      setCurrent(result.liveness)
      setMessage(result.checked ? 'Checked just now.' : 'Checked less than 30 seconds ago; showing that result.')
    } catch (cause) {
      setMessage(cause instanceof Error ? cause.message : 'The check could not run')
    } finally {
      setBusy(false)
    }
  }

  const ports = current?.ports || []
  return <Card className="mb-6" data-testid="target-liveness-card">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h2 className="flex items-center gap-3 text-lg font-semibold text-white">Liveness <LivenessPill liveness={current} /></h2>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <div><dt className="text-xs text-gray-500">DNS</dt><dd className="text-gray-200">{current?.dns ? DNS_LABEL[current.dns] || current.dns : '—'}</dd></div>
          <div><dt className="text-xs text-gray-500">Reachable</dt><dd className="text-gray-200">{yesNo(current?.reachable)}</dd></div>
          <div><dt className="text-xs text-gray-500">Live</dt><dd className="text-gray-200">{yesNo(current?.live)}</dd></div>
          <div><dt className="text-xs text-gray-500">Last checked</dt><dd className="text-gray-200" title={current?.checked_at ? new Date(current.checked_at).toLocaleString() : undefined}>
            {view.checkedAgo ? `${view.checkedAgo}${current?.trigger ? ` · ${TRIGGER_LABEL[current.trigger] || current.trigger}` : ''}` : 'Never'}</dd></div>
        </dl>
        {current?.reason && view.status !== 'live' && <p className="mt-3 text-sm text-gray-300" data-testid="target-liveness-reason">
          <span className="text-gray-500">Reason: </span>{boundedDisplayText(current.reason, 600)}</p>}
        {(current?.addresses?.length || 0) > 0 && <p className="mt-2 break-all font-mono text-xs text-gray-500">
          {current!.addresses.slice(0, 8).map(address => boundedDisplayText(address, 60)).join(', ')}</p>}
        {ports.length > 0 && <ul className="mt-2 space-y-0.5 text-xs text-gray-400" aria-label="Ports tried">
          {ports.map(port => <li key={`${port.port}-${port.mode}`}>
            <span className="font-mono">{port.port}</span> {port.mode}: {TCP_LABEL[port.tcp] || port.tcp}
            {port.answered ? port.http_status ? `, HTTP ${port.http_status}` : ', answered' : port.tcp === 'open' ? ', no answer' : ''}
          </li>)}
        </ul>}
      </div>
      <div className="flex flex-col items-end gap-2">
        <Button variant="secondary" size="sm" loading={busy} onClick={() => void checkNow()} aria-label="Check liveness now">
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Check now</Button>
        {message && <p className="max-w-xs text-right text-xs text-gray-400" role="status">{message}</p>}
      </div>
    </div>
  </Card>
}
