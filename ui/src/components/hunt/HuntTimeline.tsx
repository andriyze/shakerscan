'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from '@/components/WorkspaceLink'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Card } from '@/components/ui'
import { API_URL } from '@/lib/api'
import type { HuntV2 } from '@/lib/huntV2'
import { actionOutcomes, callArguments, requestsByAction, type ActionOutcome } from '@/lib/huntRunModel.mjs'
import { RequestRow, useExpandedSet, type HuntArchive, type HuntTransaction } from './HuntRequestsPanel'
import { formatHuntDuration, huntActionStatusClass } from './huntFormat'

type HuntAction = NonNullable<HuntV2['actions']>[number]

const formatBudget = (entries: Array<[string, number]>) => entries
  .map(([dimension, amount]) => `${amount} ${dimension.replaceAll('_', ' ')}`)
  .join(' · ')

function unsettledText(basis: string): string {
  return basis === 'legacy_reported_charge'
    ? 'Legacy reported charge: reservation versus actual was not retained.'
    : 'No durable reservation existed; displayed usage is reported execution data, not an exact settlement.'
}

const FAILED = new Set(['failed', 'blocked', 'rejected', 'cancelled', 'timed_out'])

function ActionEntry({ action, outcome, requests, expanded, onToggle }: {
  action: HuntAction; outcome: ActionOutcome | null | undefined; requests: HuntTransaction[]; expanded: boolean; onToggle: () => void
}) {
  const args = callArguments(outcome?.input)
  const requestRows = useExpandedSet()
  const references = action.result.reference_ids
  const accounting = action.result.budget_accounting
  const actualBudget = Object.entries(accounting.actual)
  const reservedBudget = Object.entries(accounting.reserved)
  const releasedBudget = Object.entries(accounting.released).filter(([, amount]) => amount > 0)
  const legacyBudget = Object.entries(action.result.budget_consumed)
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <code className="text-sm text-blue-300">{action.capability_name}</code>
        <span className={`rounded-sm px-1.5 py-0.5 text-[11px] ${huntActionStatusClass(action.status)}`}>
          {action.status.replaceAll('_', ' ')}
        </span>
        <span className="text-xs text-gray-500">
          {action.result.observation_count} observations
          {action.started_at && action.completed_at ? ` · ${formatHuntDuration(action.started_at, action.completed_at) || '0s'}` : ''}
        </span>
        {requests.length > 0 && (
          <button type="button" onClick={onToggle} aria-expanded={expanded}
            className="ml-auto inline-flex items-center gap-1 rounded-md bg-blue-500/10 px-2 py-0.5 text-xs text-blue-200 hover:bg-blue-500/20">
            {expanded ? <ChevronDown className="h-3 w-3" aria-hidden="true" /> : <ChevronRight className="h-3 w-3" aria-hidden="true" />}
            {requests.length} request{requests.length === 1 ? '' : 's'}
          </button>
        )}
      </div>
      {args.length > 0 && (
        <dl className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[11px]" aria-label="Called with">
          {args.map(arg => <div key={arg.key} className="min-w-0 max-w-full">
            <dt className="inline text-gray-500">{arg.key}=</dt>
            <dd className="inline break-all text-gray-200" title={arg.full !== arg.value ? arg.full : undefined}>{arg.value}</dd>
          </div>)}
        </dl>
      )}
      {outcome && outcome.errors.length > 0 && (
        <div className={`mt-1.5 rounded-md border px-2.5 py-1.5 text-xs ${FAILED.has(action.status) ? 'border-red-500/30 bg-red-500/5 text-red-200' : 'border-amber-500/30 bg-amber-500/5 text-amber-200'}`}>
          {outcome.errors.map(error => <p key={error} className="break-words">{error}</p>)}
        </div>
      )}
      {accounting.basis === 'settlement_failed' && (
        <p className="mt-1 text-xs text-red-300">Budget settlement failed; no released amount is asserted. Review the action receipt.</p>
      )}
      {(references.scan_ids.length > 0 || references.finding_ids.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-3">
          {references.scan_ids.map((scanId) => (
            <Link key={scanId} href={`/scans/${scanId}`} className="text-xs text-blue-300 hover:text-blue-200">Open scan {scanId.slice(0, 8)}</Link>
          ))}
          {references.finding_ids.map((findingId) => (
            <Link key={findingId} href={`/findings/${findingId}`} className="text-xs text-blue-300 hover:text-blue-200">Open finding {findingId.slice(0, 8)}</Link>
          ))}
        </div>
      )}
      {expanded && requests.length > 0 && (
        <ol className="mt-2 divide-y divide-gray-800/70 overflow-hidden rounded-lg border border-gray-800 bg-gray-950/50" aria-label={`Requests sent by ${action.capability_name}`}>
          {requests.map((row, index) => <RequestRow key={row.id} row={row} index={index} showCapability={false}
            expanded={requestRows.open.has(row.id)} onToggle={() => requestRows.toggle(row.id)} />)}
        </ol>
      )}
      <details className="mt-1.5 text-xs text-gray-500">
        <summary className="w-fit cursor-pointer text-[11px] text-gray-600 hover:text-gray-300">IDs and budget</summary>
        {(accounting.basis === 'no_reservation' || accounting.basis === 'legacy_reported_charge') && <p className="mt-2 text-amber-300/80">{unsettledText(accounting.basis)}</p>}
        {accounting.basis === 'legacy_reported_charge' && legacyBudget.length > 0 && <p className="mt-1">Reported charge: {formatBudget(legacyBudget)}</p>}
        {(accounting.basis === 'exact_settlement' || accounting.basis === 'conservative_settlement') && (
          <div className="mt-2 space-y-1">
            <p>Settled charge: {actualBudget.length > 0 ? formatBudget(actualBudget) : 'none'}</p>
            <p>
              Charge basis: {accounting.basis === 'conservative_settlement' || accounting.charge_basis === 'conservative_full_reservation'
                ? 'conservative upper bound; measured consumption was unavailable'
                : 'capability-reported settlement'}
            </p>
            {reservedBudget.length > 0 && <p>Temporarily reserved: {formatBudget(reservedBudget)}</p>}
            {releasedBudget.length > 0 && <p>Released after settlement: {formatBudget(releasedBudget)}</p>}
          </div>
        )}
        {action.started_at && <p className="mt-1">Started {new Date(action.started_at).toLocaleString()}{action.completed_at ? ` · finished ${new Date(action.completed_at).toLocaleString()}` : ''}</p>}
        <dl className="mt-2 space-y-1" aria-label="Audit identifiers">
          <div><dt className="inline">Action: </dt><dd className="inline break-all font-mono">{action.action_id}</dd></div>
          <div><dt className="inline">Receipt: </dt><dd className="inline break-all font-mono">{action.receipt_id || 'not recorded'}</dd></div>
          <div><dt className="inline">Input digest: </dt><dd className="inline break-all font-mono">{action.input_digest || 'not recorded'}</dd></div>
        </dl>
      </details>
    </li>
  )
}

/** Every capability call in order, each with the requests it sent nested under it. */
export function HuntTimeline({ hunt, archive }: { hunt: HuntV2; archive: HuntArchive }) {
  const actions = hunt.actions || []
  const { byAction, unlinked } = useMemo(() => requestsByAction(archive.rows), [archive.rows])
  const expanded = useExpandedSet()
  const unlinkedRows = useExpandedSet()
  const [outcomes, setOutcomes] = useState<Map<string, ActionOutcome> | null>(null)
  const [recordError, setRecordError] = useState<string | null>(null)
  const [failedOnly, setFailedOnly] = useState(false)
  const failedCount = actions.filter(action => FAILED.has(action.status)).length
  const shown = failedOnly ? actions.filter(action => FAILED.has(action.status)) : actions

  // The record export is the server's masked decision trace: the arguments each call was made with
  // and the reason it failed. It is the same document the Export menu downloads.
  useEffect(() => {
    let cancelled = false
    fetch(`${API_URL}/hunts/${encodeURIComponent(hunt.hunt_id)}/record`, { cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error(`Call details unavailable (${response.status})`)
        return response.json()
      })
      .then(record => { if (!cancelled) { setOutcomes(actionOutcomes(record)); setRecordError(null) } })
      .catch(cause => { if (!cancelled) setRecordError(cause instanceof Error ? cause.message : 'Call details unavailable') })
    return () => { cancelled = true }
  }, [hunt.hunt_id, actions.length])
  return (
    <Card className="p-0">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 p-4">
        <div>
          <h2 className="font-medium text-white">Timeline</h2>
          <p className="mt-1 text-xs text-gray-500">Every capability call: what it was called with, why it failed, and the requests it sent. Canonical receipts and content-safe outcomes stay under each call's IDs.</p>
        </div>
        <div className="flex items-center gap-2">
          {failedCount > 0 && <div role="group" aria-label="Filter actions" className="flex gap-1 text-xs">
            <button type="button" aria-pressed={!failedOnly} onClick={() => setFailedOnly(false)} className={`rounded-md px-2 py-1 ${!failedOnly ? 'bg-blue-500/15 text-blue-200' : 'text-gray-400 hover:bg-gray-800'}`}>All {actions.length}</button>
            <button type="button" aria-pressed={failedOnly} onClick={() => setFailedOnly(true)} className={`rounded-md px-2 py-1 ${failedOnly ? 'bg-red-500/15 text-red-200' : 'text-gray-400 hover:bg-gray-800'}`}>Failed {failedCount}</button>
          </div>}
          {failedCount === 0 && <span className="text-xs text-gray-500">{actions.length} action{actions.length === 1 ? '' : 's'}</span>}
        </div>
      </div>
      {recordError && <p role="status" className="border-b border-gray-800 px-4 py-2 text-xs text-amber-300">{recordError}; showing outcomes without call arguments.</p>}
      {actions.length === 0 ? (
        <p className="p-6 text-center text-sm text-gray-500">No capability actions were recorded.</p>
      ) : (
        <ol className="divide-y divide-gray-800" aria-label="Capability actions">
          {shown.map((action) => (
            <ActionEntry key={action.action_id} action={action} outcome={outcomes?.get(action.action_id)} requests={byAction.get(action.action_id) || []}
              expanded={expanded.open.has(action.action_id)} onToggle={() => expanded.toggle(action.action_id)} />
          ))}
        </ol>
      )}
      {unlinked.length > 0 && (
        <details className="border-t border-gray-800 px-4 py-3">
          <summary className="cursor-pointer text-xs text-gray-400">{unlinked.length} request{unlinked.length === 1 ? '' : 's'} not linked to a recorded action</summary>
          <ol className="mt-2 divide-y divide-gray-800/70 overflow-hidden rounded-lg border border-gray-800">
            {unlinked.map((row, index) => <RequestRow key={row.id} row={row} index={index}
              expanded={unlinkedRows.open.has(row.id)} onToggle={() => unlinkedRows.toggle(row.id)} />)}
          </ol>
        </details>
      )}
      {archive.rows.length < archive.total && (
        <p className="border-t border-gray-800 px-4 py-2.5 text-xs text-gray-500">Request counts cover the first {archive.rows.length} of {archive.total} recorded requests.</p>
      )}
    </Card>
  )
}
