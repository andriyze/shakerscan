/**
 * Read-only view of a legacy device-agent run.
 *
 * The engine behind these records is deleted: /devices/{id}/agent/session,
 * .../reply and .../shell-plans/{id}/confirm no longer exist. New device work
 * starts as a canonical Hunt with target_kind="device". This component exists
 * so the historical record stays auditable during the migration window, and it
 * deliberately renders no control that could start, reply to, confirm, retry,
 * or execute anything.
 */
'use client'

import Link from 'next/link'

import type { DeviceAgentSession } from '@/lib/api'
import { Card } from '@/components/ui'


export function LegacyDeviceInvestigation({ run }: { run: DeviceAgentSession }) {
  return (
    <div className="grid gap-5 lg:grid-cols-[0.9fr_1.5fr]">
      <Card className="space-y-4 p-5">
        <div>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs uppercase tracking-wide text-amber-300">Legacy device-agent run · read only</p>
            <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{run.status.replaceAll('_', ' ')}</span>
          </div>
          <h2 className="mt-3 font-medium text-white">{run.objective}</h2>
          <p className="mt-2 text-xs text-gray-500">
            This record predates canonical Hunt. Its actions and scans remain available for audit, but new work starts through the current target-bound Hunt runtime.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Safety profile</span><span className="text-white">{run.safety_profile.replaceAll('_', ' ')}</span></div>
          <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Planner turns</span><span className="text-white">{run.turns} / {run.max_turns}</span></div>
          <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Actions</span><span className="text-white">{run.actions_used}</span></div>
          <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Scans queued</span><span className="text-white">{run.scans_queued}</span></div>
        </div>
        {run.stop_reason && <p className="text-sm text-amber-200">Stopped: {run.stop_reason.replaceAll('_', ' ')}</p>}
        <Link
          href={`/hunt?target=${encodeURIComponent(run.device_target_id)}`}
          className="inline-flex rounded-lg bg-violet-600 px-3 py-2 text-sm font-medium text-white hover:bg-violet-500"
        >
          Open current Hunt launcher
        </Link>
      </Card>

      <div className="space-y-5">
        <Card className="p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="font-medium text-white">Recorded actions</h2>
              <p className="mt-1 text-xs text-gray-500">Evidence counts and linked deterministic scans from this historical run.</p>
            </div>
            <span className="text-xs text-gray-500">{run.actions.length} shown</span>
          </div>
          {run.actions.length === 0 ? (
            <p className="mt-4 text-sm text-gray-500">No actions were recorded.</p>
          ) : (
            <div className="mt-4 space-y-3">
              {run.actions.map((action) => (
                <div key={action.id} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <code className="text-sm text-blue-300">{action.tool_name}</code>
                    <span className="text-xs text-gray-400">{action.outcome} · {action.evidence_count} evidence</span>
                  </div>
                  {action.rationale && <p className="mt-2 text-xs text-gray-400">{action.rationale}</p>}
                  {action.scan_ids.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {action.scan_ids.map((scanId) => (
                        <Link key={scanId} href={`/scans/${scanId}`} className="text-xs text-blue-300 hover:text-blue-200">
                          Open scan {scanId.slice(0, 8)}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="font-medium text-white">Candidate outcome</h2>
          <div className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            {Object.entries(run.candidate_summary).map(([label, count]) => (
              <div key={label} className="rounded bg-gray-950 p-3"><span className="block text-xs capitalize text-gray-500">{label}</span><span className="text-white">{count}</span></div>
            ))}
          </div>
          {run.result?.summary && <p className="mt-4 text-sm text-gray-300">{run.result.summary}</p>}
        </Card>
      </div>
    </div>
  )
}
