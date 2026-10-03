'use client'

import Link from '@/components/WorkspaceLink'
import { Activity, ArrowUpDown, Crosshair, Globe } from 'lucide-react'
import { huntStatusLabel } from '@/lib/labels'
import type { HuntV2 } from '@/lib/huntV2'
import { cleanTargetLocator, huntActivity, huntTargetTitle, targetRetired } from '@/lib/huntListModel.mjs'
import { relativeTime } from '@/lib/targetInventoryModel.mjs'

export function huntStatusClass(status: string): string {
  if (status === 'active' || status === 'awaiting_planner') return 'bg-blue-500/10 text-blue-300 ring-blue-400/20'
  if (status === 'completed') return 'bg-emerald-500/10 text-emerald-300 ring-emerald-400/20'
  if (status === 'failed') return 'bg-red-500/10 text-red-300 ring-red-400/20'
  if (status === 'budget_exhausted') return 'bg-amber-500/10 text-amber-300 ring-amber-400/20'
  return 'bg-gray-700/40 text-gray-300 ring-gray-600/30'
}

function duration(hunt: HuntV2): string | null {
  if (!hunt.created_at) return null
  const start = new Date(hunt.created_at).getTime()
  const end = hunt.completed_at ? new Date(hunt.completed_at).getTime() : Date.now()
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null
  const seconds = Math.round((end - start) / 1000)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

export function huntRunHref(hunt: Pick<HuntV2, 'target_id' | 'hunt_id'>, section?: 'requests'): string {
  return `/hunt?target=${encodeURIComponent(hunt.target_id)}&run=${encodeURIComponent(hunt.hunt_id)}${section ? `#${section}` : ''}`
}

/** Hunt runs as scannable rows: what was asked, of which target, how far it got and how much it sent. */
export function HuntRunList({ runs, showTarget = true }: { runs: HuntV2[]; showTarget?: boolean }) {
  return <ul className="divide-y divide-gray-800/70" aria-label="Hunts">
    {runs.map(hunt => {
      const activity = huntActivity(hunt)
      const locator = cleanTargetLocator(hunt.target_url)
      const title = huntTargetTitle(hunt)
      const spent = duration(hunt)
      return <li key={hunt.hunt_id} className="group relative grid gap-x-4 gap-y-1.5 px-4 py-3 transition-colors hover:bg-gray-800/30 lg:grid-cols-[7.5rem_minmax(0,2.2fr)_minmax(0,1fr)_8rem] lg:items-center">
        <span className="flex items-center gap-2">
          <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${huntStatusClass(hunt.status)}`}>{huntStatusLabel(hunt.status)}</span>
        </span>
        <span className="min-w-0">
          <Link href={huntRunHref(hunt)} className="block truncate text-sm font-medium text-gray-100 after:absolute after:inset-0 hover:text-blue-300" title={hunt.objective}>
            {hunt.objective || 'Untitled Hunt'}
          </Link>
          <span className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-2 text-xs text-gray-500">
            {showTarget && <span className="inline-flex min-w-0 items-center gap-1"><Globe className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span className="truncate text-gray-300">{title}</span>
              {locator && locator !== title && <span className="truncate font-mono">{locator}</span>}
              {targetRetired(hunt.target_url) && <span className="text-amber-300/80">· target retired</span>}</span>}
            <span>{hunt.target_kind} · {hunt.budget_profile}</span>
            {hunt.stop_reason && !['completed', 'operator_completed'].includes(hunt.stop_reason) && <span className="text-amber-300/80">· {hunt.stop_reason.replaceAll('_', ' ')}</span>}
          </span>
        </span>
        <span className="relative z-10 flex flex-wrap items-center gap-1.5 text-xs">
          <Link href={huntRunHref(hunt, 'requests')} title="HTTP requests sent by this Hunt"
            className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 ${activity.requests ? 'bg-blue-500/10 text-blue-200 hover:bg-blue-500/20' : 'text-gray-600'}`}>
            <ArrowUpDown className="h-3 w-3" aria-hidden="true" />{activity.requests} request{activity.requests === 1 ? '' : 's'}
          </Link>
          <span className="inline-flex items-center gap-1 text-gray-400" title="Capability actions"><Activity className="h-3 w-3" aria-hidden="true" />{activity.actions}</span>
          {activity.candidates > 0 && <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-1.5 py-0.5 text-amber-300" title="Evidence-backed candidates"><Crosshair className="h-3 w-3" aria-hidden="true" />{activity.candidates}</span>}
        </span>
        <span className="text-xs text-gray-500 lg:text-right" title={hunt.created_at ? new Date(hunt.created_at).toLocaleString() : undefined}>
          {relativeTime(hunt.created_at) || '—'}{spent && <span className="text-gray-600"> · {spent}</span>}
        </span>
      </li>
    })}
  </ul>
}
