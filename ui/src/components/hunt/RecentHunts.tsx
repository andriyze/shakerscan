'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Compass, Crosshair } from 'lucide-react'
import {
  getCampaign,
  getCampaigns,
  getTargets,
  listAgentHuntRuns,
  type AgentHuntStatus,
  type Target,
} from '@/lib/api'
import { EmptyState, Skeleton } from '@/components/ui'
import { RunStatusBadge, findingCount, hostFromUrl, relativeTime, runState, type RunState } from './index'

// One investigation history. Current Deep Hunt sessions are primary; older
// guided research campaigns remain visible as legacy verifier runs.
const AGENT_RUN_STATE: Record<AgentHuntStatus, RunState> = {
  awaiting_planner: 'waiting',
  planning: 'running',
  completed: 'completed',
  cancelled: 'cancelled',
  failed: 'failed',
}

interface FeedItem {
  key: string
  engine: 'legacy_verifier' | 'deep_hunt'
  href: string
  title: string
  state: RunState
  createdAt: string
  detail: string
}

export function RecentHunts({ limit = 12 }: { limit?: number }) {
  const [items, setItems] = useState<FeedItem[] | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      const [campaignsRes, runsRes, targetsRes] = await Promise.allSettled([
        getCampaigns({ limit: 50 }),
        listAgentHuntRuns({ limit: 50 }),
        getTargets(),
      ])
      if (cancelled) return
      const campaignRows = campaignsRes.status === 'fulfilled'
        ? (campaignsRes.value.campaigns || []).filter((campaign) => campaign.campaign_type === 'autonomous_research')
        : []
      // A campaign can remain persisted as paused after its final episode
      // recommends stopping. Preserve the prior detail normalization so the
      // unified feed does not resurrect a completed hunt as "Paused".
      const campaigns = await Promise.all(campaignRows.map(async (campaign) => {
        if (campaign.status !== 'paused') return campaign
        const detail = await getCampaign(campaign.id).catch(() => null)
        return detail?.research_yield?.stop_recommended ? { ...campaign, status: 'completed' } : campaign
      }))
      if (cancelled) return
      const runs = runsRes.status === 'fulfilled' ? runsRes.value.runs || [] : []
      const targetRows: Target[] =
        targetsRes.status === 'fulfilled'
          ? Array.isArray(targetsRes.value?.targets)
            ? targetsRes.value.targets
            : Array.isArray(targetsRes.value)
              ? (targetsRes.value as Target[])
              : []
          : []
      const targetUrl = new Map(targetRows.map((t) => [t.id, t.url]))

      const legacyItems: FeedItem[] = campaigns
        .map((c) => {
          const url = String((c.target_scope?.url as string) || '')
          const found = findingCount(c)
          return {
            key: `op-${c.id}`,
            engine: 'legacy_verifier' as const,
            href: `/deep-hunt/runs/${c.id}`,
            title: hostFromUrl(url) || c.name || 'Guided verifier run',
            state: runState(c),
            createdAt: c.created_at,
            // deployment_impact.active_finding_count is linked active
            // target work, not a proof-tier count.
            detail: found > 0 ? `${found} active findings` : 'legacy guided run',
          }
        })

      const deepHuntItems: FeedItem[] = runs.map((r) => ({
        key: `ex-${r.id}`,
        engine: 'deep_hunt' as const,
        href: `/deep-hunt?run=${r.id}`,
        title: hostFromUrl(targetUrl.get(r.target_id) || '') || r.objective || 'Deep Hunt',
        state: AGENT_RUN_STATE[r.status] ?? 'idle',
        createdAt: r.created_at,
        detail: `turn ${r.iterations ?? '0'}/${r.max_iterations}`,
      }))

      const merged = [...legacyItems, ...deepHuntItems]
        .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''))
        .slice(0, limit)
      setItems(merged)
    }
    const safelyLoad = () => {
      void load().catch(() => {
        if (!cancelled) setItems((current) => current ?? [])
      })
    }
    safelyLoad()
    const timer = window.setInterval(safelyLoad, 15000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [limit])

  if (items === null) {
    return (
      <div className="mt-3 grid gap-2">
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
      </div>
    )
  }
  if (!items.length) {
    return (
      <div className="mt-3">
        <EmptyState message="No investigations yet" hint="Start a Deep Hunt to begin AI-driven exploration." />
      </div>
    )
  }

  return (
    <div className="mt-3 grid gap-2">
      {items.map((item) => (
        <Link
          key={item.key}
          href={item.href}
          className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-950/40 p-3.5 hover:border-gray-700 sm:flex-row sm:items-center"
        >
          <EngineBadge engine={item.engine} />
          <RunStatusBadge state={item.state} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-medium text-gray-200">{item.title}</div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-gray-500">
              <span>{item.detail}</span>
              <span>·</span>
              <span>started {relativeTime(item.createdAt)}</span>
            </div>
          </div>
        </Link>
      ))}
    </div>
  )
}

function EngineBadge({ engine }: { engine: 'legacy_verifier' | 'deep_hunt' }) {
  const legacy = engine === 'legacy_verifier'
  const Icon = legacy ? Crosshair : Compass
  return (
    <span
      className={`inline-flex flex-none items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
        legacy ? 'border-gray-700 bg-gray-800/50 text-gray-400' : 'border-violet-500/30 bg-violet-500/10 text-violet-300'
      }`}
    >
      <Icon className="h-3 w-3" aria-hidden="true" />
      {legacy ? 'Verifier · legacy' : 'Deep Hunt'}
    </span>
  )
}
