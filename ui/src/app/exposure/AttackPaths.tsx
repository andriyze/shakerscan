'use client'

import { useMemo, useState } from 'react'
import Link from 'next/link'
import { ChevronRight, ExternalLink, GitBranch, Radar, Target, X } from 'lucide-react'
import type { ExposureAttackPath } from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { EmptyState, ErrorState } from '@/components/ui'
import styles from './exposure.module.css'

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function severityClass(severity?: string | null) {
  if (!severity) return 'bg-gray-700 text-gray-300'
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function titleize(value?: string | null): string {
  if (!value) return 'Other'
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function compactEvidence(value: unknown): string | null {
  if (!value) return null
  if (typeof value === 'string') return value.length > 180 ? `${value.slice(0, 177)}...` : value
  try {
    const serialized = JSON.stringify(value)
    return serialized.length > 180 ? `${serialized.slice(0, 177)}...` : serialized
  } catch {
    return null
  }
}

function remediationItems(value: ExposureAttackPath['remediation']): string[] {
  if (!value) return []
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
  return value
    .split(/\n+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function PathCard({ path, onExploreAsset }: { path: ExposureAttackPath; onExploreAsset: (nodeId: string) => void }) {
  const [open, setOpen] = useState(false)
  const complete = path.status === 'complete'
  const completion = typeof path.completeness === 'number' ? Math.round(path.completeness * 100) : null
  const remediation = remediationItems(path.remediation)

  return (
    <div className={`${styles.module} ${styles.corners}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        // Scope the accessible name to the essentials — without this, the name
        // is every piece of text in the header concatenated.
        aria-label={`${path.name} — ${path.severity || 'unrated'} ${complete ? 'complete' : 'partial'} chain, ${path.steps.length} steps${path.asset_label ? `, on ${path.asset_label}` : ''}`}
        className="flex w-full items-start gap-3 p-4 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        <ChevronRight className={`mt-0.5 h-4 w-4 shrink-0 text-gray-500 transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(path.severity)}`}>
              {path.severity || 'unrated'}
            </span>
            <span className={`${styles.displayTitle} truncate text-sm text-white`}>{path.name}</span>
            <span
              className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${
                complete ? 'bg-red-500/15 text-red-300' : 'bg-amber-500/15 text-amber-300'
              }`}
            >
              {complete ? 'complete' : 'partial'}
            </span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
            {path.asset_label && (
              <span className="inline-flex items-center gap-1">
                <Target className="h-3 w-3" aria-hidden="true" />
                {path.asset_label}
              </span>
            )}
            <span>{path.steps.length} steps</span>
            {typeof path.confidence === 'number' && <span>{Math.round(path.confidence * 100)}% confidence</span>}
            {completion !== null && <span>{completion}% complete</span>}
          </div>
          {path.business_impact && <p className="mt-1.5 text-xs text-gray-400">{path.business_impact}</p>}
        </div>
      </button>

      {open && (
        <div className="border-t border-gray-800/60 px-4 pb-4 pt-3">
          {path.description && <p className="mb-3 text-xs text-gray-400">{path.description}</p>}
          {!complete && (path.missing_required || []).length > 0 && (
            <div className="mb-3 rounded border border-amber-500/20 bg-amber-500/5 p-2.5">
              <div className="text-[10px] uppercase tracking-wide text-amber-300">Missing to complete</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {(path.missing_required || []).map((item, i) => (
                  <span key={`${i}-${item}`} className="rounded bg-gray-900 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">
                    {item}
                  </span>
                ))}
              </div>
            </div>
          )}
          <ol className="relative space-y-3 pl-1">
            {path.steps.map((step, i) => {
              const evidence = compactEvidence(step.evidence)
              return (
                <li key={i} className="relative flex gap-3">
                  <div className="flex flex-col items-center">
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-teal-400/40 bg-teal-400/10 text-[10px] text-teal-200">
                      {step.step_number ?? i + 1}
                    </span>
                    {i < path.steps.length - 1 && <span className="mt-0.5 w-px flex-1 bg-gray-700" aria-hidden="true" />}
                  </div>
                  <div className="min-w-0 flex-1 pb-1">
                    <p className="text-xs text-gray-200">{step.description}</p>
                    {step.impact && <p className="mt-0.5 text-[11px] text-gray-500">→ {step.impact}</p>}
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      {step.finding_type && (
                        <span className="inline-block rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
                          {step.finding_type}
                        </span>
                      )}
                      {step.finding_id && (
                        <Link
                          href={`/findings/${step.finding_id}`}
                          title={step.finding_title || undefined}
                          className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-300 hover:text-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                        >
                          Finding <ExternalLink className="h-2.5 w-2.5" aria-hidden="true" />
                        </Link>
                      )}
                    </div>
                    {evidence && (
                      <pre className="mt-1 max-h-16 overflow-auto rounded border border-gray-800 bg-black/30 p-1.5 text-[10px] text-gray-500">
                        {evidence}
                      </pre>
                    )}
                  </div>
                </li>
              )
            })}
          </ol>
          {remediation.length > 0 && (
            <div className="mt-3 rounded border border-emerald-500/20 bg-emerald-500/5 p-2.5">
              <div className="text-[10px] uppercase tracking-wide text-emerald-400">Remediation</div>
              <ul className="mt-1 space-y-1 text-xs text-gray-300">
                {remediation.map((item, i) => (
                  <li key={`${i}-${item}`}>{item}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            <Link
              href={path.scan_href}
              className="inline-flex items-center gap-1 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              View scan <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </Link>
            {path.findings_href && (
              <Link
                href={path.findings_href}
                className="inline-flex items-center gap-1 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                Scan findings <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </Link>
            )}
            {path.asset_node_id && (
              <button
                type="button"
                onClick={() => onExploreAsset(path.asset_node_id as string)}
                className="inline-flex items-center gap-1 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <Radar className="h-3 w-3" aria-hidden="true" /> Explore asset
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function AttackPaths({
  paths,
  loading,
  error,
  onRetry,
  onExploreAsset,
}: {
  paths: ExposureAttackPath[]
  loading: boolean
  error: string | null
  onRetry: () => void
  onExploreAsset: (nodeId: string) => void
}) {
  const [typeFilter, setTypeFilter] = useState<string | null>(null)

  // Break the flat list into chain-type groups. Most datasets repeat a handful
  // of templates across many assets (e.g. SQLi→PrivEsc 3×), so a per-type
  // breakdown with worst-severity + complete count makes the list scannable and
  // gives a real filter, rather than scrolling near-identical cards.
  const groups = useMemo(() => {
    const byType = new Map<string, ExposureAttackPath[]>()
    for (const p of paths) {
      const key = p.chain_type || 'other'
      const list = byType.get(key)
      if (list) list.push(p)
      else byType.set(key, [p])
    }
    return Array.from(byType.entries())
      .map(([type, items]) => ({
        type,
        label: titleize(type),
        count: items.length,
        complete: items.filter((p) => p.status === 'complete').length,
        worst: items.reduce<string | null>(
          (acc, p) => ((SEVERITY_RANK[p.severity || ''] ?? -1) > (SEVERITY_RANK[acc || ''] ?? -1) ? p.severity ?? acc : acc),
          null
        ),
      }))
      .sort((a, b) => (SEVERITY_RANK[b.worst || ''] ?? -1) - (SEVERITY_RANK[a.worst || ''] ?? -1) || b.count - a.count)
  }, [paths])

  if (error) return <ErrorState message={error} onRetry={onRetry} />
  if (loading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className={`${styles.module} h-20 animate-pulse`} />
        ))}
      </div>
    )
  }
  if (paths.length === 0) {
    return (
      <EmptyState
        message="No attack paths correlated yet."
        hint="Run a Balanced or Thorough scan with the required active-testing and credential permissions. Paths appear only when related evidence can be correlated."
        action={{ label: 'New Scan', href: '/scan/new' }}
      />
    )
  }

  const complete = paths.filter((p) => p.status === 'complete').length
  const visible = typeFilter ? paths.filter((p) => (p.chain_type || 'other') === typeFilter) : paths
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm text-gray-400">
        <GitBranch className="h-4 w-4 text-teal-300/60" aria-hidden="true" />
        <span>
          <span className="font-semibold text-white">{paths.length}</span> exploit paths ·{' '}
          <span className="text-red-300">{complete} complete</span> · {groups.length}{' '}
          {groups.length === 1 ? 'chain type' : 'chain types'}
        </span>
        {typeFilter && (
          <button
            type="button"
            onClick={() => setTypeFilter(null)}
            className="ml-auto inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800/60 hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-3 w-3" aria-hidden="true" /> Clear filter
          </button>
        )}
      </div>

      {groups.length > 1 && (
        <div className="flex flex-wrap gap-2">
          {groups.map((g) => {
            const active = typeFilter === g.type
            return (
              <button
                key={g.type}
                type="button"
                aria-pressed={active}
                onClick={() => setTypeFilter(active ? null : g.type)}
                className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  active ? 'border-teal-400/50 bg-teal-500/15 text-teal-100' : 'border-gray-800 bg-gray-950 text-gray-300 hover:border-gray-700'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                    g.worst === 'critical'
                      ? 'bg-red-500'
                      : g.worst === 'high'
                      ? 'bg-orange-500'
                      : g.worst === 'medium'
                      ? 'bg-yellow-500'
                      : g.worst === 'low'
                      ? 'bg-blue-500'
                      : 'bg-gray-500'
                  }`}
                  aria-hidden="true"
                />
                <span className="max-w-[16rem] truncate">{g.label}</span>
                <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">
                  {g.count}
                </span>
                {g.complete > 0 && <span className="text-[10px] text-red-300">{g.complete} complete</span>}
              </button>
            )
          })}
        </div>
      )}

      <div className="space-y-3">
        {visible.map((path) => (
          <PathCard key={path.id} path={path} onExploreAsset={onExploreAsset} />
        ))}
      </div>
    </div>
  )
}
