'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ChevronRight, ExternalLink, GitBranch, Radar, Target } from 'lucide-react'
import type { ExposureAttackPath } from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { Button, EmptyState, ErrorState } from '@/components/ui'
import styles from './exposure.module.css'

function severityClass(severity?: string | null) {
  if (!severity) return 'bg-gray-700 text-gray-300'
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function PathCard({ path, onExploreAsset }: { path: ExposureAttackPath; onExploreAsset: (nodeId: string) => void }) {
  const [open, setOpen] = useState(false)
  const complete = path.status === 'complete'

  return (
    <div className={`${styles.module} ${styles.corners}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
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
          </div>
          {path.business_impact && <p className="mt-1.5 text-xs text-gray-400">{path.business_impact}</p>}
        </div>
      </button>

      {open && (
        <div className="border-t border-gray-800/60 px-4 pb-4 pt-3">
          {path.description && <p className="mb-3 text-xs text-gray-400">{path.description}</p>}
          <ol className="relative space-y-3 pl-1">
            {path.steps.map((step, i) => (
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
                  {step.finding_type && (
                    <span className="mt-1 inline-block rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
                      {step.finding_type}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ol>
          {path.remediation && (
            <div className="mt-3 rounded border border-emerald-500/20 bg-emerald-500/5 p-2.5">
              <div className="text-[10px] uppercase tracking-wide text-emerald-400">Remediation</div>
              <p className="mt-1 text-xs text-gray-300">{path.remediation}</p>
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            <Link
              href={path.scan_href}
              className="inline-flex items-center gap-1 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              View scan <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </Link>
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
        hint="Run smart or full scans — ShakerScan chains related findings into exploit paths."
        action={{ label: 'New Scan', href: '/scan/new' }}
      />
    )
  }

  const complete = paths.filter((p) => p.status === 'complete').length
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-gray-400">
        <GitBranch className="h-4 w-4 text-teal-300/60" aria-hidden="true" />
        <span>
          <span className="font-semibold text-white">{paths.length}</span> exploit paths ·{' '}
          <span className="text-red-300">{complete} complete</span>
        </span>
      </div>
      <div className="space-y-3">
        {paths.map((path) => (
          <PathCard key={path.id} path={path} onExploreAsset={onExploreAsset} />
        ))}
      </div>
    </div>
  )
}
