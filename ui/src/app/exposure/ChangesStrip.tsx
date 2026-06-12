'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { History } from 'lucide-react'
import { getExposureChanges, type ExposureChangeCategory, type ExposureChangesResponse } from '@/lib/api'
import styles from './exposure.module.css'

type AnchorMode = '7d' | '30d' | 'visit'

const LAST_VISIT_KEY = 'shakerscan-exposure-last-visit'
const SESSION_ANCHOR_KEY = 'shakerscan-exposure-visit-anchor'

// Capture "previous visit" once per browser tab: the first mount stamps the
// current time into localStorage and keeps the prior stamp as this session's
// anchor, so refreshes within the same tab don't erase the delta window.
function useLastVisitAnchor(): string | null {
  const [anchor, setAnchor] = useState<string | null>(null)
  useEffect(() => {
    try {
      let sessionAnchor = sessionStorage.getItem(SESSION_ANCHOR_KEY)
      if (sessionAnchor === null) {
        sessionAnchor = localStorage.getItem(LAST_VISIT_KEY) ?? ''
        sessionStorage.setItem(SESSION_ANCHOR_KEY, sessionAnchor)
      }
      localStorage.setItem(LAST_VISIT_KEY, new Date().toISOString())
      setAnchor(sessionAnchor || null)
    } catch {
      // Storage unavailable (private mode etc.) — day windows still work.
    }
  }, [])
  return anchor
}

const TILE_TONES: Record<string, string> = {
  new_assets: 'text-teal-300',
  new_critical: 'text-red-300',
  new_high: 'text-orange-300',
  resolved: 'text-emerald-300',
  failed_scans: 'text-red-200',
  went_stale: 'text-yellow-300',
}

function exampleTitle(category: ExposureChangeCategory): string | undefined {
  if (category.examples.length === 0) return undefined
  return category.examples
    .map((example) => (example.detail ? `${example.label} (${example.detail})` : example.label))
    .join('\n')
}

function ChangeTile({ category }: { category: ExposureChangeCategory }) {
  const tone = category.count > 0 ? TILE_TONES[category.key] || 'text-gray-200' : 'text-gray-600'
  const first = category.examples[0]
  const body = (
    <>
      <div className={`text-lg font-semibold ${tone}`}>{category.count}</div>
      <div className="text-[10px] uppercase tracking-wide text-gray-600">{category.label}</div>
      {first && category.count > 0 && (
        <div className="mt-0.5 max-w-44 truncate text-[11px] text-gray-500">{first.label}</div>
      )}
    </>
  )
  if (category.href && category.count > 0) {
    return (
      <Link
        href={category.href}
        title={exampleTitle(category)}
        className="min-w-0 rounded px-2.5 py-1.5 transition-colors hover:bg-gray-800/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        {body}
      </Link>
    )
  }
  return <div className="min-w-0 px-2.5 py-1.5">{body}</div>
}

export function ChangesStrip({ rootDomain }: { rootDomain?: string }) {
  const lastVisit = useLastVisitAnchor()
  const [mode, setMode] = useState<AnchorMode>('7d')
  const [data, setData] = useState<ExposureChangesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getExposureChanges({
        root_domain: rootDomain || undefined,
        since: mode === 'visit' && lastVisit ? lastVisit : undefined,
        days: mode === '30d' ? 30 : 7,
      })
      setData(res)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load changes')
    } finally {
      setLoading(false)
    }
  }, [rootDomain, mode, lastVisit])

  useEffect(() => {
    load()
  }, [load])

  const modeButton = (value: AnchorMode, label: string) => (
    <button
      key={value}
      type="button"
      aria-pressed={mode === value}
      onClick={() => setMode(value)}
      className={`rounded px-2 py-0.5 text-[11px] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
        mode === value ? 'bg-teal-500/15 text-teal-200 ring-1 ring-teal-400/40' : 'text-gray-500 hover:bg-gray-800/60 hover:text-gray-300'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className={`${styles.module} ${styles.corners} p-3`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="mr-1 flex shrink-0 items-center gap-2">
          <History className="h-3.5 w-3.5 text-teal-200/50" aria-hidden="true" />
          <div>
            <div className={`${styles.displayTitle} text-xs uppercase tracking-wide text-gray-400`}>What changed</div>
            <div className="flex items-center gap-1 text-[11px] text-gray-600">
              {modeButton('7d', '7d')}
              {modeButton('30d', '30d')}
              {lastVisit && modeButton('visit', 'Since last visit')}
            </div>
          </div>
        </div>
        {error ? (
          <div className="flex items-center gap-2 text-xs text-gray-500">
            {error}
            <button
              type="button"
              onClick={load}
              className="rounded px-2 py-0.5 text-teal-300 hover:bg-gray-800/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              Retry
            </button>
          </div>
        ) : loading && !data ? (
          <div className="flex gap-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-10 w-24 animate-pulse rounded bg-gray-800/50" />
            ))}
          </div>
        ) : data && data.total_changes === 0 ? (
          <span className="text-xs text-gray-600">No changes in this window.</span>
        ) : (
          data?.categories.map((category) => <ChangeTile key={category.key} category={category} />)
        )}
      </div>
    </div>
  )
}
