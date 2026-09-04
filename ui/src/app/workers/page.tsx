'use client'

import { useCallback, useEffect, useState } from 'react'
import { Button, Card, ErrorState, LastUpdated, PageHeader } from '@/components/ui'
import { getWorkers, type WorkerPoolSummary, type WorkerStats } from '@/lib/api'

const REFRESH_MS = 10_000
const POOLS: { key: keyof NonNullable<WorkerStats['pools']>; label: string; detail: string }[] = [
  { key: 'web_dast', label: 'Web DAST', detail: 'Deterministic Scan execution and verification' },
  { key: 'agent_tool', label: 'Agent tools', detail: 'Isolated process capabilities used by Hunt' },
  { key: 'device', label: 'Connected devices', detail: 'Opt-in network and device examination' },
  { key: 'model_intake', label: 'Model Intake', detail: 'Dedicated artifact inspection toolchain' },
]

function statusClass(status: WorkerPoolSummary['status']): string {
  if (status === 'ready') return 'bg-emerald-500/15 text-emerald-300'
  if (status === 'disabled') return 'bg-gray-700 text-gray-300'
  return 'bg-amber-500/15 text-amber-300'
}

function reasonLabel(reason?: string | null): string {
  return reason ? reason.replaceAll('_', ' ') : 'All reported workers are current and capable.'
}

export default function WorkersPage() {
  const [workers, setWorkers] = useState<WorkerStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)

  const load = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const response = await getWorkers()
      setWorkers(response)
      setError(response.error || null)
      setUpdatedAt(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Worker pools unavailable')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(true), REFRESH_MS)
    return () => window.clearInterval(timer)
  }, [load])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Worker Pools"
        description="Readiness is tracked independently for every release image and execution boundary."
        actions={<Button variant="secondary" size="sm" onClick={() => void load(true)} loading={refreshing}>Refresh</Button>}
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {POOLS.map(({ key, label, detail }) => {
          const pool = workers?.pools?.[key]
          return (
            <Card key={key} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="font-medium text-white">{label}</h2>
                  <p className="mt-1 text-xs text-gray-500">{detail}</p>
                </div>
                <span className={`rounded px-2 py-1 text-xs font-medium ${pool ? statusClass(pool.status) : 'bg-gray-800 text-gray-400'}`}>
                  {loading && !pool ? 'loading' : pool?.status.replace('_', ' ') || 'unknown'}
                </span>
              </div>
              <dl className="mt-5 grid grid-cols-4 gap-2 text-center">
                {([
                  ['Total', pool?.count],
                  ['Current', pool?.current],
                  ['Stale', pool?.stale],
                  ['Pending', pool?.pending],
                ] as const).map(([name, value]) => (
                  <div key={name}>
                    <dt className="text-[10px] uppercase tracking-wide text-gray-600">{name}</dt>
                    <dd className="mt-1 font-mono text-lg text-gray-200">{value ?? '—'}</dd>
                  </div>
                ))}
              </dl>
              <p className="mt-4 border-t border-gray-800 pt-3 text-xs text-gray-500">
                {pool ? reasonLabel(pool.reason) : 'Waiting for the pool summary.'}
              </p>
            </Card>
          )
        })}
      </div>

      <Card className="p-4 text-sm text-gray-400">
        <p>
          The Web DAST pool remains the source of the legacy worker count and build-fingerprint fields.
          Specialized pools use fresh heartbeats and capability checks, so a running container is not
          counted as current until it reports the expected release identity and required tools.
        </p>
      </Card>

      <LastUpdated updatedAt={updatedAt} onRefresh={() => void load(true)} refreshing={refreshing} />
    </div>
  )
}
