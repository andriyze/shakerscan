'use client'

import { useCallback, useEffect, useState } from 'react'
import {
  Button, ErrorState, LastUpdated, PageHeader, StatusDot, Table, TableCell, TableContainer, TableHead, TableHeaderCell,
  TableRow, type StatusTone,
} from '@/components/ui'
import { getWorkers, type WorkerStats } from '@/lib/api'
import { poolBadge, poolDetail } from '@/lib/workerPools.mjs'

const REFRESH_MS = 10_000
const POOLS: { key: keyof NonNullable<WorkerStats['pools']>; label: string; detail: string; optIn?: boolean }[] = [
  { key: 'web_dast', label: 'Web DAST', detail: 'Deterministic Scan execution and verification' },
  { key: 'agent_tool', label: 'Agent tools', detail: 'Isolated process capabilities used by Hunt' },
  { key: 'device', label: 'Network scanning', detail: 'Dedicated capacity for network and device examination' },
  { key: 'model_intake', label: 'Model Intake', detail: 'Dedicated artifact inspection toolchain' },
]

const BADGE_TONES: Record<string, StatusTone> = {
  ready: 'success', starting: 'info', disabled: 'neutral', 'not started': 'neutral', 'not ready': 'warning',
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

      <TableContainer>
        <Table aria-label="Worker pools">
          <TableHead>
            <tr>
              <TableHeaderCell>Pool</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell className="text-right">Total</TableHeaderCell>
              <TableHeaderCell className="text-right">Current</TableHeaderCell>
              <TableHeaderCell className="text-right">Stale</TableHeaderCell>
              <TableHeaderCell className="text-right">Pending</TableHeaderCell>
              <TableHeaderCell>Detail</TableHeaderCell>
            </tr>
          </TableHead>
          <tbody>
            {POOLS.map(({ key, label, detail, optIn }) => {
              const pool = workers?.pools?.[key]
              const badge = pool ? poolBadge(pool, optIn) : null
              const count = (value?: number) => value ?? <span className="text-gray-600" aria-label="Unknown">—</span>
              return (
                <TableRow key={key}>
                  <TableCell>
                    <h2 className="font-medium text-gray-100">{label}</h2>
                    <p className="text-xs text-gray-500">{detail}</p>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <StatusDot tone={badge ? BADGE_TONES[badge.text] || 'warning' : 'neutral'} className={badge ? '' : 'text-gray-400'}>
                      {loading && !pool ? 'loading' : badge?.text || 'unknown'}
                    </StatusDot>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{count(pool?.count)}</TableCell>
                  <TableCell className="text-right tabular-nums">{count(pool?.current)}</TableCell>
                  <TableCell className={`text-right tabular-nums ${pool?.stale ? 'text-amber-300' : ''}`}>{count(pool?.stale)}</TableCell>
                  <TableCell className="text-right tabular-nums">{count(pool?.pending)}</TableCell>
                  <TableCell className="text-xs text-gray-400">{pool ? poolDetail(pool) : 'Waiting for the pool summary.'}</TableCell>
                </TableRow>
              )
            })}
          </tbody>
        </Table>
      </TableContainer>

      <p className="max-w-4xl text-xs text-gray-500">
        The Web DAST pool remains the source of the legacy worker count and build-fingerprint fields.
        Specialized pools use fresh heartbeats and capability checks, so a running container is not
        counted as current until it reports the expected release identity and required tools.
      </p>

      <LastUpdated updatedAt={updatedAt} onRefresh={() => void load(true)} refreshing={refreshing} />
    </div>
  )
}
