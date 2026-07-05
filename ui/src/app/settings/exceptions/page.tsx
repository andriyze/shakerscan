'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { ExternalLink, RefreshCw, ShieldAlert, XCircle } from 'lucide-react'
import {
  formatDate,
  getFindingExceptions,
  updateFindingException,
  type FindingException,
  type FindingExceptionPayload,
} from '@/lib/api'
import { Badge, Button, Card, ConfirmDialog, EmptyState, ErrorState, useToast } from '@/components/ui'

type QueueFilter =
  | ''
  | 'expiring'
  | 'expired'
  | 'missing_owner'
  | 'missing_approver'
  | 'missing_controls'
  | 'policy_scoped'
  | 'target_scoped'

const QUEUE_FILTERS: Array<{ value: QueueFilter; label: string; description: string }> = [
  { value: '', label: 'Active', description: 'Exceptions with the selected status.' },
  { value: 'expiring', label: 'Expiring soon', description: 'Exceptions that expire in the next 7 days.' },
  { value: 'expired', label: 'Expired', description: 'Expired by status or expiry timestamp.' },
  { value: 'missing_owner', label: 'Missing owner', description: 'No accountable owner is recorded.' },
  { value: 'missing_approver', label: 'Missing approver', description: 'No approver is recorded.' },
  { value: 'missing_controls', label: 'No controls', description: 'No compensating controls are recorded.' },
  { value: 'policy_scoped', label: 'Policy scoped', description: 'Limited to a policy profile.' },
  { value: 'target_scoped', label: 'Target scoped', description: 'Limited to one target.' },
]

function parseQueueFilter(value: string | null): QueueFilter {
  return QUEUE_FILTERS.some((filter) => filter.value === value) ? (value as QueueFilter) : ''
}

const STATUS_STYLES: Record<string, string> = {
  active: 'bg-blue-500/15 text-blue-300',
  approved: 'bg-emerald-500/15 text-emerald-300',
  accepted_risk: 'bg-amber-500/15 text-amber-300',
  revoked: 'bg-red-500/15 text-red-300',
  expired: 'bg-gray-700 text-gray-300',
}

function exceptionToPayload(item: FindingException, status: string): FindingExceptionPayload {
  return {
    finding_id: item.finding_id || null,
    fingerprint: item.fingerprint || null,
    policy_id: item.policy_id || null,
    target_id: item.target_id || null,
    scope: item.scope || null,
    owner: item.owner || null,
    approver: item.approver || null,
    reason: item.reason || null,
    compensating_controls: item.compensating_controls || null,
    status,
    expires_at: item.expires_at || null,
  }
}

function exceptionWarnings(item: FindingException): string[] {
  const warnings: string[] = []
  const expiresAt = item.expires_at ? new Date(item.expires_at) : null
  const now = Date.now()
  if (item.status === 'expired' || (expiresAt && expiresAt.getTime() < now)) warnings.push('expired')
  if (expiresAt && expiresAt.getTime() >= now && expiresAt.getTime() <= now + 7 * 24 * 60 * 60 * 1000) warnings.push('expiring soon')
  if (!item.owner?.trim()) warnings.push('missing owner')
  if (!item.approver?.trim()) warnings.push('missing approver')
  if (!item.compensating_controls?.trim()) warnings.push('no compensating controls')
  if (item.policy_id) warnings.push('policy scoped')
  if (item.target_id) warnings.push('target scoped')
  return warnings
}

export default function ExceptionsQueuePage() {
  const toast = useToast()
  const [queueFilter, setQueueFilter] = useState<QueueFilter>('')
  const [status, setStatus] = useState('active')
  const [items, setItems] = useState<FindingException[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [revoking, setRevoking] = useState<FindingException | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setQueueFilter(parseQueueFilter(new URLSearchParams(window.location.search).get('queue_filter')))
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const res = await getFindingExceptions({
        status: queueFilter ? undefined : status || undefined,
        queue_filter: queueFilter || undefined,
        expiring_within_days: 7,
        limit: 500,
      })
      setItems(res.finding_exceptions || [])
    } catch (err) {
      console.error('Failed to fetch finding exceptions:', err)
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [queueFilter, status])

  useEffect(() => {
    load()
  }, [load])

  const summary = useMemo(() => {
    const counts = {
      expired: 0,
      expiring: 0,
      missingOwner: 0,
      missingApprover: 0,
      missingControls: 0,
    }
    for (const item of items) {
      const warnings = exceptionWarnings(item)
      if (warnings.includes('expired')) counts.expired += 1
      if (warnings.includes('expiring soon')) counts.expiring += 1
      if (warnings.includes('missing owner')) counts.missingOwner += 1
      if (warnings.includes('missing approver')) counts.missingApprover += 1
      if (warnings.includes('no compensating controls')) counts.missingControls += 1
    }
    return counts
  }, [items])

  async function revokeSelected() {
    if (!revoking) return
    setSaving(true)
    try {
      await updateFindingException(revoking.id, exceptionToPayload(revoking, 'revoked'))
      setRevoking(null)
      toast.success('Exception revoked')
      await load()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke exception')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-amber-300" />
            <h1 className="text-2xl font-bold text-white">Exceptions Queue</h1>
          </div>
          <p className="mt-1 text-sm text-gray-400">
            Review policy exceptions that can unblock deployment decisions.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link href="/settings/policy-profiles" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
            Policy profiles
          </Link>
          <Button variant="secondary" onClick={load} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-5">
        <Card className="p-3">
          <div className="text-xs uppercase text-gray-500">Total in view</div>
          <div className="mt-1 text-2xl font-semibold text-white">{items.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs uppercase text-gray-500">Expired</div>
          <div className="mt-1 text-2xl font-semibold text-gray-200">{summary.expired}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs uppercase text-gray-500">Expiring</div>
          <div className="mt-1 text-2xl font-semibold text-amber-300">{summary.expiring}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs uppercase text-gray-500">Missing owner/approver</div>
          <div className="mt-1 text-2xl font-semibold text-red-300">{summary.missingOwner + summary.missingApprover}</div>
        </Card>
        <Card className="p-3">
          <div className="text-xs uppercase text-gray-500">No controls</div>
          <div className="mt-1 text-2xl font-semibold text-red-300">{summary.missingControls}</div>
        </Card>
      </div>

      <Card className="p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm text-gray-400">Queue:</span>
          <div className="flex max-w-full flex-wrap gap-1 rounded-lg border border-gray-800 bg-gray-900 p-0.5">
            {QUEUE_FILTERS.map((filter) => (
              <button
                key={filter.value || 'all'}
                type="button"
                onClick={() => setQueueFilter(filter.value)}
                title={filter.description}
                className={`rounded-md px-2.5 py-1 text-sm transition-colors sm:px-3 ${
                  queueFilter === filter.value
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                {filter.label}
              </button>
            ))}
          </div>
          {!queueFilter && (
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              aria-label="Exception status"
              className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="">Any status</option>
              <option value="active">active</option>
              <option value="approved">approved</option>
              <option value="accepted_risk">accepted risk</option>
              <option value="revoked">revoked</option>
              <option value="expired">expired</option>
            </select>
          )}
        </div>

        {error ? (
          <ErrorState message="Failed to load finding exceptions." onRetry={load} />
        ) : loading ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-24 animate-pulse rounded-lg bg-gray-900" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <EmptyState message="No exceptions match this queue." />
        ) : (
          <div className="space-y-2">
            {items.map((item) => {
              const warnings = exceptionWarnings(item)
              return (
                <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={STATUS_STYLES[item.status] || 'bg-gray-800 text-gray-300'}>
                          {item.status.replace(/_/g, ' ')}
                        </Badge>
                        {warnings.map((warning) => (
                          <Badge
                            key={warning}
                            className={
                              warning === 'expired' || warning.startsWith('missing') || warning === 'no compensating controls'
                                ? 'bg-red-500/15 text-red-300'
                                : 'bg-amber-500/15 text-amber-300'
                            }
                          >
                            {warning}
                          </Badge>
                        ))}
                      </div>
                      <div className="grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
                        <div>
                          <div className="text-xs text-gray-500">Finding</div>
                          <div className="truncate font-mono text-xs text-gray-300">{item.finding_id || item.fingerprint || 'not scoped'}</div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500">Owner / approver</div>
                          <div className="text-gray-300">{item.owner || 'no owner'} / {item.approver || 'no approver'}</div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500">Expires</div>
                          <div className="text-gray-300">{item.expires_at ? formatDate(item.expires_at) : 'no expiry'}</div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500">Scope</div>
                          <div className="text-gray-300">
                            {item.policy_id ? 'policy' : item.target_id ? 'target' : item.scope || 'global'}
                          </div>
                        </div>
                      </div>
                      {item.reason && <p className="text-sm text-gray-400">{item.reason}</p>}
                      {item.compensating_controls && (
                        <p className="text-xs text-gray-500">Controls: {item.compensating_controls}</p>
                      )}
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-2">
                      {item.finding_id && (
                        <Link
                          href={`/findings/${item.finding_id}`}
                          className="inline-flex items-center gap-1 rounded-lg border border-gray-700 px-2.5 py-1.5 text-xs text-gray-300 hover:bg-gray-800"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                          Finding
                        </Link>
                      )}
                      {item.status !== 'revoked' && (
                        <Button size="sm" variant="danger" onClick={() => setRevoking(item)}>
                          <XCircle className="h-3.5 w-3.5" />
                          Revoke
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={Boolean(revoking)}
        title="Revoke exception"
        message={`Revoke this policy exception${revoking?.finding_id ? ` for ${revoking.finding_id}` : ''}? Deployment gates will treat the covered finding as blocking again.`}
        confirmLabel="Revoke"
        danger
        busy={saving}
        onConfirm={revokeSelected}
        onCancel={() => setRevoking(null)}
      />
    </div>
  )
}
