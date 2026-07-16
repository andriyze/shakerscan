'use client'

import { useCallback, useEffect, useState, Suspense } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { getCampaigns, formatDate, type Campaign } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { CAMPAIGN_TYPE_LABELS } from '@/lib/constants'
import {
  Button,
  CampaignStatusBadge,
  Card,
  EmptyState,
  ErrorState,
  LastUpdated,
  RiskTierBadge,
  TableSkeleton,
  useToast,
} from '@/components/ui'
import CampaignCreateForm from '@/components/CampaignCreateForm'

const CAMPAIGN_STATUSES = ['planned', 'active', 'paused', 'completed', 'cancelled']

interface CampaignFilters {
  [key: string]: string | number | undefined
  status?: string
  target?: string
}

function CampaignsContent() {
  const { filters, setFilter } = useUrlFilters<CampaignFilters>()
  const toast = useToast()
  const router = useRouter()

  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const statusFilter = filters.status || ''
  const targetFilter = (filters.target || '').trim()

  const load = useCallback(async () => {
    try {
      const res = await getCampaigns({
        limit: 100,
        status: statusFilter || undefined,
        target_id: targetFilter || undefined,
      })
      // Autonomous research runs live on the Autonomous Hunt page; keep them out
      // of the Mission Campaigns ledger so this list isn't a mix of two things.
      setCampaigns((res.campaigns || []).filter((c) => c.campaign_type !== 'autonomous_research'))
      setLoadError(false)
      setLastUpdated(new Date())
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, targetFilter])

  useEffect(() => {
    setLoading(true)
    load()
  }, [load])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Campaigns</h1>
          <p className="mt-1 text-gray-400">
            Group related security work and track current linked-finding impact. Campaigns are bookkeeping records — creating one queues no scan.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <LastUpdated updatedAt={lastUpdated} onRefresh={load} />
          <Button size="sm" onClick={() => setShowCreate(true)}>New campaign</Button>
        </div>
      </div>

      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-gray-400">Status:</span>
          <button
            type="button"
            onClick={() => setFilter('status', undefined)}
            className={`rounded-full border px-3 py-1 text-xs transition-colors ${
              !statusFilter ? 'border-blue-500 bg-blue-600/20 text-blue-300' : 'border-gray-700 text-gray-400 hover:bg-gray-800'
            }`}
          >
            All
          </button>
          {CAMPAIGN_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setFilter('status', s)}
              className={`rounded-full border px-3 py-1 text-xs capitalize transition-colors ${
                statusFilter === s ? 'border-blue-500 bg-blue-600/20 text-blue-300' : 'border-gray-700 text-gray-400 hover:bg-gray-800'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </Card>

      {loadError ? (
        <ErrorState message="Failed to load campaigns." onRetry={load} />
      ) : loading ? (
        <TableSkeleton rows={6} />
      ) : campaigns.length === 0 ? (
        <EmptyState
          message="No campaigns yet"
          hint="Create a campaign to group related security work and track its deployment impact."
          action={{ label: 'New campaign', onClick: () => setShowCreate(true) }}
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-800 text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3">Objective</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {campaigns.map((c) => (
                  <tr
                    key={c.id}
                    className="cursor-pointer hover:bg-gray-800/50"
                    onClick={() => router.push(`/campaigns/${c.id}`)}
                  >
                    <td className="px-4 py-3">
                      <Link href={`/campaigns/${c.id}`} className="font-medium text-white hover:text-blue-300" onClick={(e) => e.stopPropagation()}>
                        {c.name || c.objective}
                      </Link>
                      {c.name && <p className="mt-0.5 truncate text-xs text-gray-500">{c.objective}</p>}
                    </td>
                    <td className="px-4 py-3 text-gray-300">{CAMPAIGN_TYPE_LABELS[c.campaign_type] || c.campaign_type}</td>
                    <td className="px-4 py-3"><CampaignStatusBadge status={c.status} /></td>
                    <td className="px-4 py-3"><RiskTierBadge tier={c.risk_tier} /></td>
                    <td className="px-4 py-3 text-gray-300">
                      {c.deployment_impact?.linked_finding_count ?? 0}
                      {typeof c.deployment_impact?.active_finding_count === 'number' && c.deployment_impact.active_finding_count > 0 && (
                        <span className="ml-1 text-xs text-yellow-400">({c.deployment_impact.active_finding_count} active)</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-500">{formatDate(c.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <CampaignCreateForm
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(campaign) => {
          setShowCreate(false)
          toast.success('Campaign created')
          router.push(`/campaigns/${campaign.id}`)
        }}
      />
    </div>
  )
}

export default function CampaignsPage() {
  return (
    <Suspense fallback={
      <div className="flex h-32 items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-b-2 border-blue-500"></div>
      </div>
    }>
      <CampaignsContent />
    </Suspense>
  )
}
