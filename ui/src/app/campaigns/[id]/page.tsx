'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ArrowLeft } from 'lucide-react'
import { getCampaign, formatDate, type CampaignDetailResponse } from '@/lib/api'
import { CAMPAIGN_TYPE_LABELS } from '@/lib/constants'
import {
  CampaignStatusBadge,
  Card,
  EmptyState,
  ErrorState,
  RiskTierBadge,
  ScanStatusBadge,
  SectionCard,
  SeverityBadge,
  TableSkeleton,
} from '@/components/ui'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function Stat({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
      <p className="text-xs text-gray-500">{label}</p>
      <p className={`mt-1 text-lg font-semibold ${accent || 'text-white'}`}>{value}</p>
    </div>
  )
}

export default function CampaignDetailPage() {
  const params = useParams()
  const campaignId = params.id as string

  const [data, setData] = useState<CampaignDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await getCampaign(campaignId)
      setData(res)
      setLoadError(false)
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [campaignId])

  useEffect(() => {
    setLoading(true)
    load()
  }, [load])

  const campaign = data?.campaign
  const impact = data?.deployment_impact
  const statusRollup = data?.status_rollup || {}

  return (
    <div className="space-y-6">
      <Link href="/campaigns" className="inline-flex items-center gap-1 text-sm text-gray-400 hover:text-white">
        <ArrowLeft className="h-4 w-4" /> Back to campaigns
      </Link>

      {loadError ? (
        <ErrorState message="Failed to load campaign." onRetry={load} />
      ) : loading || !data || !campaign ? (
        <TableSkeleton rows={6} />
      ) : (
        <>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-bold text-white">{campaign.name || campaign.objective}</h1>
              <CampaignStatusBadge status={campaign.status} />
              <RiskTierBadge tier={campaign.risk_tier} />
            </div>
            <p className="mt-1 text-gray-400">{campaign.objective}</p>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
              <span>{CAMPAIGN_TYPE_LABELS[campaign.campaign_type] || campaign.campaign_type}</span>
              {campaign.target_id && <span>target: {campaign.target_id}</span>}
              {campaign.policy_profile && <span>policy: {campaign.policy_profile}</span>}
              <span>created {formatDate(campaign.created_at)}</span>
            </div>
          </div>

          <SectionCard title="Deployment impact">
            {impact && Object.keys(impact).length > 0 ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Stat label="Linked findings" value={impact.linked_finding_count ?? 0} />
                  <Stat
                    label="Active findings"
                    value={impact.active_finding_count ?? 0}
                    accent={impact.active_finding_count ? 'text-yellow-400' : 'text-white'}
                  />
                  <Stat label="Default blockers" value={impact.estimated_default_blockers ?? 0} />
                  <Stat
                    label="Blocks deploy?"
                    value={impact.blocks_deployment_estimate ? 'Yes' : 'No'}
                    accent={impact.blocks_deployment_estimate ? 'text-red-400' : 'text-green-400'}
                  />
                </div>
                {impact.by_severity && Object.keys(impact.by_severity).length > 0 && (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-gray-500">By severity:</span>
                    {SEVERITY_ORDER.filter((s) => impact.by_severity?.[s]).map((s) => (
                      <span key={s} className="inline-flex items-center gap-1">
                        <SeverityBadge severity={s} />
                        <span className="text-sm text-gray-300">{impact.by_severity?.[s]}</span>
                      </span>
                    ))}
                  </div>
                )}
                {impact.partial && (
                  <p className="text-xs text-amber-400">Rollup is partial — some linked findings could not be resolved.</p>
                )}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No linked findings yet.</p>
            )}
          </SectionCard>

          <SectionCard title={`Action ledger (${data.action_count}${data.total_action_count > data.action_count ? ` of ${data.total_action_count}` : ''})`}>
            {Object.keys(statusRollup).length > 0 && (
              <div className="mb-3 flex flex-wrap gap-2">
                {Object.entries(statusRollup).map(([status, count]) => (
                  <span key={status} className="rounded-full border border-gray-700 px-2.5 py-0.5 text-xs text-gray-300">
                    {status.replace(/_/g, ' ')}: {count}
                  </span>
                ))}
              </div>
            )}
            {data.actions.length === 0 ? (
              <EmptyState message="No actions linked" hint="Actions appear here when Arsenal command results are linked to this campaign." />
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-800 text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                      <th className="px-3 py-2">Action</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2">Risk</th>
                      <th className="px-3 py-2">Findings</th>
                      <th className="px-3 py-2">When</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {data.actions.map((a) => (
                      <tr key={a.id} className="hover:bg-gray-800/40">
                        <td className="px-3 py-2">
                          <span className="font-medium text-white">{(a.action_name || a.command).replace(/_/g, ' ')}</span>
                          {a.operator_message && <p className="mt-0.5 truncate text-xs text-gray-500" title={a.operator_message}>{a.operator_message}</p>}
                        </td>
                        <td className="px-3 py-2">
                          {a.live_scan_status ? <ScanStatusBadge status={a.live_scan_status} /> : (
                            <span className="text-xs text-gray-400">{a.status.replace(/_/g, ' ')}{a.dry_run ? ' (dry run)' : ''}</span>
                          )}
                        </td>
                        <td className="px-3 py-2"><RiskTierBadge tier={a.risk_tier} /></td>
                        <td className="px-3 py-2 text-gray-300">
                          {a.finding_ids.length > 0 ? a.finding_ids.length : '—'}
                          {a.scan_id && (
                            <Link href={`/scans/${a.scan_id}`} className="ml-2 text-xs text-blue-400 hover:text-blue-300" onClick={(e) => e.stopPropagation()}>
                              scan →
                            </Link>
                          )}
                        </td>
                        <td className="px-3 py-2 text-gray-500">{a.created_at ? formatDate(a.created_at) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>
        </>
      )}
    </div>
  )
}
