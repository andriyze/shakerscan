'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ArrowLeft, CircleStop, Pause, Play } from 'lucide-react'
import {
  cancelResearchEpisode,
  controlResearchCampaign,
  getCampaign,
  getFindings,
  getResearchEpisode,
  getResearchEpisodes,
  setResearchEpisodeAutopilot,
  type Campaign,
  type CampaignDetailResponse,
  type Finding,
  type ResearchEpisode,
  type ResearchEpisodeDetail,
  type ResearchPlannerMode,
} from '@/lib/api'
import { Button, Card, ConfirmDialog, ErrorState, SeverityBadge, Skeleton } from '@/components/ui'
import {
  LiveActivity, PROFILES, RunStatusBadge, activeEpisode, findingCount, hostFromUrl, runState,
  type Intensity,
} from '@/components/hunt'
import { InvestigatorTabs } from '@/components/hunt/InvestigatorTabs'

function metaField<T>(campaign: Campaign | null, key: string): T | undefined {
  const meta = (campaign?.metadata_json?.autonomous_research ?? {}) as Record<string, unknown>
  return meta[key] as T | undefined
}

function timeLeft(deadlineIso: string | undefined, now: number): string {
  if (!deadlineIso) return ''
  const end = new Date(deadlineIso).getTime()
  if (Number.isNaN(end)) return ''
  const secs = Math.round((end - now) / 1000)
  if (secs <= 0) return 'ceiling reached'
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  const mins = Math.floor((secs % 3600) / 60)
  if (days) return `${days}d ${hours}h left`
  if (hours) return `${hours}h ${mins}m left`
  return `${mins}m left`
}

export default function RunDetailPage() {
  const params = useParams()
  const id = params.id as string
  const [campaign, setCampaign] = useState<Campaign | null>(null)
  const [detail, setDetail] = useState<ResearchEpisodeDetail | null>(null)
  const [episodeCount, setEpisodeCount] = useState(0)
  const [yieldMetrics, setYieldMetrics] = useState<NonNullable<CampaignDetailResponse['research_yield']> | null>(null)
  const [runFindings, setRunFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pendingConfirm, setPendingConfirm] = useState<'stop' | ResearchPlannerMode | null>(null)
  const [now, setNow] = useState(() => Date.now())

  // Refs keep the polling interval from restarting on every tick / data change.
  const detailRef = useRef<ResearchEpisodeDetail | null>(null)
  detailRef.current = detail
  const campaignIdRef = useRef<string | null>(null)

  // Resolve the id (campaign or, for legacy standalone runs, an episode) into a
  // campaign summary + the episode currently worth watching.
  const load = useCallback(async () => {
    let camp: Campaign | null = null
    let episodes: ResearchEpisode[] = []
    try {
      const detailResp = await getCampaign(id)
      camp = detailResp.campaign
      setYieldMetrics(detailResp.research_yield || null)
      campaignIdRef.current = camp.id
      const list = await getResearchEpisodes({ campaign_id: camp.id, limit: 50 })
      episodes = list.episodes || []
      setEpisodeCount(episodes.length)
    } catch {
      campaignIdRef.current = null
    }
    setCampaign(camp)
    const watch = activeEpisode(episodes)
    if (watch) return getResearchEpisode(watch.id)
    if (camp) return null
    // Fallback: the id was an episode, not a campaign.
    return getResearchEpisode(id)
  }, [id])

  useEffect(() => {
    let cancelled = false
    load()
      .then((d) => { if (!cancelled) setDetail(d) })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load this run') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [load])

  // Heartbeat clock for relative times.
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])

  // Findings this run produced (hunt-driven scanner findings, stamped with the
  // campaign's research provenance). Refreshed on a slow poll alongside the run.
  useEffect(() => {
    const campId = campaign?.id
    if (!campId) return
    let cancelled = false
    const fetchRunFindings = () => {
      getFindings({ research_campaign_id: campId, limit: 25, sort_by: 'severity', sort_order: 'desc' })
        .then((d) => { if (!cancelled) setRunFindings(d.findings || []) })
        .catch(() => undefined)
    }
    fetchRunFindings()
    const t = window.setInterval(fetchRunFindings, 15000)
    return () => { cancelled = true; window.clearInterval(t) }
  }, [campaign?.id])

  // Live polling: follow the active episode; when it finishes, pick up the next
  // one the campaign chains, and keep the run summary fresh.
  useEffect(() => {
    const timer = window.setInterval(async () => {
      const current = detailRef.current
      try {
        if (!current) {
          const campId = campaignIdRef.current
          if (!campId) return
          const [summary, list] = await Promise.all([
            getCampaign(campId).catch(() => null),
            getResearchEpisodes({ campaign_id: campId, limit: 50 }),
          ])
          if (summary) {
            setCampaign(summary.campaign)
            setYieldMetrics(summary.research_yield || null)
          }
          setEpisodeCount(list.episodes?.length || 0)
          const next = (list.episodes || []).find((e) => !e.terminal)
          if (next) setDetail(await getResearchEpisode(next.id))
          return
        }
        if (!current.episode.terminal) {
          setDetail(await getResearchEpisode(current.episode.id))
          return
        }
        const campId = campaignIdRef.current
        if (!campId) return
        const [summary, list] = await Promise.all([
          getCampaign(campId).catch(() => null),
          getResearchEpisodes({ campaign_id: campId, limit: 50 }),
        ])
        if (summary) {
          setCampaign(summary.campaign)
          setYieldMetrics(summary.research_yield || null)
        }
        setEpisodeCount(list.episodes?.length || 0)
        const next = (list.episodes || []).find((e) => !e.terminal)
        if (next && next.id !== current.episode.id) setDetail(await getResearchEpisode(next.id))
      } catch { /* keep last-good view on a transient error */ }
    }, 2500)
    return () => window.clearInterval(timer)
  }, [])

  const control = async (action: 'pause' | 'resume' | 'cancel') => {
    setBusy(true); setError(null)
    try {
      const campId = campaignIdRef.current
      if (campId) {
        await controlResearchCampaign(campId, action)
        setCampaign((await getCampaign(campId)).campaign)
        if (detail && !detail.episode.terminal) {
          setDetail(await getResearchEpisode(detail.episode.id))
        }
      } else if (detail) {
        if (action === 'cancel') setDetail(await cancelResearchEpisode(detail.episode.id))
        else setDetail(await setResearchEpisodeAutopilot(detail.episode.id, action === 'resume'))
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Could not ${action} the run`)
    } finally { setBusy(false) }
  }

  const switchPlanner = async (mode: ResearchPlannerMode) => {
    if (!detail || detail.episode.terminal) return
    setBusy(true); setError(null)
    try {
      const updated = await setResearchEpisodeAutopilot(
        detail.episode.id,
        mode === 'configured_ai',
        mode,
      )
      setDetail(updated)
      const campId = campaignIdRef.current
      if (campId) setCampaign((await getCampaign(campId)).campaign)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not switch the planner')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div><Skeleton className="h-96" /></div>

  const campaignState = campaign ? runState(campaign) : (detail?.episode.terminal ? 'completed' : 'running')
  const automaticallyStopped = Boolean(yieldMetrics?.stop_recommended && yieldMetrics.stop_reason)
  const agentWaiting = Boolean(
    detail
    && !detail.episode.terminal
    && detail.episode.status === 'awaiting_planner'
    && detail.episode.autopilot_enabled === false
  )
  const state = automaticallyStopped ? 'completed' : agentWaiting ? 'waiting' : campaignState
  const intensity = String(metaField<string>(campaign, 'intensity') || '')
  const intensityName = PROFILES[intensity as Intensity]?.name || intensity
  const maxEpisodes = metaField<number>(campaign, 'max_episodes') || 0
  const deadline = metaField<string>(campaign, 'deadline_at')
  const found = findingCount(campaign)
  const targetUrl = String((campaign?.target_scope?.url as string) || '')
  const canPause = state === 'running'
  const canResume = state === 'paused' && !automaticallyStopped
  const canStop = state === 'running' || state === 'waiting' || state === 'paused'
  const preflightState = metaField<string>(campaign, 'preflight_state')
  const preflightScanId = metaField<string>(campaign, 'preflight_scan_id')
  const readiness = metaField<Record<string, unknown>>(campaign, 'readiness')
  const plannerMode = String(
    metaField<string>(campaign, 'planner_mode')
      || (detail?.episode.planner?.mode as string | undefined)
      || (detail?.episode.autopilot_enabled ? 'configured_ai' : 'agent'),
  )
  const autonomousProofs = yieldMetrics?.verified_autonomous_findings || 0
  const linkedProofs = (yieldMetrics?.verified_campaign_scan_findings || 0)
    + (yieldMetrics?.verified_campaign_retest_findings || 0)
  const netNewProofs = yieldMetrics?.net_new_verified_findings || 0
  const inconclusive = yieldMetrics?.non_scientific_experiments || 0
  const activeRun = state === 'running' || state === 'waiting' || state === 'paused'

  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <Link href="/settings/research-agent" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-white">
          <ArrowLeft className="h-4 w-4" />All hunts
        </Link>
        <InvestigatorTabs />
      </div>

      <header className="mt-3 flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <RunStatusBadge state={state} />
            {intensityName ? <span className="text-xs text-gray-500">{intensityName}</span> : null}
          </div>
          <h1 className="mt-2 truncate text-xl font-semibold text-white">{campaign?.name || hostFromUrl(targetUrl) || 'Autonomous run'}</h1>
          {targetUrl ? <p className="mt-0.5 font-mono text-xs text-gray-500">{targetUrl}</p> : null}
        </div>
        <div className="flex flex-none gap-2">
          {canPause ? <Button variant="secondary" onClick={() => control('pause')} disabled={busy}><Pause className="h-4 w-4" />Pause</Button> : null}
          {canResume ? <Button onClick={() => control('resume')} disabled={busy}><Play className="h-4 w-4" />Resume</Button> : null}
          {canStop ? <Button variant="danger" onClick={() => setPendingConfirm('stop')} disabled={busy}><CircleStop className="h-4 w-4" />Stop</Button> : null}
        </div>
      </header>

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}
      {detail && !detail.episode.terminal ? (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-gray-400">
          <span>Planner:</span>
          <Button
            variant={plannerMode === 'agent' ? 'primary' : 'secondary'}
            onClick={() => setPendingConfirm('agent')}
            disabled={busy || plannerMode === 'agent'}
          >
            Agent-guided
          </Button>
          <Button
            variant={plannerMode === 'configured_ai' ? 'primary' : 'secondary'}
            onClick={() => setPendingConfirm('configured_ai')}
            disabled={busy || plannerMode === 'configured_ai'}
          >
            Unattended
          </Button>
        </div>
      ) : null}
      {plannerMode !== 'configured_ai' && detail && !detail.episode.terminal ? (
        <div className="mt-4 rounded-lg border border-blue-500/30 bg-blue-500/[0.06] p-3 text-sm text-blue-100">
          Waiting for {plannerMode === 'local_codex' ? 'the local Codex runner' : 'your coding agent'} to choose the next bounded action. This run will not advance by itself.
          {plannerMode === 'local_codex' ? (
            <code className="mt-1 block text-xs text-blue-200">shakerscan research {detail.episode.id} 5</code>
          ) : (
            <span className="mt-1 block text-xs text-gray-400">Return to the agent session that launched this hunt and ask it to continue Deep Hunt.</span>
          )}
        </div>
      ) : null}

      {/* Vitals — the three numbers that matter */}
      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Stat label="Linked findings" value={found > 0 ? `${found}` : '0'} tone={found > 0 ? 'good' : 'muted'} hint={found > 0 ? 'active in linked work' : activeRun ? 'none yet' : 'none produced'} />
        <Stat label="Episodes" value={maxEpisodes ? `${episodeCount}/${maxEpisodes}` : `${episodeCount}`} hint="work shifts" />
        <Stat
          label="Time"
          value={state === 'running' || state === 'waiting' || state === 'paused' ? (deadline ? timeLeft(deadline, now).split(' ')[0] : '—') : 'Ended'}
          hint={state === 'running' || state === 'waiting' || state === 'paused'
            ? (deadline ? timeLeft(deadline, now).split(' ').slice(1).join(' ') || 'left' : 'no deadline')
            : 'run is not active'}
        />
      </div>

      {found > 0 ? (
        <Link href={`/findings?research_campaign_id=${encodeURIComponent(campaign?.id || '')}&status=active`} className="mt-3 flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-3 text-sm hover:bg-emerald-500/[0.1]">
          <span className="text-emerald-200">{found} active finding{found === 1 ? '' : 's'} linked to this run</span>
          <span className="text-xs text-emerald-300">View findings →</span>
        </Link>
      ) : null}

      {runFindings.length > 0 ? (
        <Card className="mt-4 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Findings from this run</h2>
            <Link href={`/findings?research_campaign_id=${encodeURIComponent(campaign?.id || '')}`} className="text-xs text-blue-300 hover:text-blue-200">
              View all →
            </Link>
          </div>
          <div className="divide-y divide-gray-800">
            {runFindings.slice(0, 8).map((finding) => (
              <Link key={finding.id} href={`/findings/${finding.id}`} className="flex items-center gap-3 py-2 hover:bg-gray-800/40 -mx-2 px-2 rounded">
                <SeverityBadge severity={finding.severity} />
                <span className="min-w-0 flex-1 truncate text-sm text-gray-200">{finding.title}</span>
                {finding.last_verification_verdict === 'exploited' ? (
                  <span className="flex-none text-xs text-emerald-300">verified</span>
                ) : (
                  <span className="flex-none text-xs text-gray-500">scan-proven</span>
                )}
              </Link>
            ))}
            {runFindings.length > 8 ? (
              <Link href={`/findings?research_campaign_id=${encodeURIComponent(campaign?.id || '')}`} className="block py-2 text-xs text-blue-300 hover:text-blue-200">
                + {runFindings.length - 8} more →
              </Link>
            ) : null}
          </div>
        </Card>
      ) : null}

      {(preflightState && preflightState !== 'completed' && preflightState !== 'not_required') || readiness?.ready === false ? (
        <Card className="mt-4 p-4">
          <div className={`text-sm font-medium ${readiness?.ready === false ? 'text-amber-300' : 'text-blue-200'}`}>
            Authenticated coverage {readiness?.ready === false ? 'blocked' : `preflight: ${preflightState}`}
          </div>
          <p className="mt-1 text-xs text-gray-500">
            Hunting starts only after the route inventory contains executable authenticated surface
            {Array.isArray(readiness?.blockers) && readiness.blockers.length > 0 ? ` · ${readiness.blockers.join(', ')}` : ''}.
          </p>
          {preflightScanId ? <Link className="mt-2 inline-block text-xs text-blue-300 hover:text-blue-200" href={`/scans/${preflightScanId}`}>View preflight scan →</Link> : null}
        </Card>
      ) : null}

      {yieldMetrics ? (
        <Card className="mt-4 p-4">
          <div className="mb-4 border-b border-gray-800 pb-4">
            <h2 className="text-sm font-semibold text-white">Run outcome</h2>
            <p className="mt-1 text-sm text-gray-300">
              {netNewProofs > 0
                ? `${netNewProofs} net-new verified finding${netNewProofs === 1 ? '' : 's'} produced by this run.`
                : autonomousProofs > 0
                  ? `${autonomousProofs} autonomous proof${autonomousProofs === 1 ? '' : 's'}; none were net-new over existing scan evidence.`
                  : linkedProofs > 0
                    ? `No net-new autonomous findings. Linked scans or retests confirmed ${linkedProofs} existing finding${linkedProofs === 1 ? '' : 's'}.`
                    : activeRun
                      ? 'No verified result yet.'
                      : 'The run ended without a verified finding.'}
            </p>
            {inconclusive > 0 ? <p className="mt-1 text-xs text-gray-500">{inconclusive} experiment{inconclusive === 1 ? ' was' : 's were'} inconclusive or blocked.</p> : null}
            {yieldMetrics.stop_reason ? <p className="mt-2 text-xs text-amber-300">Automatically stopped: {friendlyStopReason(yieldMetrics.stop_reason)}</p> : null}
            <p className="mt-2 text-xs text-gray-500">
              {netNewProofs > 0
                ? 'Next: review the finding evidence and remediation guidance.'
                : linkedProofs > 0
                  ? 'Next: review the linked findings; they were reconfirmed rather than newly discovered here.'
                  : 'Next: review blocked experiments and target readiness before starting another run.'}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
            <Metric label="Experiments" value={yieldMetrics.experiments} />
            <Metric label="Refuted" value={yieldMetrics.falsified_experiments} />
            <Metric label="Supported" value={yieldMetrics.experiment_outcomes?.supported_unverified || 0} />
            <Metric label="Inconclusive / blocked" value={yieldMetrics.non_scientific_experiments || 0} />
            <Metric label="Recon actions" value={yieldMetrics.recon_actions} />
            <Metric label="Known-vuln skips" value={yieldMetrics.novelty_suppressions} />
            <Metric label="Estimated model units used" value={yieldMetrics.model_units.toLocaleString()} />
            <Metric label="Autonomous proofs" value={yieldMetrics.verified_autonomous_findings} />
            <Metric label="Focused-scan proofs" value={yieldMetrics.verified_campaign_scan_findings || 0} />
            <Metric label="Retest confirmations" value={yieldMetrics.verified_campaign_retest_findings || 0} />
            <Metric label="Net-new over DAST" value={yieldMetrics.net_new_verified_findings || 0} />
          </div>
        </Card>
      ) : null}

      {/* The live trace */}
      <div className="mt-5">
        {detail ? <LiveActivity detail={detail} now={now} /> : (
          <Card className="p-8 text-center text-sm text-gray-500">This run has no episode activity yet.</Card>
        )}
      </div>
      <ConfirmDialog
        open={pendingConfirm === 'stop'}
        title="Stop this hunt?"
        message="The campaign and any linked work will be cancelled. You cannot resume this run afterward."
        confirmLabel="Stop hunt"
        danger
        busy={busy}
        onCancel={() => setPendingConfirm(null)}
        onConfirm={() => { setPendingConfirm(null); void control('cancel') }}
      />
      <ConfirmDialog
        open={pendingConfirm === 'agent' || pendingConfirm === 'configured_ai'}
        title={`Switch to ${pendingConfirm === 'configured_ai' ? 'unattended' : 'agent-guided'} planning?`}
        message={pendingConfirm === 'configured_ai'
          ? 'The stored AI provider will choose bounded actions on the server and can continue after you close this page.'
          : 'The run will pause between actions until your coding agent returns to continue it.'}
        confirmLabel="Switch planner"
        busy={busy}
        onCancel={() => setPendingConfirm(null)}
        onConfirm={() => {
          const mode = pendingConfirm
          setPendingConfirm(null)
          if (mode && mode !== 'stop') void switchPlanner(mode)
        }}
      />
    </div>
  )
}

function friendlyStopReason(reason: string): string {
  const labels: Record<string, string> = {
    experiment_harness_failure_ceiling: 'too many experiments could not run reliably',
    no_progress_ceiling: 'repeated actions produced no new evidence',
    experiment_yield_ceiling: 'additional experiments were unlikely to add useful evidence',
  }
  return labels[reason] || reason.replace(/_/g, ' ')
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <div><div className="text-gray-600">{label}</div><div className="mt-0.5 font-medium tabular-nums text-gray-300">{value}</div></div>
}

function Stat({ label, value, hint, tone = 'default' }: { label: string; value: string; hint?: string; tone?: 'default' | 'good' | 'muted' }) {
  const valueClass = tone === 'good' ? 'text-emerald-300' : tone === 'muted' ? 'text-gray-400' : 'text-white'
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-gray-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${valueClass}`}>{value}</div>
      {hint ? <div className="text-xs text-gray-600">{hint}</div> : null}
    </div>
  )
}
