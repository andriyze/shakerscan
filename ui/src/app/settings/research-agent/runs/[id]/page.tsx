'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ArrowLeft, CircleStop, Pause, Play } from 'lucide-react'
import {
  cancelResearchEpisode,
  controlResearchCampaign,
  getCampaign,
  getResearchEpisode,
  getResearchEpisodes,
  setResearchEpisodeAutopilot,
  type Campaign,
  type CampaignDetailResponse,
  type ResearchEpisode,
  type ResearchEpisodeDetail,
  type ResearchPlannerMode,
} from '@/lib/api'
import { Button, Card, ErrorState, Skeleton } from '@/components/ui'
import {
  LiveActivity, PROFILES, RunStatusBadge, activeEpisode, findingCount, hostFromUrl, runState,
  type Intensity,
} from '@/components/hunt'

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
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
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

  if (loading) return <div className="mx-auto max-w-4xl px-4 py-6"><Skeleton className="h-96" /></div>

  const state = campaign ? runState(campaign) : (detail?.episode.terminal ? 'completed' : 'running')
  const intensity = String(metaField<string>(campaign, 'intensity') || '')
  const intensityName = PROFILES[intensity as Intensity]?.name || intensity
  const maxEpisodes = metaField<number>(campaign, 'max_episodes') || 0
  const deadline = metaField<string>(campaign, 'deadline_at')
  const found = findingCount(campaign)
  const targetUrl = String((campaign?.target_scope?.url as string) || '')
  const canPause = state === 'running'
  const canResume = state === 'paused'
  const canStop = state === 'running' || state === 'paused'
  const preflightState = metaField<string>(campaign, 'preflight_state')
  const preflightScanId = metaField<string>(campaign, 'preflight_scan_id')
  const readiness = metaField<Record<string, unknown>>(campaign, 'readiness')
  const plannerMode = String(
    metaField<string>(campaign, 'planner_mode')
      || (detail?.episode.planner?.mode as string | undefined)
      || (detail?.episode.autopilot_enabled ? 'configured_ai' : 'agent'),
  )

  return (
    <div className="mx-auto max-w-4xl px-4 py-6">
      <Link href="/settings/research-agent" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-white">
        <ArrowLeft className="h-4 w-4" />All runs
      </Link>

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
          {canStop ? <Button variant="danger" onClick={() => control('cancel')} disabled={busy}><CircleStop className="h-4 w-4" />Stop</Button> : null}
        </div>
      </header>

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}
      {detail && !detail.episode.terminal ? (
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-gray-400">
          <span>Planner:</span>
          <Button
            variant={plannerMode === 'agent' ? 'primary' : 'secondary'}
            onClick={() => switchPlanner('agent')}
            disabled={busy || plannerMode === 'agent'}
          >
            This coding agent
          </Button>
          <Button
            variant={plannerMode === 'configured_ai' ? 'primary' : 'secondary'}
            onClick={() => switchPlanner('configured_ai')}
            disabled={busy || plannerMode === 'configured_ai'}
          >
            Stored AI provider
          </Button>
        </div>
      ) : null}
      {plannerMode !== 'configured_ai' && detail && !detail.episode.terminal ? (
        <div className="mt-4 rounded-lg border border-blue-500/30 bg-blue-500/[0.06] p-3 text-sm text-blue-100">
          Waiting for {plannerMode === 'local_codex' ? 'the local Codex runner' : 'your current coding agent'} to choose the next bounded action.
          {plannerMode === 'local_codex' ? (
            <code className="mt-1 block text-xs text-blue-200">shakerscan research {detail.episode.id} 5</code>
          ) : (
            <span className="mt-1 block text-xs text-gray-400">Return to the agent session that launched this hunt and ask it to continue Deep Hunt.</span>
          )}
        </div>
      ) : null}

      {/* Vitals — the three numbers that matter */}
      <div className="mt-5 grid grid-cols-3 gap-3">
        <Stat label="Findings" value={found > 0 ? `${found}` : '0'} tone={found > 0 ? 'good' : 'muted'} hint={found > 0 ? 'verified' : 'none yet'} />
        <Stat label="Episodes" value={maxEpisodes ? `${episodeCount}/${maxEpisodes}` : `${episodeCount}`} hint="work shifts" />
        <Stat label="Time" value={deadline ? timeLeft(deadline, now).split(' ')[0] : '—'} hint={deadline ? timeLeft(deadline, now).split(' ').slice(1).join(' ') || 'left' : 'no deadline'} />
      </div>

      {found > 0 ? (
        <Link href={`/findings?target_id=${encodeURIComponent(campaign?.target_id || '')}&status=active`} className="mt-3 flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-3 text-sm hover:bg-emerald-500/[0.1]">
          <span className="text-emerald-200">{found} verified finding{found === 1 ? '' : 's'} on this target</span>
          <span className="text-xs text-emerald-300">View findings →</span>
        </Link>
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
          <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
            <Metric label="Experiments" value={yieldMetrics.experiments} />
            <Metric label="Refuted" value={yieldMetrics.falsified_experiments} />
            <Metric label="Supported" value={yieldMetrics.experiment_outcomes?.supported_unverified || 0} />
            <Metric label="Inconclusive / blocked" value={yieldMetrics.non_scientific_experiments || 0} />
            <Metric label="Recon actions" value={yieldMetrics.recon_actions} />
            <Metric label="Known-vuln skips" value={yieldMetrics.novelty_suppressions} />
            <Metric label="Model units" value={yieldMetrics.model_units.toLocaleString()} />
            <Metric label="Verified findings" value={yieldMetrics.verified_autonomous_findings} />
          </div>
          {yieldMetrics.stop_reason ? <p className="mt-3 text-xs text-amber-300">Stopped by yield guard: {yieldMetrics.stop_reason}</p> : null}
        </Card>
      ) : null}

      {/* The live trace */}
      <div className="mt-5">
        {detail ? <LiveActivity detail={detail} now={now} /> : (
          <Card className="p-8 text-center text-sm text-gray-500">This run has no episode activity yet.</Card>
        )}
      </div>
    </div>
  )
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
