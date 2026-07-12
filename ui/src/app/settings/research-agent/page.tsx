'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Activity, ArrowRight, BrainCircuit, Check, ChevronDown, CircleStop, History,
  Pause, Play, RefreshCw, Rocket, ShieldCheck, Sparkles, Zap,
} from 'lucide-react'
import {
  cancelResearchEpisode,
  createResearchEpisode,
  createTargetPolicyApproval,
  getResearchEpisode,
  getResearchEpisodes,
  getResearchReadiness,
  getTarget,
  getTargets,
  refreshResearchObservation,
  setResearchEpisodeAutopilot,
  type ResearchBudget,
  type ResearchEpisode,
  type ResearchEpisodeDetail,
  type Target,
} from '@/lib/api'
import { Badge, Button, Card, EmptyState, ErrorState, Skeleton, buttonClasses } from '@/components/ui'

type Intensity = 'analyze' | 'hunt' | 'relentless' | 'deep_hunt'

const PROFILES: Record<Intensity, {
  name: string
  eyebrow: string
  description: string
  mode: 'read_only' | 'gated'
  maxSteps: number
  risk: 'read_only' | 'active' | 'credential'
  budget: ResearchBudget
  tone: string
}> = {
  analyze: {
    name: 'Analyze', eyebrow: 'No active probes',
    description: 'Let the LLM inspect coverage, findings, graph context, and gaps without queueing active work.',
    mode: 'read_only', maxSteps: 8, risk: 'read_only',
    budget: { steps: 8, actions: 7, active_actions: 0, requests: 0, seconds: 600, model_tokens: 75000 },
    tone: 'border-cyan-500/30 bg-cyan-500/[0.05]',
  },
  hunt: {
    name: 'Autonomous hunt', eyebrow: 'Recommended',
    description: 'Continuously select and run bounded recon, focused tests, ASM work, and deterministic retests.',
    mode: 'gated', maxSteps: 15, risk: 'active',
    budget: { steps: 15, actions: 14, active_actions: 6, requests: 250, seconds: 1800, model_tokens: 150000 },
    tone: 'border-blue-500/50 bg-blue-500/[0.08]',
  },
  relentless: {
    name: 'Relentless', eyebrow: 'Maximum bounded depth',
    description: 'Give the investigator the full supported step, request, time, and active-action budgets.',
    mode: 'gated', maxSteps: 25, risk: 'active',
    budget: { steps: 25, actions: 24, active_actions: 10, requests: 500, seconds: 3600, model_tokens: 250000 },
    tone: 'border-orange-500/40 bg-orange-500/[0.06]',
  },
  deep_hunt: {
    name: 'Deep hunt', eyebrow: 'Principal-aware workflows',
    description: 'Let the LLM design app-specific, multi-user control/test workflows using managed target principals. Credentials never enter the model context.',
    mode: 'gated', maxSteps: 25, risk: 'credential',
    budget: { steps: 25, actions: 24, active_actions: 12, requests: 500, seconds: 3600, model_tokens: 250000 },
    tone: 'border-fuchsia-500/50 bg-fuchsia-500/[0.08]',
  },
}

const ACTIVE_FAMILIES = ['sqli', 'xss', 'auth', 'bola']

function targetLabel(target: Target): string {
  const known: Record<string, string> = {
    'http://host.docker.internal:3001': 'OWASP Juice Shop (local)',
    'http://juice-shop:3000': 'OWASP Juice Shop (container)',
    'http://host.docker.internal:8888': 'OWASP crAPI (local)',
    'http://localhost:8888': 'OWASP crAPI (host)',
    'https://honey.shakerscan.com': 'ShakerScan Honey',
  }
  const name = target.name || known[target.url]
  return name ? `${name} — ${target.url}` : target.url
}

function statusClass(status: string): string {
  if (['completed', 'accepted'].includes(status)) return 'bg-green-500/15 text-green-300'
  if (['created', 'awaiting_planner', 'dispatching', 'awaiting_observation'].includes(status)) return 'bg-blue-500/15 text-blue-300'
  if (['awaiting_input', 'approval_required'].includes(status)) return 'bg-amber-500/15 text-amber-300'
  if (['cancelled', 'failed', 'blocked', 'budget_exhausted', 'rejected'].includes(status)) return 'bg-red-500/15 text-red-300'
  return 'bg-gray-800 text-gray-300'
}

function statusLabel(status: string): string {
  return ({
    awaiting_planner: 'Thinking', dispatching: 'Running action', awaiting_observation: 'Reading evidence',
    awaiting_input: 'Needs input', approval_required: 'Needs approval', budget_exhausted: 'Budget exhausted',
  } as Record<string, string>)[status] || status.replaceAll('_', ' ')
}

function episodeStatusLabel(episode: ResearchEpisode): string {
  if (episode.status === 'awaiting_planner' && !episode.autopilot_enabled) return 'Paused'
  return statusLabel(episode.status)
}

function shortDate(value?: string): string {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function budgetPercent(remaining: number, limit: number): number {
  if (!limit) return 0
  return Math.max(0, Math.min(100, Math.round((remaining / limit) * 100)))
}

function actionLabel(command?: string): string {
  if (!command) return 'Planner decision'
  return command.replaceAll('.', ' › ').replaceAll('_', ' ')
}

function plannerDiagnostics(planner?: Record<string, unknown>): string[] {
  if (!planner) return []
  const text = (key: string) => typeof planner[key] === 'string' ? planner[key] as string : ''
  const number = (key: string) => typeof planner[key] === 'number' ? planner[key] as number : null
  const used = text('model')
  const requested = text('requested_model')
  const fallback = number('fallback_index')
  const attempt = number('attempt_index')
  const repairs = Array.isArray(planner.harness_repairs)
    ? planner.harness_repairs.filter((item): item is string => typeof item === 'string')
    : []
  const usage = planner.usage && typeof planner.usage === 'object'
    ? planner.usage as Record<string, unknown>
    : {}
  const totalUnits = typeof usage.total_units === 'number' ? usage.total_units : null
  const diagnostics: string[] = []
  if (used) diagnostics.push(requested && requested !== used
    ? `Model route: ${requested} → ${used}`
    : `Model route: ${used}${fallback === 0 ? ' (primary)' : ''}`)
  const protocol = [text('provider_kind'), text('provider_mode')].filter(Boolean).join(' / ')
  if (protocol) diagnostics.push(`Provider contract: ${protocol}`)
  if (planner.schema_validated === true) diagnostics.push(
    repairs.length ? `Schema validated after harness repair: ${repairs.join(', ')}` : 'Schema validated natively; no harness repair',
  )
  else if (repairs.length) diagnostics.push(`Harness repairs: ${repairs.join(', ')}`)
  if (fallback !== null || attempt !== null) diagnostics.push(
    `Attempt ${(attempt ?? 0) + 1}; fallback route ${fallback ?? 0}`,
  )
  const latency = number('latency_ms')
  if (totalUnits !== null || latency !== null) diagnostics.push([
    totalUnits !== null ? `${totalUnits.toLocaleString()} provider units` : '',
    latency !== null ? `${latency.toLocaleString()} ms` : '',
    text('metering_quality') ? `${text('metering_quality')} metering` : '',
  ].filter(Boolean).join(' · '))
  return diagnostics
}

function IntensityCard({ value, selected, onSelect }: { value: Intensity; selected: boolean; onSelect: () => void }) {
  const profile = PROFILES[value]
  return (
    <button type="button" onClick={onSelect} className={`relative rounded-xl border p-4 text-left transition-colors ${selected ? profile.tone : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}>
      <div className="flex items-start justify-between gap-3">
        <div><div className="text-xs font-medium uppercase tracking-wider text-gray-500">{profile.eyebrow}</div><h3 className="mt-1 font-semibold text-white">{profile.name}</h3></div>
        <div className={`flex h-5 w-5 items-center justify-center rounded-full border ${selected ? 'border-blue-400 bg-blue-500 text-white' : 'border-gray-700'}`}>{selected ? <Check className="h-3.5 w-3.5" /> : null}</div>
      </div>
      <p className="mt-2 text-xs leading-5 text-gray-400">{profile.description}</p>
      <div className="mt-3 flex flex-wrap gap-1.5 text-[11px] text-gray-500"><span>{profile.maxSteps} steps</span><span>·</span><span>{profile.budget.requests} request units</span><span>·</span><span>{profile.budget.active_actions} active actions</span></div>
    </button>
  )
}

function EpisodeProgress({ detail, running }: { detail: ResearchEpisodeDetail; running: boolean }) {
  const episode = detail.episode
  const stepLimit = episode.budget_limits.steps
  const percent = stepLimit ? Math.min(100, Math.round((episode.step_count / stepLimit) * 100)) : 0
  const focus = detail.current_observation?.observation_pack.focus || {}
  const focusedFindingId = episode.subject?.type === 'finding' ? episode.subject.id : undefined
  const findingVerdict = (
    typeof focus.latest_retest_verdict === 'string' && focus.latest_retest_verdict
      ? focus.latest_retest_verdict
      : typeof focus.last_verification_verdict === 'string'
        ? focus.last_verification_verdict
        : ''
  )
  const verdictTone = ['exploited', 'likely_vulnerable'].includes(findingVerdict)
    ? 'border-red-500/30 bg-red-500/[0.08] text-red-100'
    : ['likely_fixed', 'false_positive'].includes(findingVerdict)
      ? 'border-green-500/30 bg-green-500/[0.08] text-green-100'
      : 'border-gray-700 bg-gray-900/50 text-gray-200'
  return (
    <Card className="overflow-hidden">
      <div className="border-b border-gray-800 bg-gradient-to-r from-blue-500/10 to-transparent p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2"><Badge className={statusClass(episode.status)}>{running ? 'Autopilot running' : episodeStatusLabel(episode)}</Badge><Badge className="bg-gray-800 text-gray-300">{episode.execution_mode === 'gated' ? 'active' : 'analysis only'}</Badge></div>
          <span className="text-xs text-gray-500">Step {episode.step_count} of {stepLimit}</span>
        </div>
        <h2 className="mt-3 text-xl font-semibold text-white">{episode.objective}</h2>
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-gray-800"><div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${percent}%` }} /></div>
      </div>

      <div className="grid gap-5 p-5">
        {episode.autopilot_error ? <div className="rounded-lg border border-red-500/30 bg-red-500/[0.08] p-3 text-sm text-red-200">Autopilot error: {episode.autopilot_error}</div> : null}
        {episode.requested_input ? <div className="rounded-lg border border-amber-500/30 bg-amber-500/[0.08] p-3 text-sm text-amber-200">{episode.requested_input}</div> : null}
        {detail.waiting_on?.length ? (
          <div className="rounded-lg border border-blue-500/30 bg-blue-500/[0.08] p-3 text-sm text-blue-100">
            Waiting for evidence before the LLM chooses another action:{' '}
            {detail.waiting_on.map((work, index) => (
              <span key={`${work.kind}-${work.id}`}>
                {index ? ', ' : ''}
                {work.ui_path ? <Link href={work.ui_path} className="font-medium underline underline-offset-2">{work.kind.replaceAll('_', ' ')} {work.id.slice(0, 8)}</Link> : `${work.kind} ${work.id.slice(0, 8)}`}
                {' '}({work.status})
              </span>
            ))}
          </div>
        ) : null}
        {focusedFindingId && (episode.terminal || findingVerdict) ? (
          <div className={`rounded-lg border p-4 ${verdictTone}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider opacity-70">Finding outcome</p>
                <p className="mt-1 text-lg font-semibold">{findingVerdict ? findingVerdict.replaceAll('_', ' ') : 'No conclusive proof verdict'}</p>
              </div>
              <Link href={`/findings/${encodeURIComponent(focusedFindingId)}`} className="rounded border border-current/30 px-3 py-1.5 text-xs font-medium hover:bg-white/5">Open focused finding</Link>
            </div>
            {episode.stop_reason ? <p className="mt-2 text-sm opacity-80">{episode.stop_reason.replaceAll('_', ' ')}</p> : null}
          </div>
        ) : null}

        <section>
          <div className="flex items-center justify-between"><h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Investigator activity</h3><span className="text-xs text-gray-600">newest first</span></div>
          <div className="mt-3 grid gap-2">
            {!detail.decisions.length ? <div className="rounded-lg border border-dashed border-gray-800 p-5 text-center text-sm text-gray-500">The LLM has not selected its first action yet.</div> : detail.decisions.slice(0, 8).map((decision) => {
              const diagnostics = plannerDiagnostics(decision.planner)
              const fallbackIndex = typeof decision.planner?.fallback_index === 'number' ? decision.planner.fallback_index : 0
              return <div key={decision.id} className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
                <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium capitalize text-gray-200">{actionLabel(decision.action.command || decision.decision_type)}</span><Badge className={statusClass(decision.status)}>{statusLabel(decision.status)}</Badge>{typeof decision.planner?.model === 'string' ? <Badge className={fallbackIndex > 0 ? 'bg-amber-500/10 text-amber-300' : 'bg-violet-500/10 text-violet-300'}>{decision.planner.model}{fallbackIndex > 0 ? ` · fallback ${fallbackIndex}` : ''}</Badge> : null}<span className="ml-auto text-xs text-gray-600">{Math.round(decision.confidence * 100)}% confidence</span></div>
                {decision.reason ? <p className="mt-1.5 text-sm leading-5 text-gray-400">{decision.reason}</p> : null}
                {decision.validation_errors.length ? <p className="mt-2 text-xs text-red-300">Blocked: {decision.validation_errors.join(', ')}</p> : null}
                {diagnostics.length ? <details className="mt-2 rounded border border-gray-800 bg-black/20 px-2.5 py-2"><summary className="cursor-pointer text-[11px] font-medium text-gray-500 hover:text-gray-300">Model + harness diagnostics</summary><ul className="mt-2 grid gap-1 text-[11px] text-gray-500">{diagnostics.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}
              </div>
            })}
          </div>
        </section>

        <details className="rounded-lg border border-gray-800 bg-gray-950/30">
          <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-xs font-medium text-gray-500 hover:text-gray-300"><span>Technical budgets and event log</span><ChevronDown className="h-4 w-4" /></summary>
          <div className="grid gap-4 border-t border-gray-800 p-3">
            <div className="grid gap-3 sm:grid-cols-3">
              {(['steps', 'active_actions', 'requests'] as const).map((key) => {
                const remaining = episode.remaining_budget[key]
                const limit = episode.budget_limits[key]
                const label = key === 'requests' ? 'request units' : key.replace('_', ' ')
                return <div key={key}><div className="flex justify-between text-xs"><span className="text-gray-500">{label}</span><span className="text-gray-300">{remaining} / {limit}</span></div><div className="mt-1.5 h-1.5 overflow-hidden rounded bg-gray-800"><div className="h-full bg-cyan-400" style={{ width: `${budgetPercent(remaining, limit)}%` }} /></div></div>
              })}
            </div>
            <div className="grid gap-2">{detail.events.slice(0, 12).map((event) => <div key={event.id} className="flex items-start gap-2 text-xs"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 flex-none text-gray-600" /><span className="text-gray-400">{event.summary}</span><span className="ml-auto flex-none text-gray-700">{shortDate(event.created_at)}</span></div>)}</div>
          </div>
        </details>
      </div>
    </Card>
  )
}

export default function ResearchAgentPage() {
  const router = useRouter()
  const [targets, setTargets] = useState<Target[]>([])
  const [episodes, setEpisodes] = useState<ResearchEpisode[]>([])
  const [selected, setSelected] = useState<ResearchEpisodeDetail | null>(null)
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState('Find and verify the highest-impact security weaknesses on this target. Prioritize authorization, injection, sensitive data exposure, and workflow abuse. Keep investigating until the budget is exhausted or no valuable action remains.')
  const [intensity, setIntensity] = useState<Intensity>('hunt')
  const [families, setFamilies] = useState<string[]>(ACTIVE_FAMILIES)
  const [autopilot, setAutopilot] = useState(true)
  const [authorized, setAuthorized] = useState(false)
  const [aiReady, setAiReady] = useState<boolean | null>(null)
  const [executionReady, setExecutionReady] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const profile = PROFILES[intensity]
  const activeTarget = useMemo(() => targets.find((target) => target.id === targetId), [targetId, targets])
  const autoRunning = Boolean(selected?.episode.autopilot_enabled && !selected.episode.terminal)

  const loadEpisodes = useCallback(async () => {
    const data = await getResearchEpisodes({ limit: 30 })
    setEpisodes(data.episodes || [])
    return data.episodes || []
  }, [])

  useEffect(() => {
    let cancelled = false
    const requestedEpisodeId = new URLSearchParams(window.location.search).get('episode_id')?.trim() || ''
    const requestedEpisode = requestedEpisodeId
      ? getResearchEpisode(requestedEpisodeId)
          .then((detail) => ({ detail, error: null as string | null }))
          .catch((err) => ({ detail: null, error: err instanceof Error ? err.message : 'Failed to load requested investigation' }))
      : Promise.resolve({ detail: null, error: null as string | null })
    Promise.all([getTargets(), getResearchEpisodes({ limit: 30 }), getResearchReadiness(), requestedEpisode]).then(async ([targetData, episodeData, readiness, requested]) => {
      if (cancelled) return
      const rows: Target[] = Array.isArray(targetData?.targets) ? targetData.targets : Array.isArray(targetData) ? targetData : []
      const webTargets = rows.filter((target) => /^https?:\/\//i.test(target.url) && target.discovery_source !== 'model-intake')
      const requestedTargetId = requested.detail?.episode.target_id || ''
      if (requestedTargetId && !webTargets.some((target) => target.id === requestedTargetId)) {
        const requestedTarget = await getTarget(requestedTargetId).catch(() => null)
        if (requestedTarget && /^https?:\/\//i.test(requestedTarget.url) && requestedTarget.discovery_source !== 'model-intake') {
          webTargets.unshift(requestedTarget)
        }
      }
      if (cancelled) return
      setTargets(webTargets); setTargetId(requestedTargetId || webTargets[0]?.id || '')
      setEpisodes(episodeData.episodes || [])
      if (requested.detail) setSelected(requested.detail)
      if (requested.error) setError(requested.error)
      setAiReady(readiness.planner_ready)
      setExecutionReady(readiness.execution_enabled)
    }).catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load autonomous investigator') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!selected?.episode.id || selected.episode.terminal) return
    const timer = window.setInterval(() => getResearchEpisode(selected.episode.id).then(setSelected).catch(() => undefined), 2000)
    return () => window.clearInterval(timer)
  }, [selected?.episode.id, selected?.episode.terminal])

  const openEpisode = async (id: string) => {
    setBusy(true); setError(null)
    try {
      setSelected(await getResearchEpisode(id))
      router.replace(`/settings/research-agent?episode_id=${encodeURIComponent(id)}`)
    }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load investigation') }
    finally { setBusy(false) }
  }

  const startInvestigation = async () => {
    if (!activeTarget || !objective.trim() || !aiReady) return
    if (profile.mode === 'gated' && !executionReady) { setError('Autonomous active execution is disabled by server policy.'); return }
    if (profile.mode === 'gated' && !authorized) { setError('Confirm that you own or are authorized to test this target.'); return }
    setBusy(true); setError(null)
    try {
      let approvalReceiptId: string | undefined
      if (profile.mode === 'gated') approvalReceiptId = await createTargetPolicyApproval(activeTarget.id, activeTarget.url, 120, profile.risk === 'credential' ? 'credential' : 'active')
      const detail = await createResearchEpisode({
        target_id: activeTarget.id,
        objective: objective.trim(),
        execution_mode: profile.mode,
        max_risk_tier: profile.risk,
        allowed_families: profile.mode === 'gated' ? families : [],
        max_steps: profile.maxSteps,
        budget_limits: profile.budget,
        approval_receipt_id: approvalReceiptId,
        autopilot,
        created_by: 'autonomous_investigation_ui',
      })
      setSelected(detail)
      router.replace(`/settings/research-agent?episode_id=${encodeURIComponent(detail.episode.id)}`)
      await loadEpisodes()
      setBusy(false)
    } catch (err) { setError(err instanceof Error ? err.message : 'Failed to start investigation'); setBusy(false) }
  }

  const continueInvestigation = async () => {
    if (!selected) return
    setBusy(true); setError(null)
    try { setSelected(await setResearchEpisodeAutopilot(selected.episode.id, true)); await loadEpisodes() }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to resume autonomous investigation') }
    finally { setBusy(false) }
  }

  const pauseAutopilot = async () => {
    if (!selected) return
    setBusy(true); setError(null)
    try { setSelected(await setResearchEpisodeAutopilot(selected.episode.id, false)); await loadEpisodes() }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to pause autonomous investigation') }
    finally { setBusy(false) }
  }

  const refreshObservation = async () => {
    if (!selected) return
    setBusy(true); setError(null)
    try { setSelected(await refreshResearchObservation(selected.episode.id)) }
    catch (err) { setError(err instanceof Error ? err.message : 'Observation refresh failed') }
    finally { setBusy(false) }
  }

  const cancelEpisode = async () => {
    if (!selected) return
    setBusy(true); setError(null)
    try { setSelected(await cancelResearchEpisode(selected.episode.id)); await loadEpisodes() }
    catch (err) { setError(err instanceof Error ? err.message : 'Cancellation failed') }
    finally { setBusy(false) }
  }

  if (loading) return <Skeleton className="h-96" />

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <header className="flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div><div className="flex items-center gap-2 text-sm text-blue-300"><BrainCircuit className="h-4 w-4" />Research Agent</div><h1 className="mt-1 text-3xl font-bold tracking-tight text-white">Autonomous investigation</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-gray-400">Give the LLM a target and objective. It will repeatedly choose the next ShakerScan action, inspect the evidence, and continue until it reaches a conclusion or exhausts the budget.</p></div>
        <nav className="flex rounded-lg border border-gray-800 bg-gray-950 p-1 text-sm"><span className="rounded-md bg-gray-800 px-3 py-1.5 text-white">Run investigator</span><Link href="/settings/research-agent/leads" className="px-3 py-1.5 text-gray-400 hover:text-white">Lead backlog</Link><Link href="/settings/research-agent/experiment" className="px-3 py-1.5 text-gray-400 hover:text-white">Manual test</Link></nav>
      </header>

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <main className="grid gap-5">
          <Card className="overflow-hidden">
            <div className="border-b border-gray-800 bg-gradient-to-r from-blue-500/10 via-transparent to-transparent p-5"><div className="flex items-center justify-between gap-3"><div><div className="text-xs font-semibold uppercase tracking-wider text-blue-300">New mission</div><h2 className="mt-1 text-xl font-semibold text-white">What should the investigator accomplish?</h2></div><div className={`flex items-center gap-2 rounded-full px-3 py-1.5 text-xs ${aiReady ? 'bg-emerald-500/10 text-emerald-300' : 'bg-red-500/10 text-red-300'}`} title={aiReady ? 'Provider URL, key, and model are configured. Open a decision diagnostic to verify the live contract.' : undefined}><span className={`h-2 w-2 rounded-full ${aiReady ? 'bg-emerald-400' : 'bg-red-400'}`} />{aiReady ? 'LLM configured' : 'Configure AI provider'}</div></div></div>
            <div className="grid gap-5 p-5">
              <label className="text-xs font-medium text-gray-400">Target
                <select value={targetId} onChange={(event) => { setTargetId(event.target.value); setAuthorized(false) }} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-white">{targets.map((target) => <option key={target.id} value={target.id}>{targetLabel(target)}</option>)}</select>
              </label>
              <label className="text-xs font-medium text-gray-400">Objective
                <textarea value={objective} onChange={(event) => setObjective(event.target.value)} rows={4} maxLength={2000} className="mt-1.5 w-full resize-y rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm leading-6 text-white" />
              </label>

              <div className="rounded-xl border border-blue-500/25 bg-blue-500/[0.05] p-4">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div className="grid gap-2">
                    {profile.mode === 'gated' && executionReady === false ? <div className="rounded-md border border-red-500/25 bg-red-500/[0.06] px-3 py-2 text-xs text-red-200">Active autonomous execution is disabled in server policy. Analyze mode remains available.</div> : null}
                    {profile.mode === 'gated' ? <label className="flex cursor-pointer items-start gap-3"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-1" /><span><span className="text-sm font-medium text-orange-200">I own this target or have explicit permission to test it.</span><span className="mt-0.5 block text-xs text-gray-500">Creates a target-scoped approval for active testing.</span></span></label> : null}
                    <label className="flex cursor-pointer items-start gap-3"><input type="checkbox" checked={autopilot} onChange={(event) => setAutopilot(event.target.checked)} className="mt-1" /><span><span className="block text-sm font-medium text-gray-200">Continue automatically</span><span className="mt-0.5 block text-xs text-gray-500">Runs on the server and continues if you close this page.</span></span></label>
                  </div>
                  <Button onClick={startInvestigation} disabled={busy || autoRunning || !targetId || !objective.trim() || !aiReady || (profile.mode === 'gated' && (!authorized || !executionReady))} className="min-w-56"><Rocket className="h-4 w-4" />{busy ? 'Starting…' : `Start ${profile.name.toLowerCase()}`}</Button>
                </div>
              </div>

              <section><h3 className="text-xs font-medium text-gray-400">Investigation intensity</h3><div className="mt-2 grid gap-3 md:grid-cols-2 xl:grid-cols-4">{(['analyze', 'hunt', 'relentless', 'deep_hunt'] as Intensity[]).map((value) => <IntensityCard key={value} value={value} selected={intensity === value} onSelect={() => { setIntensity(value); if (value === 'analyze') setAuthorized(false) }} />)}</div></section>

              <details className="rounded-lg border border-gray-800 bg-gray-950/30"><summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-xs font-medium text-gray-500 hover:text-gray-300"><span>Advanced family focus</span><ChevronDown className="h-4 w-4" /></summary><div className="flex flex-wrap gap-2 border-t border-gray-800 p-3">{ACTIVE_FAMILIES.map((family) => <label key={family} className="flex items-center gap-2 rounded-lg border border-gray-800 px-3 py-2 text-xs text-gray-300"><input type="checkbox" checked={families.includes(family)} onChange={() => setFamilies((current) => current.includes(family) ? current.filter((item) => item !== family) : [...current, family])} />{family.toUpperCase()}</label>)}</div></details>
            </div>
          </Card>

          {selected ? <section>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><div><h2 className="font-semibold text-white">Current investigation</h2><p className="mt-1 text-xs text-gray-500">The server investigator updates after every LLM decision and ShakerScan action.</p></div><div className="flex gap-2">{autoRunning ? <Button variant="secondary" onClick={() => pauseAutopilot().catch(() => undefined)} disabled={busy}><Pause className="h-4 w-4" />Pause</Button> : selected.episode.status === 'awaiting_planner' && !selected.episode.terminal ? <Button onClick={continueInvestigation} disabled={busy}><Play className="h-4 w-4" />Resume autopilot</Button> : null}<Button variant="secondary" onClick={refreshObservation} disabled={busy || autoRunning || selected.episode.terminal} title="Refresh evidence"><RefreshCw className="h-4 w-4" /></Button><Button variant="danger" onClick={cancelEpisode} disabled={busy || selected.episode.terminal}><CircleStop className="h-4 w-4" />Stop</Button></div></div>
            <EpisodeProgress detail={selected} running={autoRunning} />
          </section> : null}
        </main>

        <aside className="grid content-start gap-4">
          <Card className="p-4"><div className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-blue-300" /><h2 className="font-semibold text-gray-200">What autopilot does</h2></div><div className="mt-4 grid gap-3">{[['1', 'Observe', 'Load current gaps, leads, findings, graph, scope, and budgets.'], ['2', 'Choose', 'Ask the configured LLM for one concrete action and falsifier.'], ['3', 'Execute', 'Run it through ShakerScan’s scope, approval, and command gates.'], ['4', 'Learn and repeat', 'Record evidence, refresh target state, and choose the next action.']].map(([n, title, body]) => <div key={n} className="flex gap-3"><span className="flex h-6 w-6 flex-none items-center justify-center rounded-full bg-blue-500/15 text-xs text-blue-200">{n}</span><div><div className="text-sm font-medium text-gray-300">{title}</div><p className="mt-0.5 text-xs leading-5 text-gray-500">{body}</p></div></div>)}</div></Card>

          <Card className="p-4"><div className="flex items-center justify-between"><div className="flex items-center gap-2"><History className="h-4 w-4 text-gray-400" /><h2 className="font-semibold text-gray-200">Previous runs</h2></div><Button variant="ghost" size="sm" onClick={() => loadEpisodes().catch(() => undefined)}><RefreshCw className="h-3.5 w-3.5" /></Button></div>{!episodes.length ? <div className="mt-4"><EmptyState message="No investigations yet" /></div> : <div className="mt-3 grid max-h-[520px] gap-2 overflow-y-auto">{episodes.map((episode) => <button key={episode.id} type="button" onClick={() => openEpisode(episode.id)} className={`rounded-lg border p-3 text-left ${selected?.episode.id === episode.id ? 'border-blue-500/50 bg-blue-500/[0.07]' : 'border-gray-800 bg-gray-950/40 hover:border-gray-700'}`}><div className="flex items-start gap-2"><Activity className="mt-0.5 h-4 w-4 flex-none text-gray-600" /><div className="min-w-0 flex-1"><p className="line-clamp-2 text-sm text-gray-300">{episode.objective}</p><div className="mt-2 flex items-center gap-2"><Badge className={statusClass(episode.status)}>{episodeStatusLabel(episode)}</Badge><span className="text-[11px] text-gray-600">{episode.step_count}/{episode.budget_limits.steps} steps</span></div></div></div></button>)}</div>}</Card>

          {!aiReady ? <Card className="border-red-500/30 bg-red-500/[0.05] p-4"><div className="flex items-center gap-2 text-red-300"><Zap className="h-4 w-4" /><span className="text-sm font-medium">LLM provider required</span></div><p className="mt-2 text-xs leading-5 text-gray-500">Configure an OpenAI-compatible provider before starting autonomous investigation.</p><Link href="/settings" className={`${buttonClasses('secondary', 'sm')} mt-3`}>Open AI settings <ArrowRight className="h-3.5 w-3.5" /></Link></Card> : null}
        </aside>
      </div>
    </div>
  )
}
