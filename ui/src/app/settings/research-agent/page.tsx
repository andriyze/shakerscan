'use client'

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { ArrowRight, BrainCircuit, Check, ChevronDown, Rocket } from 'lucide-react'
import {
  createTargetPolicyApproval,
  getCampaign,
  getCampaigns,
  getResearchEpisode,
  getResearchReadiness,
  getTargets,
  launchResearchCampaign,
  type Campaign,
  type ResearchPlannerMode,
  type Target,
} from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Skeleton } from '@/components/ui'
import { isWebTarget } from '@/lib/targets'
import {
  DURATIONS, PROFILES, RunStatusBadge, familiesForIntensity, type DurationKey, type Intensity,
  findingCount, hostFromUrl, relativeTime, runState, targetLabel,
} from '@/components/hunt'

const DEFAULT_OBJECTIVE =
  'Find and verify the highest-impact security weaknesses on this target. Prioritize authorization, injection, sensitive data exposure, and workflow abuse. Keep going until the budget is spent or no valuable action remains.'

function intensityOf(campaign: Campaign): string {
  const meta = (campaign.metadata_json?.autonomous_research ?? {}) as Record<string, unknown>
  const value = typeof meta.intensity === 'string' ? meta.intensity : ''
  return PROFILES[value as Intensity]?.name || value || 'Hunt'
}

function episodeProgress(campaign: Campaign): { started: number; max: number } {
  const meta = (campaign.metadata_json?.autonomous_research ?? {}) as Record<string, unknown>
  return {
    started: typeof meta.episodes_started === 'number' ? meta.episodes_started : 0,
    max: typeof meta.max_episodes === 'number' ? meta.max_episodes : 0,
  }
}

function ResearchAgentPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [targets, setTargets] = useState<Target[]>([])
  const [runs, setRuns] = useState<Campaign[]>([])
  const [targetId, setTargetId] = useState('')
  const [intensity, setIntensity] = useState<Intensity>('hunt')
  const [duration, setDuration] = useState<DurationKey>('standard')
  const [authorized, setAuthorized] = useState(false)
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE)
  const [families, setFamilies] = useState<string[]>(familiesForIntensity('hunt'))
  const [plannerMode, setPlannerMode] = useState<ResearchPlannerMode>('agent')
  const [aiReady, setAiReady] = useState<boolean | null>(null)
  const [executionReady, setExecutionReady] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showAllRuns, setShowAllRuns] = useState(false)

  const profile = PROFILES[intensity]
  const availableFamilies = familiesForIntensity(intensity)
  const activeTarget = useMemo(() => targets.find((t) => t.id === targetId), [targetId, targets])
  const attentionRuns = useMemo(() => runs.filter((run) => ['active', 'paused'].includes(String(run.status))), [runs])
  const historyRuns = useMemo(() => runs.filter((run) => !['active', 'paused'].includes(String(run.status))), [runs])

  // Backend deep-links land here as ?episode_id=… — resolve to the run it belongs to.
  useEffect(() => {
    const episodeId = searchParams.get('episode_id')?.trim()
    if (!episodeId) return
    getResearchEpisode(episodeId)
      .then((detail) => router.replace(`/settings/research-agent/runs/${detail.episode.campaign_id || episodeId}`))
      .catch(() => undefined)
  }, [searchParams, router])

  const loadRuns = useCallback(async () => {
    const data = await getCampaigns({ limit: 100 }).catch(() => ({ campaigns: [] as Campaign[], count: 0, execution_enabled: false }))
    const researchRuns = (data.campaigns || []).filter((c) => c.campaign_type === 'autonomous_research')
    const normalized = await Promise.all(researchRuns.map(async (run) => {
      if (run.status !== 'paused') return run
      const detail = await getCampaign(run.id).catch(() => null)
      return detail?.research_yield?.stop_recommended ? { ...run, status: 'completed' } : run
    }))
    setRuns(normalized)
  }, [])

  useEffect(() => {
    let cancelled = false
    Promise.all([getTargets(), getResearchReadiness()])
      .then(([targetData, readiness]) => {
        if (cancelled) return
        const rows: Target[] = Array.isArray(targetData?.targets) ? targetData.targets : Array.isArray(targetData) ? targetData : []
        const web = rows.filter(isWebTarget)
        setTargets(web)
        const requestedTarget = searchParams.get('target')?.trim()
        setTargetId(requestedTarget && web.some((target) => target.id === requestedTarget) ? requestedTarget : '')
        setAiReady(readiness.configured_planner_ready ?? readiness.planner_ready)
        setPlannerMode(readiness.default_planner_mode || 'agent')
        setExecutionReady(readiness.execution_enabled)
      })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load') })
      .finally(() => { if (!cancelled) setLoading(false) })
    loadRuns()
    return () => { cancelled = true }
  }, [loadRuns, searchParams])

  const gated = profile.mode === 'gated'
  const canStart = Boolean(targetId)
    && (plannerMode !== 'configured_ai' || aiReady === true)
    && (!gated || (authorized && families.length > 0 && executionReady !== false)) && !busy

  const startHunt = async () => {
    if (!activeTarget || !canStart) return
    setBusy(true); setError(null)
    try {
      const { hours, episodes } = DURATIONS[duration]
      let approvalReceiptId: string | undefined
      if (gated) {
        approvalReceiptId = await createTargetPolicyApproval(
          activeTarget.id, activeTarget.url, hours * 60 + 10,
          profile.risk === 'credential' ? 'credential' : 'active',
        )
      }
      const res = await launchResearchCampaign({
        target_id: activeTarget.id,
        intensity,
        planner_mode: plannerMode,
        approval_receipt_id: approvalReceiptId,
        duration_hours: hours,
        max_episodes: episodes,
        objective: objective.trim() || DEFAULT_OBJECTIVE,
        allowed_families: gated ? families : [],
        created_by: 'autonomous_hunt_ui',
      })
      router.push(`/settings/research-agent/runs/${res.campaign.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the hunt')
      setBusy(false)
    }
  }

  if (loading) return <div><Skeleton className="h-96" /></div>

  return (
    <div>
      <header className="flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-blue-300"><BrainCircuit className="h-4 w-4" />AI Investigator · Operator</div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white">Turn the hunter loose on a target</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-400">Operator runs vetted, menu-driven actions and can prove findings all the way to verified. For free-form probing that composes its own requests and surfaces new leads, use <Link href="/settings/research-agent/explorer" className="text-blue-300 underline-offset-2 hover:underline">Explorer</Link>.</p>
        </div>
        <nav className="flex rounded-lg border border-gray-800 bg-gray-950 p-1 text-sm">
          <span className="rounded-md bg-gray-800 px-3 py-1.5 text-white">Operator</span>
          <Link href="/settings/research-agent/explorer" className="px-3 py-1.5 text-gray-400 hover:text-white">Explorer</Link>
          <Link href="/settings/research-agent/leads" className="px-3 py-1.5 text-gray-400 hover:text-white">Leads</Link>
          <Link href="/settings/research-agent/experiment" className="px-3 py-1.5 text-gray-400 hover:text-white">Plan a test</Link>
        </nav>
      </header>

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}
      {plannerMode === 'configured_ai' && aiReady === false ? (
        <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/[0.06] p-4 text-sm text-red-200">
          No AI provider is configured. <Link href="/settings" className="font-medium underline underline-offset-2">Open AI settings</Link> to add one before hunting.
        </div>
      ) : null}

      {/* Start a hunt — three picks */}
      <Card className="mt-5 overflow-hidden">
        <div className="grid gap-6 p-5 sm:p-6">
          <Field label="How should it run?">
            <div className="grid gap-3 sm:grid-cols-2">
              <button
                type="button"
                onClick={() => setPlannerMode('agent')}
                aria-pressed={plannerMode === 'agent'}
                className={`rounded-xl border p-3.5 text-left transition-colors ${plannerMode === 'agent' ? 'border-blue-500/60 bg-blue-500/[0.09]' : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}
              >
                <div className="font-semibold text-white">Agent-guided <span className="text-xs font-normal text-blue-300">Default</span></div>
                <p className="mt-1 text-xs leading-5 text-gray-400">Your coding agent chooses each bounded action. The hunt pauses when that agent is not connected.</p>
              </button>
              <button
                type="button"
                onClick={() => setPlannerMode('configured_ai')}
                disabled={aiReady === false}
                aria-pressed={plannerMode === 'configured_ai'}
                className={`rounded-xl border p-3.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${plannerMode === 'configured_ai' ? 'border-violet-500/60 bg-violet-500/[0.09]' : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}
              >
                <div className="font-semibold text-white">Unattended</div>
                <p className="mt-1 text-xs leading-5 text-gray-400">{aiReady === false ? 'Configure a provider in Settings first.' : 'Runs unattended on the server and continues after your agent closes.'}</p>
              </button>
            </div>
          </Field>

          <Field label="1 · Target">
            <select
              value={targetId}
              onChange={(e) => { setTargetId(e.target.value); setAuthorized(false) }}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="">Choose a target…</option>
              {!targets.length ? <option value="">No web targets — add one under Targets</option> : null}
              {targets.map((t) => <option key={t.id} value={t.id}>{targetLabel(t)} · {hostFromUrl(t.url)}</option>)}
            </select>
          </Field>

          <Field label="2 · How hard should it go?">
            <div className="grid gap-3 sm:grid-cols-2">
              {(['analyze', 'hunt'] as Intensity[]).map((value) => {
                const p = PROFILES[value]
                const on = intensity === value
                return (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={on}
                    onClick={() => {
                      setIntensity(value)
                      setFamilies(familiesForIntensity(value))
                      if (value === 'analyze') setAuthorized(false)
                    }}
                    className={`rounded-xl border p-3.5 text-left transition-colors ${on ? p.selected : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-semibold ${on ? p.accent : 'text-white'}`}>{p.name}</span>
                      <span className={`flex h-4 w-4 items-center justify-center rounded-full border ${on ? 'border-current bg-current/20' : 'border-gray-700'}`}>{on ? <Check className="h-3 w-3" /> : null}</span>
                    </div>
                    <p className="mt-0.5 text-[11px] font-medium uppercase tracking-wide text-gray-500">{p.summary}</p>
                    <p className="mt-2 text-xs leading-5 text-gray-400">{p.detail}</p>
                  </button>
                )
              })}
            </div>
            <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950/30">
              <summary className="cursor-pointer px-3 py-2.5 text-xs font-medium text-gray-500 hover:text-gray-300">Advanced hunt types</summary>
              <div className="grid gap-3 border-t border-gray-800 p-3 sm:grid-cols-2">
                {(['relentless', 'deep_hunt'] as Intensity[]).map((value) => {
                  const p = PROFILES[value]
                  const on = intensity === value
                  return (
                    <button
                      key={value}
                      type="button"
                      aria-pressed={on}
                      onClick={() => {
                        setIntensity(value)
                        setFamilies(familiesForIntensity(value))
                      }}
                      className={`rounded-xl border p-3.5 text-left transition-colors ${on ? p.selected : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`font-semibold ${on ? p.accent : 'text-white'}`}>{p.name}</span>
                        <span className={`flex h-4 w-4 items-center justify-center rounded-full border ${on ? 'border-current bg-current/20' : 'border-gray-700'}`}>{on ? <Check className="h-3 w-3" /> : null}</span>
                      </div>
                      <p className="mt-0.5 text-[11px] font-medium uppercase tracking-wide text-gray-500">{p.summary}</p>
                      <p className="mt-2 text-xs leading-5 text-gray-400">{p.detail}</p>
                    </button>
                  )
                })}
              </div>
            </details>
            {intensity === 'deep_hunt' ? (
              <p className="mt-2 text-xs text-fuchsia-200">Deep requires two configured test accounts. Readiness is checked before active work starts. <Link href="/interactive" className="underline underline-offset-2">Manage test accounts</Link>.</p>
            ) : null}
          </Field>

          <Field label="3 · How long?">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {(Object.keys(DURATIONS) as DurationKey[]).map((key) => {
                const d = DURATIONS[key]
                const on = duration === key
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setDuration(key)}
                    aria-pressed={on}
                    className={`rounded-xl border p-3 text-center transition-colors ${on ? 'border-blue-500/60 bg-blue-500/[0.09]' : 'border-gray-800 bg-gray-950/50 hover:border-gray-700'}`}
                  >
                    <div className={`text-sm font-semibold ${on ? 'text-blue-200' : 'text-white'}`}>{d.name}</div>
                    <div className="mt-0.5 text-xs text-gray-500">{d.detail}</div>
                  </button>
                )
              })}
            </div>
          </Field>

          {gated ? (
            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-orange-500/25 bg-orange-500/[0.05] p-3">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5" />
              <span className="text-sm text-orange-100">I own this target or have explicit permission to test it.
                <span className="mt-0.5 block text-xs text-gray-500">Required for active testing — creates a target-scoped approval.</span>
              </span>
            </label>
          ) : null}

          <details className="rounded-lg border border-gray-800 bg-gray-950/30">
            <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-xs font-medium text-gray-500 hover:text-gray-300">
              <span>Advanced — objective &amp; focus</span><ChevronDown className="h-4 w-4" />
            </summary>
            <div className="grid gap-4 border-t border-gray-800 p-3">
              <label className="text-xs font-medium text-gray-400">What should it focus on?
                <textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={3} maxLength={2000} className="mt-1.5 w-full resize-y rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm leading-6 text-white focus:border-blue-500 focus:outline-none" />
              </label>
              {gated ? (
                <div>
                  <div className="text-xs font-medium text-gray-400">Vulnerability families</div>
                  <div className="mt-1.5 flex flex-wrap gap-2">
                    {availableFamilies.map((f) => (
                      <label key={f} className="flex items-center gap-2 rounded-lg border border-gray-800 px-3 py-1.5 text-xs text-gray-300">
                        <input type="checkbox" checked={families.includes(f)} onChange={() => setFamilies((cur) => cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f])} />
                        {familyLabel(f)}
                      </label>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </details>

          <div className="flex items-center justify-between gap-3 border-t border-gray-800 pt-4">
            <p className="text-xs text-gray-500">
              {gated
                ? `${plannerMode === 'configured_ai' ? 'Continues on the server after this page closes.' : 'Pauses whenever your coding agent is unavailable.'} Up to ${DURATIONS[duration].episodes} episodes over ${DURATIONS[duration].detail}; each episode is limited to ${profile.budget.active_actions} active actions and ${profile.budget.requests} request units. Stops early when useful progress ends.`
                : 'Read-only — inspects evidence and sends no active probes.'}
            </p>
            <Button onClick={startHunt} disabled={!canStart} className="min-w-44">
              <Rocket className="h-4 w-4" />{busy ? 'Starting…' : `Start ${profile.name}`}
            </Button>
          </div>
        </div>
      </Card>

      {/* Runs */}
      <section className="mt-8">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-300">Runs</h2>
          <button onClick={() => loadRuns()} className="text-xs text-gray-500 hover:text-gray-300">Refresh</button>
        </div>
        {!runs.length ? (
          <div className="mt-3"><EmptyState message="No hunts yet" hint="Start one above — it'll show here with live status." /></div>
        ) : (
          <div className="mt-3 grid gap-5">
            {attentionRuns.length ? <RunGroup title="Needs attention or active" runs={attentionRuns} /> : null}
            {historyRuns.length ? (
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Recent history</h3>
                  {historyRuns.length > 8 ? <button type="button" onClick={() => setShowAllRuns((value) => !value)} className="text-xs text-blue-300 hover:text-blue-200">{showAllRuns ? 'Show recent only' : `Show all ${historyRuns.length}`}</button> : null}
                </div>
                <RunGroup runs={showAllRuns ? historyRuns : historyRuns.slice(0, 8)} />
              </div>
            ) : null}
          </div>
        )}
      </section>
    </div>
  )
}

function familyLabel(value: string): string {
  const labels: Record<string, string> = {
    sqli: 'SQL injection', xss: 'Cross-site scripting', auth: 'Authentication',
    bola: 'Object-level authorization', mass_assignment: 'Mass assignment',
    workflow: 'Workflow abuse', data_exposure: 'Sensitive data exposure',
    access_control: 'Access control', field_constraint: 'Restricted fields',
  }
  return labels[value] || value.replace(/_/g, ' ')
}

function RunGroup({ title, runs }: { title?: string; runs: Campaign[] }) {
  return (
    <div>
      {title ? <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">{title}</h3> : null}
      <div className="grid gap-2">
        {runs.map((run) => {
          const found = findingCount(run)
          const prog = episodeProgress(run)
          const state = runState(run)
          const terminal = ['completed', 'cancelled', 'failed'].includes(state)
          const url = String((run.target_scope?.url as string) || '')
          return (
            <Link key={run.id} href={`/settings/research-agent/runs/${run.id}`} className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-950/40 p-3.5 hover:border-gray-700 sm:flex-row sm:items-center">
              <RunStatusBadge state={state} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-gray-200">{hostFromUrl(url) || run.name || 'Operator run'}</div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-gray-500">
                  <span>{intensityOf(run)}</span>
                  {prog.max ? <><span>·</span><span className="tabular-nums">episode {prog.started}/{prog.max}</span></> : null}
                  <span>·</span><span>started {relativeTime(run.created_at)}</span>
                </div>
              </div>
              {found > 0 ? (
                <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium text-emerald-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />{found} verified in linked work
                </span>
              ) : <span className="text-xs text-gray-600">{terminal ? 'No verified findings' : 'No verified findings yet'}</span>}
              <ArrowRight className="hidden h-4 w-4 flex-none text-gray-600 sm:block" />
            </Link>
          )
        })}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</div>
      {children}
    </div>
  )
}

export default function Page() {
  return (
    <Suspense fallback={<div><Skeleton className="h-96" /></div>}>
      <ResearchAgentPage />
    </Suspense>
  )
}
