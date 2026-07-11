'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { BrainCircuit, PauseCircle, Play, Plus, RefreshCw, ShieldCheck, Target as TargetIcon, XCircle } from 'lucide-react'
import {
  cancelResearchEpisode,
  createResearchEpisode,
  getResearchEpisode,
  getResearchEpisodes,
  getTargets,
  planResearchEpisodeStep,
  refreshResearchObservation,
  type ResearchEpisode,
  type ResearchEpisodeDetail,
  type Target,
} from '@/lib/api'
import { Badge, Button, EmptyState, ErrorState, Skeleton } from '@/components/ui'

const FAMILY_OPTIONS = ['sqli', 'xss', 'auth', 'bola']

function statusClass(status: string): string {
  if (['completed', 'accepted'].includes(status)) return 'bg-green-500/15 text-green-300'
  if (['awaiting_planner', 'dispatching', 'awaiting_observation'].includes(status)) return 'bg-blue-500/15 text-blue-300'
  if (['awaiting_input', 'approval_required'].includes(status)) return 'bg-amber-500/15 text-amber-300'
  if (['cancelled', 'failed', 'blocked', 'budget_exhausted', 'rejected'].includes(status)) return 'bg-red-500/15 text-red-300'
  return 'bg-gray-800 text-gray-300'
}

function shortDate(value?: string): string {
  if (!value) return 'unknown'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function budgetPercent(remaining: number, limit: number): number {
  if (!limit) return 0
  return Math.max(0, Math.min(100, Math.round((remaining / limit) * 100)))
}

export default function ResearchAgentPage() {
  const [targets, setTargets] = useState<Target[]>([])
  const [episodes, setEpisodes] = useState<ResearchEpisode[]>([])
  const [selected, setSelected] = useState<ResearchEpisodeDetail | null>(null)
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState('Investigate the highest-value unexplained security gaps for this target.')
  const [mode, setMode] = useState<'shadow' | 'read_only' | 'gated'>('read_only')
  const [maxSteps, setMaxSteps] = useState(5)
  const [families, setFamilies] = useState<string[]>([])
  const [scopeReceiptId, setScopeReceiptId] = useState('')
  const [approvalReceiptId, setApprovalReceiptId] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadEpisodes = useCallback(async () => {
    const data = await getResearchEpisodes({ limit: 50 })
    setEpisodes(data.episodes || [])
    return data.episodes || []
  }, [])

  useEffect(() => {
    let cancelled = false
    Promise.all([getTargets(), getResearchEpisodes({ limit: 50 })])
      .then(([targetData, episodeData]) => {
        if (cancelled) return
        const rows: Target[] = Array.isArray(targetData?.targets) ? targetData.targets : Array.isArray(targetData) ? targetData : []
        const webTargets = rows.filter((target) => /^https?:\/\//i.test(target.url) && target.discovery_source !== 'model-intake')
        setTargets(webTargets)
        setTargetId(webTargets[0]?.id || '')
        setEpisodes(episodeData.episodes || [])
      })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load research agent') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!selected?.episode.id || selected.episode.terminal) return
    const id = window.setInterval(() => {
      getResearchEpisode(selected.episode.id).then(setSelected).catch(() => undefined)
    }, 5000)
    return () => window.clearInterval(id)
  }, [selected?.episode.id, selected?.episode.terminal])

  const selectedTarget = useMemo(
    () => targets.find((target) => target.id === selected?.episode.target_id),
    [selected?.episode.target_id, targets],
  )

  const openEpisode = async (id: string) => {
    setBusy(true)
    setError(null)
    try {
      setSelected(await getResearchEpisode(id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load episode')
    } finally {
      setBusy(false)
    }
  }

  const createEpisode = async () => {
    if (!targetId || !objective.trim()) return
    setBusy(true)
    setError(null)
    try {
      const detail = await createResearchEpisode({
        target_id: targetId,
        objective: objective.trim(),
        execution_mode: mode,
        max_risk_tier: mode === 'gated' ? 'active' : 'read_only',
        allowed_families: families,
        max_steps: maxSteps,
        budget_limits: mode === 'gated'
          ? { steps: maxSteps, actions: maxSteps, active_actions: Math.min(maxSteps, 3), requests: 100, seconds: 900, model_tokens: 50000 }
          : { steps: maxSteps, actions: maxSteps, active_actions: 0, requests: 0, seconds: 300, model_tokens: 50000 },
        scope_receipt_id: scopeReceiptId.trim() || undefined,
        approval_receipt_id: approvalReceiptId.trim() || undefined,
        created_by: 'research_agent_ui',
      })
      setSelected(detail)
      await loadEpisodes()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create episode')
    } finally {
      setBusy(false)
    }
  }

  const runStep = async () => {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      const detail = await planResearchEpisodeStep(selected.episode.id, { execute: true, timeout_seconds: 90, max_tokens: 3000 })
      setSelected(detail)
      await loadEpisodes()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Planner step failed')
    } finally {
      setBusy(false)
    }
  }

  const refreshObservation = async () => {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      setSelected(await refreshResearchObservation(selected.episode.id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Observation refresh failed')
    } finally {
      setBusy(false)
    }
  }

  const cancelEpisode = async () => {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      setSelected(await cancelResearchEpisode(selected.episode.id))
      await loadEpisodes()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cancellation failed')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <Skeleton className="h-96" />

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BrainCircuit className="h-6 w-6 text-cyan-300" />
            <h1 className="text-2xl font-bold text-white">Research Agent</h1>
          </div>
          <p className="mt-1 text-sm text-gray-400">Bounded adaptive investigation over registered ShakerScan actions</p>
        </div>
        <Button variant="secondary" onClick={() => loadEpisodes().catch(() => undefined)} title="Refresh episodes">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </header>

      {error && <ErrorState message={error} />}

      <section className="border-y border-gray-800 py-5">
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="text-sm text-gray-300">
              Target
              <select value={targetId} onChange={(event) => setTargetId(event.target.value)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-white">
                {targets.map((target) => <option key={target.id} value={target.id}>{target.name || target.url}</option>)}
              </select>
            </label>
            <label className="text-sm text-gray-300">
              Step budget
              <input type="number" min={1} max={25} value={maxSteps} onChange={(event) => setMaxSteps(Math.max(1, Math.min(25, Number(event.target.value) || 1)))} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-white" />
            </label>
            <label className="text-sm text-gray-300 md:col-span-2">
              Objective
              <textarea value={objective} onChange={(event) => setObjective(event.target.value)} rows={3} maxLength={2000} className="mt-1 w-full resize-y rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-white" />
            </label>
          </div>
          <div className="flex items-end">
            <Button onClick={createEpisode} disabled={busy || !targetId || !objective.trim()}>
              <Plus className="h-4 w-4" />
              Create episode
            </Button>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {(['shadow', 'read_only', 'gated'] as const).map((item) => (
            <button key={item} type="button" onClick={() => setMode(item)} className={`rounded-md border px-3 py-1.5 text-sm ${mode === item ? 'border-cyan-400 bg-cyan-500/15 text-cyan-200' : 'border-gray-700 text-gray-400 hover:text-white'}`}>
              {item.replace('_', ' ')}
            </button>
          ))}
          <span className="mx-1 h-8 w-px bg-gray-800" />
          {FAMILY_OPTIONS.map((family) => (
            <label key={family} className="flex items-center gap-2 rounded-md border border-gray-800 px-2.5 py-1.5 text-sm text-gray-300">
              <input type="checkbox" checked={families.includes(family)} onChange={() => setFamilies((current) => current.includes(family) ? current.filter((item) => item !== family) : [...current, family])} />
              {family.toUpperCase()}
            </label>
          ))}
        </div>

        {mode === 'gated' && (
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <label className="text-sm text-gray-300">Scope receipt<input value={scopeReceiptId} onChange={(event) => setScopeReceiptId(event.target.value)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-sm text-white" /></label>
            <label className="text-sm text-gray-300">Approval receipt<input value={approvalReceiptId} onChange={(event) => setApprovalReceiptId(event.target.value)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-sm text-white" /></label>
          </div>
        )}
      </section>

      <div className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="space-y-2">
          <h2 className="text-sm font-semibold text-gray-300">Episodes</h2>
          {episodes.length === 0 ? <EmptyState message="No research episodes" /> : episodes.map((episode) => (
            <button key={episode.id} type="button" onClick={() => openEpisode(episode.id)} className={`w-full rounded-md border p-3 text-left ${selected?.episode.id === episode.id ? 'border-cyan-500 bg-cyan-500/10' : 'border-gray-800 bg-gray-950 hover:border-gray-700'}`}>
              <div className="flex items-start justify-between gap-2"><span className="line-clamp-2 text-sm text-white">{episode.objective}</span><Badge className={statusClass(episode.status)}>{episode.status.replaceAll('_', ' ')}</Badge></div>
              <div className="mt-2 flex items-center gap-2 text-xs text-gray-500"><TargetIcon className="h-3.5 w-3.5" /><span className="truncate">{targets.find((target) => target.id === episode.target_id)?.url || episode.target_id}</span></div>
            </button>
          ))}
        </aside>

        <main className="min-w-0">
          {!selected ? <EmptyState message="Select an episode" /> : (
            <div className="space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-800 pb-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2"><Badge className={statusClass(selected.episode.status)}>{selected.episode.status.replaceAll('_', ' ')}</Badge><Badge className="bg-gray-800 text-gray-300">{selected.episode.execution_mode.replace('_', ' ')}</Badge><Badge className="bg-gray-800 text-gray-300">{selected.episode.max_risk_tier}</Badge></div>
                  <h2 className="mt-2 text-lg font-semibold text-white">{selected.episode.objective}</h2>
                  <p className="mt-1 break-all text-sm text-gray-500">{selectedTarget?.url || selected.episode.target_id}</p>
                </div>
                <div className="flex gap-2">
                  <Button variant="secondary" onClick={refreshObservation} disabled={busy || selected.episode.terminal} title="Refresh observation"><RefreshCw className="h-4 w-4" /></Button>
                  <Button onClick={runStep} disabled={busy || selected.episode.status !== 'awaiting_planner'}><Play className="h-4 w-4" />Run step</Button>
                  <Button variant="danger" onClick={cancelEpisode} disabled={busy || selected.episode.terminal} title="Cancel episode"><XCircle className="h-4 w-4" /></Button>
                </div>
              </div>

              <section>
                <h3 className="text-sm font-semibold text-gray-300">Budget</h3>
                <div className="mt-3 grid gap-3 sm:grid-cols-3">
                  {(['steps', 'actions', 'model_tokens'] as const).map((key) => {
                    const remaining = selected.episode.remaining_budget[key]
                    const limit = selected.episode.budget_limits[key]
                    return <div key={key} className="border-l-2 border-gray-700 pl-3"><div className="flex justify-between text-sm"><span className="text-gray-400">{key.replace('_', ' ')}</span><span className="text-white">{remaining} / {limit}</span></div><div className="mt-2 h-1.5 overflow-hidden rounded bg-gray-800"><div className="h-full bg-cyan-400" style={{ width: `${budgetPercent(remaining, limit)}%` }} /></div></div>
                  })}
                </div>
              </section>

              {selected.episode.requested_input && <div className="flex gap-3 border border-amber-700/50 bg-amber-500/10 p-3 text-sm text-amber-200"><PauseCircle className="mt-0.5 h-4 w-4 shrink-0" />{selected.episode.requested_input}</div>}

              <section>
                <div className="flex items-center justify-between"><h3 className="text-sm font-semibold text-gray-300">Available actions</h3><span className="text-xs text-gray-500">observation {selected.current_observation?.sequence ?? 0}</span></div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(selected.current_observation?.observation_pack.proposable_commands || []).filter((command) => command.proposable).map((command) => <Badge key={command.name} className={command.currently_executable ? 'bg-green-500/15 text-green-300' : 'bg-amber-500/15 text-amber-300'}>{command.name}</Badge>)}
                </div>
              </section>

              <section>
                <h3 className="text-sm font-semibold text-gray-300">Decisions</h3>
                <div className="mt-3 divide-y divide-gray-800 border-y border-gray-800">
                  {selected.decisions.length === 0 ? <div className="py-5 text-sm text-gray-500">No decisions recorded</div> : selected.decisions.map((decision) => (
                    <div key={decision.id} className="py-3">
                      <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-sm text-white">{decision.action.command || decision.decision_type}</span><Badge className={statusClass(decision.status)}>{decision.status}</Badge><span className="text-xs text-gray-500">{Math.round(decision.confidence * 100)}%</span></div>
                      {decision.reason && <p className="mt-1 text-sm text-gray-400">{decision.reason}</p>}
                      {decision.expected_signal && <p className="mt-2 text-xs text-gray-500">Signal: {decision.expected_signal}</p>}
                      {decision.falsifier && <p className="mt-1 text-xs text-gray-500">Falsifier: {decision.falsifier}</p>}
                      {decision.validation_errors.length > 0 && <div className="mt-2 flex flex-wrap gap-1">{decision.validation_errors.map((item) => <Badge key={item} className="bg-red-500/15 text-red-300">{item}</Badge>)}</div>}
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <h3 className="text-sm font-semibold text-gray-300">Episode log</h3>
                <div className="mt-3 space-y-2">
                  {selected.events.slice(0, 20).map((event) => <div key={event.id} className="flex items-start gap-3 text-sm"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-gray-600" /><div><span className="text-gray-300">{event.summary}</span><span className="ml-2 text-xs text-gray-600">{shortDate(event.created_at)}</span></div></div>)}
                </div>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
