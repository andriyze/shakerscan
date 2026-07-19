'use client'

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { CircleStop, Compass, Rocket, ShieldCheck } from 'lucide-react'
import {
  cancelAgentHuntSession,
  createTargetPolicyApproval,
  getAgentHuntSession,
  getAgentTwoTierFindings,
  getTargets,
  listAgentHuntRuns,
  replyAgentHuntSession,
  startAgentHuntSession,
  verifySuspectedAgentFinding,
  type AgentHuntRunSummary,
  type AgentHuntSession,
  type AgentHuntStatus,
  type AgentSuspectedFinding,
  type AgentTwoTierFindings,
  type Target,
} from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, SeverityBadge, Select, Skeleton, Textarea, useToast } from '@/components/ui'
import { RunStatusBadge, hostFromUrl, relativeTime, targetLabel, type RunState } from '@/components/hunt'
import { isWebTarget } from '@/lib/targets'

const DEFAULT_OBJECTIVE =
  'Find a net-new access-control or data-exposure weakness that DAST missed, compose the probes yourself, and back every claim with real tool-output evidence.'

const TERMINAL: AgentHuntStatus[] = ['completed', 'cancelled', 'failed']
const AGENT_RUN_STATE: Record<AgentHuntStatus, RunState> = {
  awaiting_planner: 'waiting',
  planning: 'running',
  completed: 'completed',
  cancelled: 'cancelled',
  failed: 'failed',
}
const isTerminal = (status?: AgentHuntStatus | null) => !!status && TERMINAL.includes(status)

function ExplorerPage() {
  const toast = useToast()
  const searchParams = useSearchParams()
  const [targets, setTargets] = useState<Target[]>([])
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE)
  const [maxIterations, setMaxIterations] = useState('12')
  const [tokenBudget, setTokenBudget] = useState('6000')
  const [runs, setRuns] = useState<AgentHuntRunSummary[]>([])
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [session, setSession] = useState<AgentHuntSession | null>(null)
  const [findings, setFindings] = useState<AgentTwoTierFindings | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [verifyingId, setVerifyingId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const sessionRef = useRef<AgentHuntSession | null>(null)
  sessionRef.current = session
  const findingsTargetId = session?.target_id || targetId
  const activeTarget = useMemo(() => targets.find((t) => t.id === findingsTargetId), [targets, findingsTargetId])

  const loadRuns = useCallback(async () => {
    const data = await listAgentHuntRuns({ limit: 50 }).catch(() => ({ runs: [] as AgentHuntRunSummary[], count: 0 }))
    setRuns(data.runs || [])
  }, [])

  useEffect(() => {
    let cancelled = false
    getTargets()
      .then((data) => {
        if (cancelled) return
        const rows: Target[] = Array.isArray(data?.targets) ? data.targets : Array.isArray(data) ? data : []
        const web = rows.filter(isWebTarget)
        setTargets(web)
        const requested = searchParams.get('target')?.trim()
        if (requested && web.some((t) => t.id === requested)) setTargetId(requested)
      })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load targets') })
      .finally(() => { if (!cancelled) setLoading(false) })
    loadRuns()
    const requestedRun = searchParams.get('run')?.trim()
    if (requestedRun) setSelectedRunId(requestedRun)
    return () => { cancelled = true }
  }, [loadRuns, searchParams])

  // Poll the selected session while it is non-terminal.
  useEffect(() => {
    if (!selectedRunId) return
    let cancelled = false
    const tick = () => {
      getAgentHuntSession(selectedRunId)
        .then((data) => { if (!cancelled) setSession(data) })
        .catch(() => undefined)
    }
    tick()
    const timer = window.setInterval(() => {
      if (isTerminal(sessionRef.current?.status)) return
      tick()
    }, 2500)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [selectedRunId])

  // Poll the two-tier findings for whichever target is in focus.
  useEffect(() => {
    if (!findingsTargetId) { setFindings(null); return }
    let cancelled = false
    const tick = () => {
      getAgentTwoTierFindings(findingsTargetId)
        .then((data) => { if (!cancelled) setFindings(data) })
        .catch(() => undefined)
    }
    tick()
    const timer = window.setInterval(tick, 15000)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [findingsTargetId])

  const startHunt = async () => {
    if (!targetId || starting) return
    setStarting(true); setError(null)
    try {
      const started = await startAgentHuntSession(targetId, {
        objective: objective.trim() || DEFAULT_OBJECTIVE,
        max_iterations: Math.min(24, Math.max(1, Number.parseInt(maxIterations, 10) || 12)),
        token_budget: Math.min(20000, Math.max(1000, Number.parseInt(tokenBudget, 10) || 6000)),
      })
      setSession(started)
      setSelectedRunId(started.run_id)
      toast.success('Explorer hunt started — drive it from your coding agent')
      loadRuns()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not start the hunt'
      setError(message)
      toast.error(message)
    } finally {
      setStarting(false)
    }
  }

  const cancelHunt = async () => {
    if (!selectedRunId || cancelling) return
    setCancelling(true)
    try {
      setSession(await cancelAgentHuntSession(selectedRunId))
      toast.success('Explorer hunt cancelled')
      loadRuns()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not cancel the hunt')
    } finally {
      setCancelling(false)
    }
  }

  const verifyFinding = async (finding: AgentSuspectedFinding) => {
    if (verifyingId || !activeTarget) return
    setVerifyingId(finding.id)
    try {
      const receiptId = await createTargetPolicyApproval(activeTarget.id, activeTarget.url, 30, 'credential')
      const result = await verifySuspectedAgentFinding(finding.id, receiptId)
      if (result.verified) {
        toast.success('Verified — promoted through the proof moat', { link: { href: `/findings/${result.verified_finding_id || finding.id}`, label: 'View finding' } })
      } else {
        toast.info(result.error ? `Not promoted: ${result.error}` : 'Not promoted — proof moat did not confirm it')
      }
      if (findingsTargetId) setFindings(await getAgentTwoTierFindings(findingsTargetId))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Verification failed')
    } finally {
      setVerifyingId(null)
    }
  }

  if (loading) return <div><Skeleton className="h-96" /></div>

  return (
    <div>
      <header className="flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-blue-300"><Compass className="h-4 w-4" />AI Investigator · Explorer</div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white">Free-form hunt that composes its own probes</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-400">
            Explorer is a read-only ReAct loop. It surfaces <span className="text-amber-300">suspected</span> leads backed by real tool-output evidence; the deterministic proof moat promotes them to <span className="text-emerald-300">verified</span>. It runs one planner turn at a time — start it here, then drive it from your coding agent. For vetted, menu-driven actions use <Link href="/settings/research-agent" className="text-blue-300 underline-offset-2 hover:underline">Operator</Link>.
          </p>
        </div>
        <nav className="flex rounded-lg border border-gray-800 bg-gray-950 p-1 text-sm">
          <Link href="/settings/research-agent" className="px-3 py-1.5 text-gray-400 hover:text-white">Operator</Link>
          <span className="rounded-md bg-gray-800 px-3 py-1.5 text-white">Explorer</span>
          <Link href="/settings/research-agent/leads" className="px-3 py-1.5 text-gray-400 hover:text-white">Leads</Link>
        </nav>
      </header>

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        {/* Launch */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-white">Start an Explorer hunt</h2>
          <div className="mt-4 space-y-4">
            <Field label="Target">
              <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                <option value="">Choose a target…</option>
                {!targets.length ? <option value="" disabled>No web targets — add one under Targets</option> : null}
                {targets.map((t) => <option key={t.id} value={t.id}>{targetLabel(t)} · {hostFromUrl(t.url)}</option>)}
              </Select>
            </Field>
            <Field label="Objective" hint="What should it look for? Explorer chooses its own requests to pursue this.">
              <Textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={3} maxLength={2000} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Max turns" hint="1–24 planner turns.">
                <Input type="number" min={1} max={24} value={maxIterations} onChange={(e) => setMaxIterations(e.target.value)} />
              </Field>
              <Field label="Token budget" hint="1000–20000 per run.">
                <Input type="number" min={1000} max={20000} step={500} value={tokenBudget} onChange={(e) => setTokenBudget(e.target.value)} />
              </Field>
            </div>
            <div className="flex items-center justify-between gap-3 border-t border-gray-800 pt-4">
              <p className="text-xs text-gray-500">Read-only — no writes or active scanners. Findings land in the suspected tier until the moat verifies them.</p>
              <Button onClick={startHunt} loading={starting} disabled={!targetId} className="min-w-36">
                <Rocket className="h-4 w-4" />Start hunt
              </Button>
            </div>
          </div>
        </Card>

        {/* Monitor */}
        {selectedRunId ? (
          <SessionMonitor
            session={session}
            cancelling={cancelling}
            onCancel={cancelHunt}
            onReplied={(next) => { setSession(next); loadRuns() }}
          />
        ) : (
          <Card className="flex items-center justify-center p-5">
            <EmptyState message="No hunt selected" hint="Start one, or pick a run from the history below to watch it live." />
          </Card>
        )}
      </div>

      {/* Two-tier findings */}
      {findingsTargetId ? (
        <TwoTierFindings
          findings={findings}
          verifyingId={verifyingId}
          onVerify={verifyFinding}
          targetHost={activeTarget ? hostFromUrl(activeTarget.url) : ''}
        />
      ) : null}

      {/* Run history */}
      <section className="mt-8">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-300">Explorer runs</h2>
          <button onClick={() => loadRuns()} className="text-xs text-gray-500 hover:text-gray-300">Refresh</button>
        </div>
        {!runs.length ? (
          <div className="mt-3"><EmptyState message="No Explorer hunts yet" hint="Start one above — it'll show here with live status." /></div>
        ) : (
          <div className="mt-3 grid gap-2">
            {runs.map((run) => {
              const selected = run.id === selectedRunId
              const host = hostFromUrl(String(targets.find((t) => t.id === run.target_id)?.url || ''))
              return (
                <button
                  key={run.id}
                  type="button"
                  onClick={() => { setSelectedRunId(run.id); setSession(null) }}
                  className={`flex w-full flex-col gap-3 rounded-lg border p-3.5 text-left transition-colors sm:flex-row sm:items-center ${selected ? 'border-blue-500/50 bg-blue-500/[0.06]' : 'border-gray-800 bg-gray-950/40 hover:border-gray-700'}`}
                >
                  <RunStatusBadge state={AGENT_RUN_STATE[run.status] ?? 'idle'} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-gray-200">{host || run.objective || 'Explorer run'}</div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-gray-500">
                      <span className="tabular-nums">turn {run.iterations ?? '0'}/{run.max_iterations}</span>
                      <span>·</span><span>started {relativeTime(run.created_at)}</span>
                      {run.stop_reason ? <><span>·</span><span>{run.stop_reason.replace(/_/g, ' ')}</span></> : null}
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}

function SessionMonitor({
  session,
  cancelling,
  onCancel,
  onReplied,
}: {
  session: AgentHuntSession | null
  cancelling: boolean
  onCancel: () => void
  onReplied: (next: AgentHuntSession) => void
}) {
  const toast = useToast()
  const [reply, setReply] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Keep the transcript pinned to the latest message as it grows.
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [session?.transcript.length])

  if (!session) return <Card className="p-5"><Skeleton className="h-64" /></Card>

  const terminal = isTerminal(session.status)
  const awaiting = session.status === 'awaiting_planner'

  const submitReply = async () => {
    if (!session.run_id || !reply.trim() || submitting) return
    setSubmitting(true)
    try {
      const next = await replyAgentHuntSession(session.run_id, reply.trim())
      onReplied(next)
      setReply('')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not submit the turn')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card className="flex flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <RunStatusBadge state={AGENT_RUN_STATE[session.status] ?? 'idle'} />
            <span className="text-xs tabular-nums text-gray-500">turn {session.iterations}/{session.max_iterations}</span>
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-gray-500">{session.objective}</p>
        </div>
        {!terminal ? (
          <Button variant="danger" onClick={onCancel} loading={cancelling}><CircleStop className="h-4 w-4" />Stop</Button>
        ) : null}
      </div>

      {awaiting ? (
        <div className="mt-3 rounded-lg border border-blue-500/30 bg-blue-500/[0.06] p-3 text-xs text-blue-100">
          Waiting for a planner turn. Return to the coding agent that started this hunt and ask it to continue — it reads the transcript and replies with a tool-calls block. Nothing advances on its own.
        </div>
      ) : null}
      {session.stop_reason && terminal ? (
        <p className="mt-3 text-xs text-amber-300">Stopped: {session.stop_reason.replace(/_/g, ' ')}</p>
      ) : null}
      {session.result ? (
        <div className="mt-3 grid grid-cols-3 gap-2 text-center">
          <Outcome label="Suspected" value={session.result.net_new_count} />
          <Outcome label="Verified" value={session.result.verified_count} tone="good" />
          <Outcome label="HTTP evidence" value={session.result.http_evidence_count} />
        </div>
      ) : null}

      <div ref={scrollRef} className="mt-3 max-h-80 overflow-y-auto rounded-lg border border-gray-800 bg-gray-950/60 p-2">
        {session.transcript.length ? (
          <ol className="space-y-2">
            {session.transcript.map((message, index) => <TranscriptRow key={index} role={message.role} content={message.content} />)}
          </ol>
        ) : (
          <p className="p-4 text-center text-xs text-gray-600">No transcript yet.</p>
        )}
      </div>

      {!terminal ? (
        <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950/30">
          <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-gray-500 hover:text-gray-300">Advanced — submit a planner turn manually</summary>
          <div className="space-y-2 border-t border-gray-800 p-3">
            <p className="text-[11px] leading-4 text-gray-500">Paste a fenced <code>json</code> block with <code>tool_calls</code>, or a final <code>{'{"done":true,"findings":[...]}'}</code> debrief. For power users and demos; normally your coding agent does this.</p>
            <Textarea value={reply} onChange={(e) => setReply(e.target.value)} rows={4} mono placeholder={'```json\n{"tool_calls":[{"name":"query_kb","arguments":{"kind":"findings"}}]}\n```'} disabled={!awaiting || submitting} />
            <div className="flex justify-end">
              <Button size="sm" onClick={submitReply} loading={submitting} disabled={!awaiting || !reply.trim()}>Submit turn</Button>
            </div>
          </div>
        </details>
      ) : null}
    </Card>
  )
}

function TranscriptRow({ role, content }: { role: 'system' | 'user' | 'assistant'; content: string }) {
  const isTool = role === 'user' && content.startsWith('[tool ')
  const isSteering = content.startsWith('[System:')
  const label = role === 'assistant' ? 'Planner' : isTool ? 'Tool result' : isSteering ? 'System' : role === 'system' ? 'System prompt' : 'Context'
  const tone =
    role === 'assistant' ? 'border-emerald-500/30 bg-emerald-500/[0.05] text-emerald-100'
      : isTool ? 'border-blue-500/25 bg-blue-500/[0.05] text-blue-100'
        : 'border-gray-800 bg-gray-900/60 text-gray-300'
  return (
    <li className={`rounded-md border px-2.5 py-2 ${tone}`}>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider opacity-70">{label}</div>
      <pre className="whitespace-pre-wrap break-words font-mono text-[11px] leading-5">{content}</pre>
    </li>
  )
}

function Outcome({ label, value, tone = 'default' }: { label: string; value: number; tone?: 'default' | 'good' }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-2">
      <div className={`text-lg font-semibold tabular-nums ${tone === 'good' ? 'text-emerald-300' : 'text-white'}`}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-gray-500">{label}</div>
    </div>
  )
}

function TwoTierFindings({
  findings,
  verifyingId,
  onVerify,
  targetHost,
}: {
  findings: AgentTwoTierFindings | null
  verifyingId: string | null
  onVerify: (finding: AgentSuspectedFinding) => void
  targetHost: string
}) {
  const verified = findings?.verified || []
  const suspected = findings?.suspected || []
  return (
    <section className="mt-8">
      <h2 className="text-sm font-semibold text-gray-300">Findings{targetHost ? ` · ${targetHost}` : ''}</h2>
      <div className="mt-3 grid gap-5 lg:grid-cols-2">
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Verified</h3>
            <span className="text-xs text-gray-500">proven by the moat</span>
          </div>
          {verified.length ? (
            <div className="divide-y divide-gray-800">
              {verified.map((finding) => (
                <Link key={finding.id} href={`/findings/${finding.id}`} className="-mx-2 flex items-center gap-3 rounded px-2 py-2 hover:bg-gray-800/40">
                  <SeverityBadge severity={finding.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm text-gray-200">{finding.title}</span>
                  <span className="flex-none text-xs text-emerald-300">verified</span>
                </Link>
              ))}
            </div>
          ) : (
            <p className="py-6 text-center text-xs text-gray-600">Nothing verified yet.</p>
          )}
        </Card>

        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-amber-400" />
            <h3 className="text-sm font-semibold text-white">Suspected</h3>
            <span className="text-xs text-gray-500">agent leads, not yet proven</span>
          </div>
          {suspected.length ? (
            <div className="divide-y divide-gray-800">
              {suspected.map((finding) => (
                <div key={finding.id} className="flex items-center gap-3 py-2">
                  <SeverityBadge severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <Link href={`/findings/${finding.id}`} className="block truncate text-sm text-gray-200 hover:text-white">{finding.title}</Link>
                    {finding.family ? <span className="text-[11px] text-gray-500">{finding.family.replace(/_/g, ' ')}{finding.net_new_vs_known ? ' · net-new' : ''}</span> : null}
                  </div>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => onVerify(finding)}
                    loading={verifyingId === finding.id}
                    disabled={verifyingId !== null}
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />Verify
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-6 text-center text-xs text-gray-600">No suspected leads yet.</p>
          )}
        </Card>
      </div>
      <p className="mt-2 text-[11px] text-gray-600">Verify re-runs the deterministic proof moat (needs execution enabled + a credential-tier approval; supports BOLA, auth-bypass, data-exposure, mass-assignment).</p>
    </section>
  )
}

export default function Page() {
  return (
    <Suspense fallback={<div><Skeleton className="h-96" /></div>}>
      <ExplorerPage />
    </Suspense>
  )
}
