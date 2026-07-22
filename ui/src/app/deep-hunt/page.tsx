'use client'

// Deep Hunt is the product surface. The implementation uses the keyless,
// free-form agent-hunt controller and the current coding-agent session.

import { Suspense, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { CircleStop, Compass, Rocket, ShieldCheck, Terminal } from 'lucide-react'
import {
  cancelAgentHuntSession,
  createTargetPolicyApproval,
  getAgentHuntSession,
  getAgentTwoTierFindings,
  getTargets,
  replyAgentHuntSession,
  startAgentHuntSession,
  verifySuspectedAgentFinding,
  type AgentHuntSession,
  type AgentHuntStatus,
  type AgentSuspectedFinding,
  type AgentTwoTierFindings,
  type Target,
} from '@/lib/api'
import { Button, Card, ConfirmDialog, EmptyState, ErrorState, Field, Input, SeverityBadge, Select, Skeleton, Textarea, useToast } from '@/components/ui'
import { RunStatusBadge, hostFromUrl, targetLabel, type RunState } from '@/components/hunt'
import { EngineHint, InvestigatorTabs } from '@/components/hunt/InvestigatorTabs'
import { RecentHunts } from '@/components/hunt/RecentHunts'
import { isWebTarget } from '@/lib/targets'

const DEFAULT_OBJECTIVE =
  'Explore the target autonomously, pursue the highest-value security leads, use bounded active testing where it adds evidence, and verify supported findings through the proof moat.'

const TERMINAL: AgentHuntStatus[] = ['completed', 'cancelled', 'failed']
const AGENT_RUN_STATE: Record<AgentHuntStatus, RunState> = {
  awaiting_planner: 'waiting',
  planning: 'running',
  completed: 'completed',
  cancelled: 'cancelled',
  failed: 'failed',
}
const isTerminal = (status?: AgentHuntStatus | null) => !!status && TERMINAL.includes(status)

// You can also start a hunt straight from the terminal: the current coding-agent
// session is the planner, so a plain-language ask kicks it off and drives it.
function TerminalHint({ example }: { example: string }) {
  const [copied, setCopied] = useState(false)
  const copyExample = async () => {
    try {
      await navigator.clipboard.writeText(example)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="mt-4 flex flex-col gap-3 rounded-lg border border-violet-500/25 bg-violet-500/[0.06] p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex items-start gap-3">
        <Terminal className="mt-0.5 h-5 w-5 shrink-0 text-violet-300" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium text-violet-100">Prefer the terminal? Start it from your coding agent.</p>
          <p className="mt-0.5 text-xs leading-5 text-gray-400">
            In the ShakerScan runtime (<code className="rounded bg-gray-800 px-1 py-0.5 font-mono text-[11px] text-gray-300">shakerscan agent claude</code>), just ask in plain language — the agent launches the hunt, drives each turn, and it appears here live.
          </p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <code className="rounded-md border border-gray-700 bg-gray-950 px-3 py-1.5 font-mono text-xs text-gray-200">{example}</code>
        <button
          type="button"
          onClick={copyExample}
          aria-label="Copy example command"
          className="rounded-md border border-gray-700 px-2.5 py-1.5 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

function DeepHuntPage() {
  const toast = useToast()
  const searchParams = useSearchParams()
  const [targets, setTargets] = useState<Target[]>([])
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE)
  const [maxIterations, setMaxIterations] = useState('20')
  const [tokenBudget, setTokenBudget] = useState('9000')
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [session, setSession] = useState<AgentHuntSession | null>(null)
  const [findings, setFindings] = useState<AgentTwoTierFindings | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [pendingStart, setPendingStart] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [verifyingId, setVerifyingId] = useState<string | null>(null)
  const [pendingVerify, setPendingVerify] = useState<AgentSuspectedFinding | null>(null)
  const [error, setError] = useState<string | null>(null)

  const sessionRef = useRef<AgentHuntSession | null>(null)
  sessionRef.current = session
  const findingsTargetId = session?.target_id || targetId
  const activeTarget = useMemo(() => targets.find((t) => t.id === findingsTargetId), [targets, findingsTargetId])
  const launchTarget = useMemo(() => targets.find((t) => t.id === targetId), [targets, targetId])
  const activeHost = activeTarget ? hostFromUrl(activeTarget.url) : ''
  // Use a real (random) target in the terminal example when the DB has any.
  const exampleCommand = useMemo(() => {
    const host = targets.length
      ? hostFromUrl(targets[Math.floor(Math.random() * targets.length)].url)
      : 'example.com'
    return `start a deep hunt for ${host}`
  }, [targets])

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
        const requestedObjective = searchParams.get('objective')?.trim()
        if (requestedObjective) setObjective(requestedObjective)
      })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load targets') })
      .finally(() => { if (!cancelled) setLoading(false) })
    const requestedRun = searchParams.get('run')?.trim()
    if (requestedRun) setSelectedRunId(requestedRun)
    return () => { cancelled = true }
  }, [searchParams])

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
    if (!targetId || !launchTarget || starting) return
    setStarting(true); setError(null)
    try {
      const approvalReceiptId = await createTargetPolicyApproval(
        launchTarget.id,
        launchTarget.url,
        120,
        'credential',
      )
      const started = await startAgentHuntSession(targetId, {
        objective: objective.trim() || DEFAULT_OBJECTIVE,
        max_iterations: Math.min(40, Math.max(1, Number.parseInt(maxIterations, 10) || 20)),
        token_budget: Math.min(24000, Math.max(1000, Number.parseInt(tokenBudget, 10) || 9000)),
        mode: 'deep_hunt',
        approval_receipt_id: approvalReceiptId,
      })
      setSession(started)
      setSelectedRunId(started.run_id)
      toast.success('Deep Hunt started — continue it from your coding agent')
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
      toast.success('Deep Hunt cancelled')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not cancel the hunt')
    } finally {
      setCancelling(false)
    }
  }

  // Runs only after the operator confirms the approval grant (see ConfirmDialog).
  const runVerify = async (finding: AgentSuspectedFinding) => {
    if (!activeTarget) return
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
          <div className="flex items-center gap-2 text-sm text-blue-300"><Compass className="h-4 w-4" />AI Investigator</div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-white">Deep Hunt</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-400">
            Your coding agent explores freely, runs bounded active probes, and backs every claim with real tool output. Evidence-backed leads begin <span className="text-amber-300">suspected</span>; supported proof workflows promote them to <span className="text-emerald-300">verified</span>.
          </p>
        </div>
        <div className="flex flex-col items-start gap-1.5 sm:items-end">
          <InvestigatorTabs />
          <EngineHint />
        </div>
      </header>

      <TerminalHint example={exampleCommand} />

      {error ? <div className="mt-4"><ErrorState message={error} /></div> : null}

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        {/* Launch */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold text-white">Start a Deep Hunt</h2>
          <div className="mt-4 space-y-4">
            <Field label="Target">
              <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                <option value="">Choose a target…</option>
                {!targets.length ? <option value="" disabled>No web targets — add one under Targets</option> : null}
                {targets.map((t) => <option key={t.id} value={t.id}>{targetLabel(t)} · {hostFromUrl(t.url)}</option>)}
              </Select>
            </Field>
            <Field label="Objective" hint="What should it investigate? The AI chooses its own requests and tools.">
              <Textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={3} maxLength={2000} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Max turns" hint="1–40 planner turns.">
                <Input type="number" min={1} max={40} value={maxIterations} onChange={(e) => setMaxIterations(e.target.value)} />
              </Field>
              <Field label="Token budget" hint="1000–24000 per run.">
                <Input type="number" min={1000} max={24000} step={500} value={tokenBudget} onChange={(e) => setTokenBudget(e.target.value)} />
              </Field>
            </div>
            <div className="flex items-center justify-between gap-3 border-t border-gray-800 pt-4">
              <p className="text-xs text-gray-500">
                Active, same-origin security testing with hard turn, request, and action ceilings. Arbitrary write requests remain blocked; deterministic workflows handle proof and controlled mutation.
              </p>
              <Button onClick={() => setPendingStart(true)} loading={starting} disabled={!targetId} className="min-w-36">
                <Rocket className="h-4 w-4" />Start Deep Hunt
              </Button>
            </div>
          </div>
        </Card>

        {/* Monitor */}
        {selectedRunId ? (
          <SessionMonitor session={session} cancelling={cancelling} onCancel={cancelHunt} onReplied={setSession} />
        ) : (
          <Card className="flex items-center justify-center p-5">
            <EmptyState message="No hunt selected" hint="Start one, or pick a run from the feed below to watch it live." />
          </Card>
        )}
      </div>

      {/* Two-tier findings */}
      {findingsTargetId ? (
        <TwoTierFindings findings={findings} verifyingId={verifyingId} onVerify={setPendingVerify} targetHost={activeHost} />
      ) : null}

      {/* Unified history retains legacy guided runs alongside current Deep Hunts. */}
      <section className="mt-8">
        <h2 className="text-sm font-semibold text-gray-300">Recent investigations</h2>
        <RecentHunts />
      </section>

      <ConfirmDialog
        open={pendingStart}
        title="Authorize Deep Hunt?"
        message={
          <div className="space-y-2">
            <p>Deep Hunt performs AI-driven exploration and bounded active exploitation against <span className="font-mono text-gray-200">{launchTarget ? hostFromUrl(launchTarget.url) : 'this target'}</span>.</p>
            <p className="text-xs text-gray-500">Continue only if you own the target or have explicit permission. This creates a target-scoped, expiring credential-tier approval. Requests remain same-origin and bounded; arbitrary write methods stay blocked.</p>
          </div>
        }
        confirmLabel="Authorize & start"
        busy={starting}
        onCancel={() => setPendingStart(false)}
        onConfirm={() => { setPendingStart(false); void startHunt() }}
      />

      <ConfirmDialog
        open={pendingVerify !== null}
        title="Verify this finding?"
        message={
          <div className="space-y-2">
            <p>This creates a target-scoped, <span className="text-gray-200">credential-tier approval receipt</span>{activeHost ? <> for <span className="font-mono text-gray-200">{activeHost}</span></> : null} and re-runs the deterministic proof moat against the live target.</p>
            <p className="text-xs text-gray-500">Only proceed if you own the target or have explicit permission to actively test it. Needs execution enabled; supports BOLA, auth-bypass, data-exposure, and mass-assignment.</p>
          </div>
        }
        confirmLabel="Create approval & verify"
        busy={verifyingId !== null}
        onCancel={() => setPendingVerify(null)}
        onConfirm={() => { const finding = pendingVerify; setPendingVerify(null); if (finding) void runVerify(finding) }}
      />
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

      <div className="mt-3 flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Activity</h3>
        <span className="hidden text-[10px] text-gray-600 sm:inline">what the agent did, step by step</span>
      </div>
      <div ref={scrollRef} className="mt-1.5 max-h-80 overflow-y-auto rounded-lg border border-gray-800 bg-gray-950/60 p-2">
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

// Pull a fenced ```json block (or raw JSON) out of a planner message.
function extractPlannerJson(content: string): Record<string, unknown> | null {
  const fence = content.match(/```(?:json)?\s*([\s\S]*?)```/)
  const raw = (fence ? fence[1] : content).trim()
  if (!raw.startsWith('{') && !raw.startsWith('[')) return null
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function toolCallSummary(call: Record<string, unknown>): string {
  const name = String(call.name || 'tool')
  const args = (call.arguments || {}) as Record<string, unknown>
  const method = typeof args.method === 'string' ? args.method : ''
  const focus =
    (typeof args.path === 'string' && args.path) ||
    (typeof args.kind === 'string' && args.kind) ||
    (typeof args.target === 'string' && args.target) ||
    (typeof args.name === 'string' && args.name) ||
    ''
  return [name, method, focus].filter(Boolean).join(' ')
}

function RawDetails({ label, content }: { label: string; content: string }) {
  return (
    <details className="mt-1">
      <summary className="cursor-pointer text-[10px] uppercase tracking-wider text-gray-500 hover:text-gray-300">{label}</summary>
      <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-5 text-gray-400">{content}</pre>
    </details>
  )
}

// Renders the raw ReAct transcript as a readable activity log: planner tool
// calls become "http_request GET /path" chips, tool results collapse to
// "name -> ok/error" with the payload behind a disclosure, the final debrief
// lists its findings, and the bulky system prompt / context pack collapse away.
function TranscriptRow({ role, content }: { role: 'system' | 'user' | 'assistant'; content: string }) {
  // System prompt + the big objective/context pack: technical setup, collapse.
  if (role === 'system' || (role === 'user' && !content.startsWith('[tool ') && !content.startsWith('[System:'))) {
    return (
      <li>
        <details className="rounded-md border border-gray-800 bg-gray-900/40">
          <summary className="cursor-pointer px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500 hover:text-gray-300">
            {role === 'system' ? 'System prompt' : 'Objective & context'}
          </summary>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words border-t border-gray-800 px-2.5 py-2 font-mono text-[11px] leading-5 text-gray-400">{content}</pre>
        </details>
      </li>
    )
  }

  // Tool result: "[tool NAME -> ok|error] {payload}"
  if (role === 'user' && content.startsWith('[tool ')) {
    const match = content.match(/^\[tool (\S+) -> (ok|error)\]\s*([\s\S]*)$/)
    const name = match?.[1] || 'tool'
    const ok = match?.[2] !== 'error'
    const payload = (match?.[3] || content).trim()
    return (
      <li className="rounded-md border border-blue-500/25 bg-blue-500/[0.05] px-2.5 py-2">
        <div className="flex items-center gap-2 text-[11px] text-blue-100">
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${ok ? 'bg-emerald-400' : 'bg-red-400'}`} aria-hidden="true" />
          <span className="font-medium">{name}</span>
          <span className={ok ? 'text-emerald-300' : 'text-red-300'}>→ {ok ? 'ok' : 'error'}</span>
        </div>
        {payload ? <RawDetails label="result" content={payload} /> : null}
      </li>
    )
  }

  // Anti-stall / system steering line.
  if (content.startsWith('[System:')) {
    return <li className="rounded-md border border-gray-800 bg-gray-900/60 px-2.5 py-1.5 text-[11px] text-gray-400">{content}</li>
  }

  // Planner (assistant) turn.
  const parsed = extractPlannerJson(content)
  const toolCalls = parsed && Array.isArray(parsed.tool_calls) ? (parsed.tool_calls as Record<string, unknown>[]) : null
  const done = Boolean(parsed && parsed.done === true)
  const findings = done && parsed && Array.isArray(parsed.findings) ? (parsed.findings as Record<string, unknown>[]) : null
  return (
    <li className="rounded-md border border-emerald-500/30 bg-emerald-500/[0.05] px-2.5 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300/80">Planner</div>
      {toolCalls ? (
        <div className="mt-1 flex flex-wrap gap-1.5">
          {toolCalls.map((call, i) => (
            <span key={i} className="rounded bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[11px] text-emerald-200">{toolCallSummary(call)}</span>
          ))}
        </div>
      ) : done ? (
        <div className="mt-1">
          <div className="text-xs font-medium text-emerald-200">
            Concluded{findings && findings.length ? ` — ${findings.length} finding${findings.length === 1 ? '' : 's'}` : parsed?.abstained ? ' — abstained (no finding)' : ''}
          </div>
          {findings && findings.length ? (
            <div className="mt-1.5 grid gap-1">
              {findings.map((finding, i) => (
                <div key={i} className="flex items-center gap-2">
                  <SeverityBadge severity={String(finding.severity || 'info')} />
                  <span className="min-w-0 truncate text-xs text-emerald-100">{String(finding.title || 'finding')}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      ) : (
        <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] leading-5 text-emerald-100/80">{content}</pre>
      )}
      {toolCalls || done ? <RawDetails label="raw" content={content} /> : null}
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
      <p className="mt-2 text-[11px] text-gray-600">Verify creates a credential-tier approval and re-runs the deterministic proof moat (needs execution enabled; supports BOLA, auth-bypass, data-exposure, mass-assignment).</p>
    </section>
  )
}

export default function Page() {
  return (
    <Suspense fallback={<div><Skeleton className="h-96" /></div>}>
      <DeepHuntPage />
    </Suspense>
  )
}
