'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import { AlertTriangle, ArrowLeft, Square, Terminal } from 'lucide-react'
import HttpArchiveExport from '@/components/HttpArchiveExport'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'
import { CopyButton } from '@/components/findings/detail/CopyButton'
import { Button, Card, ConfirmDialog, Tabs, useToast } from '@/components/ui'
import type { DeviceAgentShellPlan } from '@/lib/api'
import { cancelHuntV2, confirmHuntShellPlan, getHuntV2, type HuntV2 } from '@/lib/huntV2'
import { agentHandoff, defaultRunTab, exhaustedDimension, huntIsLive, pendingDecisions, type RunTab } from '@/lib/huntRunModel.mjs'
import { HUNT_SESSION_NON_AUTONOMOUS_NOTICE, huntStatusLabel } from '@/lib/labels'
import HuntBudgetEditor from './HuntBudgetEditor'
import { HuntDetails, ShellPlanCard } from './HuntDetails'
import { HuntRequestsPanel, useHuntTransactions } from './HuntRequestsPanel'
import { HuntResults } from './HuntResults'
import { huntStatusClass } from './HuntRunList'
import { HuntTimeline } from './HuntTimeline'
import { formatHuntDuration } from './huntFormat'

function AgentHandoff({ hunt, started }: { hunt: HuntV2; started: boolean }) {
  const handoff = agentHandoff(hunt)
  const body = <div className="mt-3 space-y-2">
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 truncate rounded-md bg-black/40 px-3 py-2 font-mono text-xs text-gray-100">{handoff.command}</code>
      <CopyButton text={handoff.command} label="Copy command" />
    </div>
    <div className="flex items-start gap-2">
      <p className="min-w-0 flex-1 rounded-md bg-black/40 px-3 py-2 font-mono text-xs leading-relaxed text-gray-300">{handoff.prompt}</p>
      <CopyButton text={handoff.prompt} label="Copy prompt" />
    </div>
  </div>
  return <Card className="border-blue-500/25 bg-blue-500/5 p-4">
    <div className="flex items-start gap-3">
      <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-blue-300" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-blue-100">{started ? 'Your coding agent is driving this Hunt' : 'Waiting for your coding agent'}</p>
        <p className="mt-0.5 text-xs text-blue-100/70">{HUNT_SESSION_NON_AUTONOMOUS_NOTICE}</p>
        {started
          ? <details className="text-xs"><summary className="mt-2 cursor-pointer text-blue-300">Connect another terminal</summary>{body}</details>
          : <>{<p className="mt-2 text-xs text-gray-400">Run this in a terminal, then paste the prompt into the agent.</p>}{body}</>}
      </div>
    </div>
  </Card>
}

/**
 * One Hunt run for the operator: what it is doing, what needs a human decision, what it found,
 * the requests it sent, and the exports. Planner-facing context stays in the exported record.
 */
export function HuntRunView({ hunt, onChange, target }: {
  hunt: HuntV2
  onChange: (hunt: HuntV2) => void
  target: { title: string; locator: string } | null
}) {
  const toast = useToast()
  const router = useRouter()
  const live = huntIsLive(hunt)
  const [tab, setTab] = useState<RunTab>(() => defaultRunTab(hunt, typeof window === 'undefined' ? '' : window.location.hash))
  const [objectiveOpen, setObjectiveOpen] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [confirmingPlanId, setConfirmingPlanId] = useState<string | null>(null)
  const actions = hunt.actions || []
  const archive = useHuntTransactions(hunt.hunt_id, actions.length + (hunt.budget_used.http_requests || 0))

  useEffect(() => {
    if (!['active', 'awaiting_planner'].includes(hunt.status)) return
    let cancelled = false
    const refresh = () => getHuntV2(hunt.hunt_id)
      .then((current) => { if (!cancelled) onChange(current) })
      .catch(() => undefined)
    const timer = window.setInterval(refresh, 5000)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [hunt.hunt_id, hunt.status, onChange])

  const shellPlans = useMemo<DeviceAgentShellPlan[]>(() => {
    const deviceState = hunt.context_pack?.device_state
    if (!deviceState || typeof deviceState !== 'object' || Array.isArray(deviceState)) return []
    const plans = (deviceState as { shell_plans?: unknown }).shell_plans
    return Array.isArray(plans)
      ? plans.filter((plan): plan is DeviceAgentShellPlan => Boolean(plan && typeof plan === 'object' && 'plan_id' in plan))
      : []
  }, [hunt.context_pack])
  const decisions = pendingDecisions(hunt, shellPlans)
  const planDecisions = decisions.filter(decision => decision.kind === 'ssh_plan')
  const budgetDecision = decisions.find(decision => decision.kind === 'budget')
  // Once the budget decision has appeared it stays until the operator leaves: extending the budget
  // changes the Hunt's status, and the result of that extension must remain readable.
  const [budgetDecisionShown, setBudgetDecisionShown] = useState(false)
  useEffect(() => { if (budgetDecision) setBudgetDecisionShown(true) }, [budgetDecision])
  const showBudget = Boolean(budgetDecision) || (budgetDecisionShown && !hunt.completed_at)

  // Links such as a history row's request count change only the hash; follow them to the tab.
  useEffect(() => {
    const follow = () => setTab(defaultRunTab(hunt, window.location.hash))
    window.addEventListener('hashchange', follow)
    return () => window.removeEventListener('hashchange', follow)
  }, [hunt])

  function selectTab(next: string) {
    setTab(next as RunTab)
    window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}#${next}`)
  }

  async function confirmShellPlan(plan: DeviceAgentShellPlan) {
    setConfirmingPlanId(plan.plan_id)
    try {
      onChange(await confirmHuntShellPlan(hunt.hunt_id, plan))
      toast.success('Exact SSH command plan queued')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to confirm SSH command plan')
    } finally {
      setConfirmingPlanId(null)
    }
  }

  async function stop() {
    setStopping(true)
    try {
      onChange(await cancelHuntV2(hunt.hunt_id))
      toast.success('Hunt stopped')
      setConfirmStop(false)
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to stop Hunt')
    } finally {
      setStopping(false)
    }
  }

  const findingCount = hunt.outcome_summary?.finding_ids.length ?? 0
  const candidateCount = hunt.outcome_summary?.candidate_ids.length ?? hunt.budget_used.candidates ?? 0
  const stoppable = !hunt.completed_at && ['active', 'awaiting_planner', 'budget_exhausted'].includes(hunt.status)

  return <div className="space-y-5">
    <div className="space-y-3">
      <Link href="/hunt" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200"><ArrowLeft className="h-4 w-4" aria-hidden="true" />Hunts</Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1 basis-96">
          <h1 className={`text-xl font-semibold leading-snug text-white sm:text-2xl ${objectiveOpen ? '' : 'line-clamp-2'}`}>{hunt.objective || 'Hunt'}</h1>
          {(hunt.objective || '').length > 160 && (
            <button type="button" onClick={() => setObjectiveOpen((open) => !open)} aria-expanded={objectiveOpen} className="mt-1 text-xs text-blue-300 hover:text-blue-200">
              {objectiveOpen ? 'Show less' : 'Show full objective'}
            </button>
          )}
          <p className="mt-1 flex flex-wrap items-center gap-x-2 text-sm text-gray-400">
            <Link href={`/targets/${encodeURIComponent(hunt.target_id)}/asset`} className="text-blue-300 hover:text-blue-200">{target?.title || hunt.target_id}</Link>
            {target?.locator && target.locator !== target.title && <span className="font-mono text-xs text-gray-500">{target.locator}</span>}
            <span className="text-gray-600">·</span><span>{hunt.target_kind}</span>
            <span className="text-gray-600">·</span><span>{hunt.budget_profile}{(hunt.budget_revision ?? 0) > 0 ? ' (amended)' : ''}</span>
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-medium ring-1 ring-inset ${huntStatusClass(hunt.status)}`}>
            {live && <span className="h-2 w-2 animate-pulse rounded-full bg-current" aria-hidden="true" />}
            {huntStatusLabel(hunt.status)}
          </span>
          <HttpArchiveExport ownerKind="hunt" ownerId={hunt.hunt_id} variant="menu" />
          {stoppable && <Button size="sm" variant="danger" onClick={() => setConfirmStop(true)}><Square className="h-3.5 w-3.5" aria-hidden="true" />Stop</Button>}
          {/* A running Hunt blocks its own deletion; the preview says so and an abandoned one is cancelled. */}
          <DeleteRecordsButton selection={{ kind: 'hunt', id: hunt.hunt_id }} label="Delete" subject="this Hunt"
            variant="secondary" className="px-2.5 py-1 text-sm" onDeleted={() => router.push('/hunt')} />
        </div>
      </div>
    </div>

    {live && <AgentHandoff hunt={hunt} started={actions.length > 0} />}

    {(planDecisions.length > 0 || showBudget) && <section aria-label="Needs your decision"
      className={`space-y-3 rounded-xl border p-4 ${decisions.length > 0 ? 'border-amber-500/40 bg-amber-500/5' : 'border-gray-800 bg-gray-900/60'}`}>
      <h2 className={`flex items-center gap-2 text-sm font-semibold ${decisions.length > 0 ? 'text-amber-100' : 'text-gray-200'}`}>
        <AlertTriangle className="h-4 w-4" aria-hidden="true" />{decisions.length > 0 ? 'Needs your decision' : 'Decision made'}
      </h2>
      {planDecisions.map(decision => <ShellPlanCard key={decision.id} plan={shellPlans.find(plan => plan.plan_id === decision.id)!}
        confirming={confirmingPlanId === decision.id} onConfirm={confirmShellPlan} />)}
      {showBudget && <div className="space-y-2">
        <p className="text-sm text-amber-100/90">
          {budgetDecision
            ? `The Hunt ran out of budget${budgetDecision.reason ? ` (${budgetDecision.reason})` : ''}. Extend it to let the agent continue, or stop the Hunt.`
            : 'The budget was extended. Your coding agent can continue this Hunt.'}
        </p>
        <HuntBudgetEditor hunt={hunt} onChanged={onChange} initialDimension={exhaustedDimension(hunt)} />
      </div>}
    </section>}

    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {[
        { label: 'HTTP requests', value: (hunt.budget_used.http_requests || 0).toLocaleString(), tab: 'requests' },
        { label: 'Capability calls', value: `${hunt.budget_used.agent_actions || 0} / ${hunt.budget.max_capability_calls || 0}`, tab: 'timeline' },
        { label: 'Findings · candidates', value: `${findingCount} · ${candidateCount}`, tab: 'results' },
        { label: hunt.completed_at ? 'Duration' : 'Running for', value: formatHuntDuration(hunt.created_at, hunt.completed_at) || '—', tab: 'details' },
      ].map(item => <button key={item.label} type="button" onClick={() => selectTab(item.tab)}
        className="rounded-xl border border-gray-800 bg-gray-900/60 p-3 text-left transition-colors hover:border-gray-700">
        <span className="block text-xs text-gray-500">{item.label}</span>
        <span className="text-lg font-semibold text-white">{item.value}</span>
      </button>)}
    </div>

    <Tabs ariaLabel="Hunt sections" active={tab} onChange={selectTab} items={[
      { key: 'results', label: 'Results', badge: findingCount || undefined },
      { key: 'requests', label: 'Requests', badge: archive.total || undefined },
      { key: 'timeline', label: 'Timeline', badge: actions.length || undefined },
      { key: 'details', label: 'Details' },
    ]} />

    {tab === 'results' && <HuntResults hunt={hunt} />}
    {tab === 'requests' && <HuntRequestsPanel archive={archive} />}
    {tab === 'timeline' && <HuntTimeline hunt={hunt} archive={archive} />}
    {tab === 'details' && <HuntDetails hunt={hunt} shellPlans={shellPlans} confirmingPlanId={confirmingPlanId} onConfirmPlan={confirmShellPlan} onChanged={onChange} />}

    <ConfirmDialog open={confirmStop} danger busy={stopping} title="Stop this Hunt?" confirmLabel="Stop Hunt"
      message="The Hunt stops accepting capability calls. Recorded requests, evidence and findings stay; your agent cannot continue this run."
      onConfirm={() => void stop()} onCancel={() => setConfirmStop(false)} />
  </div>
}
