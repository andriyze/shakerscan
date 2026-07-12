'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  ArrowRight, Bot, CheckCircle2, ChevronRight, CircleDot,
  Gauge, Lightbulb, LockKeyhole, Pause, RefreshCw, Route, ShieldCheck, Target,
} from 'lucide-react'
import {
  getFamilyProofContracts,
  getTargets,
  scheduleHypotheses,
  transitionHypothesis,
  type FamilyProofContracts,
  type HypothesisScheduleResponse,
  type ScheduledLead,
} from '@/lib/api'
import { Badge, Button, Card, EmptyState, ErrorState, Skeleton, buttonClasses } from '@/components/ui'

interface TargetLite { id: string; url: string; name?: string | null }

const FAMILY_LABELS: Record<string, string> = {
  bola: 'Object access control', idor: 'Object access control', auth_bypass: 'Authentication bypass',
  bfla: 'Function authorization', mass_assignment: 'Mass assignment', injection: 'Injection',
  workflow: 'Workflow integrity', data_exposure: 'Sensitive data exposure',
}

const PROOF_LABELS: Record<string, string> = {
  distinct_identity: 'Two genuinely different accounts', ownership_established: 'Object ownership is established',
  cross_principal_access: 'A second account can access the object', denial_control: 'A denial/control request is captured',
  cross_principal_denied: 'The second account is correctly denied', same_account: 'Both sessions resolve to one account',
  forbidden_field_accepted: 'Restricted field is accepted', observable_state_change: 'The restricted value actually changes',
  control_rejected: 'A control request is rejected', forbidden_field_rejected: 'The restricted field is rejected',
  payload_control_differential: 'Payload and control behave differently', deterministic_family_proof: 'Family-specific proof succeeds',
  control_equivalent: 'Payload and control are equivalent', protected_resource_accessed: 'Protected resource is reached',
  unauthenticated_control: 'Unauthenticated control is captured', access_denied_unauthenticated: 'Unauthenticated request is denied',
  transition_invariant_broken: 'Expected workflow transition is bypassed', before_after_state: 'Before/after state is captured',
  invariant_held: 'The workflow invariant holds', sensitive_value_present: 'A sensitive value—not only its field name—is observed',
  name_only_classification: 'Only a sensitive-looking field name is present',
}

function text(value: unknown): string { return typeof value === 'string' ? value.trim() : '' }

function familyLabel(family: string): string {
  return FAMILY_LABELS[family.toLowerCase()] || family.replaceAll('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function statusLabel(status: string): string {
  return ({ open: 'Ready', claimed: 'In review', testing: 'Test planned', supported: 'Signal observed' } as Record<string, string>)[status] || status
}

function severityClass(severity?: string | null): string {
  if (severity === 'critical') return 'bg-red-500/15 text-red-300 border-red-500/30'
  if (severity === 'high') return 'bg-orange-500/15 text-orange-300 border-orange-500/30'
  if (severity === 'medium') return 'bg-amber-500/15 text-amber-300 border-amber-500/30'
  return 'bg-gray-800 text-gray-300 border-gray-700'
}

function selectedContract(contracts: FamilyProofContracts | null, family: string) {
  if (!contracts) return undefined
  const canonical = contracts.aliases[family] || family
  return contracts.contracts[canonical]
}

function experimentHref(lead: ScheduledLead): string {
  const h = lead.hypothesis
  const next = h?.next_test_action || {}
  const q = new URLSearchParams()
  if (h?.target_id) q.set('target', h.target_id)
  q.set('lead', h?.id || lead.hypothesis_id)
  q.set('family', h?.family || '')
  q.set('objective', text(h?.title) || text(h?.description) || `Investigate ${familyLabel(h?.family || 'security lead')}`)
  const expected = text(next.expected_signal) || text(h?.metadata_json?.expected_signal)
  const falsifier = text(next.falsifier) || text(h?.metadata_json?.falsifier)
  const path = text(next.path) || text(next.route) || text(h?.metadata_json?.route_template)
  if (expected) q.set('expected', expected)
  if (falsifier) q.set('falsifier', falsifier)
  if (path) q.set('path', path)
  return `/settings/research-agent/experiment?${q.toString()}`
}

function nextAction(lead: ScheduledLead): { href: string; label: string; description: string } {
  const h = lead.hypothesis
  const action = h?.next_test_action || {}
  const command = text(action.command)
  const parameters = action.parameters && typeof action.parameters === 'object' ? action.parameters as Record<string, unknown> : {}
  if (command === 'finding.retest' && text(parameters.finding_id)) {
    return { href: `/findings/${encodeURIComponent(text(parameters.finding_id))}`, label: 'Review and retest finding', description: 'Open the existing finding and use its deterministic retest workflow.' }
  }
  if (command.startsWith('ai_gate') || h?.source === 'ai_gate') {
    return { href: '/settings/ai-gate', label: 'Open AI Gate', description: 'Continue with the AI-target probe and transcript workflow.' }
  }
  if (command.startsWith('model_intake') || h?.source === 'model_intake') {
    return { href: '/settings/model-intake', label: 'Open Model Intake', description: 'Continue with the artifact trust and verification workflow.' }
  }
  if (command.startsWith('asm.')) {
    return { href: '/asm', label: 'Open attack-surface work', description: 'Continue with the target’s coverage and endpoint workflow.' }
  }
  return { href: experimentHref(lead), label: 'Prepare bounded test', description: 'Prepare a control and test sequence. No requests are sent during plan validation.' }
}

function PriorityReason({ lead }: { lead: ScheduledLead }) {
  const b = lead.breakdown || {}
  const reasons = [
    b.boundary_value >= 3 ? 'crosses a security boundary' : null,
    b.impact >= 4 ? 'could have high impact' : null,
    b.novelty >= 2 ? 'has not been tested before' : null,
    b.reachability >= 2 ? 'appears reachable now' : null,
  ].filter(Boolean)
  return <span>{reasons.length ? reasons.join(' · ') : 'ranked from available evidence and test cost'}</span>
}

function LeadCard({ lead, selected, onSelect }: { lead: ScheduledLead; selected: boolean; onSelect: () => void }) {
  const h = lead.hypothesis
  const status = String(h?.effective_status || h?.status || 'open')
  return (
    <button type="button" onClick={onSelect}
      className={`w-full text-left rounded-xl border p-4 transition-colors ${selected ? 'border-blue-500/70 bg-blue-500/[0.07]' : 'border-gray-800 bg-gray-900 hover:border-gray-700'}`}>
      <div className="flex items-start gap-3">
        <div className={`mt-0.5 rounded-lg p-2 ${selected ? 'bg-blue-500/15 text-blue-300' : 'bg-gray-800 text-gray-400'}`}>
          <CircleDot className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold text-gray-100">{familyLabel(h?.family || 'lead')}</h3>
            <Badge className={severityClass(h?.severity_guess)}>{h?.severity_guess || 'unrated'}</Badge>
            <Badge className="bg-gray-800 text-gray-300">{statusLabel(status)}</Badge>
          </div>
          <p className="mt-1.5 text-sm text-gray-300 line-clamp-2">{h?.title || h?.description || 'Untitled investigation lead'}</p>
          <div className="mt-2 flex items-center gap-2 text-xs text-gray-500">
            <Lightbulb className="h-3.5 w-3.5 text-amber-300" />
            <PriorityReason lead={lead} />
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-xl text-white">{lead.priority?.toFixed(1) ?? '—'}</div>
          <div className="text-[10px] uppercase tracking-wider text-gray-600">priority</div>
        </div>
        <ChevronRight className="mt-2 h-4 w-4 text-gray-600" />
      </div>
    </button>
  )
}

function LeadInspector({ lead, contracts, busy, onTransition }: {
  lead: ScheduledLead | null
  contracts: FamilyProofContracts | null
  busy: boolean
  onTransition: (lead: ScheduledLead, state: string) => Promise<void>
}) {
  if (!lead?.hypothesis) return <Card className="p-6 text-sm text-gray-500">Select a lead to see the recommended investigation.</Card>
  const h = lead.hypothesis
  const status = String(h.effective_status || h.status || 'open')
  const next = h.next_test_action || {}
  const expected = text(next.expected_signal) || text(h.metadata_json?.expected_signal)
  const falsifier = text(next.falsifier) || text(h.metadata_json?.falsifier)
  const contract = selectedContract(contracts, h.family)
  const needsAuth = Boolean(h.metadata_json?.requires_auth || ['bola', 'idor', 'bfla', 'auth_bypass'].includes(h.family))
  const action = nextAction(lead)

  return (
    <div className="grid gap-4 lg:sticky lg:top-5">
      <Card className="overflow-hidden">
        <div className="border-b border-gray-800 bg-gradient-to-br from-blue-500/10 to-transparent p-5">
          <div className="flex items-center justify-between gap-3">
            <Badge className="bg-blue-500/15 text-blue-300">Work order</Badge>
            <span className="text-xs text-gray-500">~{lead.request_cost || 1} requests</span>
          </div>
          <h2 className="mt-3 text-xl font-semibold text-white">{h.title || familyLabel(h.family)}</h2>
          <p className="mt-2 text-sm leading-6 text-gray-400">{h.description || 'Validate this lead with a bounded control and test sequence.'}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {needsAuth ? <Badge className="bg-violet-500/15 text-violet-300"><LockKeyhole className="mr-1 h-3 w-3" />Two-account context</Badge> : null}
            <Badge className="bg-gray-800 text-gray-300"><Route className="mr-1 h-3 w-3" />{h.source.replaceAll('_', ' ')}</Badge>
            {h.cwe ? <Badge className="bg-gray-800 text-gray-300">{h.cwe}</Badge> : null}
          </div>
        </div>

        <div className="grid gap-5 p-5">
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Decision rule</h3>
            <div className="mt-2 grid gap-2">
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.06] p-3">
                <div className="text-xs font-medium text-emerald-300">Signal to look for</div>
                <p className="mt-1 text-sm text-gray-300">{expected || 'A repeatable difference between the control and test request.'}</p>
              </div>
              <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
                <div className="text-xs font-medium text-gray-400">What would disprove it</div>
                <p className="mt-1 text-sm text-gray-400">{falsifier || 'The control and test behave equivalently under the same conditions.'}</p>
              </div>
            </div>
          </section>

          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Safe next step</h3>
            <p className="mt-1 text-sm text-gray-400">{action.description}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Link href={action.href} className={buttonClasses('primary', 'md')}>
                {action.label} <ArrowRight className="h-4 w-4" />
              </Link>
              {status === 'open' ? <Button variant="secondary" onClick={() => onTransition(lead, 'claimed')} disabled={busy}>Start review</Button> : null}
              {['claimed', 'testing', 'supported'].includes(status) ? <Button variant="ghost" onClick={() => onTransition(lead, 'open')} disabled={busy}>Release</Button> : null}
              {['open', 'claimed', 'testing', 'supported'].includes(status) ? <Button variant="ghost" onClick={() => onTransition(lead, 'blocked')} disabled={busy}><Pause className="h-4 w-4" /> Park</Button> : null}
            </div>
          </section>
        </div>
      </Card>

      <Card className="p-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-300" />
          <h2 className="font-semibold text-gray-200">Proof required before a finding</h2>
        </div>
        <p className="mt-1 text-xs leading-5 text-gray-500">This is a system checklist, not a form. ShakerScan must observe these facts during live verification.</p>
        <div className="mt-4 grid gap-2">
          {(contract?.requires || []).map((item) => (
            <div key={item} className="flex items-start gap-2 rounded-lg bg-gray-950/60 px-3 py-2.5 text-sm text-gray-400">
              <CheckCircle2 className="mt-0.5 h-4 w-4 flex-none text-gray-600" />
              <span>{PROOF_LABELS[item] || item.replaceAll('_', ' ')}</span>
            </div>
          ))}
          {!contract ? <p className="text-sm text-amber-300">This work order uses its product-specific verifier; the generic experiment checklist is not applicable.</p> : null}
        </div>
        <Link href="/evidence" className="mt-4 inline-flex items-center gap-1 text-xs text-blue-300 hover:text-blue-200">View evidence ledger <ArrowRight className="h-3 w-3" /></Link>
      </Card>
    </div>
  )
}

export default function InvestigationWorkspacePage() {
  const [targets, setTargets] = useState<TargetLite[]>([])
  const [targetId, setTargetId] = useState('')
  const [budget, setBudget] = useState(12)
  const [data, setData] = useState<HypothesisScheduleResponse | null>(null)
  const [contracts, setContracts] = useState<FamilyProofContracts | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([getTargets(), getFamilyProofContracts()]).then(([targetData, proofData]) => {
      const list = (targetData?.targets || targetData || []) as TargetLite[]
      setTargets(list)
      setContracts(proofData)
    }).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load investigation context'))
  }, [])

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const next = await scheduleHypotheses({ targetId: targetId || undefined, remainingRequests: budget, limit: 50 })
      setData(next)
      setSelectedId((current) => current && next.scheduled.some((x) => x.hypothesis_id === current) ? current : (next.scheduled[0]?.hypothesis_id || ''))
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed to load investigation leads') }
    finally { setLoading(false) }
  }, [targetId, budget])

  useEffect(() => { load().catch(() => undefined) }, [load])

  const selected = useMemo(() => data?.scheduled.find((x) => x.hypothesis_id === selectedId) || null, [data, selectedId])
  const visibleLeads = useMemo(() => data?.scheduled.slice(0, 12) || [], [data])

  const transition = useCallback(async (lead: ScheduledLead, to: string) => {
    const h = lead.hypothesis
    if (!h) return
    setBusy(true); setNotice(null)
    try {
      const result = await transitionHypothesis(h.id, { to, expected_version: h.version, reason: `investigation workspace: ${to}` })
      setNotice(`${familyLabel(h.family)} moved to ${statusLabel(result.to).toLowerCase()}.`)
      await load()
    } catch (e) { setNotice(e instanceof Error ? e.message : 'The update was rejected') }
    finally { setBusy(false) }
  }, [load])

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <header className="flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-blue-300"><Bot className="h-4 w-4" /> Research Agent</div>
          <h1 className="mt-1 text-3xl font-bold tracking-tight text-white">Investigation workspace</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-400">Prioritized security leads, bounded work orders, and clear proof requirements. Leads are not findings until live verification succeeds.</p>
        </div>
        <nav className="flex rounded-lg border border-gray-800 bg-gray-950 p-1 text-sm">
          <span className="rounded-md bg-gray-800 px-3 py-1.5 text-white">Leads</span>
          <Link href="/settings/research-agent/experiment" className="px-3 py-1.5 text-gray-400 hover:text-white">Experiment</Link>
          <Link href="/settings/research-agent" className="px-3 py-1.5 text-gray-400 hover:text-white">Episodes</Link>
        </nav>
      </header>

      <Card className="mt-5 p-4">
        <div className="grid gap-4 md:grid-cols-[minmax(260px,1fr)_180px_auto] md:items-end">
          <label className="text-xs font-medium text-gray-400">Target
            <select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200">
              <option value="">All registered targets</option>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.name ? `${t.name} — ` : ''}{t.url}</option>)}
            </select>
          </label>
          <label className="text-xs font-medium text-gray-400">Request budget
            <select value={budget} onChange={(e) => setBudget(Number(e.target.value))} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200">
              <option value={6}>Focused · 6</option><option value={12}>Balanced · 12</option><option value={24}>Extended · 24</option>
            </select>
          </label>
          <Button variant="secondary" onClick={() => load().catch(() => undefined)} disabled={loading || busy}><RefreshCw className="h-4 w-4" />Refresh</Button>
        </div>
      </Card>

      {notice ? <div className="mt-4 rounded-lg border border-blue-500/20 bg-blue-500/[0.07] px-4 py-3 text-sm text-blue-200">{notice}</div> : null}

      <div className="mt-5 grid gap-4 sm:grid-cols-3">
        <Card className="p-4"><div className="flex items-center gap-2 text-xs text-gray-500"><Target className="h-4 w-4 text-blue-300" />Ready to investigate</div><div className="mt-2 text-2xl font-semibold text-white">{data?.counts.scheduled ?? '—'}</div></Card>
        <Card className="p-4"><div className="flex items-center gap-2 text-xs text-gray-500"><Gauge className="h-4 w-4 text-amber-300" />Deferred by budget</div><div className="mt-2 text-2xl font-semibold text-white">{data?.counts.deferred ?? '—'}</div></Card>
        <Card className="p-4"><div className="flex items-center gap-2 text-xs text-gray-500"><ShieldCheck className="h-4 w-4 text-emerald-300" />Proof-backed findings</div><div className="mt-2 text-sm font-medium text-gray-300">Created only after verification</div></Card>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_430px]">
        <section>
          <div className="mb-3 flex items-end justify-between"><div><h2 className="font-semibold text-white">Recommended next work</h2><p className="mt-1 text-xs text-gray-500">Ranked by impact, boundary value, novelty, reachability, and cost.</p></div></div>
          {loading ? <div className="grid gap-3"><Skeleton className="h-28" /><Skeleton className="h-28" /></div>
            : error ? <ErrorState message={error} onRetry={() => load().catch(() => undefined)} />
            : !data?.scheduled.length ? <EmptyState message="No leads are ready" hint="Try a different target or increase the request budget. New leads also appear after discovery and application-graph analysis." />
            : <><div className="grid gap-3">{visibleLeads.map((lead) => <LeadCard key={lead.hypothesis_id} lead={lead} selected={selectedId === lead.hypothesis_id} onSelect={() => setSelectedId(lead.hypothesis_id)} />)}</div>{data.counts.scheduled > visibleLeads.length ? <p className="mt-3 text-center text-xs text-gray-600">Showing the top {visibleLeads.length} of {data.counts.scheduled}. Choose a target to narrow the worklist.</p> : null}</>}
        </section>
        <aside><LeadInspector lead={selected} contracts={contracts} busy={busy} onTransition={transition} /></aside>
      </div>
    </div>
  )
}
