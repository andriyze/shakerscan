'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { BrainCircuit, RefreshCw, ShieldCheck, FlaskConical, ArrowLeft } from 'lucide-react'
import {
  scheduleHypotheses,
  transitionHypothesis,
  getFamilyProofContracts,
  evaluateFamilyProof,
  type HypothesisScheduleResponse,
  type ScheduledLead,
  type FamilyProofContracts,
  type FamilyProofVerdict,
} from '@/lib/api'
import { Badge, Button, Card, EmptyState, ErrorState, Skeleton } from '@/components/ui'

// Mirror of api/hypothesis_lifecycle.py legal edges — surfaces only valid next states.
const TRANSITIONS: Record<string, string[]> = {
  open: ['claimed', 'blocked', 'dead'],
  claimed: ['testing', 'open', 'blocked', 'dead'],
  testing: ['supported', 'refuted', 'blocked', 'exhausted', 'open'],
  supported: ['promoted', 'refuted', 'testing', 'blocked', 'exhausted'],
  blocked: ['open', 'dead', 'exhausted'],
  exhausted: ['open', 'dead'],
  refuted: [],
  promoted: [],
  dead: [],
}

const BREAKDOWN_POSITIVE = ['impact', 'boundary_value', 'novelty', 'evidence_strength', 'reachability']
const BREAKDOWN_NEGATIVE = ['request_cost', 'prior_failures', 'blocker_penalty']

function statusClass(status: string): string {
  if (status === 'promoted') return 'bg-green-500/15 text-green-300'
  if (['supported', 'testing', 'claimed'].includes(status)) return 'bg-blue-500/15 text-blue-300'
  if (['blocked', 'exhausted'].includes(status)) return 'bg-amber-500/15 text-amber-300'
  if (['refuted', 'dead'].includes(status)) return 'bg-red-500/15 text-red-300'
  return 'bg-gray-800 text-gray-300'
}

function verdictClass(verdict: string): string {
  if (verdict === 'verified') return 'bg-green-500/15 text-green-300'
  if (verdict === 'supported_unverified') return 'bg-blue-500/15 text-blue-300'
  if (verdict === 'inconclusive' || verdict === 'blocked') return 'bg-amber-500/15 text-amber-300'
  if (verdict === 'refuted') return 'bg-red-500/15 text-red-300'
  return 'bg-gray-800 text-gray-300'
}

function LeadCard({ lead, onTransition, busy }: {
  lead: ScheduledLead
  onTransition: (lead: ScheduledLead, to: string) => void
  busy: boolean
}) {
  const h = lead.hypothesis
  const status = String(h?.effective_status || h?.status || 'open')
  const nextStates = (TRANSITIONS[status] || []).filter((s) => s !== 'refuted')
  const b = lead.breakdown || {}
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm font-semibold text-white">{h?.family || 'lead'}</span>
            <Badge className={statusClass(status)}>{status}</Badge>
            {h?.severity_guess ? <Badge className="bg-gray-800 text-gray-300">{h.severity_guess}</Badge> : null}
          </div>
          {h?.title ? <p className="mt-1 text-sm text-gray-400 truncate">{h.title}</p> : null}
          <p className="mt-1 font-mono text-xs text-gray-600 truncate">{h?.dedupe_key}</p>
        </div>
        <div className="text-right flex-none">
          <div className="text-2xl font-mono font-semibold text-white tabular-nums">
            {lead.priority == null ? '—' : lead.priority.toFixed(2)}
          </div>
          <div className="text-xs text-gray-500">priority</div>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {BREAKDOWN_POSITIVE.filter((k) => k in b).map((k) => (
          <span key={k} className="font-mono text-[11px] text-emerald-300/90 bg-emerald-500/10 rounded px-1.5 py-0.5">
            +{b[k]} {k}
          </span>
        ))}
        {BREAKDOWN_NEGATIVE.filter((k) => k in b && b[k] > 0).map((k) => (
          <span key={k} className="font-mono text-[11px] text-rose-300/90 bg-rose-500/10 rounded px-1.5 py-0.5">
            −{b[k]} {k}
          </span>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {nextStates.map((to) => (
          <Button key={to} variant="secondary" size="sm" disabled={busy || !h} onClick={() => onTransition(lead, to)}>
            → {to}
          </Button>
        ))}
        <Badge className="bg-gray-800/60 text-gray-500" title="Refuting a lead requires a deterministic verification (the negative gate), not a button.">
          refuted: needs verification
        </Badge>
      </div>
    </Card>
  )
}

function FamilyProofPanel() {
  const [contracts, setContracts] = useState<FamilyProofContracts | null>(null)
  const [family, setFamily] = useState<string>('')
  const [evidence, setEvidence] = useState<Record<string, boolean>>({})
  const [reexecuted, setReexecuted] = useState(false)
  const [verdict, setVerdict] = useState<FamilyProofVerdict | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    getFamilyProofContracts()
      .then((c) => {
        setContracts(c)
        if (c.families.length) setFamily(c.families[0])
      })
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load contracts'))
  }, [])

  const contract = contracts?.contracts[family]
  const predicates = useMemo(() => {
    if (!contract) return [] as string[]
    return [...(contract.requires || []), ...(contract.refute_if || [])]
  }, [contract])

  useEffect(() => {
    setEvidence({})
    setVerdict(null)
  }, [family])

  const evaluate = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const payload = { family, evidence: { ...evidence, reexecuted_at_handoff: reexecuted } }
      setVerdict(await evaluateFamilyProof(payload))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Evaluation failed')
    } finally {
      setBusy(false)
    }
  }, [family, evidence, reexecuted])

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-blue-300" />
        <h2 className="text-sm font-semibold text-gray-200">Family proof handoff</h2>
      </div>
      <p className="mt-1 text-xs text-gray-500">
        Deterministic verifier: only <span className="font-mono">verified</span> is promotable. An LLM
        label or bare anomaly can never reach verified; unsupported families fail closed.
      </p>

      {error ? <p className="mt-2 text-xs text-red-300">{error}</p> : null}

      <div className="mt-3 grid gap-3">
        <label className="text-xs text-gray-400">
          Family
          <select
            value={family}
            onChange={(e) => setFamily(e.target.value)}
            className="mt-1 w-full rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200"
          >
            {(contracts?.families || []).map((f) => (
              <option key={f} value={f}>{f}{contract?.cwe && f === family ? ` · ${contract.cwe}` : ''}</option>
            ))}
          </select>
        </label>

        <div className="grid gap-1.5">
          <span className="text-xs text-gray-400">Observed evidence</span>
          {predicates.map((p) => {
            const refuting = (contract?.refute_if || []).includes(p)
            return (
              <label key={p} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!evidence[p]}
                  onChange={(e) => setEvidence((prev) => ({ ...prev, [p]: e.target.checked }))}
                />
                <span className={refuting ? 'text-rose-300 font-mono text-xs' : 'text-gray-300 font-mono text-xs'}>
                  {p}{refuting ? ' (refuting)' : ''}
                </span>
              </label>
            )
          })}
          <label className="flex items-center gap-2 text-sm mt-1">
            <input type="checkbox" checked={reexecuted} onChange={(e) => setReexecuted(e.target.checked)} />
            <span className="text-emerald-300 font-mono text-xs">reexecuted_at_handoff (required for verified)</span>
          </label>
        </div>

        <Button onClick={evaluate} disabled={busy || !family} className="w-fit">
          <FlaskConical className="h-4 w-4" /> Evaluate contract
        </Button>
      </div>

      {verdict ? (
        <div className="mt-4 border-t border-gray-800 pt-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge className={verdictClass(verdict.verdict)}>{verdict.verdict}</Badge>
            <Badge className={verdict.promotable ? 'bg-green-500/15 text-green-300' : 'bg-gray-800 text-gray-400'}>
              {verdict.promotable ? 'promotable' : 'not promotable'}
            </Badge>
            {verdict.cwe ? <Badge className="bg-gray-800 text-gray-300">{verdict.cwe}</Badge> : null}
            <Badge className="bg-gray-800 text-gray-300">{verdict.evidence_strength}</Badge>
          </div>
          <p className="mt-2 text-xs text-gray-500 font-mono">{verdict.reason}</p>
          {verdict.missing?.length ? (
            <p className="mt-1 text-xs text-amber-300 font-mono">missing: {verdict.missing.join(', ')}</p>
          ) : null}
          {verdict.evidence_instance_id ? (
            <p className="mt-1 text-xs text-gray-600 font-mono">evidence: {verdict.evidence_instance_id}</p>
          ) : null}
        </div>
      ) : null}
    </Card>
  )
}

export default function AdaptiveLeadsPage() {
  const [data, setData] = useState<HypothesisScheduleResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [targetId, setTargetId] = useState('')
  const [authAvailable, setAuthAvailable] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await scheduleHypotheses({
        targetId: targetId.trim() || undefined,
        authAvailable,
        limit: 50,
      }))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to schedule leads')
    } finally {
      setLoading(false)
    }
  }, [targetId, authAvailable])

  useEffect(() => { load().catch(() => undefined) }, [load])

  const doTransition = useCallback(async (lead: ScheduledLead, to: string) => {
    const h = lead.hypothesis
    if (!h) return
    setBusy(true)
    setNotice(null)
    try {
      const res = await transitionHypothesis(h.id, {
        to,
        expected_version: h.version,
        reason: `adaptive workbench: ${to}`,
      })
      setNotice(`${h.family}: ${res.from} → ${res.to}`)
      await load()
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Transition rejected')
    } finally {
      setBusy(false)
    }
  }, [load])

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <BrainCircuit className="h-6 w-6 text-blue-300" />
          <h1 className="text-2xl font-bold text-white">Adaptive Leads &amp; Proof</h1>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/settings/research-agent" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1">
            <ArrowLeft className="h-4 w-4" /> Episodes
          </Link>
          <Link href="/settings/research-agent/experiment" className="text-sm text-emerald-300 hover:text-emerald-200 inline-flex items-center gap-1">
            <FlaskConical className="h-4 w-4" /> Experiment
          </Link>
          <Button variant="secondary" size="sm" onClick={() => load().catch(() => undefined)} disabled={loading || busy}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        </div>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        Deterministic hypothesis scheduling (Wave 6), gated lifecycle transitions (Wave 4), and the
        family proof handoff (Wave 5). Read-only ranking; transitions and proof are gated server-side.
      </p>

      <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
        <div>
          <Card className="p-3 mb-4">
            <div className="flex flex-wrap items-end gap-3">
              <label className="text-xs text-gray-400">
                Target id (optional)
                <input
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  placeholder="all targets"
                  className="mt-1 block w-64 rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200"
                />
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={authAvailable} onChange={(e) => setAuthAvailable(e.target.checked)} />
                auth available
              </label>
              {data ? (
                <span className="text-xs text-gray-500 ml-auto">
                  {data.counts.scheduled} scheduled · {data.counts.deferred} deferred · {data.counts.excluded} excluded
                </span>
              ) : null}
            </div>
          </Card>

          {notice ? <p className="mb-3 text-xs text-blue-300 font-mono">{notice}</p> : null}

          {loading ? (
            <div className="grid gap-3"><Skeleton className="h-28" /><Skeleton className="h-28" /></div>
          ) : error ? (
            <ErrorState message={error} onRetry={() => load().catch(() => undefined)} />
          ) : !data || data.scheduled.length === 0 ? (
            <EmptyState message="No schedulable leads" hint="Hypotheses appear here once ingested; terminal/blocked leads are excluded." />
          ) : (
            <div className="grid gap-3">
              {data.scheduled.map((lead) => (
                <LeadCard key={lead.hypothesis_id} lead={lead} onTransition={doTransition} busy={busy} />
              ))}
            </div>
          )}
        </div>

        <FamilyProofPanel />
      </div>
    </div>
  )
}
