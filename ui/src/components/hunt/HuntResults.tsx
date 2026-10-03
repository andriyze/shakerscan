'use client'

import { useEffect, useState } from 'react'
import Link from '@/components/WorkspaceLink'
import { Card, SeverityBadge } from '@/components/ui'
import { getFindings, type Finding } from '@/lib/api'
import type { HuntV2 } from '@/lib/huntV2'
import { huntIsLive } from '@/lib/huntRunModel.mjs'
import { isProvenFinding } from '@/lib/scanDetailPresentation.mjs'
import InvestigationReviewPanel from './InvestigationReviewPanel'

const FINDING_LIMIT = 100

function pathOf(url?: string | null): string {
  if (!url) return ''
  try { const parsed = new URL(url); return `${parsed.host}${parsed.pathname}` } catch { return url }
}

function HuntFindings({ huntId, version }: { huntId: string; version: number }) {
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    getFindings({ hunt_id: huntId, include_candidates: true, limit: FINDING_LIMIT })
      .then(result => { if (!cancelled) { setFindings(result.findings); setTotal(result.total ?? result.findings.length); setError(null) } })
      .catch(cause => { if (!cancelled) setError(cause instanceof Error ? cause.message : 'Could not load findings') })
    return () => { cancelled = true }
  }, [huntId, version])

  return <Card className="p-0">
    <div className="flex items-center justify-between gap-3 border-b border-gray-800 p-4">
      <h2 className="font-medium text-white">Findings</h2>
      {findings && <span className="text-xs text-gray-500">{total}</span>}
    </div>
    {error ? <p role="alert" className="p-4 text-sm text-amber-300">{error}</p>
      : !findings ? <p role="status" className="p-4 text-sm text-gray-400">Loading findings…</p>
      : findings.length === 0 ? <p className="p-4 text-sm text-gray-500">This Hunt recorded no findings. That is not evidence the target is clean.</p>
      : <ul className="divide-y divide-gray-800/70" aria-label="Hunt findings">
        {findings.map(finding => <li key={finding.id} className="relative flex items-center gap-3 px-4 py-2.5 hover:bg-gray-800/30">
          <SeverityBadge severity={finding.severity} />
          <span className="min-w-0 flex-1">
            <Link href={`/findings/${finding.id}`} className="block truncate text-sm text-gray-100 after:absolute after:inset-0 hover:text-blue-300">{finding.title}</Link>
            <span className="block truncate font-mono text-[11px] text-gray-500">{pathOf(finding.url)}</span>
          </span>
          <span className={`shrink-0 rounded-md px-2 py-0.5 text-xs ${isProvenFinding(finding) ? 'bg-emerald-500/10 text-emerald-300' : 'bg-gray-800 text-gray-400'}`}>
            {isProvenFinding(finding) ? 'verified' : 'unverified'}
          </span>
        </li>)}
      </ul>}
    {findings && total > findings.length && <p className="border-t border-gray-800 px-4 py-2.5 text-xs text-gray-500">Showing the first {findings.length} of {total}.</p>}
  </Card>
}

const DEBRIEF_FOLD = 700

function DebriefText({ text }: { text: string }) {
  const [open, setOpen] = useState(false)
  const long = text.length > DEBRIEF_FOLD
  return <div className="mt-2">
    <p className={`whitespace-pre-line text-sm leading-relaxed text-gray-200 ${long && !open ? 'line-clamp-[10]' : ''}`}><span className="sr-only">Planner debrief: </span>{text}</p>
    {long && <button type="button" onClick={() => setOpen(value => !value)} aria-expanded={open} className="mt-1 text-xs text-blue-300 hover:text-blue-200">
      {open ? 'Show less' : 'Show full debrief'}
    </button>}
  </div>
}

/** What the run concluded: the debrief, unfinished leads, findings and candidates. */
export function HuntResults({ hunt }: { hunt: HuntV2 }) {
  const summary = hunt.outcome_summary
  const debrief = hunt.final_debrief
  const live = huntIsLive(hunt)
  const version = (hunt.actions || []).length
  return <div className="space-y-5">
    <Card className="p-5">
      <h2 className="font-medium text-white">Debrief</h2>
      {debrief?.summary
        ? <DebriefText text={debrief.summary} />
        : <p className="mt-2 text-sm text-gray-500">{live || !hunt.completed_at ? 'No debrief yet. Your coding agent writes one when it finishes the Hunt.' : 'This Hunt ended without a planner debrief.'}</p>}
      {debrief?.next_actions && debrief.next_actions.length > 0 && <div className="mt-4">
        <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500">Unfinished leads</h3>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-gray-300">
          {debrief.next_actions.map(action => <li key={action}>{action}</li>)}
        </ul>
      </div>}
      {summary && <details className="mt-4 text-xs text-gray-400">
        <summary className="cursor-pointer text-gray-500 hover:text-gray-300">Factual run record</summary>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
          <span>{summary.successful_calls ?? summary.capability_calls} succeeded</span>
          <span>{summary.unsuccessful_calls ?? 0} unsuccessful</span>
          {(summary.indeterminate_calls ?? 0) > 0 && <span>{summary.indeterminate_calls} outcome unknown</span>}
          {(summary.partial_calls ?? 0) > 0 && <span>{summary.partial_calls} partial</span>}
          <span>{summary.executed_calls ?? summary.total_capability_calls} executed · {summary.total_capability_calls} attempted</span>
          <span>{hunt.outcome_summary?.observation_count} observations</span>
          <span>{hunt.outcome_summary?.finding_ids.length} findings</span>
          <span>{summary.candidate_ids.length} candidates</span>
          <span>{hunt.outcome_summary?.evidence_ids.length} evidence objects</span>
          <span>{Object.entries(summary.action_statuses).map(([status, count]) => `${count} ${status.replaceAll('_', ' ')}`).join(' · ')}</span>
        </div>
      </details>}
    </Card>

    <HuntFindings huntId={hunt.hunt_id} version={version} />

    {summary && summary.candidate_ids.length > 0 && <Card className="p-5">
      <h2 className="font-medium text-white">Candidate boundaries</h2>
      <p className="mt-1 text-xs text-gray-500">Evidence-backed leads the agent recorded. A candidate is not a verified finding.</p>
      <div className="mt-3 space-y-1 text-sm">
        {summary.candidate_ids.map((id) => (
          <Link key={id} href={`/ai-gate/boundary?hunt=${encodeURIComponent(hunt.hunt_id)}&candidate=${encodeURIComponent(id)}`} className="block break-all text-blue-300 hover:text-blue-200">
            Open candidate {id}
          </Link>
        ))}
      </div>
    </Card>}

    {hunt.queued_scan?.scan_id && (
      <Link href={`/scans/${hunt.queued_scan.scan_id}`} className="block rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-blue-200 hover:bg-blue-500/10">
        Open queued Scan {hunt.queued_scan.scan_id.slice(0, 8)} · {hunt.queued_scan.status}
      </Link>
    )}

    <InvestigationReviewPanel hideWhenEmpty />
  </div>
}
