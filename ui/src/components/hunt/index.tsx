'use client'

// Shared building blocks for the Hunt surface: one place for the
// "how hard" intensity profiles, the "how long" duration presets, run/episode
// status semantics, and the live activity trace. Kept self-contained so the hub,
// the run-detail page, and the Scans page read a run the same way without
// touching shared primitives other pages depend on.

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { Badge, Card } from '@/components/ui'
import type { Campaign, ResearchBudget, ResearchEpisode, ResearchEpisodeDetail } from '@/lib/api'

export type Intensity = 'analyze' | 'hunt' | 'relentless' | 'deep_hunt'

// How hard the hunter goes. Mirrors RESEARCH_LAUNCH_PROFILES on the server; the
// server remains the source of truth for the actual budgets and risk ceiling.
export const PROFILES: Record<Intensity, {
  name: string
  summary: string
  detail: string
  mode: 'read_only' | 'gated'
  maxSteps: number
  risk: 'read_only' | 'active' | 'credential'
  budget: ResearchBudget
  accent: string
  selected: string
}> = {
  analyze: {
    name: 'Analyze',
    summary: 'Look, don\'t touch',
    detail: 'Reviews coverage, findings, and gaps. Sends no active probes and needs no permission.',
    mode: 'read_only', maxSteps: 8, risk: 'read_only',
    budget: { steps: 8, actions: 7, active_actions: 0, requests: 0, seconds: 600, model_tokens: 75000 },
    accent: 'text-cyan-300', selected: 'border-cyan-500/50 bg-cyan-500/[0.07]',
  },
  hunt: {
    name: 'Hunt',
    summary: 'Standard hunt',
    detail: 'Runs bounded recon, focused tests, and deterministic retests. The everyday choice.',
    mode: 'gated', maxSteps: 15, risk: 'active',
    budget: { steps: 15, actions: 14, active_actions: 6, requests: 250, seconds: 1800, model_tokens: 150000 },
    accent: 'text-blue-300', selected: 'border-blue-500/60 bg-blue-500/[0.09]',
  },
  relentless: {
    name: 'Relentless',
    summary: 'Deeper, longer',
    detail: 'Full step, request, and time budgets per episode for harder-to-reach weaknesses.',
    mode: 'gated', maxSteps: 25, risk: 'active',
    budget: { steps: 25, actions: 24, active_actions: 10, requests: 500, seconds: 3600, model_tokens: 250000 },
    accent: 'text-orange-300', selected: 'border-orange-500/50 bg-orange-500/[0.07]',
  },
  deep_hunt: {
    name: 'Deep',
    summary: 'Multi-user workflows',
    detail: 'Designs app-specific control/test workflows across two logins to prove access-control, field, and business-logic flaws. Credentials never enter the model.',
    mode: 'gated', maxSteps: 25, risk: 'credential',
    budget: { steps: 25, actions: 24, active_actions: 12, requests: 500, seconds: 3600, model_tokens: 500000 },
    accent: 'text-fuchsia-300', selected: 'border-fuchsia-500/60 bg-fuchsia-500/[0.09]',
  },
}

export function targetLabel(target: { name?: string | null; url: string }): string {
  const known: Record<string, string> = {
    'http://host.docker.internal:3001': 'OWASP Juice Shop',
    'http://juice-shop:3000': 'OWASP Juice Shop',
    'http://host.docker.internal:8888': 'OWASP crAPI',
    'http://localhost:8888': 'OWASP crAPI',
    'https://honey.shakerscan.com': 'ShakerScan Honey',
  }
  return target.name || known[target.url] || hostFromUrl(target.url)
}

export function hostFromUrl(url: string): string {
  try { return new URL(url).host } catch { return url }
}

function shortDate(value?: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

// "3 minutes ago" style relative label; drives the heartbeat so "is it alive?"
// is answerable at a glance without reading a timestamp.
export function relativeTime(value?: string | null, now: number = Date.now()): string {
  if (!value) return ''
  const then = new Date(value).getTime()
  if (Number.isNaN(then)) return ''
  const secs = Math.max(0, Math.round((now - then) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.round(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}

// ---- Run (campaign) status: what the operator watches --------------------

export type RunState = 'running' | 'waiting' | 'paused' | 'completed' | 'cancelled' | 'failed' | 'idle'

export function runState(campaign: Pick<Campaign, 'status'>): RunState {
  const s = String(campaign.status || '').toLowerCase()
  if (s === 'active') return 'running'
  if (s === 'paused') return 'paused'
  if (s === 'completed') return 'completed'
  if (s === 'cancelled') return 'cancelled'
  if (s === 'failed') return 'failed'
  return 'idle'
}

const RUN_STATE_STYLE: Record<RunState, { label: string; className: string; pulse: boolean }> = {
  running: { label: 'Running', className: 'bg-blue-500/20 text-blue-300', pulse: true },
  waiting: { label: 'Waiting for agent', className: 'bg-violet-500/20 text-violet-300', pulse: false },
  paused: { label: 'Paused', className: 'bg-yellow-500/20 text-yellow-300', pulse: false },
  completed: { label: 'Done', className: 'bg-green-500/20 text-green-300', pulse: false },
  cancelled: { label: 'Stopped', className: 'bg-orange-500/20 text-orange-300', pulse: false },
  failed: { label: 'Failed', className: 'bg-red-500/20 text-red-300', pulse: false },
  idle: { label: 'Idle', className: 'bg-gray-500/20 text-gray-400', pulse: false },
}

export function RunStatusBadge({ state, className = '' }: { state: RunState; className?: string }) {
  const style = RUN_STATE_STYLE[state]
  return (
    <Badge className={`${style.className} ${className}`}>
      {style.pulse && <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" aria-hidden="true" />}
      {style.label}
    </Badge>
  )
}

// ---- Episode status: the moment-to-moment state inside a run --------------

function episodeStatusLabel(status: string, autopilot?: boolean): string {
  if (status === 'awaiting_planner' && autopilot === false) return 'Waiting for agent'
  return ({
    created: 'Starting', awaiting_planner: 'Thinking', dispatching: 'Running a test',
    awaiting_observation: 'Reading evidence', awaiting_input: 'Needs input',
    approval_required: 'Needs approval', budget_exhausted: 'Shift complete',
    completed: 'Done', cancelled: 'Stopped', failed: 'Failed', blocked: 'Blocked',
  } as Record<string, string>)[status] || status.replace(/_/g, ' ')
}

function episodeStatusClass(status: string): string {
  if (['completed', 'accepted'].includes(status)) return 'bg-green-500/20 text-green-300'
  if (['created', 'awaiting_planner', 'dispatching', 'awaiting_observation'].includes(status)) return 'bg-blue-500/20 text-blue-300'
  if (['awaiting_input', 'approval_required'].includes(status)) return 'bg-amber-500/20 text-amber-300'
  if (['cancelled', 'failed', 'blocked', 'rejected'].includes(status)) return 'bg-red-500/20 text-red-300'
  if (status === 'budget_exhausted') return 'bg-gray-500/20 text-gray-400'
  return 'bg-gray-800 text-gray-300'
}

// ---- Turning a raw planner decision into a plain-English sentence ---------

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

// The one job here: make "what the AI just did" legible. A move like an
// experiment.workflow against /orders/11 becomes "Testing GET /orders/11 for
// auth bypass" instead of a JSON blob.
function decisionSentence(action?: { command?: string; parameters?: Record<string, unknown> }): {
  verb: string
  detail: string
} {
  const command = action?.command || ''
  const p = (action?.parameters || {}) as Record<string, unknown>
  const route = str(p.route) || str(p.path) || (Array.isArray(p.steps) && p.steps.length
    ? str((p.steps[0] as Record<string, unknown>)?.path) : '')
  const method = str(p.method) || (Array.isArray(p.steps) && p.steps.length
    ? str((p.steps[0] as Record<string, unknown>)?.method) : '')
  const family = (str(p.proof_family) || str(p.check_family) || str(p.family)).replace(/_/g, ' ')
  const target = [method, route].filter(Boolean).join(' ').trim()
  const steps = Array.isArray(p.steps) ? p.steps as Record<string, unknown>[] : []
  const changedStep = steps.find((step) => str(step.role) === 'mutation') || steps[1]
  const changedTarget = changedStep
    ? [str(changedStep.method), str(changedStep.path)].filter(Boolean).join(' ').trim()
    : ''
  const workflowDetail = changedTarget
    ? `${changedTarget}${target && target !== changedTarget ? ` · baseline ${target}` : ''}`
    : (str(p.objective) || target)

  switch (command) {
    case 'experiment.workflow':
      return { verb: `Testing for ${family || 'a vulnerability'}`, detail: workflowDetail }
    case 'experiment.http_diff':
      return { verb: 'Comparing responses', detail: str(p.objective) || target }
    case 'asm.improve':
      return { verb: 'Probing attack surface', detail: family ? `${family} checks` : (target || 'next batch') }
    case 'asm.gaps':
      return { verb: 'Checking coverage gaps', detail: '' }
    case 'asm.activity':
      return { verb: 'Reviewing recent activity', detail: '' }
    case 'hypothesis.situation_report':
      return { verb: 'Reviewing the situation', detail: '' }
    case 'hypothesis.schedule':
      return { verb: 'Ranking what to test next', detail: '' }
    case 'scan.result':
      return { verb: 'Reading scan results', detail: '' }
    case 'scan.submit':
      return { verb: 'Starting a scan', detail: target }
    default:
      return { verb: (command || 'Planner decision').replace(/[._]/g, ' '), detail: target }
  }
}

// ---- The signature element: a live, readable trace of the AI at work ------

export function LiveActivity({ detail, now }: { detail: ResearchEpisodeDetail; now: number }) {
  const episode = detail.episode
  const stepLimit = episode.budget_limits.steps || 0
  const percent = stepLimit ? Math.min(100, Math.round((episode.step_count / stepLimit) * 100)) : 0
  const running = Boolean(episode.autopilot_enabled) && !episode.terminal
  const lastMove = detail.decisions[0]?.created_at || episode.updated_at

  const previous = (detail.current_observation?.observation_pack.previous_observation ?? {}) as Record<string, unknown>
  const experimentResult = (previous.experiment_result ?? {}) as Record<string, unknown>
  const familyProof = (experimentResult.family_proof ?? {}) as Record<string, unknown>
  const promotion = (experimentResult.promotion ?? {}) as Record<string, unknown>
  const provenFindingId = str(promotion.finding_id)

  return (
    <div className="grid gap-4">
      {/* Heartbeat — answers "is it alive?" without reading a timestamp */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950/50 px-4 py-3">
        <div className="flex items-center gap-3">
          <span className={`relative flex h-2.5 w-2.5 ${running ? '' : 'opacity-60'}`}>
            {running && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-75" />}
            <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${running ? 'bg-blue-400' : episode.terminal ? 'bg-gray-500' : 'bg-yellow-400'}`} />
          </span>
          <div>
            <div className="text-sm font-medium text-white">
              {running ? 'Working' : episodeStatusLabel(episode.status, episode.autopilot_enabled)}
            </div>
            <div className="text-xs text-gray-500">
              {lastMove ? `last move ${relativeTime(lastMove, now)}` : 'no moves yet'} · shift step {episode.step_count}/{stepLimit || '—'}
            </div>
          </div>
        </div>
        <div className="h-1.5 w-40 overflow-hidden rounded-full bg-gray-800">
          <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${percent}%` }} />
        </div>
      </div>

      {/* Attention banners */}
      {episode.autopilot_error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/[0.08] p-3 text-sm text-red-200">Autopilot error: {episode.autopilot_error}</div>
      ) : null}
      {episode.requested_input ? (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/[0.08] p-3 text-sm text-amber-200">{episode.requested_input}</div>
      ) : null}
      {detail.waiting_on?.length ? (
        <div className="rounded-lg border border-blue-500/25 bg-blue-500/[0.06] p-3 text-sm text-blue-100">
          Waiting on evidence:{' '}
          {detail.waiting_on.map((work, index) => (
            <span key={`${work.kind}-${work.id}`}>
              {index ? ', ' : ''}
              {work.ui_path
                ? <Link href={work.ui_path} className="font-medium underline underline-offset-2">{work.kind.replace(/_/g, ' ')} {work.id.slice(0, 8)}</Link>
                : `${work.kind} ${work.id.slice(0, 8)}`} ({work.status})
            </span>
          ))}
        </div>
      ) : null}

      {/* A freshly proven finding — the payoff */}
      {typeof familyProof.verdict === 'string' && familyProof.verdict === 'verified' ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.08] p-4">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
            <p className="text-xs font-semibold uppercase tracking-wider text-emerald-300">Verified finding</p>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <span className="text-base font-semibold text-white">Proven {str(familyProof.family).replace(/_/g, ' ') || 'weakness'}</span>
            {familyProof.reproduction_count === 2 ? <Badge className="bg-emerald-500/10 text-emerald-300">reproduced twice</Badge> : null}
            {familyProof.restoration_verified === true ? <Badge className="bg-blue-500/10 text-blue-300">state restored</Badge> : null}
          </div>
          {provenFindingId ? (
            <Link href={`/findings/${encodeURIComponent(provenFindingId)}`} className="mt-3 inline-flex items-center rounded border border-emerald-400/30 px-3 py-1.5 text-xs font-medium text-emerald-200 hover:bg-emerald-500/10">
              Open finding <ArrowRight className="ml-1 h-3.5 w-3.5" />
            </Link>
          ) : null}
        </div>
      ) : null}

      {/* The activity feed — each move as a readable sentence */}
      <section>
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">Activity</h3>
          <span className="text-xs text-gray-600">newest first</span>
        </div>
        <div className="mt-3 grid gap-2">
          {!detail.decisions.length ? (
            <div className="rounded-lg border border-dashed border-gray-800 p-5 text-center text-sm text-gray-500">
              Picking the first move…
            </div>
          ) : detail.decisions.slice(0, 12).map((decision) => {
            const sentence = decisionSentence(decision.action)
            const blocked = decision.validation_errors.length > 0
            return (
              <div key={decision.id} className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-gray-200">{sentence.verb}</span>
                  {sentence.detail ? <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[11px] text-gray-400">{sentence.detail}</code> : null}
                  <Badge className={`ml-auto ${episodeStatusClass(decision.status)}`}>{blocked ? 'blocked' : decision.status.replace(/_/g, ' ')}</Badge>
                </div>
                {(decision.reason || blocked) ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-300">
                      {blocked ? 'Why this was blocked' : 'Why this action'}
                    </summary>
                    {decision.reason ? <p className="mt-1.5 text-xs leading-5 text-gray-500">{decision.reason}</p> : null}
                    {blocked ? <p className="mt-1.5 text-xs text-red-300">Diagnostics: {decision.validation_errors.join(', ')}</p> : null}
                  </details>
                ) : null}
              </div>
            )
          })}
        </div>
      </section>

      {/* Technical detail stays out of the way */}
      <details className="rounded-lg border border-gray-800 bg-gray-950/30">
        <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-xs font-medium text-gray-500 hover:text-gray-300">
          <span>Budgets &amp; event log</span>
        </summary>
        <div className="grid gap-4 border-t border-gray-800 p-3">
          <div className="grid gap-3 sm:grid-cols-3">
            {(['steps', 'active_actions', 'requests'] as const).map((key) => {
              const remaining = episode.remaining_budget[key]
              const limit = episode.budget_limits[key]
              const pct = limit ? Math.max(0, Math.min(100, Math.round((remaining / limit) * 100))) : 0
              return (
                <div key={key}>
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-500">{key === 'requests' ? 'request units remaining' : `${key.replace(/_/g, ' ')} remaining`}</span>
                    <span className="tabular-nums text-gray-300">{remaining} of {limit}</span>
                  </div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded bg-gray-800"><div className="h-full bg-cyan-400" style={{ width: `${pct}%` }} /></div>
                </div>
              )
            })}
          </div>
          <div className="grid gap-2">
            {detail.events.slice(0, 12).map((event) => (
              <div key={event.id} className="flex items-start gap-2 text-xs">
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 flex-none text-gray-600" />
                <span className="text-gray-400">{event.summary}</span>
                <span className="ml-auto flex-none text-gray-700">{shortDate(event.created_at)}</span>
              </div>
            ))}
          </div>
        </div>
      </details>
    </div>
  )
}

// Episodes chained under one run share a campaign_id. Given the episode list for
// a run, pick the one the operator should be watching: the live episode if any,
// otherwise the most recent.
export function activeEpisode(episodes: ResearchEpisode[]): ResearchEpisode | undefined {
  const live = episodes.find((e) => !e.terminal)
  if (live) return live
  return [...episodes].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))[0]
}

// This is the count of active findings associated with the linked target work.
// It is not necessarily net-new evidence produced by the autonomous planner.
export function findingCount(campaign?: Pick<Campaign, 'deployment_impact'> | null): number {
  return campaign?.deployment_impact?.active_finding_count ?? 0
}

export function episodesStarted(campaign: Campaign): { started: number; max: number } {
  const meta = (campaign.metadata_json?.autonomous_research ?? {}) as Record<string, unknown>
  return {
    started: typeof meta.episodes_started === 'number' ? meta.episodes_started : 0,
    max: typeof meta.max_episodes === 'number' ? meta.max_episodes : 0,
  }
}

export { Card }
