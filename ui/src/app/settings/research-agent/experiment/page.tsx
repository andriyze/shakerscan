'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle, ArrowRight, Braces, Check, ChevronDown, Clock3,
  FileCheck2, FlaskConical, Info, Plus, Route, ShieldCheck, Sparkles, Target, Trash2,
} from 'lucide-react'
import { executeArsenalCommand, getTargets, type ArsenalExecuteResult } from '@/lib/api'
import { Badge, Button, Card, ErrorState } from '@/components/ui'
import { isWebTarget } from '@/lib/targets'

interface TargetLite { id: string; url: string; name?: string | null; discovery_source?: string | null }
type StepRole = 'control' | 'mutation' | 'verify'
interface StepDraft {
  label: string
  role: StepRole
  method: string
  path: string
  query: string
  headers: string
  json_body: string
  compare_to: string
}

const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']
const ROLE_INFO: Record<StepRole, { label: string; description: string; tone: string }> = {
  control: { label: 'Baseline', description: 'Normal behavior to compare against', tone: 'bg-blue-500/15 text-blue-300' },
  mutation: { label: 'Test change', description: 'One deliberate input or workflow change', tone: 'bg-amber-500/15 text-amber-300' },
  verify: { label: 'Confirm result', description: 'Check whether the effect persisted', tone: 'bg-emerald-500/15 text-emerald-300' },
}

function blankStep(index: number, path = '/'): StepDraft {
  return {
    label: index === 0 ? 'baseline' : index === 1 ? 'test' : 'confirm',
    role: index === 0 ? 'control' : index === 1 ? 'mutation' : 'verify',
    method: 'GET', path, query: '', headers: '', json_body: '', compare_to: index === 0 ? '' : 'baseline',
  }
}

function parseKv(value: string, separator: string): Record<string, string> {
  const result: Record<string, string> = {}
  value.split(/\n/).forEach((line) => {
    const trimmed = line.trim(); if (!trimmed) return
    const index = trimmed.indexOf(separator)
    if (index > 0) result[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim()
  })
  return result
}

function buildStep(step: StepDraft): Record<string, unknown> {
  const result: Record<string, unknown> = { label: step.label, role: step.role, method: step.method, path: step.path }
  const query = parseKv(step.query, '='); if (Object.keys(query).length) result.query = query
  const headers = parseKv(step.headers, ':'); if (Object.keys(headers).length) result.headers = headers
  if (step.json_body.trim()) result.json_body = JSON.parse(step.json_body)
  if (step.compare_to) result.compare_to = step.compare_to
  return result
}

function templateSteps(kind: 'differential' | 'input' | 'workflow', path: string): StepDraft[] {
  if (kind === 'workflow') {
    return [blankStep(0, path), { ...blankStep(1, path), method: 'POST' }, blankStep(2, path)]
  }
  if (kind === 'input') {
    return [blankStep(0, path), { ...blankStep(1, path), method: 'POST', json_body: '{\n  "field": "test-value"\n}' }]
  }
  return [blankStep(0, path), { ...blankStep(1, path), query: 'test=value' }]
}

function StepEditor({ step, index, steps, update, remove }: {
  step: StepDraft; index: number; steps: StepDraft[]
  update: (patch: Partial<StepDraft>) => void; remove: () => void
}) {
  const role = ROLE_INFO[step.role]
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 bg-gray-950/40 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-full border border-gray-700 bg-gray-900 text-xs font-semibold text-gray-300">{index + 1}</div>
          <div>
            <div className="flex items-center gap-2"><span className="text-sm font-medium text-gray-200">{role.label}</span><Badge className={role.tone}>{step.role}</Badge></div>
            <p className="text-xs text-gray-600">{role.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select value={step.role} onChange={(e) => update({ role: e.target.value as StepRole })} aria-label={`Role for step ${index + 1}`} className="rounded-lg border border-gray-700 bg-gray-950 px-2 py-1.5 text-xs text-gray-300">
            {(Object.keys(ROLE_INFO) as StepRole[]).map((key) => <option key={key} value={key}>{ROLE_INFO[key].label}</option>)}
          </select>
          {steps.length > 2 ? <button type="button" onClick={remove} className="rounded p-1.5 text-gray-500 hover:bg-red-500/10 hover:text-red-300" aria-label={`Remove step ${index + 1}`}><Trash2 className="h-4 w-4" /></button> : null}
        </div>
      </div>

      <div className="grid gap-4 p-4">
        <div className="grid gap-3 sm:grid-cols-[130px_minmax(0,1fr)]">
          <label className="text-xs font-medium text-gray-400">Method
            <select value={step.method} onChange={(e) => update({ method: e.target.value })} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-semibold text-gray-200">
              {METHODS.map((method) => <option key={method}>{method}</option>)}
            </select>
          </label>
          <label className="text-xs font-medium text-gray-400">Relative path
            <div className="mt-1.5 flex items-center rounded-lg border border-gray-700 bg-gray-950 focus-within:border-blue-500">
              <Route className="ml-3 h-4 w-4 flex-none text-gray-600" />
              <input value={step.path} onChange={(e) => update({ path: e.target.value })} placeholder="/api/resource" className="min-w-0 flex-1 bg-transparent px-2 py-2 text-sm font-mono text-gray-200 outline-none" />
            </div>
          </label>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs font-medium text-gray-400">Step name
            <input value={step.label} onChange={(e) => update({ label: e.target.value.replace(/\s+/g, '_') })} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200" />
          </label>
          <label className="text-xs font-medium text-gray-400">Compare with
            <select value={step.compare_to} disabled={index === 0} onChange={(e) => update({ compare_to: e.target.value })} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 disabled:opacity-50">
              {index === 0 ? <option value="">First step is the baseline</option> : null}
              {steps.slice(0, index).map((candidate) => <option key={candidate.label} value={candidate.label}>{candidate.label || 'unnamed step'}</option>)}
            </select>
          </label>
        </div>

        <details className="group rounded-lg border border-gray-800 bg-gray-950/30">
          <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-sm text-gray-400 hover:text-gray-200">
            <span className="flex items-center gap-2"><Braces className="h-4 w-4" />Request details <span className="text-xs text-gray-600">query, headers, JSON body</span></span>
            <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" />
          </summary>
          <div className="grid gap-3 border-t border-gray-800 p-3 sm:grid-cols-2">
            <label className="text-xs text-gray-500">Query parameters <span className="text-gray-700">(key=value per line)</span>
              <textarea value={step.query} onChange={(e) => update({ query: e.target.value })} rows={3} placeholder={'page=1\nfilter=active'} className="mt-1.5 w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs font-mono text-gray-300" />
            </label>
            <label className="text-xs text-gray-500">Non-sensitive headers <span className="text-gray-700">(Name: value)</span>
              <textarea value={step.headers} onChange={(e) => update({ headers: e.target.value })} rows={3} placeholder="Accept: application/json" className="mt-1.5 w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs font-mono text-gray-300" />
            </label>
            <label className="text-xs text-gray-500 sm:col-span-2">JSON request body
              <textarea value={step.json_body} onChange={(e) => update({ json_body: e.target.value })} rows={4} placeholder={'{\n  "field": "value"\n}'} className="mt-1.5 w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs font-mono text-gray-300" />
            </label>
          </div>
        </details>
      </div>
    </Card>
  )
}

export default function ExperimentBuilderPage() {
  const [targets, setTargets] = useState<TargetLite[]>([])
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState('')
  const [expected, setExpected] = useState('')
  const [falsifier, setFalsifier] = useState('')
  const [timeout, setTimeoutValue] = useState(10)
  const [steps, setSteps] = useState<StepDraft[]>([blankStep(0), blankStep(1)])
  const [result, setResult] = useState<ArsenalExecuteResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const initialPath = params.get('path') || '/'
    setTargetId(params.get('target') || '')
    setObjective(params.get('objective') || '')
    setExpected(params.get('expected') || '')
    setFalsifier(params.get('falsifier') || '')
    if (initialPath !== '/') setSteps([blankStep(0, initialPath), blankStep(1, initialPath)])
    getTargets().then((data) => {
      const list = ((data?.targets || data || []) as TargetLite[]).filter(isWebTarget)
      setTargets(list)
      setTargetId((current) => current || list[0]?.id || '')
    }).catch(() => undefined)
  }, [])

  const issues = useMemo(() => {
    const list: string[] = []
    if (!targetId) list.push('Choose a registered target')
    if (!objective.trim()) list.push('Describe what you want to learn')
    if (!expected.trim()) list.push('Define the signal you expect')
    if (!falsifier.trim()) list.push('Define what would disprove the lead')
    const labels = new Set<string>()
    steps.forEach((step, index) => {
      if (!step.label.trim()) list.push(`Name step ${index + 1}`)
      else if (labels.has(step.label)) list.push(`Step name “${step.label}” is duplicated`)
      labels.add(step.label)
      if (!step.path.startsWith('/')) list.push(`Step ${index + 1} needs a relative path starting with /`)
      if (step.json_body.trim()) { try { JSON.parse(step.json_body) } catch { list.push(`Step ${index + 1} has invalid JSON`) } }
    })
    return list
  }, [targetId, objective, expected, falsifier, steps])

  const payload = useMemo(() => ({
    target_id: targetId, objective, expected_signal: expected, falsifier, timeout_seconds: timeout,
    steps: issues.some((x) => x.includes('invalid JSON')) ? [] : steps.map(buildStep),
  }), [targetId, objective, expected, falsifier, timeout, steps, issues])

  const updateStep = (index: number, patch: Partial<StepDraft>) => setSteps((current) => current.map((step, i) => i === index ? { ...step, ...patch } : step))

  const applyTemplate = (kind: 'differential' | 'input' | 'workflow') => {
    const path = steps[0]?.path && steps[0].path !== '/' ? steps[0].path : '/api/resource'
    setSteps(templateSteps(kind, path)); setResult(null)
  }

  const validate = useCallback(async () => {
    if (issues.length) { setError(issues[0]); return }
    setBusy(true); setError(null); setResult(null)
    try {
      setResult(await executeArsenalCommand({ command: 'experiment.http_diff', parameters: payload, execute: false, created_by: 'experiment_workbench' }))
    } catch (e) { setError(e instanceof Error ? e.message : 'Plan validation failed') }
    finally { setBusy(false) }
  }, [issues, payload])

  const selectedTarget = targets.find((target) => target.id === targetId)

  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <header className="flex flex-col gap-4 border-b border-gray-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <nav className="mb-2 inline-flex rounded-lg border border-gray-800 bg-gray-950 p-1 text-sm">
            <Link href="/settings/research-agent" className="px-3 py-1.5 text-gray-400 hover:text-white">Autonomous Hunt</Link>
            <Link href="/settings/research-agent/leads" className="px-3 py-1.5 text-gray-400 hover:text-white">Leads</Link>
            <span className="rounded-md bg-gray-800 px-3 py-1.5 text-white">Manual test</span>
          </nav>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">Prepare a bounded experiment</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-400">Define a baseline, change one thing, and compare the result. Validation checks the plan and records intent—it does not send requests.</p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/[0.06] px-3 py-2 text-xs text-emerald-200"><ShieldCheck className="h-4 w-4" />Same-origin · bounded · approval-gated</div>
      </header>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="grid gap-5">
          <Card className="p-5">
            <div className="mb-4 flex items-center gap-3"><div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-300">1</div><div><h2 className="font-semibold text-white">Target and decision rule</h2><p className="text-xs text-gray-500">Be explicit about what this experiment can prove or disprove.</p></div></div>
            <div className="grid gap-4">
              <label className="text-xs font-medium text-gray-400">Registered target
                <select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-gray-200">
                  {!targets.length ? <option value="">No registered targets</option> : null}
                  {targets.map((target) => <option key={target.id} value={target.id}>{target.name ? `${target.name} — ` : ''}{target.url}</option>)}
                </select>
              </label>
              <label className="text-xs font-medium text-gray-400">What are you trying to learn?
                <textarea value={objective} onChange={(e) => setObjective(e.target.value)} rows={2} placeholder="Can a second user read an object they do not own?" className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-gray-200 placeholder:text-gray-700" />
              </label>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-xs font-medium text-emerald-300">Evidence that supports the lead
                  <textarea value={expected} onChange={(e) => setExpected(e.target.value)} rows={3} placeholder="The test request returns another user's object while the control is denied." className="mt-1.5 w-full rounded-lg border border-emerald-500/20 bg-emerald-500/[0.04] px-3 py-2.5 text-sm text-gray-300 placeholder:text-gray-700" />
                </label>
                <label className="text-xs font-medium text-gray-400">Evidence that disproves the lead
                  <textarea value={falsifier} onChange={(e) => setFalsifier(e.target.value)} rows={3} placeholder="Both requests are denied or return only the current user's object." className="mt-1.5 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm text-gray-300 placeholder:text-gray-700" />
                </label>
              </div>
            </div>
          </Card>

          <section>
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div className="flex items-center gap-3"><div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-300">2</div><div><h2 className="font-semibold text-white">Request sequence</h2><p className="text-xs text-gray-500">Use a template or build a two-to-four step comparison.</p></div></div>
              <div className="flex flex-wrap gap-2">
                <Button variant="secondary" size="sm" onClick={() => applyTemplate('differential')}><Sparkles className="h-3.5 w-3.5" />Simple differential</Button>
                <Button variant="secondary" size="sm" onClick={() => applyTemplate('input')}>Input validation</Button>
                <Button variant="secondary" size="sm" onClick={() => applyTemplate('workflow')}>Before / after</Button>
              </div>
            </div>
            <div className="grid gap-3">{steps.map((step, index) => <StepEditor key={`${index}-${step.role}`} step={step} index={index} steps={steps} update={(patch) => updateStep(index, patch)} remove={() => setSteps((current) => current.filter((_, i) => i !== index))} />)}</div>
            {steps.length < 4 ? <Button variant="secondary" className="mt-3" onClick={() => setSteps((current) => [...current, blankStep(current.length, current.at(-1)?.path || '/')])}><Plus className="h-4 w-4" />Add confirmation step</Button> : null}
          </section>
        </div>

        <aside className="grid content-start gap-4 xl:sticky xl:top-5">
          <Card className="p-5">
            <div className="flex items-center gap-3"><div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-300">3</div><div><h2 className="font-semibold text-white">Review plan</h2><p className="text-xs text-gray-500">Nothing runs from this screen.</p></div></div>
            <div className="mt-5 grid gap-3 text-sm">
              <div className="flex min-w-0 items-start gap-2"><Target className="mt-0.5 h-4 w-4 flex-none text-gray-500" /><div className="min-w-0"><div className="text-xs text-gray-600">Target</div><div className="truncate text-gray-300" title={selectedTarget?.url}>{selectedTarget?.name || selectedTarget?.url || 'Not selected'}</div></div></div>
              <div className="flex items-start gap-2"><FlaskConical className="mt-0.5 h-4 w-4 text-gray-500" /><div><div className="text-xs text-gray-600">Sequence</div><div className="text-gray-300">{steps.length} steps · maximum 4 requests</div></div></div>
              <div className="flex items-start gap-2"><Clock3 className="mt-0.5 h-4 w-4 text-gray-500" /><div className="min-w-0 flex-1"><div className="flex justify-between text-xs text-gray-600"><span>Per-request timeout</span><span>{timeout}s</span></div><input type="range" min={1} max={15} value={timeout} onChange={(e) => setTimeoutValue(Number(e.target.value))} className="mt-2 w-full" /></div></div>
            </div>

            <div className="mt-5 border-t border-gray-800 pt-4">
              {issues.length ? <div className="grid gap-2">{issues.slice(0, 4).map((issue) => <div key={issue} className="flex items-start gap-2 text-xs text-amber-300"><AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-none" />{issue}</div>)}</div>
                : <div className="flex items-center gap-2 text-sm text-emerald-300"><Check className="h-4 w-4" />Ready to validate</div>}
              <Button onClick={validate} disabled={busy || issues.length > 0} className="mt-4 w-full"><FileCheck2 className="h-4 w-4" />Validate experiment plan</Button>
              <p className="mt-2 text-center text-[11px] leading-4 text-gray-600">Validation records a dry-run intent. Active execution requires a matching scope and approval receipt.</p>
            </div>
          </Card>

          {error ? <ErrorState message={error} /> : null}
          {result ? <Card className="border-blue-500/30 bg-blue-500/[0.05] p-5">
            <div className="flex items-center gap-2 text-blue-200"><FileCheck2 className="h-5 w-5" /><h2 className="font-semibold">Plan recorded</h2></div>
            <p className="mt-2 text-sm leading-6 text-gray-400">No requests were sent. The plan is ready for the separate scope and approval flow.</p>
            {result.execution_blocked_reason ? <div className="mt-3 rounded-lg bg-gray-950/60 p-3 text-xs text-gray-400"><span className="font-medium text-amber-300">Execution gate:</span> {result.execution_blocked_reason}</div> : null}
            <Link href="/settings/research-agent/leads" className="mt-4 inline-flex items-center gap-1 text-sm text-blue-300 hover:text-blue-200">Return to leads <ArrowRight className="h-4 w-4" /></Link>
          </Card> : null}

          <details className="group rounded-lg border border-gray-800 bg-gray-900">
            <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-xs text-gray-500 hover:text-gray-300"><span className="flex items-center gap-2"><Info className="h-4 w-4" />Technical payload</span><ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" /></summary>
            <pre className="max-h-80 overflow-auto border-t border-gray-800 p-4 text-[10px] text-gray-500">{JSON.stringify(payload, null, 2)}</pre>
          </details>
        </aside>
      </div>
    </div>
  )
}
