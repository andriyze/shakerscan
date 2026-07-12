'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { FlaskConical, Plus, Trash2, Play, ArrowLeft } from 'lucide-react'
import { getTargets, executeArsenalCommand, type ArsenalExecuteResult } from '@/lib/api'
import { Badge, Button, Card, ErrorState } from '@/components/ui'

interface TargetLite {
  id: string
  url: string
  name?: string | null
}

interface StepDraft {
  label: string
  role: 'control' | 'mutation' | 'verify'
  method: string
  path: string
  query: string
  headers: string
  json_body: string
  compare_to: string
}

const ROLES: StepDraft['role'][] = ['control', 'mutation', 'verify']
const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']

function blankStep(index: number): StepDraft {
  return {
    label: index === 0 ? 'control' : index === 1 ? 'mutation' : `step_${index + 1}`,
    role: index === 0 ? 'control' : 'mutation',
    method: 'GET',
    path: '/',
    query: '',
    headers: '',
    json_body: '',
    compare_to: index === 0 ? '' : 'control',
  }
}

function parseKv(text: string, sep: RegExp): Record<string, string> {
  const out: Record<string, string> = {}
  text.split(/\n/).forEach((line) => {
    const t = line.trim()
    if (!t) return
    const m = t.split(sep)
    if (m.length >= 2) out[m[0].trim()] = m.slice(1).join('').trim()
  })
  return out
}

function buildStep(s: StepDraft): Record<string, unknown> {
  const step: Record<string, unknown> = { label: s.label, role: s.role, method: s.method, path: s.path }
  const query = parseKv(s.query, /=/)
  if (Object.keys(query).length) step.query = query
  const headers = parseKv(s.headers, /:/)
  if (Object.keys(headers).length) step.headers = headers
  if (s.json_body.trim()) {
    try { step.json_body = JSON.parse(s.json_body) } catch { step.json_body = { __invalid_json: s.json_body } }
  }
  if (s.compare_to.trim()) step.compare_to = s.compare_to.trim()
  return step
}

export default function ExperimentBuilderPage() {
  const [targets, setTargets] = useState<TargetLite[]>([])
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState('')
  const [expected, setExpected] = useState('')
  const [falsifier, setFalsifier] = useState('')
  const [timeout, setTimeout] = useState(10)
  const [steps, setSteps] = useState<StepDraft[]>([blankStep(0), blankStep(1)])
  const [result, setResult] = useState<ArsenalExecuteResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    getTargets()
      .then((data) => {
        const list: TargetLite[] = (data?.targets || data || []) as TargetLite[]
        setTargets(list)
        if (list.length) setTargetId(list[0].id)
      })
      .catch(() => undefined)
  }, [])

  const payload = useMemo(() => ({
    target_id: targetId,
    objective,
    expected_signal: expected,
    falsifier,
    timeout_seconds: timeout,
    steps: steps.map(buildStep),
  }), [targetId, objective, expected, falsifier, timeout, steps])

  const updateStep = (i: number, patch: Partial<StepDraft>) =>
    setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)))

  const submit = useCallback(async () => {
    setBusy(true); setError(null); setResult(null)
    try {
      setResult(await executeArsenalCommand({
        command: 'experiment.http_diff',
        parameters: payload,
        execute: false, // dry-run: the server gates active execution (approval + flag)
        created_by: 'experiment_workbench',
      }))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Submission failed')
    } finally {
      setBusy(false)
    }
  }, [payload])

  const experiment = (result?.result as Record<string, unknown> | undefined)?.experiment as Record<string, unknown> | undefined
  const observations = (experiment?.observations as unknown[] | undefined) || []
  const comparisons = (experiment?.comparisons as unknown[] | undefined) || []

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      <div className="flex items-center justify-between gap-3 mb-1">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-6 w-6 text-emerald-300" />
          <h1 className="text-2xl font-bold text-white">Experiment Builder</h1>
        </div>
        <Link href="/settings/research-agent/leads" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1">
          <ArrowLeft className="h-4 w-4" /> Leads
        </Link>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        Build a bounded same-origin control/mutation/verify HTTP differential (2–4 steps) without raw
        JSON. Active execution is gated server-side (approval receipt + <span className="font-mono">confirm_authorized</span> +
        router flag); this submits a dry-run and shows the gate state.
      </p>

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <div className="grid gap-4">
          <Card className="p-4 grid gap-3">
            <label className="text-xs text-gray-400">
              Target
              <select value={targetId} onChange={(e) => setTargetId(e.target.value)}
                className="mt-1 w-full rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200">
                {targets.length === 0 ? <option value="">no targets — add one first</option> : null}
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name || t.url}</option>)}
              </select>
            </label>
            <div className="grid gap-2 sm:grid-cols-2">
              <input value={objective} onChange={(e) => setObjective(e.target.value)} placeholder="objective"
                className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200" />
              <input type="number" min={1} max={15} value={timeout} onChange={(e) => setTimeout(Number(e.target.value))}
                className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200" placeholder="timeout s" />
              <input value={expected} onChange={(e) => setExpected(e.target.value)} placeholder="expected signal"
                className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200" />
              <input value={falsifier} onChange={(e) => setFalsifier(e.target.value)} placeholder="falsifier"
                className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200" />
            </div>
          </Card>

          {steps.map((s, i) => (
            <Card key={i} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Badge className="bg-gray-800 text-gray-300">step {i + 1}</Badge>
                  <select value={s.role} onChange={(e) => updateStep(i, { role: e.target.value as StepDraft['role'] })}
                    className="rounded bg-gray-950 border border-gray-800 px-1.5 py-1 text-xs text-gray-200">
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                {steps.length > 2 ? (
                  <button onClick={() => setSteps((p) => p.filter((_, idx) => idx !== i))} className="text-gray-500 hover:text-red-300" aria-label="remove step">
                    <Trash2 className="h-4 w-4" />
                  </button>
                ) : null}
              </div>
              <div className="grid gap-2 sm:grid-cols-[110px_1fr]">
                <input value={s.label} onChange={(e) => updateStep(i, { label: e.target.value })} placeholder="label"
                  className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200 font-mono" />
                <div className="flex gap-2">
                  <select value={s.method} onChange={(e) => updateStep(i, { method: e.target.value })}
                    className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200 font-mono">
                    {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                  <input value={s.path} onChange={(e) => updateStep(i, { path: e.target.value })} placeholder="/relative/path"
                    className="flex-1 rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-sm text-gray-200 font-mono" />
                </div>
              </div>
              <div className="grid gap-2 sm:grid-cols-2 mt-2">
                <textarea value={s.query} onChange={(e) => updateStep(i, { query: e.target.value })} rows={2}
                  placeholder="query (key=value per line)" className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-xs text-gray-200 font-mono" />
                <textarea value={s.headers} onChange={(e) => updateStep(i, { headers: e.target.value })} rows={2}
                  placeholder="headers (Name: value per line)" className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-xs text-gray-200 font-mono" />
              </div>
              <div className="grid gap-2 sm:grid-cols-[1fr_140px] mt-2">
                <textarea value={s.json_body} onChange={(e) => updateStep(i, { json_body: e.target.value })} rows={2}
                  placeholder='json body (e.g. {"id":"${var}"})' className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-xs text-gray-200 font-mono" />
                <input value={s.compare_to} onChange={(e) => updateStep(i, { compare_to: e.target.value })} placeholder="compare_to label"
                  className="rounded bg-gray-950 border border-gray-800 px-2 py-1.5 text-xs text-gray-200 font-mono" />
              </div>
            </Card>
          ))}

          <div className="flex items-center gap-2">
            {steps.length < 4 ? (
              <Button variant="secondary" size="sm" onClick={() => setSteps((p) => [...p, blankStep(p.length)])}>
                <Plus className="h-4 w-4" /> Add step
              </Button>
            ) : null}
            <Button onClick={submit} disabled={busy || !targetId || steps.length < 2}>
              <Play className="h-4 w-4" /> Build &amp; submit (dry-run)
            </Button>
          </div>
        </div>

        <div className="grid gap-4">
          {error ? <ErrorState message={error} /> : null}
          {result ? (
            <Card className="p-4">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className={result.dispatched ? 'bg-green-500/15 text-green-300' : 'bg-amber-500/15 text-amber-300'}>
                  {result.dispatched ? 'dispatched' : result.dry_run ? 'dry-run' : 'not dispatched'}
                </Badge>
                {result.execution_blocked_reason ? (
                  <Badge className="bg-amber-500/15 text-amber-300" title="Active execution gate">
                    {result.execution_blocked_reason}
                  </Badge>
                ) : null}
              </div>
              {observations.length ? (
                <p className="mt-2 text-xs text-gray-400">{observations.length} observations · {comparisons.length} comparisons</p>
              ) : (
                <p className="mt-2 text-xs text-gray-500">
                  Gated: active experiments need an approval receipt + <span className="font-mono">confirm_authorized</span> +
                  the router flag. The contract validated and the intent was recorded.
                </p>
              )}
            </Card>
          ) : null}

          <Card className="p-4">
            <h2 className="text-xs font-semibold text-gray-400 mb-2">Constructed payload</h2>
            <pre className="text-[11px] text-gray-400 font-mono overflow-x-auto max-h-96">{JSON.stringify(payload, null, 2)}</pre>
          </Card>
        </div>
      </div>
    </div>
  )
}
