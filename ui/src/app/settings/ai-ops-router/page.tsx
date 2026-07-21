'use client'

import { useState } from 'react'
import { Wand2 } from 'lucide-react'
import { routeAiOps, type AIOpsRouteResponse } from '@/lib/api'
import { Badge, Button, Card, ConfirmDialog, Input, PageHeader, SectionCard, Textarea, useToast } from '@/components/ui'

function PlannedCall({ call }: { call: NonNullable<AIOpsRouteResponse['planned_api_call']> }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
      <div className="flex items-center gap-2">
        <span className="rounded bg-blue-600/20 px-1.5 py-0.5 text-xs font-semibold text-blue-300">{call.method}</span>
        <span className="font-mono text-sm text-white">{call.path}</span>
      </div>
      {call.body && (
        <pre className="mt-2 max-h-64 overflow-auto rounded border border-gray-800 bg-gray-900 p-2 text-xs text-gray-300">
          {JSON.stringify(call.body, null, 2)}
        </pre>
      )}
    </div>
  )
}

export default function AIOpsRouterPage() {
  const toast = useToast()
  const [prompt, setPrompt] = useState('')
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<AIOpsRouteResponse | null>(null)
  const [previewInput, setPreviewInput] = useState<{ prompt: string; target?: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Execution confirmations — all three required before the server will queue work.
  const [confirmAuthorized, setConfirmAuthorized] = useState(false)
  const [confirmHighRisk, setConfirmHighRisk] = useState(false)
  const [confirmExecute, setConfirmExecute] = useState(false)
  const [executing, setExecuting] = useState(false)

  const allConfirmed = confirmAuthorized && confirmHighRisk

  function invalidatePreview() {
    setResult(null)
    setPreviewInput(null)
    setConfirmAuthorized(false)
    setConfirmHighRisk(false)
    setConfirmExecute(false)
  }

  async function preview() {
    if (!prompt.trim()) { setError('Enter a natural-language request.'); return }
    setLoading(true); setError(null)
    try {
      const input = { prompt: prompt.trim(), target: target.trim() || undefined }
      const res = await routeAiOps(input)
      setResult(res)
      setPreviewInput(input)
      setConfirmAuthorized(false)
      setConfirmHighRisk(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to route request')
    } finally {
      setLoading(false)
    }
  }

  async function execute() {
    if (!previewInput) {
      toast.error('Preview the current request before executing it')
      return
    }
    setExecuting(true)
    try {
      const res = await routeAiOps({
        ...previewInput,
        execute: true,
        confirm_execution: true,
        confirm_authorized: confirmAuthorized,
        confirm_high_risk: confirmHighRisk,
      })
      setResult(res)
      if (res.execution_allowed && !res.dry_run) {
        toast.success('Operation executed')
      } else {
        toast.info(res.execution_blocked_reason || 'Execution not allowed — still a dry run')
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to execute operation')
    } finally {
      setExecuting(false)
      setConfirmExecute(false)
      setConfirmAuthorized(false)
      setConfirmHighRisk(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Operations Router"
        icon={<Wand2 className="h-5 w-5" />}
        description={
          <>
            Translate a natural-language DAST/ASM request into a safe, explicit API plan. Active or state-changing intents
            dry-run by default and require explicit confirmation plus the <code className="text-xs">AI_OPS_ROUTER_EXECUTE_ENABLED</code> server flag to run.
          </>
        }
      />

      <Card className="p-4 space-y-3">
        <div>
          <label htmlFor="ops-prompt" className="mb-1 block text-xs font-medium text-gray-400">Request</label>
          <Textarea
            id="ops-prompt"
            value={prompt}
            onChange={(e) => { setPrompt(e.target.value); invalidatePreview() }}
            rows={3}
            placeholder="e.g. Run full coverage on this target, or improve ASM coverage for the API"
          />
        </div>
        <div>
          <label htmlFor="ops-target" className="mb-1 block text-xs font-medium text-gray-400">Target (optional)</label>
          <Input
            id="ops-target"
            type="text"
            value={target}
            onChange={(e) => { setTarget(e.target.value); invalidatePreview() }}
            placeholder="https://example.com"
          />
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <Button onClick={preview} disabled={loading}>{loading ? 'Planning…' : 'Preview plan'}</Button>
      </Card>

      {result && (
        <SectionCard title="Planned operation">
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className="bg-purple-500/20 text-purple-300">{result.intent}</Badge>
              {result.safety_preset && <Badge className="bg-gray-800 text-gray-300">{result.safety_preset}</Badge>}
              <Badge className={result.dry_run ? 'bg-gray-500/20 text-gray-400' : 'bg-green-500/20 text-green-400'}>
                {result.dry_run ? 'dry run' : 'executed'}
              </Badge>
              {result.requires_confirmation && <Badge className="bg-amber-500/20 text-amber-300">confirmation required</Badge>}
              <Badge className={result.execution_allowed ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                execution {result.execution_allowed ? 'allowed' : 'blocked'}
              </Badge>
            </div>

            {result.explanation && <p className="text-sm text-gray-300">{result.explanation}</p>}
            {result.execution_blocked_reason && (
              <p className="text-sm text-amber-400">Blocked: {result.execution_blocked_reason}</p>
            )}

            {result.planned_api_call && <PlannedCall call={result.planned_api_call} />}

            {result.missing_inputs.length > 0 && (
              <div>
                <p className="mb-1 text-xs text-gray-500">Missing inputs</p>
                <div className="flex flex-wrap gap-1.5">
                  {result.missing_inputs.map((m) => <Badge key={m} className="bg-amber-500/15 text-amber-300">{m}</Badge>)}
                </div>
              </div>
            )}

            {result.non_goals && result.non_goals.length > 0 && (
              <div>
                <p className="mb-1 text-xs text-gray-500">Non-goals</p>
                <ul className="list-inside list-disc text-xs text-gray-400">
                  {result.non_goals.map((n) => <li key={n}>{n}</li>)}
                </ul>
              </div>
            )}

            {result.authorization_assumption && (
              <p className="text-xs text-gray-500">{result.authorization_assumption}</p>
            )}

            {result.requires_confirmation && (
              <div className="space-y-2 rounded-lg border border-gray-800 bg-gray-950 p-3">
                <p className="text-xs text-gray-400">This is an active or state-changing intent. Confirm before executing:</p>
                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={confirmAuthorized} onChange={(e) => setConfirmAuthorized(e.target.checked)} className="accent-blue-500" />
                  I am authorized to test this target
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={confirmHighRisk} onChange={(e) => setConfirmHighRisk(e.target.checked)} className="accent-blue-500" />
                  I understand the blast radius of this action
                </label>
                <Button variant="danger" size="sm" disabled={!allConfirmed} onClick={() => setConfirmExecute(true)}>
                  Execute operation
                </Button>
                {!result.execution_allowed && (
                  <p className="text-xs text-gray-500">Note: the server may still return a dry run unless AI_OPS_ROUTER_EXECUTE_ENABLED is set.</p>
                )}
              </div>
            )}
          </div>
        </SectionCard>
      )}

      <ConfirmDialog
        open={confirmExecute}
        title="Execute this operation?"
        message={previewInput
          ? `Queue the previewed operation for ${previewInput.target || 'the selected target'}. Editing the request invalidates this confirmation.`
          : 'Preview the request again before execution.'}
        confirmLabel="Execute"
        danger
        busy={executing}
        onConfirm={execute}
        onCancel={() => setConfirmExecute(false)}
      />
    </div>
  )
}
