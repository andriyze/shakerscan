'use client'

import { Suspense, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { Compass, ShieldCheck } from 'lucide-react'
import {
  cancelHuntV2,
  getDevices,
  getTargets,
  startHuntV2,
  type DeviceTarget,
  type HuntV2,
  type Target,
} from '@/lib/api'
import { Button, Card, EmptyState, Field, Select, Textarea, useToast } from '@/components/ui'

type TargetChoice = { id: string; kind: 'web' | 'device'; label: string; detail: string }

function HuntContent() {
  const searchParams = useSearchParams()
  const toast = useToast()
  const [webTargets, setWebTargets] = useState<Target[]>([])
  const [devices, setDevices] = useState<DeviceTarget[]>([])
  const [targetId, setTargetId] = useState('')
  const [objective, setObjective] = useState('Find exploitable vulnerabilities and record evidence-backed candidates.')
  const [budget, setBudget] = useState<'fast' | 'balanced' | 'thorough'>('balanced')
  const [approvalReceipt, setApprovalReceipt] = useState('')
  const [requestCollectionIds, setRequestCollectionIds] = useState('')
  const [hunt, setHunt] = useState<HuntV2 | null>(null)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([getTargets(), getDevices({ limit: 200 }).catch(() => ({ devices: [] as DeviceTarget[] }))])
      .then(([targetRows, deviceRows]) => {
        if (cancelled) return
        const targets = Array.isArray(targetRows?.targets) ? targetRows.targets : Array.isArray(targetRows) ? targetRows : []
        setWebTargets(targets)
        setDevices(deviceRows.devices || [])
        const requested = searchParams.get('target') || searchParams.get('target_id')
        if (requested) setTargetId(requested)
        const requestedObjective = searchParams.get('objective')
        if (requestedObjective) setObjective(requestedObjective)
      })
      .catch((cause) => setError(cause instanceof Error ? cause.message : 'Failed to load targets'))
      .finally(() => setLoading(false))
    return () => { cancelled = true }
  }, [searchParams])

  const choices = useMemo<TargetChoice[]>(() => [
    ...webTargets.map((target) => ({ id: target.id, kind: 'web' as const, label: target.name || target.url, detail: target.url })),
    ...devices.filter((device) => device.is_active).map((device) => ({ id: device.id, kind: 'device' as const, label: device.name, detail: device.primary_locator })),
  ], [webTargets, devices])

  async function start() {
    if (!targetId) return
    setStarting(true)
    setError(null)
    try {
      const created = await startHuntV2({
        target_id: targetId,
        objective: objective.trim(),
        budget_profile: budget,
        approval_receipt_id: approvalReceipt.trim() || undefined,
        request_collection_ids: requestCollectionIds.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean),
      })
      setHunt(created)
      toast.success('Hunt started')
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Failed to start Hunt'
      setError(message)
      toast.error(message)
    } finally {
      setStarting(false)
    }
  }

  async function cancel() {
    if (!hunt) return
    try {
      setHunt(await cancelHuntV2(hunt.hunt_id))
      toast.success('Hunt cancelled')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to cancel Hunt')
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-violet-500/10 p-2 text-violet-300"><Compass className="h-6 w-6" /></div>
        <div>
          <h1 className="text-2xl font-semibold text-white">Hunt</h1>
          <p className="mt-1 text-sm text-gray-400">One evidence-driven investigation for web, API, network, and connected-device targets.</p>
        </div>
      </div>

      {!hunt ? (
        <Card className="p-5 space-y-5">
          {loading ? <p className="text-sm text-gray-400">Loading targets…</p> : choices.length === 0 ? (
            <EmptyState message="No targets available" hint="Add a web or connected-device target first." />
          ) : (
            <>
              <Field label="Target">
                <Select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
                  <option value="">Choose a target</option>
                  {choices.map((choice) => <option key={`${choice.kind}:${choice.id}`} value={choice.id}>{choice.kind === 'device' ? 'Device' : 'Web'} · {choice.label} · {choice.detail}</option>)}
                </Select>
              </Field>
              <Field label="Objective">
                <Textarea rows={4} value={objective} onChange={(event) => setObjective(event.target.value)} />
              </Field>
              <Field label="Budget">
                <Select value={budget} onChange={(event) => setBudget(event.target.value as typeof budget)}>
                  <option value="fast">Fast</option>
                  <option value="balanced">Balanced</option>
                  <option value="thorough">Thorough</option>
                </Select>
              </Field>
              <Field label="Approval receipt ID (optional)">
                <div>
                  <input value={approvalReceipt} onChange={(event) => setApprovalReceipt(event.target.value)} className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white" />
                  <p className="mt-1 text-xs text-gray-500">Without a valid target-bound receipt, Hunt exposes passive capabilities only.</p>
                </div>
              </Field>
              <Field label="Bound request collection IDs (optional)">
                <div>
                  <input value={requestCollectionIds} onChange={(event) => setRequestCollectionIds(event.target.value)} placeholder="UUIDs separated by commas" className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white" />
                  <p className="mt-1 text-xs text-gray-500">Collections are fixed at creation; the agent receives only their redacted index.</p>
                </div>
              </Field>
              {error && <p className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-300">{error}</p>}
              <div className="flex justify-end"><Button onClick={start} loading={starting} disabled={!targetId || !objective.trim()}>Start Hunt</Button></div>
            </>
          )}
        </Card>
      ) : (
        <div className="grid gap-5 lg:grid-cols-[1fr_1.4fr]">
          <Card className="p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <div><p className="text-xs uppercase tracking-wide text-gray-500">{hunt.target_kind} Hunt</p><h2 className="mt-1 font-medium text-white">{hunt.objective}</h2></div>
              <span className="rounded bg-blue-500/10 px-2 py-1 text-xs text-blue-300">{hunt.status}</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Budget</span><span className="text-white">{hunt.budget_profile}</span></div>
              <div className="rounded bg-gray-950 p-3"><span className="block text-xs text-gray-500">Capability calls</span><span className="text-white">{hunt.budget_used.agent_actions || 0} / {hunt.budget.max_capability_calls || 0}</span></div>
            </div>
            <div className="flex items-start gap-2 rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />The runtime binds every capability to this target. Candidates require evidence and cannot become verified findings directly.</div>
            {['active', 'awaiting_planner'].includes(hunt.status) && <Button variant="danger" onClick={cancel}>Cancel Hunt</Button>}
          </Card>
          <Card className="p-5">
            <h2 className="font-medium text-white">Available capabilities</h2>
            <p className="mt-1 text-xs text-gray-500">Your coding agent can query context and call these through the Hunt API.</p>
            <div className="mt-4 space-y-2">
              {hunt.capabilities.map((capability) => (
                <div key={capability.name} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                  <div className="flex items-center justify-between gap-3"><code className="text-sm text-blue-300">{capability.name}</code><span className="text-xs text-gray-500">{capability.risk_tier}</span></div>
                  <p className="mt-1 text-xs text-gray-400">{capability.description}</p>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

export default function HuntPage() {
  return <Suspense fallback={<p className="text-sm text-gray-400">Loading Hunt…</p>}><HuntContent /></Suspense>
}
