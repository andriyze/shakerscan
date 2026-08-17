'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { Bot, CircleStop, ShieldAlert, Terminal } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  cancelDeviceAgentSession,
  confirmDeviceAgentShellPlan,
  getDevice,
  getDeviceCapabilities,
  getDeviceAgentSession,
  getDeviceCredentials,
  getDeviceRequestCollections,
  listDeviceAgentSessions,
  startDeviceAgentSession,
  type DeviceCredentialProfile,
  type DeviceRequestCollection,
  type DeviceAgentSession,
  type DeviceDetailResponse,
  type DeviceCapabilitiesResponse,
} from '@/lib/api'
import { Button, Card, ErrorState, Field, Input, PageHeader, Select, Skeleton, Textarea, useToast } from '@/components/ui'

const DEFAULT_OBJECTIVE = 'Investigate this device autonomously, choose the smallest useful scans, correlate service and web evidence, and identify the highest-value next actions.'
const TERMINAL = new Set(['completed', 'cancelled', 'failed'])

export default function DeviceAgentPage() {
  const params = useParams()
  const deviceId = params.id as string
  const toast = useToast()
  const [data, setData] = useState<DeviceDetailResponse | null>(null)
  const [session, setSession] = useState<DeviceAgentSession | null>(null)
  const [credentials, setCredentials] = useState<DeviceCredentialProfile[]>([])
  const [requestCollections, setRequestCollections] = useState<DeviceRequestCollection[]>([])
  const [capabilityPack, setCapabilityPack] = useState<DeviceCapabilitiesResponse | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE)
  const [safetyProfile, setSafetyProfile] = useState<'observe_only' | 'safe_remote' | 'authenticated_active'>('safe_remote')
  const [sshCredentialId, setSshCredentialId] = useState('')
  const [webCredentialId, setWebCredentialId] = useState('')
  const [requestCollectionIds, setRequestCollectionIds] = useState<string[]>([])
  const [confirmRequestReplay, setConfirmRequestReplay] = useState(false)
  const [allowStateChangingRequests, setAllowStateChangingRequests] = useState(false)
  const [allowUntrustedTlsCredentials, setAllowUntrustedTlsCredentials] = useState(false)
  const [maxTurns, setMaxTurns] = useState('12')
  const [confirmed, setConfirmed] = useState(false)
  const [loading, setLoading] = useState(true)
  const [restoringRun, setRestoringRun] = useState(true)
  const [starting, setStarting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [confirmingPlan, setConfirmingPlan] = useState<string | null>(null)
  const [confirmedPlans, setConfirmedPlans] = useState<Record<string, boolean>>({})
  const [error, setError] = useState<string | null>(null)
  const sessionRef = useRef<DeviceAgentSession | null>(null)
  sessionRef.current = session

  const loadDevice = useCallback(async () => {
    try {
      const [device, credentialData, capabilities, collections] = await Promise.all([getDevice(deviceId), getDeviceCredentials(deviceId), getDeviceCapabilities(deviceId), getDeviceRequestCollections(deviceId)])
      setData(device); setCredentials(credentialData.profiles || []); setCapabilityPack(capabilities); setRequestCollections(collections.collections || []); setError(null)
    }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not load connected device') }
    finally { setLoading(false) }
  }, [deviceId])

  useEffect(() => { loadDevice() }, [loadDevice])
  useEffect(() => {
    let stopped = false
    const restore = async () => {
      const requestedRunId = new URLSearchParams(window.location.search).get('run')
      if (requestedRunId) {
        if (!stopped) { setRunId(requestedRunId); setRestoringRun(false) }
        return
      }
      try {
        const recent = await listDeviceAgentSessions({ device_target_id: deviceId, limit: 20 })
        const active = recent.runs.find((run) => !TERMINAL.has(run.status))
        if (!stopped && active) {
          setRunId(active.id)
          window.history.replaceState(null, '', `${window.location.pathname}?run=${encodeURIComponent(active.id)}`)
        }
      } catch (err) {
        if (!stopped) setError(err instanceof Error ? err.message : 'Could not restore active Device Hunt')
      } finally {
        if (!stopped) setRestoringRun(false)
      }
    }
    restore()
    return () => { stopped = true }
  }, [deviceId])
  useEffect(() => {
    if (!runId) return
    let stopped = false
    const tick = () => {
      if (stopped) return
      getDeviceAgentSession(runId).then((value) => {
      if (stopped) return
      if (value.device_target_id !== deviceId) {
        stopped = true
        setError('This investigation run belongs to a different connected device.')
        setSession(null)
        setRunId(null)
        window.history.replaceState(null, '', window.location.pathname)
        return
      }
      setError(null)
      setSession(value)
    }).catch((err) => {
      if (!stopped) setError(err instanceof Error ? err.message : 'Could not load Device Hunt')
      })
    }
    tick()
    const timer = window.setInterval(() => {
      if (!TERMINAL.has(sessionRef.current?.status || '')) tick()
    }, 2500)
    return () => { stopped = true; window.clearInterval(timer) }
  }, [runId, deviceId])

  const example = useMemo(() => `Run Device Hunt on connected device ${data?.device.primary_locator || 'tv.lan'}`, [data])

  const start = async () => {
    if (!confirmed || starting) return
    setStarting(true)
    try {
      const value = await startDeviceAgentSession(deviceId, {
        objective: objective.trim() || DEFAULT_OBJECTIVE,
        safety_profile: safetyProfile,
        max_turns: Math.max(1, Math.min(30, Number.parseInt(maxTurns, 10) || 12)),
        confirm_authorized: true,
        ssh_credential_profile_id: sshCredentialId || undefined,
        web_credential_profile_id: webCredentialId || undefined,
        request_collection_ids: requestCollectionIds,
        confirm_request_replay: requestCollectionIds.length > 0 && confirmRequestReplay,
        allow_state_changing_requests: requestCollectionIds.length > 0 && allowStateChangingRequests,
        allow_untrusted_tls_credentials: safetyProfile === 'authenticated_active' && Boolean(webCredentialId || requestCollectionIds.length) && allowUntrustedTlsCredentials,
      })
      setSession(value)
      setRunId(value.id)
      window.history.replaceState(null, '', `${window.location.pathname}?run=${encodeURIComponent(value.id)}`)
      toast.success('Device Hunt started — continue it from your coding agent')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not start Device Hunt'
      setError(message); toast.error(message)
    } finally { setStarting(false) }
  }

  const cancel = async () => {
    if (!runId || cancelling) return
    setCancelling(true)
    try { setSession(await cancelDeviceAgentSession(runId)); toast.success('Device Hunt cancelled') }
    catch (err) { toast.error(err instanceof Error ? err.message : 'Could not cancel Device Hunt') }
    finally { setCancelling(false) }
  }

  const confirmShellPlan = async (planId: string) => {
    if (!runId || confirmingPlan || !confirmedPlans[planId]) return
    const plan = session?.shell_plans?.find((item) => item.plan_id === planId)
    if (!plan) return
    setConfirmingPlan(planId)
    try {
      setSession(await confirmDeviceAgentShellPlan(runId, plan))
      setConfirmedPlans((current) => ({ ...current, [planId]: false }))
      toast.success('Exact remote-device SSH commands confirmed and queued')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not confirm SSH shell plan')
    } finally { setConfirmingPlan(null) }
  }

  if (loading || restoringRun) return <Skeleton className="h-96" />
  if (!data) return <ErrorState message={error || 'Could not load connected device'} onRetry={loadDevice} />

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader backHref={`/devices/${deviceId}`} backLabel={data.device.name} title="Device Hunt" description="The agentic connected-device workflow: your coding agent chooses bounded device scans, reasons over normalized evidence, and may propose remote SSH commands. ShakerScan fixes scope and requires your exact confirmation before any proposed shell plan runs." icon={<Bot className="h-6 w-6" />} />

      <Card className="mb-6 border-violet-500/25 bg-violet-500/[0.05] p-4">
        <div className="flex items-start gap-3"><Terminal className="mt-0.5 h-5 w-5 text-violet-300" /><div><p className="text-sm font-medium text-violet-100">Run it from your coding agent</p><p className="mt-1 text-xs leading-5 text-gray-400">Ask in plain language from the ShakerScan runtime. The agent starts this session, submits each tool-planning turn, and the activity appears here.</p><code className="mt-2 inline-block rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-xs text-gray-200">{example}</code></div></div>
      </Card>

      {capabilityPack && <Card className="mb-6 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold text-white">Connected-device capability pack</h2><p className="mt-1 text-sm text-gray-500">The planner sees these playbooks. Registered tools run within their contracts; proposed SSH shell commands remain inert until you confirm the exact immutable plan.</p></div><div className="flex gap-2 text-xs"><span className="rounded bg-emerald-500/10 px-2 py-1 text-emerald-300">{capabilityPack.summary.ready || 0} ready</span><span className="rounded bg-blue-500/10 px-2 py-1 text-blue-300">{capabilityPack.summary.completed || 0} covered</span><span className="rounded bg-violet-500/10 px-2 py-1 text-violet-300">{capabilityPack.summary.approval_required || 0} approval</span><span className="rounded bg-amber-500/10 px-2 py-1 text-amber-300">{capabilityPack.summary.blocked || 0} blocked</span></div></div>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{capabilityPack.items.filter((item) => item.state !== 'not_applicable').map((item) => <div key={item.id} className="rounded border border-gray-800 bg-gray-950/60 p-3"><div className="flex items-start justify-between gap-2"><p className="text-sm font-medium text-gray-200">{item.title}</p><span className={`rounded px-1.5 py-0.5 text-[10px] ${item.state === 'completed' ? 'bg-blue-500/15 text-blue-300' : item.state === 'ready' ? 'bg-emerald-500/15 text-emerald-300' : item.state === 'blocked' ? 'bg-amber-500/15 text-amber-300' : 'bg-gray-800 text-gray-400'}`}>{item.state.replace(/_/g, ' ')}</span></div><p className="mt-1 text-xs text-gray-600">{item.implementation.replace(/_/g, ' ')} · {item.minimum_profile.replace(/_/g, ' ')}</p>{item.blockers.length > 0 && <p className="mt-1 text-xs text-amber-400/70">{item.blockers.join(', ').replace(/_/g, ' ')}</p>}</div>)}</div>
      </Card>}

      {!session && <Card className="p-5">
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="Objective"><Textarea rows={5} value={objective} onChange={(event) => setObjective(event.target.value)} /></Field>
          <div className="space-y-4">
            <Field label="Safety profile" hint="The agent cannot change this after launch."><Select value={safetyProfile} onChange={(event) => { const value = event.target.value as typeof safetyProfile; setSafetyProfile(value); if (value !== 'authenticated_active') { setSshCredentialId(''); setWebCredentialId(''); setAllowStateChangingRequests(false); setAllowUntrustedTlsCredentials(false) } }}><option value="observe_only">Observe only</option><option value="safe_remote">Safe remote</option><option value="authenticated_active">Authenticated active</option></Select></Field>
            {safetyProfile === 'authenticated_active' && <div className="grid gap-3 sm:grid-cols-2"><Field label="SSH credential"><Select value={sshCredentialId} onChange={(event) => setSshCredentialId(event.target.value)}><option value="">None</option>{credentials.filter((profile) => profile.auth_kind.startsWith('ssh_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</Select></Field><Field label="Web credential"><Select value={webCredentialId} onChange={(event) => { setWebCredentialId(event.target.value); if (!event.target.value && requestCollectionIds.length === 0) setAllowUntrustedTlsCredentials(false) }}><option value="">None</option>{credentials.filter((profile) => profile.auth_kind.startsWith('web_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</Select></Field><p className="sm:col-span-2 text-xs text-gray-500">The agent can select scans using these profiles and propose commands for a confirmed SSH service. Secret values never enter its transcript. Every shell proposal requires a separate exact-command confirmation below.</p></div>}
            {safetyProfile === 'authenticated_active' && <label className="flex items-start gap-3 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-100"><input type="checkbox" checked={allowUntrustedTlsCredentials} disabled={!webCredentialId && requestCollectionIds.length === 0} onChange={(event) => setAllowUntrustedTlsCredentials(event.target.checked)} className="mt-1" /><span><strong className="block">Permit credentials over unverified device HTTPS</strong>This authority is fixed for Device Hunt. The AI cannot enable it; without it, secret-bearing requests are withheld on self-signed or otherwise untrusted TLS.</span></label>}
            {requestCollections.length > 0 && <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4"><p className="text-sm font-medium text-orange-100">Bind imported API requests</p><p className="mt-1 text-xs text-gray-400">Device Hunt can inspect the redacted inventory and decide when request-aware scans are useful. It never sees tokens, cookies, body values, or environment values.</p><div className="mt-3 space-y-2">{requestCollections.map((collection) => <label key={collection.id} className="flex items-start gap-3 rounded border border-gray-800 bg-gray-950/60 p-3 text-sm text-gray-300"><input type="checkbox" checked={requestCollectionIds.includes(collection.id)} onChange={(event) => { const ids = event.target.checked ? [...requestCollectionIds, collection.id] : requestCollectionIds.filter((id) => id !== collection.id); setRequestCollectionIds(ids); if (!ids.length) { setConfirmRequestReplay(false); setAllowStateChangingRequests(false); if (!webCredentialId) setAllowUntrustedTlsCredentials(false) } }} className="mt-1" /><span><strong className="block text-white">{collection.name}</strong>{collection.summary.request_count} requests · {collection.summary.state_changing_request_count} state-changing</span></label>)}</div>{requestCollectionIds.length > 0 && <div className="mt-3 space-y-2"><label className="flex items-start gap-3 text-sm text-amber-100"><input type="checkbox" checked={confirmRequestReplay} onChange={(event) => setConfirmRequestReplay(event.target.checked)} className="mt-1" /><span>I authorize Device Hunt to queue scans that replay safe requests from these collections against this device.</span></label><label className={`flex items-start gap-3 text-sm ${safetyProfile === 'authenticated_active' ? 'text-red-200' : 'text-gray-600'}`}><input type="checkbox" disabled={safetyProfile !== 'authenticated_active'} checked={allowStateChangingRequests} onChange={(event) => setAllowStateChangingRequests(event.target.checked)} className="mt-1" /><span><strong className="block">Permit exact POST, PUT, PATCH, and DELETE replay</strong>This authority is fixed for the session. The AI can use it but cannot enable or expand it.</span></label></div>}</div>}
            <Field label="Maximum planner turns"><Input type="number" min="1" max="30" value={maxTurns} onChange={(event) => setMaxTurns(event.target.value)} /></Field>
            <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" /><span>I confirm I am authorized to let the AI direct bounded scans of this exact device.</span></label>
            <Button disabled={!confirmed || (requestCollectionIds.length > 0 && !confirmRequestReplay)} loading={starting} onClick={start}><Bot className="h-4 w-4" /> Start Device Hunt</Button>
          </div>
        </div>
      </Card>}

      {session && <div className="space-y-6">
        <Card className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-4"><div><p className="text-xs uppercase tracking-wide text-gray-500">Status</p><p className="mt-1 text-lg font-semibold text-white">{session.status.replace(/_/g, ' ')}</p><p className="mt-1 text-sm text-gray-400">{session.objective}</p></div>{!TERMINAL.has(session.status) && <Button variant="danger" loading={cancelling} onClick={cancel}><CircleStop className="h-4 w-4" /> Cancel</Button>}</div>
          <div className="mt-5 grid gap-3 sm:grid-cols-4"><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Planner turns left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.turns_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Actions left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.actions_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Scans left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.scans_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Fragility units left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.fragility_remaining}</p></div></div>
          {session.capabilities.traffic_frozen && <p className="mt-4 rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-200">Device traffic is frozen because a health circuit breaker fired. Read-only evidence tools remain available.</p>}
          <p className="mt-4 text-xs text-gray-500">Target fixed · safety profile <span className="text-gray-300">{session.safety_profile.replace(/_/g, ' ')}</span> · imported collections <span className="text-gray-300">{session.capabilities.request_collections_bound || 0}</span>{session.capabilities.state_changing_requests_authorized ? ' · state-changing replay explicitly authorized' : ''} · AI leads are hypotheses; deterministic device scans remain authoritative.</p>
        </Card>

        {(session.shell_plans || []).length > 0 && <Card className="border-amber-500/25 p-5">
          <div className="flex items-start gap-3"><ShieldAlert className="mt-0.5 h-5 w-5 text-amber-300" /><div><h2 className="font-semibold text-white">Remote-device SSH shell plans</h2><p className="mt-1 text-sm text-gray-500">These commands target the registered device only. A proposal does nothing until you review and confirm that exact digest.</p></div></div>
          <div className="mt-4 space-y-4">{session.shell_plans.slice().reverse().map((plan) => <div key={plan.plan_id} className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium text-gray-100">{plan.purpose}</p><p className="mt-1 text-xs text-gray-500">{plan.target_locator}:{plan.ssh_port} · timeout {plan.timeout_seconds}s per command</p></div><span className={`rounded px-2 py-1 text-xs ${plan.status === 'proposed' ? 'bg-amber-500/15 text-amber-300' : plan.status === 'queued' ? 'bg-blue-500/15 text-blue-300' : 'bg-gray-800 text-gray-400'}`}>{plan.status}</span></div>
            <p className="mt-3 text-sm text-amber-100/80">{plan.risk_summary}</p>
            {plan.detected_risks.length > 0 && <p className="mt-2 text-xs text-red-300">Detected risk markers: {plan.detected_risks.join(', ').replace(/-/g, ' ')}</p>}
            <div className="mt-3 space-y-2">{plan.commands.map((command, index) => <pre key={index} className="overflow-x-auto whitespace-pre-wrap rounded border border-gray-800 bg-black p-3 text-xs text-gray-200"><span className="select-none text-gray-600">{index + 1}. </span>{command}</pre>)}</div>
            <p className="mt-3 break-all font-mono text-[10px] text-gray-600">SHA-256 {plan.plan_digest} · host key {plan.expected_host_key_fingerprint}</p>
            {plan.scan_id && <Link href={`/devices/${deviceId}?scan=${plan.scan_id}`} className="mt-3 inline-block text-xs text-blue-400 hover:text-blue-300">Open queued device scan</Link>}
            {plan.status === 'proposed' && <div className="mt-4 rounded border border-red-500/25 bg-red-500/5 p-3"><label className="flex items-start gap-3 text-sm text-red-100"><input type="checkbox" checked={Boolean(confirmedPlans[plan.plan_id])} onChange={(event) => setConfirmedPlans((current) => ({ ...current, [plan.plan_id]: event.target.checked }))} className="mt-1" /><span>I reviewed every command above and explicitly authorize this immutable plan to run on <strong>{plan.target_locator}:{plan.ssh_port}</strong>. I understand it may modify, disrupt, or expose data from the remote device.</span></label><Button variant="danger" className="mt-3" disabled={!confirmedPlans[plan.plan_id]} loading={confirmingPlan === plan.plan_id} onClick={() => confirmShellPlan(plan.plan_id)}><Terminal className="h-4 w-4" /> Confirm and run {plan.confirmation_phrase}</Button></div>}
          </div>)}</div>
        </Card>}

        {session.result && <Card className="p-5"><h2 className="font-semibold text-white">Device Hunt result</h2><p className="mt-2 text-sm leading-6 text-gray-300">{session.result.summary || 'No summary supplied.'}</p>{(session.result.leads || []).length > 0 && <div className="mt-4 space-y-3">{session.result.leads?.map((lead) => <div key={`${lead.title}-${lead.evidence_refs.join('-')}`} className="rounded border border-amber-500/20 bg-amber-500/5 p-3"><p className="font-medium text-amber-100">{lead.title}</p><p className="mt-1 text-sm text-gray-400">{lead.rationale}</p><p className="mt-2 font-mono text-xs text-gray-500">{lead.evidence_refs.join(', ')}</p></div>)}</div>}</Card>}

        <Card className="p-5"><h2 className="font-semibold text-white">Recent activity</h2><div className="mt-3 space-y-3">{session.events.length ? session.events.slice(-8).reverse().map((event, index) => <pre key={index} className="overflow-x-auto whitespace-pre-wrap rounded bg-gray-950 p-3 text-xs text-gray-400">{JSON.stringify(event, null, 2)}</pre>) : <p className="text-sm text-gray-500">Waiting for the coding agent’s first planner turn.</p>}</div></Card>
      </div>}

      {error && <p className="mt-4 text-sm text-red-300">{error}</p>}
      <p className="mt-6 text-xs text-gray-600">Run ID: {session?.id || 'not started'} · <Link href={`/devices/${deviceId}`} className="text-blue-400 hover:text-blue-300">Back to device</Link></p>
    </div>
  )
}
