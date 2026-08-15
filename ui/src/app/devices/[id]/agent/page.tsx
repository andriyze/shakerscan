'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { Bot, CircleStop, Terminal } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  cancelDeviceAgentSession,
  getDevice,
  getDeviceAgentSession,
  getDeviceCredentials,
  startDeviceAgentSession,
  type DeviceCredentialProfile,
  type DeviceAgentSession,
  type DeviceDetailResponse,
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
  const [runId, setRunId] = useState<string | null>(null)
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE)
  const [safetyProfile, setSafetyProfile] = useState<'observe_only' | 'safe_remote' | 'authenticated_active'>('safe_remote')
  const [sshCredentialId, setSshCredentialId] = useState('')
  const [webCredentialId, setWebCredentialId] = useState('')
  const [maxTurns, setMaxTurns] = useState('12')
  const [confirmed, setConfirmed] = useState(false)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const sessionRef = useRef<DeviceAgentSession | null>(null)
  sessionRef.current = session

  const loadDevice = useCallback(async () => {
    try {
      const [device, credentialData] = await Promise.all([getDevice(deviceId), getDeviceCredentials(deviceId)])
      setData(device); setCredentials(credentialData.profiles || []); setError(null)
    }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not load connected device') }
    finally { setLoading(false) }
  }, [deviceId])

  useEffect(() => { loadDevice() }, [loadDevice])
  useEffect(() => { setRunId(new URLSearchParams(window.location.search).get('run')) }, [])
  useEffect(() => {
    if (!runId) return
    let stopped = false
    const tick = () => getDeviceAgentSession(runId).then((value) => {
      if (stopped) return
      if (value.device_target_id !== deviceId) {
        setError('This investigation run belongs to a different connected device.')
        setSession(null)
        return
      }
      setError(null)
      setSession(value)
    }).catch((err) => {
      if (!stopped) setError(err instanceof Error ? err.message : 'Could not load AI device investigation')
    })
    tick()
    const timer = window.setInterval(() => {
      if (!TERMINAL.has(sessionRef.current?.status || '')) tick()
    }, 2500)
    return () => { stopped = true; window.clearInterval(timer) }
  }, [runId, deviceId])

  const example = useMemo(() => `investigate connected device ${data?.device.primary_locator || 'tv.lan'} with the AI device agent`, [data])

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
      })
      setSession(value)
      setRunId(value.id)
      toast.success('AI device investigation started — continue it from your coding agent')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not start AI device investigation'
      setError(message); toast.error(message)
    } finally { setStarting(false) }
  }

  const cancel = async () => {
    if (!runId || cancelling) return
    setCancelling(true)
    try { setSession(await cancelDeviceAgentSession(runId)); toast.success('AI device investigation cancelled') }
    catch (err) { toast.error(err instanceof Error ? err.message : 'Could not cancel investigation') }
    finally { setCancelling(false) }
  }

  if (loading) return <Skeleton className="h-96" />
  if (!data) return <ErrorState message={error || 'Could not load connected device'} onRetry={loadDevice} />

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader backHref={`/devices/${deviceId}`} backLabel={data.device.name} title="AI Device Investigation" description="Your coding agent chooses bounded device scans and reasons over normalized evidence while ShakerScan fixes scope, safety, budgets, and findings authority." icon={<Bot className="h-6 w-6" />} />

      <Card className="mb-6 border-violet-500/25 bg-violet-500/[0.05] p-4">
        <div className="flex items-start gap-3"><Terminal className="mt-0.5 h-5 w-5 text-violet-300" /><div><p className="text-sm font-medium text-violet-100">Run it from your coding agent</p><p className="mt-1 text-xs leading-5 text-gray-400">Ask in plain language from the ShakerScan runtime. The agent starts this session, submits each tool-planning turn, and the activity appears here.</p><code className="mt-2 inline-block rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-xs text-gray-200">{example}</code></div></div>
      </Card>

      {!session && <Card className="p-5">
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="Objective"><Textarea rows={5} value={objective} onChange={(event) => setObjective(event.target.value)} /></Field>
          <div className="space-y-4">
            <Field label="Safety profile" hint="The agent cannot change this after launch."><Select value={safetyProfile} onChange={(event) => { const value = event.target.value as typeof safetyProfile; setSafetyProfile(value); if (value !== 'authenticated_active') { setSshCredentialId(''); setWebCredentialId('') } }}><option value="observe_only">Observe only</option><option value="safe_remote">Safe remote</option><option value="authenticated_active">Authenticated active</option></Select></Field>
            {safetyProfile === 'authenticated_active' && <div className="grid gap-3 sm:grid-cols-2"><Field label="SSH credential"><Select value={sshCredentialId} onChange={(event) => setSshCredentialId(event.target.value)}><option value="">None</option>{credentials.filter((profile) => profile.auth_kind.startsWith('ssh_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</Select></Field><Field label="Web credential"><Select value={webCredentialId} onChange={(event) => setWebCredentialId(event.target.value)}><option value="">None</option>{credentials.filter((profile) => profile.auth_kind.startsWith('web_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</Select></Field><p className="sm:col-span-2 text-xs text-gray-500">The agent can select scans that use these profiles, but secret values never enter its transcript or evidence.</p></div>}
            <Field label="Maximum planner turns"><Input type="number" min="1" max="30" value={maxTurns} onChange={(event) => setMaxTurns(event.target.value)} /></Field>
            <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" /><span>I confirm I am authorized to let the AI direct bounded scans of this exact device.</span></label>
            <Button disabled={!confirmed} loading={starting} onClick={start}><Bot className="h-4 w-4" /> Start investigation</Button>
          </div>
        </div>
      </Card>}

      {session && <div className="space-y-6">
        <Card className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-4"><div><p className="text-xs uppercase tracking-wide text-gray-500">Status</p><p className="mt-1 text-lg font-semibold text-white">{session.status.replace(/_/g, ' ')}</p><p className="mt-1 text-sm text-gray-400">{session.objective}</p></div>{!TERMINAL.has(session.status) && <Button variant="danger" loading={cancelling} onClick={cancel}><CircleStop className="h-4 w-4" /> Cancel</Button>}</div>
          <div className="mt-5 grid gap-3 sm:grid-cols-4"><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Planner turns left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.turns_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Actions left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.actions_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Scans left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.scans_remaining}</p></div><div className="rounded bg-gray-950 p-3"><p className="text-xs text-gray-500">Fragility units left</p><p className="mt-1 text-xl font-semibold text-white">{session.budgets.fragility_remaining}</p></div></div>
          {session.capabilities.traffic_frozen && <p className="mt-4 rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-200">Device traffic is frozen because a health circuit breaker fired. Read-only evidence tools remain available.</p>}
          <p className="mt-4 text-xs text-gray-500">Target fixed · safety profile <span className="text-gray-300">{session.safety_profile.replace(/_/g, ' ')}</span> · AI leads are hypotheses; deterministic device scans remain authoritative.</p>
        </Card>

        {session.result && <Card className="p-5"><h2 className="font-semibold text-white">Investigation result</h2><p className="mt-2 text-sm leading-6 text-gray-300">{session.result.summary || 'No summary supplied.'}</p>{(session.result.leads || []).length > 0 && <div className="mt-4 space-y-3">{session.result.leads?.map((lead) => <div key={`${lead.title}-${lead.evidence_refs.join('-')}`} className="rounded border border-amber-500/20 bg-amber-500/5 p-3"><p className="font-medium text-amber-100">{lead.title}</p><p className="mt-1 text-sm text-gray-400">{lead.rationale}</p><p className="mt-2 font-mono text-xs text-gray-500">{lead.evidence_refs.join(', ')}</p></div>)}</div>}</Card>}

        <Card className="p-5"><h2 className="font-semibold text-white">Recent activity</h2><div className="mt-3 space-y-3">{session.events.length ? session.events.slice(-8).reverse().map((event, index) => <pre key={index} className="overflow-x-auto whitespace-pre-wrap rounded bg-gray-950 p-3 text-xs text-gray-400">{JSON.stringify(event, null, 2)}</pre>) : <p className="text-sm text-gray-500">Waiting for the coding agent’s first planner turn.</p>}</div></Card>
      </div>}

      {error && <p className="mt-4 text-sm text-red-300">{error}</p>}
      <p className="mt-6 text-xs text-gray-600">Run ID: {session?.id || 'not started'} · <Link href={`/devices/${deviceId}`} className="text-blue-400 hover:text-blue-300">Back to device</Link></p>
    </div>
  )
}
