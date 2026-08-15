'use client'

import Link from 'next/link'
import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { Bot, ChevronDown, ChevronUp, CircleHelp, Globe, KeyRound, MapPin, Pencil, Router, Wifi, WifiOff } from 'lucide-react'
import { changeDeviceLocator, createDeviceCredential, deactivateDeviceCredential, formatDate, getDevice, getDeviceCredentials, renameDevice, scanDevice, type DeviceCredentialProfile, type DeviceDetailResponse } from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Modal, PageHeader, ScanStatusBadge, Select, TableSkeleton, Textarea, useToast } from '@/components/ui'

const policyBadgeClass: Record<string, string> = {
  allow: 'bg-emerald-500/15 text-emerald-300',
  deny: 'bg-red-500/15 text-red-300',
  review: 'bg-amber-500/15 text-amber-300',
  require: 'bg-amber-500/15 text-amber-300',
}

export default function DeviceDetailPage() {
  const params = useParams()
  const deviceId = params.id as string
  const toast = useToast()
  const [data, setData] = useState<DeviceDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [scanOpen, setScanOpen] = useState(false)
  const [credentialOpen, setCredentialOpen] = useState(false)
  const [locatorOpen, setLocatorOpen] = useState(false)
  const [renameOpen, setRenameOpen] = useState(false)
  const [credentials, setCredentials] = useState<DeviceCredentialProfile[]>([])
  const [credentialSaving, setCredentialSaving] = useState(false)
  const [locatorSaving, setLocatorSaving] = useState(false)
  const [renameSaving, setRenameSaving] = useState(false)
  const [showInconclusive, setShowInconclusive] = useState(false)
  const [locatorForm, setLocatorForm] = useState({ locator: '', reason: '', confirm_same_device: false })
  const [renameName, setRenameName] = useState('')
  const [credentialForm, setCredentialForm] = useState({ name: '', auth_kind: 'ssh_password', username: '', secret: '', secondary_secret: '', login_path: '/login', port: '' })
  const [scanning, setScanning] = useState(false)
  const [scan, setScan] = useState({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', ssh_credential_profile_id: '', web_credential_profile_id: '', include_ssh_host_review: false, confirm_authorized: false })

  const load = useCallback(async () => {
    try {
      const [device, credentialData] = await Promise.all([getDevice(deviceId), getDeviceCredentials(deviceId)])
      setData(device); setCredentials(credentialData.profiles || []); setFailed(false)
    } catch { setFailed(true) } finally { setLoading(false) }
  }, [deviceId])

  useEffect(() => { load(); const timer = setInterval(load, 10_000); return () => clearInterval(timer) }, [load])

  async function queueScan() {
    setScanning(true)
    try {
      const queued = await scanDevice(deviceId, {
        profile: scan.profile as 'inventory' | 'posture' | 'thorough',
        safety_profile: scan.safety_profile as 'observe_only' | 'safe_remote' | 'authenticated_active',
        confirm_authorized: scan.confirm_authorized,
        include_web_dast: scan.include_web_dast,
        web_scan_type: scan.web_scan_type as 'quick' | 'standard' | 'deep',
        max_web_origins: 8,
        ssh_credential_profile_id: scan.ssh_credential_profile_id || undefined,
        web_credential_profile_id: scan.web_credential_profile_id || undefined,
        capability_ids: scan.include_ssh_host_review ? ['ssh-authenticated-host-review'] : undefined,
      })
      setScanOpen(false)
      toast.success('Device scan queued', { link: { href: `/scans/${queued.scan_id}`, label: 'View report' } })
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to queue scan')
    } finally { setScanning(false) }
  }

  async function saveCredential() {
    setCredentialSaving(true)
    try {
      await createDeviceCredential(deviceId, {
        name: credentialForm.name.trim(),
        auth_kind: credentialForm.auth_kind as DeviceCredentialProfile['auth_kind'],
        username: credentialForm.username.trim() || undefined,
        secret: credentialForm.secret,
        secondary_secret: credentialForm.secondary_secret || undefined,
        login_path: credentialForm.auth_kind === 'web_form' ? credentialForm.login_path : undefined,
        port: credentialForm.port ? Number(credentialForm.port) : undefined,
      })
      setCredentialOpen(false)
      setCredentialForm({ name: '', auth_kind: 'ssh_password', username: '', secret: '', secondary_secret: '', login_path: '/login', port: '' })
      toast.success('Encrypted device credential saved')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to save credential')
    } finally { setCredentialSaving(false) }
  }

  async function saveLocator() {
    setLocatorSaving(true)
    try {
      const result = await changeDeviceLocator(deviceId, {
        locator: locatorForm.locator.trim(),
        reason: locatorForm.reason.trim() || undefined,
        confirm_same_device: locatorForm.confirm_same_device,
      })
      setLocatorOpen(false)
      setLocatorForm({ locator: '', reason: '', confirm_same_device: false })
      toast.success(result.status === 'changed' ? 'Device address changed' : 'Device already uses this address')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to change device address')
    } finally { setLocatorSaving(false) }
  }

  async function saveName() {
    const name = renameName.trim()
    if (!name) return
    setRenameSaving(true)
    try {
      await renameDevice(deviceId, name)
      setRenameOpen(false)
      toast.success('Device renamed')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to rename device')
    } finally { setRenameSaving(false) }
  }

  if (loading) return <div className="mx-auto max-w-7xl"><TableSkeleton rows={6} /></div>
  if (failed || !data) return <div className="mx-auto max-w-7xl"><ErrorState message="Could not load connected device" onRetry={load} /></div>
  const { device, interfaces, services, scans, locator_history: locatorHistory } = data
  const observations = data.inconclusive_observations || []
  const observationTotal = data.inconclusive_observations_total ?? observations.length
  const reachability = data.reachability || device.last_reachability
  const reachabilityTone = reachability?.status === 'online'
    ? 'border-emerald-500/25 bg-emerald-500/5 text-emerald-100'
    : reachability?.status === 'unreachable'
      ? 'border-red-500/25 bg-red-500/5 text-red-100'
      : 'border-amber-500/25 bg-amber-500/5 text-amber-100'
  const ReachabilityIcon = reachability?.status === 'online' ? Wifi : reachability?.status === 'unreachable' ? WifiOff : CircleHelp

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader backHref="/devices" backLabel="Connected devices" title={device.name} description={device.primary_locator} icon={<Router className="h-6 w-6" />} actions={<><Button variant="secondary" onClick={() => { setRenameName(device.name); setRenameOpen(true) }}><Pencil className="h-4 w-4" /> Rename</Button><Button variant="secondary" onClick={() => { setLocatorForm({ locator: device.primary_locator, reason: '', confirm_same_device: false }); setLocatorOpen(true) }}><MapPin className="h-4 w-4" /> Change address</Button><Link href={`/devices/${device.id}/agent`} className="inline-flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-sm text-violet-200 hover:bg-violet-500/20"><Bot className="h-4 w-4" /> AI investigation</Link><Link href={`/findings?source_type=device&device_target_id=${device.id}`} className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 hover:bg-gray-700">View findings</Link><Button onClick={() => { setScan({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', ssh_credential_profile_id: '', web_credential_profile_id: '', include_ssh_host_review: false, confirm_authorized: false }); setScanOpen(true) }}>Scan device</Button></>} />

      <Card className={`mb-6 border p-4 ${reachabilityTone}`}>
        <div className="flex items-start gap-3"><ReachabilityIcon className="mt-0.5 h-5 w-5 shrink-0" /><div><p className="font-medium">{reachability ? `Device ${reachability.status === 'online' ? 'online' : reachability.status}` : 'Device reachability not checked'}</p><p className="mt-1 text-sm opacity-75">{reachability?.reason || 'Run a device scan to require a positive network response before port and policy checks begin.'}</p>{reachability?.status === 'online' && <p className="mt-2 text-xs opacity-70">Network accessible · {reachability.service_accessible === true ? 'at least one service responded' : reachability.service_accessible === false ? 'no listening TCP service found with complete visibility' : 'service accessibility still being assessed'} · {reachability.confidence} confidence</p>}</div></div>
      </Card>

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {[
          ['Class', device.device_class], ['Manufacturer', device.manufacturer || 'Unknown'], ['Model', device.model || 'Unknown'],
          ['Policy', device.policy_name || 'Default'], ['Posture', device.last_grade ? `${device.last_grade} · ${device.last_score ?? '—'}` : 'Not scanned'],
        ].map(([label, value]) => <Card key={label} className="p-3"><p className="text-xs text-gray-500">{label}</p><p className="mt-1 truncate font-medium text-white">{value}</p></Card>)}
      </div>

      <section className="mb-6">
        <h2 className="mb-3 text-lg font-semibold text-white">Observed services</h2>
        {services.length === 0 ? <EmptyState message="No service inventory yet" hint="Run a device scan to inventory listening TCP and UDP services." /> : (
          <div className="overflow-hidden rounded-lg border border-gray-800"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Port</th><th className="px-4 py-3">Service</th><th className="px-4 py-3">Product</th><th className="px-4 py-3">Policy</th><th className="px-4 py-3">Web interface</th><th className="px-4 py-3">Last seen</th></tr></thead><tbody className="divide-y divide-gray-800 bg-gray-950/50">{services.map((service) => (
            <tr key={service.id}><td className="px-4 py-3 font-mono text-gray-200">{service.port}/{service.transport}</td><td className="px-4 py-3 text-white">{service.service_name}</td><td className="px-4 py-3 text-gray-400">{[service.product, service.version].filter(Boolean).join(' ') || '—'}</td><td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs ${policyBadgeClass[service.policy_disposition || ''] || 'bg-gray-700 text-gray-300'}`}>{service.policy_disposition || 'unreviewed'}</span></td><td className="px-4 py-3">{service.web_origin ? <a href={service.web_origin} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-blue-300 hover:text-blue-200"><Globe className="h-3.5 w-3.5" /> {service.web_origin}</a> : <span className="text-gray-600">—</span>}</td><td className="px-4 py-3 text-xs text-gray-500">{formatDate(service.last_seen_at)}</td></tr>
          ))}</tbody></table></div></div>
        )}
      </section>

      {observations.length > 0 && (
        <section className="mb-6">
          <h2 className="mb-1 text-lg font-semibold text-white">Unconfirmed port probes</h2>
          <p className="mb-3 text-sm text-gray-500">The latest scan received no response from these probes. They are not confirmed open, are not listening services, and do not affect policy or score.</p>
          <Card className="overflow-hidden p-0">
            <button type="button" onClick={() => setShowInconclusive(!showInconclusive)} className="flex w-full items-center justify-between gap-4 p-4 text-left hover:bg-gray-900/70" aria-expanded={showInconclusive}>
              <span><strong className="block text-sm text-white">{observationTotal} no-response probe{observationTotal === 1 ? '' : 's'}</strong><span className="text-xs text-gray-500">Not confirmed open · details hidden by default</span></span>
              {showInconclusive ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
            </button>
            {showInconclusive && <div className="divide-y divide-amber-500/10 border-t border-gray-800 bg-amber-950/10">
              {observations.map((observation) => (
                <div key={observation.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm">
                  <span className="font-mono text-gray-200">{observation.port}/{observation.transport}</span>
                  <span className="text-gray-400">Expected protocol: {observation.service_name || 'unknown'}</span>
                  <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">No response</span>
                  <span className="text-xs font-medium text-amber-200">Not confirmed open</span>
                </div>
              ))}
            </div>}
          </Card>
        </section>
      )}

      <section className="mb-6">
        <div className="mb-3 flex items-center justify-between"><div><h2 className="text-lg font-semibold text-white">Authentication profiles</h2><p className="text-sm text-gray-500">Encrypted, device-bound credentials are resolved only inside the device worker. The AI planner never sees secret values.</p></div><Button size="sm" variant="secondary" onClick={() => setCredentialOpen(true)}><KeyRound className="h-4 w-4" /> Add credential</Button></div>
        <Card className="p-4">{credentials.length ? <div className="space-y-3">{credentials.map((profile) => <div key={profile.id} className="flex items-center justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><div><p className="text-sm font-medium text-white">{profile.name}</p><p className="text-xs text-gray-500">{profile.auth_kind.replace(/_/g, ' ')}{profile.username ? ` · ${profile.username}` : ''}{profile.port ? ` · port ${profile.port}` : ''} · {profile.status}</p></div><Button size="sm" variant="ghost" onClick={async () => { try { await deactivateDeviceCredential(deviceId, profile.id); toast.success('Credential deactivated'); await load() } catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to deactivate credential') } }}>Deactivate</Button></div>)}</div> : <p className="text-sm text-gray-500">No credentials configured. Unauthenticated scans remain available.</p>}</Card>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section><h2 className="mb-3 text-lg font-semibold text-white">Interfaces and identity</h2><Card className="p-4"><div className="mb-4 border-b border-gray-800 pb-3"><p className="text-xs text-gray-500">Permanent device ID</p><p className="mt-1 break-all font-mono text-xs text-gray-300">{device.id}</p></div>{interfaces.length ? <div className="space-y-3">{interfaces.map((item) => <div key={item.id} className="flex items-start justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><div><p className="font-mono text-sm text-white">{item.locator}{item.locator === device.primary_locator && <span className="ml-2 rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] text-blue-300">current</span>}</p><p className="text-xs text-gray-500">{item.hostname || item.locator_type}</p></div><div className="text-right text-xs text-gray-400"><p>{item.mac_address || 'No MAC observed'}</p><p>{item.network_zone || 'Zone not assigned'}</p></div></div>)}</div> : <p className="text-sm text-gray-500">No interfaces observed.</p>}</Card>{locatorHistory.length > 1 && <Card className="mt-3 p-4"><p className="mb-3 text-sm font-medium text-white">Address history</p><div className="space-y-2">{locatorHistory.slice(0, 8).map((entry) => <div key={entry.id} className="flex items-start justify-between gap-3 text-xs"><div><p className="font-mono text-gray-300">{entry.locator}</p><p className="text-gray-600">{entry.change_reason || entry.change_source}</p></div><p className="whitespace-nowrap text-gray-500">{formatDate(entry.changed_at)}</p></div>)}</div></Card>}</section>
        <section><h2 className="mb-3 text-lg font-semibold text-white">Recent device scans</h2><Card className="p-4">{scans.length ? <div className="space-y-3">{scans.slice(0, 8).map((item) => <Link key={item.id} href={`/scans/${item.id}`} className="flex items-center justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0 hover:text-blue-300"><div><p className="text-sm text-white">{item.current_phase?.replace(/_/g, ' ') || item.scan_type}</p><p className="text-xs text-gray-500">{formatDate(item.created_at)}</p></div><ScanStatusBadge status={item.status} /></Link>)}</div> : <p className="text-sm text-gray-500">No scans yet.</p>}</Card></section>
      </div>

      <Modal open={scanOpen} title={`Scan ${device.name}`} onClose={() => setScanOpen(false)} footer={<><Button variant="secondary" onClick={() => setScanOpen(false)}>Cancel</Button><Button loading={scanning} disabled={!scan.confirm_authorized} onClick={queueScan}>Queue scan</Button></>}>
        <div className="space-y-4">
          <Field label="Coverage"><Select value={scan.profile} onChange={(event) => setScan({ ...scan, profile: event.target.value })}><option value="inventory">Inventory — top 100 TCP ports + curated UDP, lightest</option><option value="posture">Posture — all 65,535 TCP ports + curated UDP, slower</option><option value="thorough">Thorough — all 65,535 TCP ports + deeper fingerprints, heaviest</option></Select></Field>
          {scan.profile !== 'inventory' && <p className="rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">This profile checks every TCP port and can take hours on slow or filtered devices. Start with Inventory unless complete port coverage is required.</p>}
          <Field label="Safety level" hint="Safety is independent from port coverage."><Select value={scan.safety_profile} onChange={(event) => { const safety_profile = event.target.value; setScan({ ...scan, safety_profile, include_web_dast: safety_profile === 'observe_only' ? false : scan.include_web_dast, ssh_credential_profile_id: safety_profile === 'authenticated_active' ? scan.ssh_credential_profile_id : '', web_credential_profile_id: safety_profile === 'authenticated_active' ? scan.web_credential_profile_id : '', include_ssh_host_review: safety_profile === 'authenticated_active' ? scan.include_ssh_host_review : false }) }}><option value="observe_only">Observe only — discovery and fingerprints</option><option value="safe_remote">Safe remote — bounded non-destructive checks</option><option value="authenticated_active">Authenticated active — supplied SSH/web credentials</option><option value="lab_invasive" disabled>Lab invasive — dedicated runner required</option></Select></Field>
          {scan.safety_profile === 'authenticated_active' && <div className="grid gap-4 sm:grid-cols-2"><Field label="SSH credential"><Select value={scan.ssh_credential_profile_id} onChange={(event) => setScan({ ...scan, ssh_credential_profile_id: event.target.value, include_ssh_host_review: event.target.value ? scan.include_ssh_host_review : false })}><option value="">No SSH authentication</option>{credentials.filter((profile) => profile.auth_kind.startsWith('ssh_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}{profile.port ? ` · ${profile.port}` : ''}</option>)}</Select></Field><Field label="Web credential"><Select value={scan.web_credential_profile_id} onChange={(event) => setScan({ ...scan, web_credential_profile_id: event.target.value })}><option value="">No web authentication</option>{credentials.filter((profile) => profile.auth_kind.startsWith('web_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}{profile.port ? ` · ${profile.port}` : ''}</option>)}</Select></Field></div>}
          {scan.safety_profile === 'authenticated_active' && <label className="flex items-start gap-3 rounded-lg border border-violet-500/20 bg-violet-500/5 p-3 text-sm text-gray-300"><input type="checkbox" checked={scan.include_ssh_host_review} disabled={!scan.ssh_credential_profile_id} onChange={(event) => setScan({ ...scan, include_ssh_host_review: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Collect read-only SSH host evidence</strong>Runs only server-owned identity, listener, process, account, hardening, package, and update bundles. Commands and output are bounded and secrets are redacted.</span></label>}
          <label className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300"><input type="checkbox" checked={scan.include_web_dast} disabled={scan.safety_profile === 'observe_only'} onChange={(event) => setScan({ ...scan, include_web_dast: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Check web interfaces on every discovered port</strong>{scan.safety_profile === 'observe_only' ? 'Observe-only discovers origins without launching Web DAST children.' : 'Runs bounded passive Web DAST as hidden device-owned checks.'}</span></label>
          {scan.include_web_dast && <Field label="Web coverage"><Select value={scan.web_scan_type} onChange={(event) => setScan({ ...scan, web_scan_type: event.target.value })}><option value="quick">Quick</option><option value="standard">Standard</option><option value="deep">Deep passive</option></Select></Field>}
          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={scan.confirm_authorized} onChange={(event) => setScan({ ...scan, confirm_authorized: event.target.checked })} className="mt-1" />I confirm I am authorized to scan this device and its listening services{scan.ssh_credential_profile_id || scan.web_credential_profile_id ? ', and I authorize one bounded attempt with each selected credential' : ''}.</label>
        </div>
      </Modal>

      <Modal open={credentialOpen} title="Add encrypted device credential" onClose={() => setCredentialOpen(false)} footer={<><Button variant="secondary" onClick={() => setCredentialOpen(false)}>Cancel</Button><Button loading={credentialSaving} disabled={!credentialForm.name.trim() || !credentialForm.secret || (['ssh_password', 'ssh_private_key', 'web_form'].includes(credentialForm.auth_kind) && !credentialForm.username.trim())} onClick={saveCredential}>Save credential</Button></>}>
        <div className="space-y-4">
          <Field label="Profile name" required><Input value={credentialForm.name} onChange={(event) => setCredentialForm({ ...credentialForm, name: event.target.value })} placeholder="Device administrator" /></Field>
          <Field label="Authentication type"><Select value={credentialForm.auth_kind} onChange={(event) => setCredentialForm({ ...credentialForm, auth_kind: event.target.value })}><option value="ssh_password">SSH password</option><option value="ssh_private_key">SSH private key</option><option value="web_authorization_header">Web Authorization header</option><option value="web_cookie">Web session cookie</option><option value="web_form">Web login form</option></Select></Field>
          {['ssh_password', 'ssh_private_key', 'web_form'].includes(credentialForm.auth_kind) && <Field label="Username" required><Input value={credentialForm.username} onChange={(event) => setCredentialForm({ ...credentialForm, username: event.target.value })} autoComplete="off" /></Field>}
          <Field label={credentialForm.auth_kind === 'ssh_private_key' ? 'Private key' : credentialForm.auth_kind === 'web_authorization_header' ? 'Authorization value' : credentialForm.auth_kind === 'web_cookie' ? 'Cookie value' : 'Password'} required>{credentialForm.auth_kind === 'ssh_private_key' ? <Textarea rows={7} value={credentialForm.secret} onChange={(event) => setCredentialForm({ ...credentialForm, secret: event.target.value })} /> : <Input type="password" value={credentialForm.secret} onChange={(event) => setCredentialForm({ ...credentialForm, secret: event.target.value })} autoComplete="new-password" />}</Field>
          {credentialForm.auth_kind === 'ssh_private_key' && <Field label="Key passphrase (optional)"><Input type="password" value={credentialForm.secondary_secret} onChange={(event) => setCredentialForm({ ...credentialForm, secondary_secret: event.target.value })} autoComplete="new-password" /></Field>}
          {credentialForm.auth_kind === 'web_form' && <Field label="Login path" hint="Relative to each discovered web origin."><Input value={credentialForm.login_path} onChange={(event) => setCredentialForm({ ...credentialForm, login_path: event.target.value })} placeholder="/login" /></Field>}
          <Field label="Limit to port (optional)"><Input type="number" min="1" max="65535" value={credentialForm.port} onChange={(event) => setCredentialForm({ ...credentialForm, port: event.target.value })} /></Field>
          <p className="rounded border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-100">ShakerScan performs at most one supplied SSH authentication attempt per credential profile and device scan, with cross-scan cooldown and daily limits. It never guesses passwords or keys. Web credentials apply only to bounded device-owned web children.</p>
        </div>
      </Modal>

      <Modal open={locatorOpen} title="Change device address" onClose={() => setLocatorOpen(false)} footer={<><Button variant="secondary" onClick={() => setLocatorOpen(false)}>Cancel</Button><Button loading={locatorSaving} disabled={!locatorForm.locator.trim() || !locatorForm.confirm_same_device} onClick={saveLocator}>Save address</Button></>}>
        <div className="space-y-4">
          <p className="text-sm text-gray-400">The permanent device ID, scan history, findings, policies, and credentials will stay unchanged. Future scans will use the new address.</p>
          <Field label="Current IP address or hostname" required hint="Enter one address only; URLs and network ranges are not accepted."><Input value={locatorForm.locator} onChange={(event) => setLocatorForm({ ...locatorForm, locator: event.target.value })} placeholder="192.168.1.45 or tv.lan" /></Field>
          <Field label="Reason (optional)"><Input value={locatorForm.reason} onChange={(event) => setLocatorForm({ ...locatorForm, reason: event.target.value })} placeholder="DHCP assigned a new address" /></Field>
          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={locatorForm.confirm_same_device} onChange={(event) => setLocatorForm({ ...locatorForm, confirm_same_device: event.target.checked })} className="mt-1" /><span>I verified that this address belongs to the same physical device. ShakerScan will not automatically trust an IP that may have been reassigned to something else.</span></label>
        </div>
      </Modal>

      <Modal open={renameOpen} title="Rename connected device" onClose={() => setRenameOpen(false)} footer={<><Button variant="secondary" onClick={() => setRenameOpen(false)}>Cancel</Button><Button loading={renameSaving} disabled={!renameName.trim() || renameName.trim() === device.name} onClick={saveName}>Save name</Button></>}>
        <Field label="Device name" required hint="This changes the display name only. Device identity, address, scans, policies, and credentials stay unchanged."><Input value={renameName} maxLength={160} autoFocus onChange={(event) => setRenameName(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && renameName.trim() && renameName.trim() !== device.name) saveName() }} /></Field>
      </Modal>
    </div>
  )
}
