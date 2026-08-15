'use client'

import Link from 'next/link'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Plus, Router, ShieldCheck } from 'lucide-react'
import {
  createDevice,
  getDevicePolicies,
  getDeviceReadiness,
  getDevices,
  scanDevice,
  type DevicePolicy,
  type DeviceTarget,
} from '@/lib/api'
import { Button, Card, CardSkeleton, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select, useToast } from '@/components/ui'

const DEVICE_CLASSES = [
  ['generic', 'Connected device'], ['media', 'TV or media device'], ['camera', 'Camera'],
  ['printer', 'Printer'], ['router', 'Router or access point'], ['nas', 'NAS or storage'],
  ['conference', 'Conference equipment'], ['building', 'Building system'], ['industrial', 'Industrial device'],
] as const
const PAGE_SIZE = 50

export default function DevicesPage() {
  const toast = useToast()
  const [devices, setDevices] = useState<DeviceTarget[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [policies, setPolicies] = useState<DevicePolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [enabled, setEnabled] = useState(true)
  const [workerReady, setWorkerReady] = useState(false)
  const [readinessReason, setReadinessReason] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [addOpen, setAddOpen] = useState(false)
  const [scanTarget, setScanTarget] = useState<DeviceTarget | null>(null)
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState(false)
  const loadSequence = useRef(0)
  const [form, setForm] = useState({ name: '', primary_locator: '', device_class: 'generic', manufacturer: '', model: '', policy_id: '' })
  const [scanForm, setScanForm] = useState({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', confirm_authorized: false })

  const load = useCallback(async () => {
    const sequence = ++loadSequence.current
    setLoading(true)
    try {
      const [deviceData, policyData, readiness] = await Promise.all([
        getDevices({ search: search || undefined, limit: PAGE_SIZE, offset: page * PAGE_SIZE }), getDevicePolicies(), getDeviceReadiness(),
      ])
      if (sequence !== loadSequence.current) return
      setDevices(deviceData.devices || [])
      setTotal(deviceData.total || 0)
      setPolicies(policyData.policies || [])
      setEnabled(readiness.enabled)
      setWorkerReady(readiness.status === 'ready')
      setReadinessReason(readiness.reason || null)
      setFailed(false)
    } catch {
      if (sequence === loadSequence.current) setFailed(true)
    } finally {
      if (sequence === loadSequence.current) setLoading(false)
    }
  }, [search, page])

  useEffect(() => { const timer = setTimeout(load, 250); return () => clearTimeout(timer) }, [load])
  useEffect(() => { setPage(0) }, [search])

  async function addDevice() {
    if (!form.primary_locator.trim()) return
    setSaving(true)
    try {
      await createDevice({
        ...form,
        name: form.name.trim() || undefined,
        primary_locator: form.primary_locator.trim(),
        manufacturer: form.manufacturer.trim() || undefined,
        model: form.model.trim() || undefined,
        policy_id: form.policy_id || undefined,
      })
      setAddOpen(false)
      setForm({ name: '', primary_locator: '', device_class: 'generic', manufacturer: '', model: '', policy_id: '' })
      toast.success('Connected device added')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to add device')
    } finally {
      setSaving(false)
    }
  }

  async function startScan() {
    if (!scanTarget) return
    setScanning(true)
    try {
      const queued = await scanDevice(scanTarget.id, {
        profile: scanForm.profile as 'inventory' | 'posture' | 'thorough',
        safety_profile: scanForm.safety_profile as 'observe_only' | 'safe_remote' | 'authenticated_active',
        confirm_authorized: scanForm.confirm_authorized,
        include_web_dast: scanForm.include_web_dast,
        web_scan_type: scanForm.web_scan_type as 'quick' | 'standard' | 'deep',
        max_web_origins: 8,
      })
      setScanTarget(null)
      toast.success('Device scan queued', { link: { href: `/scans/${queued.scan_id}`, label: 'View report' } })
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to queue scan')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader
        title="Connected Devices"
        description="Inventory listening services on TVs, cameras, routers, appliances, and other network-connected systems without mixing them into Web DAST targets."
        icon={<Router className="h-6 w-6" />}
        actions={<>
          <Link href="/devices/policies" className="inline-flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 hover:bg-gray-700"><ShieldCheck className="h-4 w-4" /> Service policies</Link>
          <Button onClick={() => setAddOpen(true)} disabled={!enabled}><Plus className="h-4 w-4" /> Add device</Button>
        </>}
      />

      {!enabled && <Card className="mb-4 border-amber-500/30 bg-amber-500/5 p-4 text-sm text-amber-200">Connected-device scanning is disabled by the operator.</Card>}
      {enabled && !workerReady && <Card className="mb-4 border-amber-500/30 bg-amber-500/5 p-4 text-sm text-amber-200">Device inventory is available, but scans are paused until a current device worker with Nmap is ready{readinessReason ? ` (${readinessReason.replace(/_/g, ' ')})` : ''}.</Card>}

      <div className="mb-4 max-w-md"><Input value={search} onChange={(event) => { setPage(0); setSearch(event.target.value) }} placeholder="Search name, address, or manufacturer" aria-label="Search connected devices" /></div>

      {loading ? <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3"><CardSkeleton /><CardSkeleton /><CardSkeleton /></div>
        : failed ? <ErrorState message="Could not load connected devices" onRetry={load} />
        : devices.length === 0 ? <EmptyState message="No connected devices yet" hint="Add one hostname or IP address. Device scans remain separate from Web DAST targets." action={{ label: 'Add device', onClick: () => setAddOpen(true) }} />
        : <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{devices.map((device) => (
          <Card key={device.id} className="p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0"><Link href={`/devices/${device.id}`} className="font-semibold text-white hover:text-blue-300">{device.name}</Link><p className="mt-1 truncate font-mono text-xs text-gray-400">{device.primary_locator}</p></div>
              {device.last_grade ? <span className="rounded-md bg-gray-800 px-2 py-1 text-sm font-bold text-gray-200">{device.last_grade}</span> : null}
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded bg-gray-950 p-2"><div className="text-lg font-semibold text-white">{device.services_count || 0}</div><div className="text-gray-500">services</div></div>
              <div className="rounded bg-gray-950 p-2"><div className="text-lg font-semibold text-white">{device.active_findings_count || 0}</div><div className="text-gray-500">findings</div></div>
              <div className="rounded bg-gray-950 p-2"><div className="truncate text-sm font-semibold text-white">{device.device_class}</div><div className="text-gray-500">class</div></div>
            </div>
            <div className="mt-4 flex items-center justify-between text-xs text-gray-500"><span>{device.policy_name || 'Default policy'}</span><Button size="sm" disabled={!workerReady} onClick={() => { setScanTarget(device); setScanForm({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', confirm_authorized: false }) }}>Scan</Button></div>
          </Card>
        ))}</div>}
      {!loading && !failed && total > PAGE_SIZE && <div className="mt-5 flex items-center justify-between text-sm text-gray-400"><span>Showing {page * PAGE_SIZE + 1}–{Math.min(total, (page + 1) * PAGE_SIZE)} of {total}</span><div className="flex gap-2"><Button size="sm" variant="secondary" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</Button><Button size="sm" variant="secondary" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((value) => value + 1)}>Next</Button></div></div>}

      <Modal open={addOpen} title="Add connected device" onClose={() => setAddOpen(false)} footer={<><Button variant="secondary" onClick={() => setAddOpen(false)}>Cancel</Button><Button loading={saving} onClick={addDevice}>Add device</Button></>}>
        <div className="space-y-4">
          <Field label="Hostname or IP address" required hint="One device only; URLs and network ranges are not accepted."><Input value={form.primary_locator} onChange={(event) => setForm({ ...form, primary_locator: event.target.value })} placeholder="tv.lan or 192.168.1.40" /></Field>
          <Field label="Display name"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Living room TV" /></Field>
          <Field label="Device class"><Select value={form.device_class} onChange={(event) => setForm({ ...form, device_class: event.target.value })}>{DEVICE_CLASSES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select></Field>
          <div className="grid gap-4 sm:grid-cols-2"><Field label="Manufacturer"><Input value={form.manufacturer} onChange={(event) => setForm({ ...form, manufacturer: event.target.value })} /></Field><Field label="Model"><Input value={form.model} onChange={(event) => setForm({ ...form, model: event.target.value })} /></Field></div>
          <Field label="Service policy"><Select value={form.policy_id} onChange={(event) => setForm({ ...form, policy_id: event.target.value })}><option value="">Default connected-device policy</option>{policies.map((policy) => <option key={policy.id} value={policy.id}>{policy.name}</option>)}</Select></Field>
        </div>
      </Modal>

      <Modal open={Boolean(scanTarget)} title={`Scan ${scanTarget?.name || 'device'}`} onClose={() => setScanTarget(null)} footer={<><Button variant="secondary" onClick={() => setScanTarget(null)}>Cancel</Button><Button loading={scanning} disabled={!scanForm.confirm_authorized} onClick={startScan}>Queue scan</Button></>}>
        <div className="space-y-4">
          <Field label="Coverage"><Select value={scanForm.profile} onChange={(event) => setScanForm({ ...scanForm, profile: event.target.value })}><option value="inventory">Inventory — top 100 TCP ports + curated UDP, lightest</option><option value="posture">Posture — all 65,535 TCP ports + curated UDP, slower</option><option value="thorough">Thorough — all 65,535 TCP ports + deeper fingerprints, heaviest</option></Select></Field>
          {scanForm.profile !== 'inventory' && <p className="rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">This profile checks every TCP port and can take hours on slow or filtered devices. Start with Inventory unless complete port coverage is required.</p>}
          <Field label="Safety level" hint="Safety is independent from port coverage."><Select value={scanForm.safety_profile} onChange={(event) => { const safety_profile = event.target.value; setScanForm({ ...scanForm, safety_profile, include_web_dast: safety_profile === 'observe_only' ? false : scanForm.include_web_dast }) }}><option value="observe_only">Observe only — discovery and fingerprints</option><option value="safe_remote">Safe remote — bounded non-destructive checks</option><option value="authenticated_active">Authenticated active — credentials can be selected on the device page</option><option value="lab_invasive" disabled>Lab invasive — dedicated runner required</option></Select></Field>
          <label className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300"><input type="checkbox" checked={scanForm.include_web_dast} disabled={scanForm.safety_profile === 'observe_only'} onChange={(event) => setScanForm({ ...scanForm, include_web_dast: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Check discovered web interfaces</strong>{scanForm.safety_profile === 'observe_only' ? 'Observe-only discovers origins without launching Web DAST children.' : 'Run bounded passive Web DAST on HTTP(S) found on any port. These internal checks do not create Web targets.'}</span></label>
          {scanForm.include_web_dast && <Field label="Web coverage"><Select value={scanForm.web_scan_type} onChange={(event) => setScanForm({ ...scanForm, web_scan_type: event.target.value })}><option value="quick">Quick</option><option value="standard">Standard</option><option value="deep">Deep passive</option></Select></Field>}
          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={scanForm.confirm_authorized} onChange={(event) => setScanForm({ ...scanForm, confirm_authorized: event.target.checked })} className="mt-1" /><span>I confirm I am authorized to scan this device and its listening services.</span></label>
        </div>
      </Modal>
    </div>
  )
}
