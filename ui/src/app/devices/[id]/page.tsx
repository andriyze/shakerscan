'use client'

import Link from 'next/link'
import { Suspense, useCallback, useEffect, useState } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import { Activity, Bot, ChevronDown, ChevronUp, CircleHelp, ExternalLink, FileJson, Globe, KeyRound, MapPin, Pencil, Router, Trash2, Upload, Wifi, WifiOff } from 'lucide-react'
import { changeDeviceLocator, createDeviceCredential, createDeviceRequestCollection, deactivateDeviceCredential, deactivateDeviceRequestCollection, formatDate, getDevice, getDeviceCredentials, getDeviceRequestCollections, getDeviceScanActivity, getScan, renameDevice, scanDevice, type DeviceCredentialProfile, type DeviceDetailResponse, type DeviceRequestCollection, type DeviceScanActivity, type DeviceService, type Scan } from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Modal, PageHeader, ScanStatusBadge, Select, TableSkeleton, Textarea, useToast } from '@/components/ui'

const policyBadgeClass: Record<string, string> = {
  allow: 'bg-emerald-500/15 text-emerald-300',
  deny: 'bg-red-500/15 text-red-300',
  review: 'bg-amber-500/15 text-amber-300',
  require: 'bg-amber-500/15 text-amber-300',
}

function parsePortHints(value: string): number[] {
  if (!value.trim()) return []
  const segments = value.split(',').map((item) => item.trim())
  if (segments.some((item) => !/^\d+$/.test(item))) throw new Error('Port hints must be comma-separated whole numbers')
  const ports = Array.from(new Set(segments.map(Number)))
  if (ports.some((port) => port < 1 || port > 65535)) throw new Error('Port hints must be between 1 and 65535')
  return ports
}

function serviceKey(service: Pick<DeviceService, 'transport' | 'port'>): string {
  return `${String(service.transport || 'tcp').toLowerCase()}/${Number(service.port)}`
}

function scanServices(scan: Scan | null, collection: 'services' | 'inconclusive_observations', expectedState: 'open' | 'open|filtered'): DeviceService[] {
  const result = scan?.result
  const posture = result && typeof result.device_posture === 'object' && result.device_posture !== null
    ? result.device_posture as Record<string, unknown>
    : null
  const rows = Array.isArray(posture?.[collection]) ? posture[collection] as unknown[] : []
  return rows.flatMap((raw, index) => {
    if (!raw || typeof raw !== 'object') return []
    const row = raw as Record<string, unknown>
    const port = Number(row.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535 || String(row.state || expectedState) !== expectedState) return []
    const transport = String(row.transport || 'tcp').toLowerCase()
    return [{
      id: String(row.id || `${scan?.id || 'scan'}-${transport}-${port}-${index}`),
      transport,
      port,
      state: expectedState,
      service_name: String(row.service_name || 'unknown'),
      product: row.product ? String(row.product) : null,
      version: row.version ? String(row.version) : null,
      cpe: row.cpe ? String(row.cpe) : null,
      encrypted: typeof row.encrypted === 'boolean' ? row.encrypted : null,
      web_origin: row.web_origin ? String(row.web_origin) : null,
      policy_disposition: row.policy_disposition ? String(row.policy_disposition) : null,
      policy_reason: row.policy_reason ? String(row.policy_reason) : null,
      last_seen_at: String(row.last_seen_at || scan?.completed_at || scan?.created_at || ''),
    }]
  }).sort((left, right) => left.transport.localeCompare(right.transport) || left.port - right.port)
}

function DeviceDetailContent() {
  const params = useParams()
  const searchParams = useSearchParams()
  const deviceId = params.id as string
  const selectedScanId = searchParams.get('scan')?.trim() || null
  const toast = useToast()
  const [data, setData] = useState<DeviceDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [scanOpen, setScanOpen] = useState(false)
  const [credentialOpen, setCredentialOpen] = useState(false)
  const [requestImportOpen, setRequestImportOpen] = useState(false)
  const [locatorOpen, setLocatorOpen] = useState(false)
  const [renameOpen, setRenameOpen] = useState(false)
  const [credentials, setCredentials] = useState<DeviceCredentialProfile[]>([])
  const [requestCollections, setRequestCollections] = useState<DeviceRequestCollection[]>([])
  const [requestImportSaving, setRequestImportSaving] = useState(false)
  const [requestImport, setRequestImport] = useState<{ name: string; format: 'auto' | 'postman_collection' | 'har' | 'openapi'; document: Record<string, unknown> | null; documentFile: string; environment: Record<string, unknown> | null; environmentFile: string; baseUrl: string }>({ name: '', format: 'auto', document: null, documentFile: '', environment: null, environmentFile: '', baseUrl: '' })
  const [credentialSaving, setCredentialSaving] = useState(false)
  const [locatorSaving, setLocatorSaving] = useState(false)
  const [renameSaving, setRenameSaving] = useState(false)
  const [showInconclusive, setShowInconclusive] = useState(false)
  const [locatorForm, setLocatorForm] = useState({ locator: '', reason: '', confirm_same_device: false })
  const [renameName, setRenameName] = useState('')
  const [credentialForm, setCredentialForm] = useState({ name: '', auth_kind: 'ssh_password', username: '', secret: '', secondary_secret: '', login_path: '/login', port: '' })
  const [scanning, setScanning] = useState(false)
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [selectedScanLoading, setSelectedScanLoading] = useState(false)
  const [selectedScanError, setSelectedScanError] = useState<string | null>(null)
  const [scanActivity, setScanActivity] = useState<DeviceScanActivity | null>(null)
  const [scan, setScan] = useState({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', port_hints: '', ssh_credential_profile_id: '', web_credential_profile_id: '', include_ssh_host_review: false, request_collection_ids: [] as string[], confirm_request_replay: false, allow_state_changing_requests: false, allow_untrusted_tls_credentials: false, confirm_authorized: false })

  const load = useCallback(async () => {
    try {
      const [device, credentialData, collectionData] = await Promise.all([getDevice(deviceId), getDeviceCredentials(deviceId), getDeviceRequestCollections(deviceId)])
      setData(device); setCredentials(credentialData.profiles || []); setRequestCollections(collectionData.collections || []); setFailed(false)
    } catch { setFailed(true) } finally { setLoading(false) }
  }, [deviceId])

  useEffect(() => { load(); const timer = setInterval(load, 10_000); return () => clearInterval(timer) }, [load])

  useEffect(() => {
    let stopped = false
    let timer: ReturnType<typeof setTimeout> | null = null
    if (!selectedScanId) {
      setSelectedScan(null)
      setSelectedScanError(null)
      setSelectedScanLoading(false)
      return () => undefined
    }
    setSelectedScanLoading(true)
    const refresh = async () => {
      try {
        const next = await getScan(selectedScanId)
        if (stopped) return
        if (next.device_target_id !== deviceId || !['device_posture', 'device_probe'].includes(String(next.run_kind || next.scan_type))) {
          setSelectedScan(null)
          setSelectedScanError('That scan does not belong to this connected device.')
          return
        }
        setSelectedScan(next)
        setSelectedScanError(null)
        if (!['completed', 'failed', 'cancelled'].includes(next.status)) timer = setTimeout(refresh, 5_000)
      } catch (error) {
        if (!stopped) setSelectedScanError(error instanceof Error ? error.message : 'Could not load the selected device scan')
      } finally {
        if (!stopped) setSelectedScanLoading(false)
      }
    }
    refresh()
    return () => { stopped = true; if (timer) clearTimeout(timer) }
  }, [deviceId, selectedScanId])

  useEffect(() => {
    let stopped = false
    let timer: ReturnType<typeof setTimeout> | null = null
    if (!selectedScanId) { setScanActivity(null); return () => undefined }
    const refresh = async () => {
      try {
        const activity = await getDeviceScanActivity(selectedScanId)
        if (stopped) return
        setScanActivity(activity)
        if (!['completed', 'failed', 'cancelled'].includes(activity.status)) timer = setTimeout(refresh, 3_000)
      } catch { if (!stopped) setScanActivity(null) }
    }
    refresh()
    return () => { stopped = true; if (timer) clearTimeout(timer) }
  }, [selectedScanId])

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
        port_hints: parsePortHints(scan.port_hints),
        ssh_credential_profile_id: scan.ssh_credential_profile_id || undefined,
        web_credential_profile_id: scan.web_credential_profile_id || undefined,
        request_collection_ids: scan.request_collection_ids,
        confirm_request_replay: scan.request_collection_ids.length > 0 && scan.confirm_request_replay,
        allow_state_changing_requests: scan.request_collection_ids.length > 0 && scan.allow_state_changing_requests,
        allow_untrusted_tls_credentials: scan.safety_profile === 'authenticated_active' && Boolean(scan.web_credential_profile_id || scan.request_collection_ids.length) && scan.allow_untrusted_tls_credentials,
        capability_ids: scan.include_ssh_host_review ? ['ssh-authenticated-host-review'] : undefined,
      })
      setScanOpen(false)
      toast.success('Device scan queued', { link: { href: `/devices/${deviceId}?scan=${queued.scan_id}`, label: 'Track scan activity' } })
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to queue scan')
    } finally { setScanning(false) }
  }

  async function readJsonFile(file: File): Promise<Record<string, unknown>> {
    if (file.size > 5 * 1024 * 1024) throw new Error('JSON file is larger than 5 MiB')
    let parsed: unknown
    try { parsed = JSON.parse(await file.text()) } catch { throw new Error(`${file.name} is not valid JSON`) }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${file.name} must contain one JSON object`)
    return parsed as Record<string, unknown>
  }

  async function chooseRequestFile(file: File | undefined, kind: 'document' | 'environment') {
    if (!file) return
    try {
      const parsed = await readJsonFile(file)
      if (kind === 'document') {
        const detected = parsed.log && typeof parsed.log === 'object' ? 'har' : typeof parsed.openapi === 'string' || typeof parsed.swagger === 'string' ? 'openapi' : Array.isArray(parsed.item) ? 'postman_collection' : requestImport.format
        setRequestImport({ ...requestImport, format: detected, document: parsed, documentFile: file.name, environment: detected === 'postman_collection' ? requestImport.environment : null, environmentFile: detected === 'postman_collection' ? requestImport.environmentFile : '', baseUrl: detected === 'openapi' ? requestImport.baseUrl : '' })
      }
      else setRequestImport({ ...requestImport, environment: parsed, environmentFile: file.name })
    } catch (error) { toast.error(error instanceof Error ? error.message : 'Could not read JSON file') }
  }

  async function saveRequestCollection() {
    if (!requestImport.document) return
    setRequestImportSaving(true)
    try {
      const result = await createDeviceRequestCollection(deviceId, {
        name: requestImport.name.trim() || undefined,
        format: requestImport.format,
        document: requestImport.document,
        environment: requestImport.format === 'postman_collection' || requestImport.format === 'auto' ? requestImport.environment || undefined : undefined,
        base_url: requestImport.format === 'openapi' || requestImport.format === 'auto' ? requestImport.baseUrl.trim() || undefined : undefined,
      })
      setRequestImportOpen(false)
      setRequestImport({ name: '', format: 'auto', document: null, documentFile: '', environment: null, environmentFile: '', baseUrl: '' })
      toast.success(`Imported ${result.collection.summary.request_count} API request${result.collection.summary.request_count === 1 ? '' : 's'}`)
      await load()
    } catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to import request collection') }
    finally { setRequestImportSaving(false) }
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
  const exactScanServices = selectedScanId ? scanServices(selectedScan, 'services', 'open') : []
  const visibleServices = selectedScanId ? exactScanServices : services
  const visibleServiceKeys = new Set(visibleServices.map(serviceKey))
  const previouslyObservedServices = selectedScan
    ? services.filter((service) => !visibleServiceKeys.has(serviceKey(service)))
    : []
  const tcpOpenCount = visibleServices.filter((service) => String(service.transport).toLowerCase() === 'tcp').length
  const udpOpenCount = visibleServices.filter((service) => String(service.transport).toLowerCase() === 'udp').length
  const webOpenCount = visibleServices.filter((service) => Boolean(service.web_origin)).length
  const selectedScanTerminal = Boolean(selectedScan && ['completed', 'failed', 'cancelled'].includes(selectedScan.status))
  const observations = selectedScanId
    ? scanServices(selectedScan, 'inconclusive_observations', 'open|filtered')
    : data.inconclusive_observations || []
  const observationTotal = selectedScanId ? observations.length : data.inconclusive_observations_total ?? observations.length
  const selectedPosture = selectedScan?.result && typeof selectedScan.result.device_posture === 'object' && selectedScan.result.device_posture !== null
    ? selectedScan.result.device_posture as Record<string, unknown>
    : null
  const selectedReachability = selectedPosture?.reachability && typeof selectedPosture.reachability === 'object'
    ? selectedPosture.reachability as unknown as typeof data.reachability
    : null
  const applicationSurface = selectedPosture?.application_surface && typeof selectedPosture.application_surface === 'object'
    ? selectedPosture.application_surface as Record<string, unknown>
    : null
  const applicationSummary = applicationSurface?.summary && typeof applicationSurface.summary === 'object'
    ? applicationSurface.summary as Record<string, unknown>
    : {}
  const applicationPlatforms = Array.isArray(applicationSurface?.platforms)
    ? applicationSurface.platforms.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    : []
  const applicationObservations = Array.isArray(applicationSurface?.observations)
    ? applicationSurface.observations.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    : []
  const controlledOperations = Array.isArray(applicationSurface?.controlled_operations)
    ? applicationSurface.controlled_operations.filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
    : []
  const reachability = selectedScanId ? selectedReachability : data.reachability || device.last_reachability
  const reachabilityTone = reachability?.status === 'online'
    ? 'border-emerald-500/25 bg-emerald-500/5 text-emerald-100'
    : reachability?.status === 'unreachable'
      ? 'border-red-500/25 bg-red-500/5 text-red-100'
      : 'border-amber-500/25 bg-amber-500/5 text-amber-100'
  const ReachabilityIcon = reachability?.status === 'online' ? Wifi : reachability?.status === 'unreachable' ? WifiOff : CircleHelp

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader backHref="/devices" backLabel="Connected devices" title={device.name} description={device.primary_locator} icon={<Router className="h-6 w-6" />} actions={<><Button variant="secondary" onClick={() => { setRenameName(device.name); setRenameOpen(true) }}><Pencil className="h-4 w-4" /> Rename</Button><Button variant="secondary" onClick={() => { setLocatorForm({ locator: device.primary_locator, reason: '', confirm_same_device: false }); setLocatorOpen(true) }}><MapPin className="h-4 w-4" /> Change address</Button><Link href={`/devices/${device.id}/agent`} className="inline-flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-sm text-violet-200 hover:bg-violet-500/20"><Bot className="h-4 w-4" /> Device Hunt</Link><Link href={`/findings?source_type=device&device_target_id=${device.id}`} className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 hover:bg-gray-700">View findings</Link><Button onClick={() => { setScan({ profile: 'inventory', safety_profile: 'safe_remote', include_web_dast: true, web_scan_type: 'standard', port_hints: '', ssh_credential_profile_id: '', web_credential_profile_id: '', include_ssh_host_review: false, request_collection_ids: [], confirm_request_replay: false, allow_state_changing_requests: false, allow_untrusted_tls_credentials: false, confirm_authorized: false }); setScanOpen(true) }}>Scan device</Button></>} />

      {selectedScanId && (
        <Card className="mb-4 border-blue-500/25 bg-blue-500/5 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-blue-100">Viewing one device scan</p>
              <p className="mt-1 text-xs text-gray-400">
                {selectedScan ? `${selectedScan.status.replace(/_/g, ' ')} · ${formatDate(selectedScan.created_at)} · ${selectedScan.current_phase?.replace(/_/g, ' ') || selectedScan.scan_type}` : selectedScanLoading ? 'Loading scan evidence…' : selectedScanError || selectedScanId}
              </p>
            </div>
            <div className="flex gap-2">
              {selectedScan && <Link href={`/scans/${selectedScan.id}`} className="inline-flex items-center gap-1 rounded border border-blue-500/30 px-3 py-1.5 text-xs text-blue-200 hover:bg-blue-500/10">Full report <ExternalLink className="h-3.5 w-3.5" /></Link>}
              <Link href={`/devices/${device.id}`} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">Show known inventory</Link>
            </div>
          </div>
        </Card>
      )}

      {selectedScanId && scanActivity && (
        <Card className="mb-6 overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
            <div className="flex items-center gap-2"><Activity className={`h-4 w-4 ${selectedScanTerminal ? 'text-emerald-300' : 'animate-pulse text-blue-300'}`} /><div><p className="text-sm font-medium text-white">Scan activity</p><p className="text-xs text-gray-500">Meaningful events only; commands, payloads, and secrets are hidden.</p></div></div>
            <span className="text-xs text-gray-400">{scanActivity.progress}%</span>
          </div>
          <div className="max-h-80 divide-y divide-gray-800/70 overflow-y-auto">
            {scanActivity.events.slice(-20).map((event, index) => {
              const details = event.details || {}
              return <div key={`${event.timestamp}-${event.phase}-${index}`} className="flex gap-3 px-4 py-3">
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${event.kind === 'error' || event.kind === 'warning' ? 'bg-amber-400' : event.kind === 'complete' ? 'bg-emerald-400' : 'bg-blue-400'}`} />
                <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><p className="text-sm text-gray-200">{event.message}</p>{typeof event.progress === 'number' && <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{event.progress}%</span>}</div><div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-gray-500">{Object.entries(details).filter(([, value]) => value !== null && value !== undefined && value !== '').map(([key, value]) => <span key={key}>{key.replace(/_/g, ' ')}: <strong className="font-medium text-gray-400">{String(value)}</strong></span>)}<span>{formatDate(event.timestamp)}</span></div></div>
              </div>
            })}
          </div>
        </Card>
      )}

      <Card className={`mb-6 border p-4 ${reachabilityTone}`}>
        <div className="flex items-start gap-3"><ReachabilityIcon className="mt-0.5 h-5 w-5 shrink-0" /><div><p className="font-medium">{reachability ? `Device ${reachability.status === 'online' ? 'online' : reachability.status}` : 'Device reachability not checked'}</p><p className="mt-1 text-sm opacity-75">{reachability?.reason || 'Run a device scan to require a positive network response before port and policy checks begin.'}</p>{reachability?.status === 'online' && <p className="mt-2 text-xs opacity-70">Network accessible · {reachability.service_accessible === true ? 'at least one service responded' : reachability.service_accessible === false ? 'no listening TCP service found with complete visibility' : 'service accessibility still being assessed'} · {reachability.confidence} confidence</p>}</div></div>
      </Card>

      <Card className="mb-6 border-blue-500/25 bg-blue-500/5 p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-blue-200">{selectedScanId ? 'Open ports in this scan' : 'Known open ports'}</p>
            <div className="mt-1 flex items-end gap-3"><span className="text-4xl font-semibold text-white">{visibleServices.length}</span><span className="pb-1 text-sm text-gray-400">confirmed listening service{visibleServices.length === 1 ? '' : 's'}</span></div>
            <p className="mt-2 text-xs text-gray-500">{selectedScanId ? 'Only services positively confirmed by the selected scan are shown.' : 'The device inventory retains ports positively confirmed by completed scans.'}</p>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="rounded bg-gray-950/70 px-2.5 py-1.5 text-gray-300">TCP {tcpOpenCount}</span>
            <span className="rounded bg-gray-950/70 px-2.5 py-1.5 text-gray-300">UDP {udpOpenCount}</span>
            <span className="rounded bg-gray-950/70 px-2.5 py-1.5 text-gray-300">Web {webOpenCount}</span>
          </div>
        </div>
        {visibleServices.length > 0 ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {visibleServices.map((service) => <a key={service.id} href="#open-port-details" className="rounded-lg border border-blue-500/20 bg-gray-950/70 px-3 py-2 font-mono text-sm text-blue-100 hover:border-blue-400/50"><strong>{service.port}/{String(service.transport).toUpperCase()}</strong><span className="ml-2 font-sans text-xs text-gray-400">{service.service_name || 'unknown'}</span></a>)}
          </div>
        ) : selectedScanId && !selectedScanTerminal ? (
          <p className="mt-4 rounded border border-gray-800 bg-gray-950/50 p-3 text-sm text-gray-400">{selectedScanError || 'Waiting for this scan to confirm listening services…'}</p>
        ) : (
          <p className="mt-4 rounded border border-gray-800 bg-gray-950/50 p-3 text-sm text-gray-400">No listening service was positively confirmed{selectedScanId ? ' by this scan' : ''}.</p>
        )}
      </Card>

      {selectedScanId && (
        <section className="mb-6">
          <div className="mb-3 flex flex-wrap items-end justify-between gap-3"><div><h2 className="text-lg font-semibold text-white">Device API surface</h2><p className="text-sm text-gray-500">Protocol-aware checks selected from confirmed ports and device evidence—not a generic web wordlist.</p></div>{applicationSurface && <span className="rounded bg-violet-500/10 px-2.5 py-1 text-xs text-violet-200">Catalog {String(applicationSurface.catalog_version || 'built in')}</span>}</div>
          <Card className="overflow-hidden p-0">
            {!applicationSurface ? <div className="p-5 text-sm text-gray-400">{selectedScanTerminal ? 'This scan predates device API discovery or did not produce application evidence.' : 'Waiting for platform and API discovery…'}</div> : <>
              <div className="grid gap-px border-b border-gray-800 bg-gray-800 sm:grid-cols-4">
                {[
                  ['Platforms', Number(applicationSummary.candidate_platforms || 0)],
                  ['Responding APIs', Number(applicationSummary.responding_endpoints || 0)],
                  ['Auth boundaries', Number(applicationSummary.authentication_boundaries || 0)],
                  ['Control families', Number(applicationSummary.available_control_families || 0)],
                ].map(([label, value]) => <div key={String(label)} className="bg-gray-950 p-4"><p className="text-xs text-gray-500">{label}</p><p className="mt-1 text-2xl font-semibold text-white">{value}</p></div>)}
              </div>
              {applicationPlatforms.length > 0 && <div className="border-b border-gray-800 p-4"><p className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Detected platforms</p><div className="flex flex-wrap gap-2">{applicationPlatforms.map((platform, index) => <span key={`${String(platform.id)}-${index}`} className={`rounded-full border px-2.5 py-1 text-xs ${platform.confidence === 'confirmed' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' : 'border-blue-500/25 bg-blue-500/10 text-blue-200'}`}>{String(platform.title || platform.id)} · {String(platform.confidence || 'candidate')}</span>)}</div></div>}
              {applicationObservations.length > 0 ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Platform / API</th><th className="px-4 py-3">Request</th><th className="px-4 py-3">Result</th><th className="px-4 py-3">Evidence</th></tr></thead><tbody className="divide-y divide-gray-800 bg-gray-950/50">{applicationObservations.map((observation, index) => {
                const status = Number(observation.status || 0)
                const outcome = String(observation.outcome || 'observed')
                return <tr key={`${String(observation.platform)}-${String(observation.id)}-${index}`}><td className="px-4 py-3"><p className="font-medium text-white">{String(observation.title || observation.id || 'Device API')}</p><p className="text-xs text-gray-500">{String(observation.platform_title || observation.platform || 'UPnP')}</p></td><td className="px-4 py-3"><p className="font-mono text-xs text-gray-300">{String(observation.method || 'GET')} {String(observation.path || '/')}</p><p className="mt-1 text-xs text-gray-600">{String(observation.transport || 'http')} · {String(observation.origin || '')}</p></td><td className="px-4 py-3"><span className={`rounded px-2 py-1 text-xs ${outcome === 'confirmed' ? 'bg-emerald-500/10 text-emerald-200' : observation.auth_required ? 'bg-amber-500/10 text-amber-200' : status > 0 ? 'bg-blue-500/10 text-blue-200' : 'bg-gray-800 text-gray-400'}`}>{outcome.replace(/_/g, ' ')}</span>{status > 0 && <span className="ml-2 font-mono text-xs text-gray-500">HTTP {status}</span>}</td><td className="px-4 py-3 text-xs text-gray-400">{observation.auth_required ? 'Authentication required' : `${Number(observation.body_bytes || 0)} bytes · body hash retained`}</td></tr>
              })}</tbody></table></div> : <div className="p-5 text-sm text-gray-400">No known API endpoint responded in this scan. The catalog still remains available for imported and Device Hunt-directed requests.</div>}
              {controlledOperations.length > 0 && <details className="border-t border-gray-800"><summary className="cursor-pointer px-4 py-3 text-sm font-medium text-violet-200">Active test surfaces available with confirmation ({controlledOperations.length})</summary><div className="grid gap-2 border-t border-gray-800 p-4 sm:grid-cols-2">{controlledOperations.map((operation, index) => <div key={`${String(operation.platform)}-${String(operation.family)}-${index}`} className="rounded border border-violet-500/15 bg-violet-500/5 p-3"><p className="text-sm font-medium text-white">{String(operation.family || 'Device operation').replace(/_/g, ' ')}</p><p className="mt-1 text-xs text-gray-400">{String(operation.platform_title || operation.platform)} · {String(operation.action_class || 'active test').replace(/_/g, ' ')}</p><p className="mt-2 text-xs text-violet-200">Available in Authenticated active using an exact user-confirmed request, including through Device Hunt.</p></div>)}</div></details>}
            </>}
          </Card>
        </section>
      )}

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {[
          ['Class', device.device_class], ['Manufacturer', device.manufacturer || 'Unknown'], ['Model', device.model || 'Unknown'],
          ['Policy', device.policy_name || 'Default'], ['Posture', device.last_grade ? `${device.last_grade} · ${device.last_score ?? '—'}` : 'Not scanned'],
        ].map(([label, value]) => <Card key={label} className="p-3"><p className="text-xs text-gray-500">{label}</p><p className="mt-1 truncate font-medium text-white">{value}</p></Card>)}
      </div>

      <section id="open-port-details" className="mb-6 scroll-mt-6">
        <h2 className="mb-1 text-lg font-semibold text-white">{selectedScanId ? 'Open-port details for this scan' : 'Known open-port details'}</h2>
        <p className="mb-3 text-sm text-gray-500">Confirmed responses only. Silent or ambiguous probes are never shown as open.</p>
        {visibleServices.length === 0 ? <EmptyState message="No confirmed open ports" hint={selectedScanId ? 'This scan has not confirmed a listening service.' : 'Run a device scan to inventory listening TCP and UDP services.'} /> : (
          <div className="overflow-hidden rounded-lg border border-gray-800"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Open port</th><th className="px-4 py-3">Service</th><th className="px-4 py-3">Product</th><th className="px-4 py-3">Policy</th><th className="px-4 py-3">Web interface</th><th className="px-4 py-3">Confirmed</th></tr></thead><tbody className="divide-y divide-gray-800 bg-gray-950/50">{visibleServices.map((service) => (
            <tr key={service.id}><td className="px-4 py-3 font-mono text-gray-200">{service.port}/{service.transport}</td><td className="px-4 py-3 text-white">{service.service_name}</td><td className="px-4 py-3 text-gray-400">{[service.product, service.version].filter(Boolean).join(' ') || '—'}</td><td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs ${policyBadgeClass[service.policy_disposition || ''] || 'bg-gray-700 text-gray-300'}`}>{service.policy_disposition || 'unreviewed'}</span></td><td className="px-4 py-3">{service.web_origin ? <a href={service.web_origin} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-blue-300 hover:text-blue-200"><Globe className="h-3.5 w-3.5" /> {service.web_origin}</a> : <span className="text-gray-600">—</span>}</td><td className="px-4 py-3 text-xs text-gray-500">{formatDate(service.last_seen_at)}</td></tr>
          ))}</tbody></table></div></div>
        )}
      </section>

      {selectedScanId && previouslyObservedServices.length > 0 && (
        <details className="mb-6 rounded-lg border border-gray-800 bg-gray-950/30">
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300">Previously observed on this device ({previouslyObservedServices.length})</summary>
          <div className="flex flex-wrap gap-2 border-t border-gray-800 p-4">
            {previouslyObservedServices.map((service) => <span key={service.id} className="rounded border border-gray-800 bg-gray-950 px-2.5 py-1.5 font-mono text-xs text-gray-400">{service.port}/{String(service.transport).toUpperCase()} · <span className="font-sans">{service.service_name || 'unknown'}</span></span>)}
          </div>
          <p className="px-4 pb-4 text-xs text-gray-600">These ports were confirmed by an earlier scan, but not by the selected scan. This does not prove they are currently closed.</p>
        </details>
      )}

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
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold text-white">API request collections</h2><p className="text-sm text-gray-500">Import Postman, HAR, OpenAPI, or Swagger JSON so scans test real device endpoints—not just ports.</p></div><Button size="sm" variant="secondary" onClick={() => setRequestImportOpen(true)}><Upload className="h-4 w-4" /> Import API requests</Button></div>
        <Card className="p-4">{requestCollections.length ? <div className="space-y-4">{requestCollections.map((collection) => <div key={collection.id} className="rounded-lg border border-gray-800 bg-gray-950/40 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div className="flex min-w-0 gap-3"><FileJson className="mt-0.5 h-5 w-5 shrink-0 text-orange-300" /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><p className="truncate text-sm font-medium text-white">{collection.name}</p><span className="rounded bg-orange-500/10 px-2 py-0.5 text-[10px] uppercase text-orange-300">{collection.format === 'postman_collection' ? 'Postman' : collection.format === 'har' ? 'HAR 1.2' : collection.summary.spec_version?.startsWith('2.') ? 'Swagger 2.0' : 'OpenAPI'}</span></div><p className="mt-1 text-xs text-gray-500">{collection.summary.request_count} requests · {collection.summary.safe_request_count} safe methods · {collection.summary.state_changing_request_count} state-changing · encrypted</p><div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(collection.summary.methods).map(([method, count]) => <span key={method} className="rounded bg-gray-800 px-2 py-0.5 font-mono text-[10px] text-gray-300">{method} {count}</span>)}{collection.summary.port_hints.map((port) => <span key={port} className="rounded bg-blue-500/10 px-2 py-0.5 text-[10px] text-blue-300">port {port}</span>)}</div></div></div><Button size="sm" variant="ghost" onClick={async () => { try { await deactivateDeviceRequestCollection(deviceId, collection.id); toast.success('Request collection removed'); await load() } catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to remove collection') } }}><Trash2 className="h-4 w-4" /> Remove</Button></div><details className="mt-3 border-t border-gray-800 pt-3"><summary className="cursor-pointer text-xs font-medium text-gray-400">Preview redacted request inventory</summary><div className="mt-3 max-h-64 space-y-2 overflow-y-auto">{collection.summary.requests.map((request) => <div key={request.id} className="flex flex-wrap items-center gap-2 rounded bg-gray-900/70 px-3 py-2 text-xs"><span className={`rounded px-1.5 py-0.5 font-mono ${request.safe_method ? 'bg-emerald-500/10 text-emerald-300' : 'bg-amber-500/10 text-amber-300'}`}>{request.method}</span><span className="min-w-0 flex-1 truncate font-mono text-gray-300">{request.url}</span><span className="text-gray-600">{request.auth_type}</span></div>)}</div>{collection.summary.scripts_ignored > 0 && <p className="mt-3 text-xs text-amber-300">{collection.summary.scripts_ignored} Postman script{collection.summary.scripts_ignored === 1 ? ' was' : 's were'} ignored and will never execute.</p>}{Boolean(collection.summary.external_refs_ignored) && <p className="mt-3 text-xs text-amber-300">{collection.summary.external_refs_ignored} external reference{collection.summary.external_refs_ignored === 1 ? ' was' : 's were'} ignored; ShakerScan never fetches imported references.</p>}</details></div>)}</div> : <div className="flex items-center gap-3"><FileJson className="h-5 w-5 text-gray-600" /><div><p className="text-sm text-gray-400">No request collections imported</p><p className="text-xs text-gray-600">Port discovery can find a web server, but imported traffic or API specifications tell ShakerScan how the device API is actually used.</p></div></div>}</Card>
      </section>

      <section className="mb-6">
        <div className="mb-3 flex items-center justify-between"><div><h2 className="text-lg font-semibold text-white">Authentication profiles</h2><p className="text-sm text-gray-500">Encrypted, device-bound credentials are resolved only inside the device worker. The AI planner never sees secret values.</p></div><Button size="sm" variant="secondary" onClick={() => setCredentialOpen(true)}><KeyRound className="h-4 w-4" /> Add credential</Button></div>
        <Card className="p-4">{credentials.length ? <div className="space-y-3">{credentials.map((profile) => <div key={profile.id} className="flex items-center justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><div><p className="text-sm font-medium text-white">{profile.name}</p><p className="text-xs text-gray-500">{profile.auth_kind.replace(/_/g, ' ')}{profile.username ? ` · ${profile.username}` : ''}{profile.port ? ` · port ${profile.port}` : ''} · {profile.status}</p></div><Button size="sm" variant="ghost" onClick={async () => { try { await deactivateDeviceCredential(deviceId, profile.id); toast.success('Credential deactivated'); await load() } catch (error) { toast.error(error instanceof Error ? error.message : 'Failed to deactivate credential') } }}>Deactivate</Button></div>)}</div> : <p className="text-sm text-gray-500">No credentials configured. Unauthenticated scans remain available.</p>}</Card>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section><h2 className="mb-3 text-lg font-semibold text-white">Interfaces and identity</h2><Card className="p-4"><div className="mb-4 border-b border-gray-800 pb-3"><p className="text-xs text-gray-500">Permanent device ID</p><p className="mt-1 break-all font-mono text-xs text-gray-300">{device.id}</p></div>{interfaces.length ? <div className="space-y-3">{interfaces.map((item) => <div key={item.id} className="flex items-start justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><div><p className="font-mono text-sm text-white">{item.locator}{item.locator === device.primary_locator && <span className="ml-2 rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] text-blue-300">current</span>}</p><p className="text-xs text-gray-500">{item.hostname || item.locator_type}</p></div><div className="text-right text-xs text-gray-400"><p>{item.mac_address || 'No MAC observed'}</p><p>{item.network_zone || 'Zone not assigned'}</p></div></div>)}</div> : <p className="text-sm text-gray-500">No interfaces observed.</p>}</Card>{locatorHistory.length > 1 && <Card className="mt-3 p-4"><p className="mb-3 text-sm font-medium text-white">Address history</p><div className="space-y-2">{locatorHistory.slice(0, 8).map((entry) => <div key={entry.id} className="flex items-start justify-between gap-3 text-xs"><div><p className="font-mono text-gray-300">{entry.locator}</p><p className="text-gray-600">{entry.change_reason || entry.change_source}</p></div><p className="whitespace-nowrap text-gray-500">{formatDate(entry.changed_at)}</p></div>)}</div></Card>}</section>
        <section><h2 className="mb-3 text-lg font-semibold text-white">Recent device scans</h2><Card className="p-4">{scans.length ? <div className="space-y-3">{scans.slice(0, 8).map((item) => <div key={item.id} className="flex items-center justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><Link href={`/devices/${device.id}?scan=${item.id}`} className="min-w-0 flex-1 hover:text-blue-300"><p className="truncate text-sm text-white">{item.current_phase?.replace(/_/g, ' ') || item.scan_type}</p><p className="text-xs text-gray-500">{formatDate(item.created_at)} · show open ports</p></Link><div className="flex items-center gap-2"><ScanStatusBadge status={item.status} /><Link href={`/scans/${item.id}`} aria-label="Open full scan report" title="Open full scan report" className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-blue-300"><ExternalLink className="h-4 w-4" /></Link></div></div>)}</div> : <p className="text-sm text-gray-500">No scans yet.</p>}</Card></section>
      </div>

      <Modal open={scanOpen} title={`Scan ${device.name}`} onClose={() => setScanOpen(false)} footer={<><Button variant="secondary" onClick={() => setScanOpen(false)}>Cancel</Button><Button loading={scanning} disabled={!scan.confirm_authorized || (scan.request_collection_ids.length > 0 && !scan.confirm_request_replay)} onClick={queueScan}>Queue scan</Button></>}>
        <div className="space-y-4">
          <Field label="Coverage"><Select value={scan.profile} onChange={(event) => setScan({ ...scan, profile: event.target.value })}><option value="inventory">Inventory — top 100 TCP ports + curated UDP, lightest</option><option value="posture">Posture — all 65,535 TCP ports + curated UDP, slower</option><option value="thorough">Thorough — all 65,535 TCP ports + deeper fingerprints, heaviest</option></Select></Field>
          {scan.profile !== 'inventory' && <p className="rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">This profile checks every TCP port and can take hours on slow or filtered devices. Start with Inventory unless complete port coverage is required.</p>}
          <Field label="Known TCP ports (optional)" hint="Previously observed and policy-defined ports are included automatically."><Input value={scan.port_hints} onChange={(event) => setScan({ ...scan, port_hints: event.target.value })} placeholder="7345, 9443" /></Field>
          <Field label="Safety level" hint="Safety is independent from port coverage."><Select value={scan.safety_profile} onChange={(event) => { const safety_profile = event.target.value; setScan({ ...scan, safety_profile, include_web_dast: safety_profile === 'observe_only' ? false : scan.include_web_dast, ssh_credential_profile_id: safety_profile === 'authenticated_active' ? scan.ssh_credential_profile_id : '', web_credential_profile_id: safety_profile === 'authenticated_active' ? scan.web_credential_profile_id : '', include_ssh_host_review: safety_profile === 'authenticated_active' ? scan.include_ssh_host_review : false, allow_state_changing_requests: safety_profile === 'authenticated_active' ? scan.allow_state_changing_requests : false, allow_untrusted_tls_credentials: safety_profile === 'authenticated_active' ? scan.allow_untrusted_tls_credentials : false }) }}><option value="observe_only">Observe only — discovery and fingerprints</option><option value="safe_remote">Safe remote — bounded non-destructive checks</option><option value="authenticated_active">Authenticated active — supplied SSH/web credentials</option><option value="lab_invasive" disabled>Lab invasive — dedicated runner required</option></Select></Field>
          {scan.safety_profile === 'authenticated_active' && <div className="grid gap-4 sm:grid-cols-2"><Field label="SSH credential"><Select value={scan.ssh_credential_profile_id} onChange={(event) => setScan({ ...scan, ssh_credential_profile_id: event.target.value, include_ssh_host_review: event.target.value ? scan.include_ssh_host_review : false })}><option value="">No SSH authentication</option>{credentials.filter((profile) => profile.auth_kind.startsWith('ssh_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}{profile.port ? ` · ${profile.port}` : ''}</option>)}</Select></Field><Field label="Web credential"><Select value={scan.web_credential_profile_id} onChange={(event) => setScan({ ...scan, web_credential_profile_id: event.target.value, allow_untrusted_tls_credentials: event.target.value || scan.request_collection_ids.length ? scan.allow_untrusted_tls_credentials : false })}><option value="">No web authentication</option>{credentials.filter((profile) => profile.auth_kind.startsWith('web_') && profile.execution_compatible).map((profile) => <option key={profile.id} value={profile.id}>{profile.name}{profile.port ? ` · ${profile.port}` : ''}</option>)}</Select></Field></div>}
          {scan.safety_profile === 'authenticated_active' && <label className="flex items-start gap-3 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-100"><input type="checkbox" checked={scan.allow_untrusted_tls_credentials} disabled={!scan.web_credential_profile_id && scan.request_collection_ids.length === 0} onChange={(event) => setScan({ ...scan, allow_untrusted_tls_credentials: event.target.checked })} className="mt-1" /><span><strong className="block">Permit credentials over unverified device HTTPS</strong>Use only on a trusted local network. Without this confirmation, ShakerScan still tests the interface and reports TLS problems but withholds credentials and imported secrets.</span></label>}
          {scan.safety_profile === 'authenticated_active' && <label className="flex items-start gap-3 rounded-lg border border-violet-500/20 bg-violet-500/5 p-3 text-sm text-gray-300"><input type="checkbox" checked={scan.include_ssh_host_review} disabled={!scan.ssh_credential_profile_id} onChange={(event) => setScan({ ...scan, include_ssh_host_review: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Collect read-only SSH host evidence</strong>Runs only server-owned identity, listener, process, account, hardening, package, and update bundles. Commands and output are bounded and secrets are redacted.</span></label>}
          <label className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300"><input type="checkbox" checked={scan.include_web_dast} disabled={scan.safety_profile === 'observe_only'} onChange={(event) => setScan({ ...scan, include_web_dast: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Check web interfaces on every discovered port</strong>{scan.safety_profile === 'observe_only' ? 'Observe-only discovers origins without launching Web DAST children.' : 'Runs bounded web and imported API-request checks as hidden device-owned work.'}</span></label>
          {scan.include_web_dast && <Field label="Web coverage"><Select value={scan.web_scan_type} onChange={(event) => setScan({ ...scan, web_scan_type: event.target.value })}><option value="quick">Quick</option><option value="standard">Standard request-aware</option><option value="deep">Deep request-aware</option></Select></Field>}
          {scan.include_web_dast && requestCollections.length > 0 && <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4"><p className="text-sm font-medium text-orange-100">Use real imported API requests</p><p className="mt-1 text-xs text-gray-400">Selected collections are resolved in the worker and pinned to web origins discovered on this device.</p><div className="mt-3 space-y-2">{requestCollections.map((collection) => { const checked = scan.request_collection_ids.includes(collection.id); return <label key={collection.id} className="flex items-start gap-3 rounded border border-gray-800 bg-gray-950/60 p-3 text-sm text-gray-300"><input type="checkbox" checked={checked} onChange={(event) => { const ids = event.target.checked ? [...scan.request_collection_ids, collection.id] : scan.request_collection_ids.filter((id) => id !== collection.id); setScan({ ...scan, request_collection_ids: ids, confirm_request_replay: ids.length ? scan.confirm_request_replay : false, allow_state_changing_requests: ids.length ? scan.allow_state_changing_requests : false }) }} className="mt-1" /><span><strong className="block text-white">{collection.name}</strong>{collection.summary.request_count} requests · {collection.summary.state_changing_request_count} POST/PUT/PATCH/DELETE</span></label>})}</div>{scan.request_collection_ids.length > 0 && <div className="mt-3 space-y-2"><label className="flex items-start gap-3 text-sm text-amber-100"><input type="checkbox" checked={scan.confirm_request_replay} onChange={(event) => setScan({ ...scan, confirm_request_replay: event.target.checked })} className="mt-1" /><span>I authorize replay of safe imported requests against this device. Collection scripts are ignored and secrets stay encrypted.</span></label><label className={`flex items-start gap-3 text-sm ${scan.safety_profile === 'authenticated_active' ? 'text-red-200' : 'text-gray-600'}`}><input type="checkbox" checked={scan.allow_state_changing_requests} disabled={scan.safety_profile !== 'authenticated_active'} onChange={(event) => setScan({ ...scan, allow_state_changing_requests: event.target.checked })} className="mt-1" /><span><strong className="block">Also replay POST, PUT, PATCH, and DELETE exactly as saved</strong>This can change device state. It requires Authenticated active safety and is never enabled by the AI itself.</span></label></div>}</div>}
          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={scan.confirm_authorized} onChange={(event) => setScan({ ...scan, confirm_authorized: event.target.checked })} className="mt-1" />I confirm I am authorized to scan this device and its listening services{scan.ssh_credential_profile_id || scan.web_credential_profile_id ? ', and I authorize one bounded attempt with each selected credential' : ''}.</label>
        </div>
      </Modal>

      <Modal open={requestImportOpen} title="Import API requests" onClose={() => setRequestImportOpen(false)} footer={<><Button variant="secondary" onClick={() => setRequestImportOpen(false)}>Cancel</Button><Button loading={requestImportSaving} disabled={!requestImport.document} onClick={saveRequestCollection}>Import requests</Button></>}>
        <div className="space-y-4">
          <p className="text-sm text-gray-400">Upload captured HAR traffic, an OpenAPI/Swagger specification, or a Postman collection. ShakerScan encrypts the source, shows only a redacted inventory, and binds every request to this device.</p>
          <Field label="Display name (optional)"><Input value={requestImport.name} onChange={(event) => setRequestImport({ ...requestImport, name: event.target.value })} placeholder="LG TV local API" /></Field>
          <Field label="Format"><Select value={requestImport.format} onChange={(event) => setRequestImport({ ...requestImport, format: event.target.value as typeof requestImport.format, environment: event.target.value === 'postman_collection' ? requestImport.environment : null, environmentFile: event.target.value === 'postman_collection' ? requestImport.environmentFile : '', baseUrl: event.target.value === 'openapi' ? requestImport.baseUrl : '' })}><option value="auto">Detect from JSON</option><option value="har">HAR 1.2 — captured browser or proxy traffic</option><option value="openapi">OpenAPI 3.x or Swagger 2.0</option><option value="postman_collection">Postman Collection v2</option></Select></Field>
          <Field label="Request document JSON" required hint="Up to 5 MiB and 500 requests or operations."><label className="flex cursor-pointer items-center justify-between rounded-lg border border-dashed border-gray-700 bg-gray-950 p-4 hover:border-orange-500/50"><span className="flex items-center gap-3"><Upload className="h-5 w-5 text-orange-300" /><span><strong className="block text-sm text-white">{requestImport.documentFile || 'Choose JSON file'}</strong><span className="text-xs text-gray-500">HAR 1.2, OpenAPI 3.x, Swagger 2.0, or Postman v2</span></span></span><input type="file" accept="application/json,.json,.har" className="sr-only" onChange={(event) => chooseRequestFile(event.target.files?.[0], 'document')} /></label></Field>
          {requestImport.format === 'postman_collection' && <Field label="Postman environment JSON (optional)" hint="Variable values may contain secrets and are encrypted at rest."><label className="flex cursor-pointer items-center justify-between rounded-lg border border-dashed border-gray-700 bg-gray-950 p-4 hover:border-blue-500/50"><span className="flex items-center gap-3"><FileJson className="h-5 w-5 text-blue-300" /><span><strong className="block text-sm text-white">{requestImport.environmentFile || 'Choose environment file'}</strong><span className="text-xs text-gray-500">baseUrl, tokens, IDs, and other variables</span></span></span><input type="file" accept="application/json,.json" className="sr-only" onChange={(event) => chooseRequestFile(event.target.files?.[0], 'environment')} /></label></Field>}
          {requestImport.format === 'openapi' && <Field label="Device base URL (optional)" hint="Use this when the specification has no usable server URL."><Input value={requestImport.baseUrl} onChange={(event) => setRequestImport({ ...requestImport, baseUrl: event.target.value })} placeholder="https://192.168.1.187:3001" /></Field>}
          <div className="rounded border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs text-emerald-100"><strong className="block">Safe import boundary</strong>HAR response bodies, Postman scripts, and external OpenAPI references never execute. Imported hosts cannot redirect scanning away from this registered device. Header values, bodies, cookies, tokens, and environment values are never exposed in the UI or Device Hunt.</div>
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

export default function DeviceDetailPage() {
  return (
    <Suspense fallback={<div className="mx-auto max-w-7xl"><TableSkeleton rows={6} /></div>}>
      <DeviceDetailContent />
    </Suspense>
  )
}
