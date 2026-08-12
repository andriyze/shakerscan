'use client'

import Link from 'next/link'
import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { Globe, Router } from 'lucide-react'
import { formatDate, getDevice, scanDevice, type DeviceDetailResponse } from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Modal, PageHeader, ScanStatusBadge, Select, TableSkeleton, useToast } from '@/components/ui'

export default function DeviceDetailPage() {
  const params = useParams()
  const deviceId = params.id as string
  const toast = useToast()
  const [data, setData] = useState<DeviceDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [scanOpen, setScanOpen] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scan, setScan] = useState({ profile: 'posture', include_web_dast: true, web_scan_type: 'standard', confirm_authorized: false })

  const load = useCallback(async () => {
    try { setData(await getDevice(deviceId)); setFailed(false) } catch { setFailed(true) } finally { setLoading(false) }
  }, [deviceId])

  useEffect(() => { load(); const timer = setInterval(load, 10_000); return () => clearInterval(timer) }, [load])

  async function queueScan() {
    setScanning(true)
    try {
      const queued = await scanDevice(deviceId, {
        profile: scan.profile as 'inventory' | 'posture' | 'thorough',
        confirm_authorized: scan.confirm_authorized,
        include_web_dast: scan.include_web_dast,
        web_scan_type: scan.web_scan_type as 'quick' | 'standard' | 'deep',
        max_web_origins: 8,
      })
      setScanOpen(false)
      toast.success('Device scan queued', { link: { href: `/scans/${queued.scan_id}`, label: 'View report' } })
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to queue scan')
    } finally { setScanning(false) }
  }

  if (loading) return <div className="mx-auto max-w-7xl"><TableSkeleton rows={6} /></div>
  if (failed || !data) return <div className="mx-auto max-w-7xl"><ErrorState message="Could not load connected device" onRetry={load} /></div>
  const { device, interfaces, services, scans } = data

  return (
    <div className="mx-auto max-w-7xl">
      <PageHeader backHref="/devices" backLabel="Connected devices" title={device.name} description={device.primary_locator} icon={<Router className="h-6 w-6" />} actions={<><Link href={`/findings?source_type=device&device_target_id=${device.id}`} className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 hover:bg-gray-700">View findings</Link><Button onClick={() => { setScan({ profile: 'posture', include_web_dast: true, web_scan_type: 'standard', confirm_authorized: false }); setScanOpen(true) }}>Scan device</Button></>} />

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
            <tr key={service.id}><td className="px-4 py-3 font-mono text-gray-200">{service.port}/{service.transport}</td><td className="px-4 py-3 text-white">{service.service_name}</td><td className="px-4 py-3 text-gray-400">{[service.product, service.version].filter(Boolean).join(' ') || '—'}</td><td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs ${service.policy_disposition === 'deny' ? 'bg-red-500/15 text-red-300' : service.policy_disposition === 'review' ? 'bg-amber-500/15 text-amber-300' : 'bg-emerald-500/15 text-emerald-300'}`}>{service.policy_disposition || 'unreviewed'}</span></td><td className="px-4 py-3">{service.web_origin ? <a href={service.web_origin} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-blue-300 hover:text-blue-200"><Globe className="h-3.5 w-3.5" /> {service.web_origin}</a> : <span className="text-gray-600">—</span>}</td><td className="px-4 py-3 text-xs text-gray-500">{formatDate(service.last_seen_at)}</td></tr>
          ))}</tbody></table></div></div>
        )}
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section><h2 className="mb-3 text-lg font-semibold text-white">Interfaces and identity</h2><Card className="p-4">{interfaces.length ? <div className="space-y-3">{interfaces.map((item) => <div key={item.id} className="flex items-start justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0"><div><p className="font-mono text-sm text-white">{item.locator}</p><p className="text-xs text-gray-500">{item.hostname || item.locator_type}</p></div><div className="text-right text-xs text-gray-400"><p>{item.mac_address || 'No MAC observed'}</p><p>{item.network_zone || 'Zone not assigned'}</p></div></div>)}</div> : <p className="text-sm text-gray-500">No interfaces observed.</p>}</Card></section>
        <section><h2 className="mb-3 text-lg font-semibold text-white">Recent device scans</h2><Card className="p-4">{scans.length ? <div className="space-y-3">{scans.slice(0, 8).map((item) => <Link key={item.id} href={`/scans/${item.id}`} className="flex items-center justify-between gap-3 border-b border-gray-800 pb-3 last:border-0 last:pb-0 hover:text-blue-300"><div><p className="text-sm text-white">{item.current_phase?.replace(/_/g, ' ') || item.scan_type}</p><p className="text-xs text-gray-500">{formatDate(item.created_at)}</p></div><ScanStatusBadge status={item.status} /></Link>)}</div> : <p className="text-sm text-gray-500">No scans yet.</p>}</Card></section>
      </div>

      <Modal open={scanOpen} title={`Scan ${device.name}`} onClose={() => setScanOpen(false)} footer={<><Button variant="secondary" onClick={() => setScanOpen(false)}>Cancel</Button><Button loading={scanning} disabled={!scan.confirm_authorized} onClick={queueScan}>Queue scan</Button></>}>
        <div className="space-y-4">
          <Field label="Coverage"><Select value={scan.profile} onChange={(event) => setScan({ ...scan, profile: event.target.value })}><option value="inventory">Inventory — top TCP and common UDP</option><option value="posture">Posture — all TCP and common UDP</option><option value="thorough">Thorough — all TCP with deeper fingerprinting</option></Select></Field>
          <label className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300"><input type="checkbox" checked={scan.include_web_dast} onChange={(event) => setScan({ ...scan, include_web_dast: event.target.checked })} className="mt-1" /><span><strong className="block text-white">Check web interfaces on every discovered port</strong>Runs bounded passive Web DAST as hidden device-owned checks.</span></label>
          {scan.include_web_dast && <Field label="Web coverage"><Select value={scan.web_scan_type} onChange={(event) => setScan({ ...scan, web_scan_type: event.target.value })}><option value="quick">Quick</option><option value="standard">Standard</option><option value="deep">Deep passive</option></Select></Field>}
          <label className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-100"><input type="checkbox" checked={scan.confirm_authorized} onChange={(event) => setScan({ ...scan, confirm_authorized: event.target.checked })} className="mt-1" />I confirm I am authorized to scan this device and its listening services.</label>
        </div>
      </Modal>
    </div>
  )
}
