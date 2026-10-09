'use client'

import { useCallback, useEffect, useState } from 'react'
import { SharedServicePorts } from './SharedServicePorts'
import { TargetSkillEditor } from './TargetSkillEditor'
import { TargetActionsEditor } from './TargetActionsEditor'
import { TargetKnowledgeEditor } from './TargetKnowledgeEditor'
import { TargetHuntPermissions } from './TargetHuntPermissions'
import { AssetCollections } from '@/components/collections/AssetCollections'
import { AssetCredentials } from '@/components/collections/AssetCredentials'
import { useRouter } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import { Button, Card, CardSkeleton, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select } from '@/components/ui'
import { formatDate } from '@/lib/api'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { authorizeTargetAsset, enableTargetNetworkView, getTargetAsset, getTargetAssetHistory, renameTargetAsset, type AssetDetail, type AssetHistory, type AssetHistoryKind } from '@/lib/targetAssetApi'

export function TargetAssetDetail({ id }: {id: string}) {
  const router = useRouter()
  const [data,setData] = useState<AssetDetail | null>(null)
  const [error,setError] = useState<string | null>(null)
  const [busy,setBusy] = useState(false)
  const [refresh,setRefresh] = useState(0)
  const [edit,setEdit] = useState<'name' | 'authority' | null>(null)
  const [value,setValue] = useState('')
  const [confirmed,setConfirmed] = useState(false)
  const [historyKind,setHistoryKind] = useState<AssetHistoryKind>('scans')
  const [historyOffset,setHistoryOffset] = useState(0)
  const [history,setHistory] = useState<AssetHistory | null>(null)
  const [historyError,setHistoryError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    getTargetAsset(id,controller.signal).then((result) => {if (!controller.signal.aborted) {setData(result);setError(null)}})
      .catch((cause) => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load target')})
    return () => controller.abort()
  },[id,refresh])
  const assetId = data?.target.id
  useEffect(() => {
    if (!assetId) return
    const controller = new AbortController(); setHistory(null);setHistoryError(null)
    getTargetAssetHistory(assetId,historyKind,historyOffset,controller.signal)
      .then((result) => {if (!controller.signal.aborted) setHistory(result)})
      .catch((cause) => {if (!controller.signal.aborted) setHistoryError(cause instanceof Error ? cause.message : 'Could not load history')})
    return () => controller.abort()
  },[assetId,historyKind,historyOffset,refresh])

  const openNetwork = useCallback(async (hunt = false) => {
    if (!data) return
    setBusy(true);setError(null)
    try {
      if (!data.target.connected_device) await enableTargetNetworkView(data.target.id)
      router.push(hunt ? `/devices/${data.target.id}/agent` : `/devices/${data.target.id}?action=scan`)
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not open network workflow')}
    finally {setBusy(false)}
  },[data,router])
  async function save() {
    if (!data || !value.trim()) return
    setBusy(true)
    try {
      if (edit === 'name') await renameTargetAsset(data.target.id,value.trim())
      else {if (!confirmed) return; await authorizeTargetAsset(data.target.id,value.trim(),data.target.environment)}
      setEdit(null);setRefresh((current) => current+1);setError(null)
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not update target')}
    finally {setBusy(false)}
  }
  if (!data) return error ? <ErrorState message={error} /> : <CardSkeleton count={4} />
  const target = data.target
  const authorizedOrigins = data.origins.filter(origin => origin.is_active && origin.authorized).length
  return <div>
    <div className="mb-4"><Link href="/targets" className="text-sm text-blue-300">← Targets</Link></div>
    <PageHeader title={target.name || target.locator} description={`${target.locator} · ${target.environment} · one asset across application and network views`} actions={<div className="flex flex-wrap gap-2">
      <Button variant="secondary" onClick={() => {setEdit('name');setValue(target.name || target.locator)}}>Rename</Button>
      {featureEnabled('devices') && target.is_active && <><Button variant="secondary" loading={busy} onClick={() => void openNetwork(true)}>Network Hunt</Button><Button loading={busy} onClick={() => void openNetwork()}>Start network scan</Button></>}
    </div>} />
    <SharedServicePorts knowledge={data.service_intelligence} targetId={target.id} />
    <TargetSkillEditor targetId={target.id} targetName={target.name || target.locator} />
    <TargetActionsEditor targetId={target.id} />
    <div className="mb-6"><TargetKnowledgeEditor targetId={target.id} /></div>
    <TargetHuntPermissions targetId={target.id} />
    {error && <div className="mb-4" role="alert"><ErrorState message={error} /></div>}
    <Card className="mb-6"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="text-sm text-gray-300">Asset ID <span className="font-mono text-xs text-gray-500">{target.id}</span></p><p className="mt-2 text-sm text-gray-400">{target.connected_device ? [target.device_class,target.manufacturer,target.model,target.firmware_version].filter(Boolean).join(' · ') : 'No device-specific profile yet. Enabling the network view reuses this target.'}</p><p className="mt-2 text-xs text-gray-500">Credentials, collections, findings, and execution history are shared. Each application origin keeps its exact scope.</p></div><div className="text-sm">{data.authorization ? <span className="text-emerald-300">Authorized by {data.authorization.approved_by}</span> : <>{authorizedOrigins > 0 && <p className="mb-2 max-w-xs text-xs text-teal-300">{authorizedOrigins === 1 ? 'One web address is' : `${authorizedOrigins} web addresses are`} authorized on {authorizedOrigins === 1 ? 'its' : 'their'} own; scans of {authorizedOrigins === 1 ? 'it' : 'them'} run under that authority. Authorizing the asset also covers the host and its other services.</p>}<Button variant="secondary" onClick={() => {setEdit('authority');setValue('operator');setConfirmed(false)}}>Authorize asset</Button></>}{target.connected_device && <div className="mt-3"><Link href={`/devices/${target.id}`} className="text-blue-300">Connected Devices view →</Link></div>}</div></div></Card>
    <section className="mb-6"><h2 className="mb-3 text-lg font-semibold text-white">Application origins</h2>{data.origins.length === 0 ? <EmptyState message="No application origins recorded" hint="A network scan can discover HTTP services. Adding a URL on this host attaches it to this same asset." /> : <Card className="overflow-hidden p-0"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Origin</th><th className="px-4 py-3">Last assessment</th><th className="px-4 py-3">Scope / actions</th></tr></thead><tbody className="divide-y divide-gray-800">{data.origins.map((origin) => <tr key={origin.id}><td className="px-4 py-3"><Link href={`/targets/${origin.id}/asset`} className="break-all text-blue-300">{origin.url}</Link><p className="mt-1 text-xs text-gray-500">{origin.name || 'Application service'}</p></td><td className="px-4 py-3 text-gray-400">{origin.last_scanned_at ? formatDate(origin.last_scanned_at) : 'Not scanned'}{origin.last_grade && <span className="ml-2">{origin.last_grade}</span>}</td><td className="px-4 py-3">{!origin.current_membership ? <span className="text-xs text-amber-200">Historical address; no inherited credentials or authority</span> : origin.is_active ? <><Link href={`/scan/new?${new URLSearchParams({target:origin.url})}`} className="text-blue-300">Configure web scan</Link><span className={`ml-2 text-xs ${origin.authorized ? 'text-emerald-300' : 'text-gray-500'}`}>{origin.authorized ? 'Authorized' : 'Not authorized'}</span></> : <span className="text-gray-500">Inactive service</span>}<div className="mt-2"><TargetSkillEditor compact targetId={origin.id} targetName={origin.name || origin.url} /></div></td></tr>)}</tbody></table></div></Card>}</section>
    <section className="mb-6"><h2 className="mb-3 text-lg font-semibold text-white">Shared inputs</h2><div className="space-y-4"><AssetCredentials assetId={target.id} credentials={data.credentials} /><AssetCollections assetId={target.id} assetLocator={target.locator} origins={data.origins} collections={data.request_collections} onChanged={() => setRefresh(value => value + 1)} /></div></section>
    <section><div className="mb-3 flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold text-white">Asset history</h2><Select aria-label="History kind" value={historyKind} onChange={(event) => {setHistoryKind(event.target.value as AssetHistoryKind);setHistoryOffset(0)}}><option value="scans">Scans</option><option value="findings">Findings</option><option value="hunts">Hunts</option></Select></div>{historyError ? <ErrorState message={historyError} /> : !history ? <CardSkeleton count={1} /> : history.items.length === 0 ? <EmptyState message="No history for this selection" /> : <Card className="overflow-hidden p-0"><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-gray-900 text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Record / service</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Created</th></tr></thead><tbody className="divide-y divide-gray-800">{history.items.map((item) => <tr key={item.id}><td className="px-4 py-3"><div className="break-all text-gray-200">{historyKind === 'scans' ? <Link href={`/scans/${item.id}`} className="text-blue-300">{item.target_url || item.id}</Link> : item.title || item.id}</div><div className="mt-1 text-xs text-gray-500">{item.run_kind || item.scan_type || item.severity || historyKind} · {item.target_id === target.id ? 'Host' : 'Application service'}</div></td><td className="px-4 py-3 text-gray-400">{item.status || 'Recorded'}{item.grade ? ` · ${item.grade}` : ''}</td><td className="px-4 py-3 text-xs text-gray-500">{formatDate(item.created_at)}</td></tr>)}</tbody></table></div></Card>}<div className="mt-4 flex items-center justify-between"><Button variant="secondary" disabled={!history || historyOffset===0} onClick={() => setHistoryOffset(Math.max(0,historyOffset-25))}>Previous</Button><span className="text-xs text-gray-500">{history ? `${history.total} records` : 'Loading…'}</span><Button variant="secondary" disabled={!history || historyOffset+25>=history.total} onClick={() => setHistoryOffset(historyOffset+25)}>Next</Button></div></section>
    <Modal open={edit !== null} title={edit === 'name' ? 'Rename asset' : 'Authorize asset and services'} onClose={() => {if (!busy) setEdit(null)}}><div className="space-y-4"><Field label={edit === 'name' ? 'Name' : 'Approved by'}><Input value={value} onChange={(event) => setValue(event.target.value)} /></Field>{edit === 'authority' && <label className="flex items-start gap-2 text-sm text-gray-300"><input type="checkbox" className="mt-1" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I am authorized to test this host and its linked services. Reuse this authority until revoked; explicit service restrictions still apply. It covers the credentials attached to this target.</span></label>}<Button disabled={!value.trim() || (edit === 'authority' && !confirmed)} loading={busy} onClick={() => void save()}>Save</Button></div></Modal>
  </div>
}
