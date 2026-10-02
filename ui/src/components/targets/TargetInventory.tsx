'use client'

import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import { ArrowUpRight, Globe2, Network, Search, Layers3, Plus } from 'lucide-react'
import { Button, Card, CardSkeleton, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select } from '@/components/ui'
import { getTargetAssets, registerTargetAsset, enableTargetNetworkView, type TargetAsset, type TargetAssetGroup } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'
import { TargetSkillEditor } from './TargetSkillEditor'
import { TargetHierarchy } from './TargetHierarchy'

export function TargetInventory({ domainView }: {domainView: ReactNode}) {
  const router = useRouter()
  const parameters = useSearchParams()
  const domains = parameters.get('view') === 'domains'
  const [search, setSearch] = useState(parameters.get('search') || '')
  const [assetType, setAssetType] = useState<'all'|'web'|'network'>(() => {
    const view = parameters.get('type')
    return view === 'web' || view === 'network' ? view : 'all'
  })
  const [offset, setOffset] = useState(0)
  const [includeInactive, setIncludeInactive] = useState(false)
  const [assets, setAssets] = useState<TargetAsset[]>([])
  const [groups, setGroups] = useState<TargetAssetGroup[]>([])
  const [totalGroups, setTotalGroups] = useState(0)
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set())
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [draft, setDraft] = useState({locator:'',name:'',ports:'',environment:'production',authorized:false,approvedBy:'operator'})
  const [formError, setFormError] = useState<string | null>(null)
  const [refreshVersion, setRefreshVersion] = useState(0)

  useEffect(() => {
    if (domains) return
    const controller = new AbortController()
    setLoading(true)
    const timer = setTimeout(() => {
      getTargetAssets({search,offset,limit:50,include_inactive:includeInactive,group_by:'domain',
        asset_type:assetType === 'all' ? undefined : assetType}, controller.signal)
        .then((result) => { if (!controller.signal.aborted) {
          setAssets(result.targets); setTotal(result.total)
          // Tolerate an older server's flat response during a rolling upgrade.
          const grouped = result.groups || result.targets.map(asset => ({root_domain:asset.locator,targets:[asset]}))
          setGroups(grouped); setTotalGroups(result.total_groups ?? result.total); setError(null)
        } })
        .catch((cause) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load target inventory') })
        .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    }, 200)
    return () => { clearTimeout(timer); controller.abort() }
  }, [domains, search, offset, includeInactive, refreshVersion, assetType])

  async function add(event: FormEvent) {
    event.preventDefault(); setBusy('add'); setFormError(null)
    try {
      const parts = draft.ports.trim() ? draft.ports.split(',').map(value => value.trim()) : []
      if (parts.length > 128 || parts.some(value => !/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535)) throw new Error('Enter up to 128 TCP ports, from 1 to 65535, separated by commas')
      const id = await registerTargetAsset({locator:draft.locator,name:draft.name.trim() || undefined,
        environment:draft.environment,approvedBy:draft.authorized ? draft.approvedBy.trim() : undefined,
        portHints:[...new Set(parts.map(Number))]})
      router.push(`/targets/${id}/asset`)
    } catch (cause) { setFormError(cause instanceof Error ? cause.message : 'Could not add target') }
    finally { setBusy(null) }
  }
  async function network(asset: TargetAsset) {
    setBusy(asset.id); setError(null)
    try {
      if (!asset.connected_device) await enableTargetNetworkView(asset.id)
      router.push(`/devices/${asset.id}?action=scan`)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not open network scan') }
    finally { setBusy(null) }
  }

  if (domains) return <><div className="mb-4"><Link href="/targets" className="text-sm text-blue-300">← Asset inventory</Link><p className="mt-1 text-xs text-gray-500">Domain discovery and application-service configuration. These service records belong to the same assets.</p></div>{domainView}</>
  return <div>
    <PageHeader title="Targets" description="Your domains, devices, and services — ready for Scan and Hunt." actions={<div className="flex flex-wrap gap-2"><Link href="/targets?view=domains"><Button variant="secondary">Domain discovery</Button></Link><Button onClick={() => { setAdding(true); setFormError(null) }}><Plus className="mr-2 h-4 w-4" />Add target</Button></div>} />
    <Card className="mb-6 overflow-hidden border-gray-800/80 bg-gradient-to-br from-gray-900 to-gray-950">
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 sm:p-5">
        <div role="group" aria-label="Target view" className="flex max-w-full flex-wrap gap-1 rounded-xl bg-gray-950/80 p-1">
          {([{id:'all',label:'All targets',icon:Layers3},{id:'web',label:'Web',icon:Globe2},{id:'network',label:'IP / network',icon:Network}] as const).map(item => <button key={item.id} aria-pressed={assetType === item.id} onClick={() => {setAssetType(item.id);setOffset(0)}} className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${assetType === item.id ? 'bg-blue-500/15 text-blue-200 ring-1 ring-inset ring-blue-400/25' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'}`}><item.icon className="h-4 w-4" />{item.label}</button>)}
        </div>
        <span className="text-sm text-gray-400" aria-live="polite">{loading ? 'Updating…' : <><strong className="font-semibold text-gray-200">{total}</strong> target{total === 1 ? '' : 's'} <span className="mx-2 text-gray-700">/</span>{totalGroups} group{totalGroups === 1 ? '' : 's'}</>}</span>
      </div>
      <div className="flex flex-wrap items-center gap-4 border-t border-gray-800/70 px-4 py-3 sm:px-5">
        <div className="relative min-w-0 flex-1 sm:min-w-64"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" /><Input aria-label="Search target assets" placeholder="Search targets or services…" value={search} onChange={(event) => {setSearch(event.target.value);setOffset(0)}} className="w-full pl-9" /></div>
        <label className="flex items-center gap-2 text-xs text-gray-400"><input className="accent-blue-500" type="checkbox" checked={includeInactive} onChange={(event) => {setIncludeInactive(event.target.checked);setOffset(0)}} /> Include retired targets</label>
      </div>
    </Card>
    {error && <div className="mb-4" role="alert"><ErrorState message={error} /></div>}
    {loading && assets.length === 0 ? <CardSkeleton count={3} /> : assets.length === 0 ? <EmptyState message="No targets" hint="Add a domain, hostname, IP address, or application URL." /> : <TargetHierarchy groups={groups} searching={Boolean(search.trim())} expanded={expandedDomains} onToggle={domain => setExpandedDomains(current => {
      const next = new Set(current)
      if (next.has(domain)) next.delete(domain)
      else next.add(domain)
      return next
    })} onDiscoverySettled={domain => {
      setExpandedDomains(current => new Set(current).add(domain))
      setRefreshVersion(value => value + 1)
    }} renderAsset={(asset) => <tr key={asset.id} data-testid="target-asset-row">
        <td className="w-[35%] px-4 py-4"><div className="flex items-start gap-3"><div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${asset.connected_device || asset.locator.includes(':') || /^\d+\./.test(asset.locator) ? 'bg-cyan-500/10 text-cyan-300' : 'bg-blue-500/10 text-blue-300'}`}>{asset.connected_device ? <Network className="h-4 w-4" /> : <Globe2 className="h-4 w-4" />}</div><div className="min-w-0"><Link href={`/targets/${asset.id}/asset`} className="break-all font-medium text-gray-100 hover:text-blue-300">{asset.name || asset.locator}</Link>{asset.name && asset.name !== asset.locator && <div className="mt-0.5 break-all font-mono text-xs text-gray-500">{asset.locator}</div>}<div className="mt-1.5 flex flex-wrap gap-1.5 text-[11px] text-gray-400"><span className="rounded-md bg-gray-800/70 px-1.5 py-0.5">{asset.environment}</span>{!asset.is_active && <span className="text-amber-300">Retired</span>}{asset.connected_device && <span className="px-1.5 py-0.5">{asset.device_class || 'Network'}</span>}</div></div></div></td>
        <td className="px-3 py-4"><div className="flex flex-wrap gap-x-4 gap-y-2 text-xs"><span className="text-gray-500"><strong className="mr-1 font-medium text-gray-300">{asset.origin_count ?? 0}</strong>apps</span><span className="text-gray-500"><strong className="mr-1 font-medium text-gray-300">{asset.service_count ?? 0}</strong>ports</span><span className={(asset.active_findings_count ?? 0) > 0 ? 'text-amber-300/80' : 'text-gray-500'}><strong className="mr-1 font-medium">{asset.active_findings_count ?? 0}</strong>findings</span></div></td>
        <td className="px-4 py-4"><div className="flex flex-wrap items-center justify-end gap-2"><Link href={`/targets/${asset.id}/asset`} className="inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs text-blue-300 hover:bg-blue-400/10">Open asset<ArrowUpRight className="h-3.5 w-3.5" /></Link><TargetSkillEditor compact targetId={asset.id} targetName={asset.name || asset.locator} hasSkill={asset.has_target_skill} />{featureEnabled('devices') && asset.is_active && <Button aria-label="Start network scan" size="sm" variant="secondary" loading={busy === asset.id} onClick={() => void network(asset)}>Network scan</Button>}<DeleteRecordsButton selection={{ kind: 'target', target_id: asset.id }} archived={!asset.is_active} subject={asset.url || asset.locator} onDeleted={() => setRefreshVersion((value) => value + 1)} onArchived={() => setRefreshVersion((value) => value + 1)} /></div></td>
      </tr>} />}
    <div className="mt-4 flex items-center justify-between"><Button variant="secondary" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0,offset-50))}>Previous</Button><span className="text-xs text-gray-500">{totalGroups ? `Groups ${offset+1}–${Math.min(totalGroups,offset+50)} of ${totalGroups}` : '0 groups'}</span><Button variant="secondary" disabled={offset+50 >= totalGroups || loading} onClick={() => setOffset(offset+50)}>Next</Button></div>
    <Modal open={adding} title="Add target asset" onClose={() => {if (busy !== 'add') setAdding(false)}}><form onSubmit={(event) => void add(event)} className="space-y-4">
      <Field label="Hostname, IP address, or application URL"><Input required value={draft.locator} onChange={(event) => setDraft({...draft,locator:event.target.value})} placeholder="device.local or https://app.example.com:8443" /></Field>
      <Field label="Name"><Input value={draft.name} onChange={(event) => setDraft({...draft,name:event.target.value})} /></Field>
      {!/^https?:\/\//i.test(draft.locator.trim()) && <Field label="Known TCP ports (optional)" hint="Ports to include in network scans; these are hints, not discovered services."><Input value={draft.ports} onChange={(event) => setDraft({...draft,ports:event.target.value})} placeholder="8008, 8009, 8060" /></Field>}
      <Field label="Environment"><Select value={draft.environment} onChange={(event) => setDraft({...draft,environment:event.target.value})}><option value="production">Production</option><option value="staging">Staging</option><option value="lab">Lab</option></Select></Field>
      <label className="flex items-start gap-2 text-sm text-gray-300"><input className="mt-1" type="checkbox" checked={draft.authorized} onChange={(event) => setDraft({...draft,authorized:event.target.checked})} /><span>I am authorized to test this asset and its services. Record one standing authorization for subsequent scans and Hunts.</span></label>
      {draft.authorized && <Field label="Approved by"><Input required value={draft.approvedBy} onChange={(event) => setDraft({...draft,approvedBy:event.target.value})} /></Field>}
      {formError && <p role="alert" className="text-sm text-red-300">{formError}</p>}
      <Button type="submit" loading={busy === 'add'}>Add target</Button>
    </form></Modal>
  </div>
}
