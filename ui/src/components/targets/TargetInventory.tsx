'use client'

import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
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
      getTargetAssets({search,offset,limit:50,include_inactive:includeInactive,group_by:'domain'}, controller.signal)
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
  }, [domains, search, offset, includeInactive, refreshVersion])

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
    <PageHeader title="Targets" description="Domains with their subdomains, plus IP and internal hosts. Each target shares services, credentials, findings, and instructions across Scan and Hunt." actions={<div className="flex flex-wrap gap-2"><Link href="/targets?view=domains"><Button variant="secondary">Domain discovery</Button></Link><Button onClick={() => { setAdding(true); setFormError(null) }}>Add target</Button></div>} />
    <Card className="mb-5 flex flex-wrap items-center gap-4">
      <Input aria-label="Search target assets" placeholder="Search assets or application origins" value={search} onChange={(event) => {setSearch(event.target.value);setOffset(0)}} className="max-w-md" />
      <label className="flex items-center gap-2 text-sm text-gray-400"><input type="checkbox" checked={includeInactive} onChange={(event) => {setIncludeInactive(event.target.checked);setOffset(0)}} /> Include retired targets</label>
      <span className="ml-auto text-sm text-gray-400">{loading ? 'Loading…' : `${total} target${total === 1 ? '' : 's'} · ${totalGroups} domain / host group${totalGroups === 1 ? '' : 's'}`}</span>
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
        <td className="px-4 py-4"><Link href={`/targets/${asset.id}/asset`} className="font-medium text-white hover:text-blue-300">{asset.name || asset.locator}</Link><div className="mt-1 break-all font-mono text-xs text-gray-500">{asset.locator}</div><div className="mt-1 text-xs text-gray-500">{asset.environment}{asset.is_active ? '' : ' · retired'}{asset.connected_device ? ` · ${asset.device_class || 'connected device'}` : ''}</div></td>
        <td className="px-4 py-4 text-gray-300">{asset.origin_count ?? 0}</td>
        <td className="px-4 py-4 text-gray-300">{asset.service_count ?? 0}</td>
        <td className="px-4 py-4 text-gray-300">{asset.active_findings_count ?? 0}</td>
        <td className="px-4 py-4"><div className="flex flex-wrap items-center gap-3"><Link href={`/targets/${asset.id}/asset`} className="text-blue-300">Open asset</Link><TargetSkillEditor compact targetId={asset.id} targetName={asset.name || asset.locator} hasSkill={asset.has_target_skill} /><DeleteRecordsButton selection={{ kind: 'target', target_id: asset.id }} archived={!asset.is_active} subject={asset.url || asset.locator} onDeleted={() => setRefreshVersion((value) => value + 1)} onArchived={() => setRefreshVersion((value) => value + 1)} />{featureEnabled('devices') && asset.is_active && <Button size="sm" variant="secondary" loading={busy === asset.id} onClick={() => void network(asset)}>Start network scan</Button>}</div></td>
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
