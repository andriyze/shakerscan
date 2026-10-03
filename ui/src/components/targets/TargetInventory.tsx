'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Globe, Play, Plus, ShieldCheck, X } from 'lucide-react'
import { Button, ConfirmDialog, EmptyState, ErrorState, Field, Input, PageHeader, Skeleton, useToast } from '@/components/ui'
import { restoreTarget, scanTarget } from '@/lib/api'
import {
  createWebTarget, enableTargetNetworkView, getTargetAssets, revokeTargetAsset,
  type InventoryFacets, type TargetAsset, type TargetAssetGroup,
} from '@/lib/targetAssetApi'
import { filtersFromQuery, groupSections, inventoryParams, queryFromFilters } from '@/lib/targetInventoryModel.mjs'
import { AddTargetsDialog } from './inventory/AddTargetsDialog'
import { AuthorizeDialog } from './inventory/AuthorizeDialog'
import { InventorySummary, InventoryToolbar, type InventoryFilters } from './inventory/InventoryControls'
import { ColumnHeader, DomainGroup, NetworkGroup } from './inventory/TargetGroups'
import { assetKind, type RowActions } from './inventory/TargetRow'

const PAGE_GROUPS = 40
const SCANNING_REFRESH_MS = 10_000

/** One inventory of domains, hosts and devices, grouped by domain, ready for Scan and Hunt. */
export function TargetInventory() {
  const router = useRouter()
  const toast = useToast()
  const parameters = useSearchParams()
  const [filters, setFilters] = useState<InventoryFilters>(() => filtersFromQuery(parameters))
  const [query, setQuery] = useState(filters)
  const [offset, setOffset] = useState(0)
  const [groups, setGroups] = useState<TargetAssetGroup[]>([])
  const [facets, setFacets] = useState<InventoryFacets | null>(null)
  const [totals, setTotals] = useState({ targets: 0, groups: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshVersion, setRefreshVersion] = useState(0)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState<string | null>(null)
  const [adding, setAdding] = useState(parameters.get('add') === '1')
  const [authorizing, setAuthorizing] = useState<TargetAsset[]>([])
  const [revoking, setRevoking] = useState<TargetAsset | null>(null)
  const [revokeReason, setRevokeReason] = useState('')
  const searchInput = useRef<HTMLInputElement>(null)
  const refresh = useCallback(() => setRefreshVersion(value => value + 1), [])

  // Typing waits briefly; every other control applies at once.
  useEffect(() => {
    const delay = filters.search === query.search ? 0 : 250
    const timer = setTimeout(() => setQuery(filters), delay)
    return () => clearTimeout(timer)
  }, [filters, query.search])

  useEffect(() => {
    const search = queryFromFilters(query)
    const url = `${window.location.pathname}${search ? `?${search}` : ''}`
    if (url !== `${window.location.pathname}${window.location.search}`) {
      // Shallow: filters never round-trip through the App Router (see useUrlFilters).
      window.history.replaceState({ ...(window.history.state || {}), __shakerscanFilterEntry: true }, '', url)
    }
  }, [query])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    getTargetAssets(inventoryParams(query, offset, PAGE_GROUPS) as Parameters<typeof getTargetAssets>[0], controller.signal)
      .then(result => {
        if (controller.signal.aborted) return
        // Tolerate an older server's flat response during a rolling upgrade.
        setGroups(result.groups || result.targets.map(asset => ({ root_domain: asset.locator, targets: [asset] })))
        setFacets(result.facets || null)
        setTotals({ targets: result.total, groups: result.total_groups ?? result.total })
        setError(null)
      })
      .catch(cause => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load targets') })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [query, offset, refreshVersion])

  const assets = useMemo(() => groups.flatMap(group => group.targets), [groups])
  const scanningNow = assets.some(asset => asset.scanning)
  useEffect(() => {
    if (!scanningNow) return
    const timer = setInterval(() => { if (document.visibilityState === 'visible') refresh() }, SCANNING_REFRESH_MS)
    return () => clearInterval(timer)
  }, [scanningNow, refresh])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) && !target.isContentEditable) {
        event.preventDefault(); searchInput.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  function change(next: Partial<InventoryFilters>) {
    setFilters(current => ({ ...current, ...next }))
    setOffset(0)
    setSelected(new Set())
  }

  const narrowed = Boolean(query.search.trim() || query.findings || query.activity || query.authorization)
  const isOpen = (group: TargetAssetGroup) => expanded[group.root_domain] ?? (narrowed || group.targets.length <= 5)

  async function webScan(asset: TargetAsset) {
    const apps = (asset.origins || []).filter(origin => origin.is_active)
    if (apps.length) {
      const results = await Promise.allSettled(apps.map(origin => scanTarget(origin.id, { budget_profile: 'balanced' })))
      const started = results.filter((result): result is PromiseFulfilledResult<{ scan_id?: string }> => result.status === 'fulfilled')
      const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
      return { started: started.length, scanId: started.length === 1 ? started[0].value?.scan_id : undefined, error: failed?.reason }
    }
    // A domain with no known web app yet: register it without a scheme so the first scan
    // detects HTTP or HTTPS, then scan it.
    const web = await createWebTarget(asset.locator, asset.environment)
    const result = await scanTarget(web.id, { budget_profile: 'balanced' }) as { scan_id?: string }
    return { started: 1, scanId: result?.scan_id, error: undefined }
  }

  async function networkScan(asset: TargetAsset) {
    setBusy(asset.id)
    try {
      if (!asset.connected_device) await enableTargetNetworkView(asset.id)
      router.push(`/devices/${asset.id}?action=scan`)
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not open network scan')
      setBusy(null)
    }
  }

  async function scan(asset: TargetAsset) {
    const apps = (asset.origins || []).filter(origin => origin.is_active)
    if (!apps.length && assetKind(asset) !== 'domain') { await networkScan(asset); return }
    setBusy(asset.id)
    try {
      const outcome = await webScan(asset)
      if (outcome.started) {
        toast.success(outcome.started === 1 ? `Scan started for ${asset.locator}` : `${outcome.started} scans started for ${asset.locator}`,
          { link: outcome.scanId ? { href: `/scans/${outcome.scanId}`, label: 'View scan' } : { href: '/scans', label: 'View scans' } })
      }
      if (outcome.error) toast.error(outcome.error instanceof Error ? outcome.error.message : 'Some scans did not start')
      refresh()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not start the scan')
    } finally { setBusy(null) }
  }

  async function bulkScan() {
    const chosen = assets.filter(asset => selected.has(asset.id) && asset.is_active)
    const webable = chosen.filter(asset => (asset.origins || []).some(origin => origin.is_active) || assetKind(asset) === 'domain')
    setBusy('bulk')
    let started = 0
    const failures: string[] = []
    for (const asset of webable) {
      try {
        const outcome = await webScan(asset)
        started += outcome.started
        if (outcome.error) failures.push(asset.locator)
      } catch { failures.push(asset.locator) }
    }
    setBusy(null)
    const skipped = chosen.length - webable.length
    if (started) toast.success(`${started} scan${started === 1 ? '' : 's'} started`, { link: { href: '/scans', label: 'View scans' } })
    if (failures.length) toast.error(`Could not scan ${failures.slice(0, 3).join(', ')}${failures.length > 3 ? ` and ${failures.length - 3} more` : ''}`)
    if (skipped) toast.info(`${skipped} selected host${skipped === 1 ? ' has' : 's have'} no web app yet — use Network scan from its menu to discover services.`)
    setSelected(new Set())
    refresh()
  }

  const actions: RowActions = {
    scan: asset => void scan(asset),
    networkScan: asset => void networkScan(asset),
    authorize: chosen => setAuthorizing(chosen),
    revoke: asset => { setRevokeReason(''); setRevoking(asset) },
    restore: async asset => {
      setBusy(asset.id)
      try { await restoreTarget(asset.id); toast.success(`Restored ${asset.locator}`); refresh() }
      catch (cause) { toast.error(cause instanceof Error ? cause.message : 'Could not restore the target') }
      finally { setBusy(null) }
    },
    refresh,
  }

  const selection = {
    selected,
    toggle: (ids: string[], value: boolean) => setSelected(current => {
      const next = new Set(current)
      for (const id of ids) { if (value) next.add(id); else next.delete(id) }
      return next
    }),
  }
  const sections = groupSections(groups)
  const chosenAssets = assets.filter(asset => selected.has(asset.id))
  const firstRun = !loading && !error && facets?.total === 0 && !query.search.trim()

  return <div className={selected.size ? 'pb-24' : ''}>
    <PageHeader title="Targets" description="Every domain, host and device you test — one inventory for Scan and Hunt."
      actions={<Button onClick={() => setAdding(true)}><Plus className="h-4 w-4" aria-hidden="true" />Add targets</Button>} />

    {firstRun ? <div className="rounded-2xl border border-dashed border-gray-700 bg-gray-900/40 px-6 py-16 text-center">
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/10 text-blue-300"><Globe className="h-6 w-6" aria-hidden="true" /></div>
      <h2 className="text-lg font-semibold text-white">Add what you want to test</h2>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-gray-400">Paste domains, URLs, IP addresses or hostnames. ShakerScan groups them by domain, works out HTTP or HTTPS and finds open ports when you scan.</p>
      <Button className="mt-6" onClick={() => setAdding(true)}><Plus className="h-4 w-4" aria-hidden="true" />Add targets</Button>
    </div> : <>
      <InventorySummary facets={facets} filters={filters} onChange={change} />
      <InventoryToolbar filters={filters} facets={facets} onChange={change} searchRef={searchInput} />
      {error && <div className="mb-4" role="alert"><ErrorState message={error} /></div>}
      <div className="@container" role="table" aria-label="Targets" aria-busy={loading}>
        <ColumnHeader />
        {loading && !groups.length
          ? <div className="space-y-4">{Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-24 w-full rounded-xl" />)}</div>
          : !groups.length
            ? <div className="rounded-xl border border-gray-800 p-6"><EmptyState message="No targets match" hint="Try a different search or clear the filters."
                action={{ label: 'Clear filters', onClick: () => change({ search: '', environment: '', authorization: '', findings: '', activity: '', asset_type: '', archived: false }) }} /></div>
            : <div className={`space-y-4 ${loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}`}>
                {sections.domains.map(group => <DomainGroup key={group.root_domain} group={group} open={isOpen(group)}
                  onToggle={() => setExpanded(current => ({ ...current, [group.root_domain]: !isOpen(group) }))}
                  onDiscovered={() => { setExpanded(current => ({ ...current, [group.root_domain]: true })); refresh() }}
                  selection={selection} actions={actions} busy={busy} />)}
                <NetworkGroup targets={sections.network} selection={selection} actions={actions} busy={busy} />
              </div>}
      </div>
      {totals.groups > PAGE_GROUPS && <div className="mt-4 flex items-center justify-between gap-3">
        <Button variant="secondary" size="sm" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE_GROUPS))}>Previous</Button>
        <span className="text-xs text-gray-500">Groups {offset + 1}–{Math.min(totals.groups, offset + PAGE_GROUPS)} of {totals.groups} · {totals.targets} targets</span>
        <Button variant="secondary" size="sm" disabled={offset + PAGE_GROUPS >= totals.groups || loading} onClick={() => setOffset(offset + PAGE_GROUPS)}>Next</Button>
      </div>}
      {!loading && groups.length > 0 && totals.groups <= PAGE_GROUPS && <p className="mt-3 text-center text-xs text-gray-600" aria-live="polite">{totals.targets} target{totals.targets === 1 ? '' : 's'} in {totals.groups} group{totals.groups === 1 ? '' : 's'}</p>}
    </>}

    {selected.size > 0 && <div className="fixed inset-x-0 bottom-0 z-40 md:left-64" role="region" aria-label="Selected targets">
      <div className="mx-auto mb-4 flex w-fit max-w-[calc(100%-2rem)] flex-wrap items-center gap-2 rounded-2xl border border-gray-700 bg-gray-900/95 px-3 py-2 shadow-2xl shadow-black/50 backdrop-blur">
        <span className="px-2 text-sm font-medium text-white">{selected.size} selected</span>
        <Button size="sm" loading={busy === 'bulk'} onClick={() => void bulkScan()}><Play className="h-3.5 w-3.5" aria-hidden="true" />Scan</Button>
        <Button size="sm" variant="secondary" disabled={!chosenAssets.some(asset => !asset.authorized && asset.is_active)} onClick={() => setAuthorizing(chosenAssets)}><ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />Authorize</Button>
        <Button size="sm" variant="ghost" aria-label="Clear selection" onClick={() => setSelected(new Set())}><X className="h-4 w-4" aria-hidden="true" /></Button>
      </div>
    </div>}

    <AddTargetsDialog open={adding} onClose={() => setAdding(false)} onAdded={() => { setOffset(0); refresh() }} />
    {authorizing.length > 0 && <AuthorizeDialog assets={authorizing} onClose={() => setAuthorizing([])} onDone={(count, failures) => {
      setAuthorizing([])
      if (count) toast.success(`Authorized ${count} target${count === 1 ? '' : 's'} for testing`)
      if (failures.length) toast.error(failures[0])
      setSelected(new Set())
      refresh()
    }} />}
    <ConfirmDialog open={revoking !== null} title="Revoke authorization?"
      message={<div className="space-y-3 text-sm text-gray-300">
        <p>Scans and Hunts of <strong className="break-all text-white">{revoking?.locator}</strong> stop active testing until it is authorized again. This applies to its linked web apps and services.</p>
        <Field label="Reason"><Input value={revokeReason} maxLength={300} onChange={event => setRevokeReason(event.target.value)} placeholder="Engagement ended" /></Field>
      </div>}
      confirmLabel="Revoke" danger busy={busy === 'revoke'}
      onCancel={() => { if (busy !== 'revoke') setRevoking(null) }}
      onConfirm={async () => {
        const asset = revoking
        if (!asset) return
        setBusy('revoke')
        try {
          await revokeTargetAsset(asset.id, 'operator', revokeReason.trim() || 'Revoked from the Targets page')
          toast.success(`Revoked authorization for ${asset.locator}`)
          refresh()
        } catch (cause) { toast.error(cause instanceof Error ? cause.message : 'Could not revoke authorization') }
        finally { setBusy(null); setRevoking(null) }
      }} />
  </div>
}
