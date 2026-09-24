'use client'

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/WorkspaceLink'
import { getServiceIntelligence, type ServicePage, type ServiceRecord, type ServiceTarget } from '@/lib/serviceIntelligence'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { Button, Card, EmptyState, ErrorState } from '@/components/ui'

const PAGE_SIZE = 10
const readable = (value: string) => value.replaceAll('_', ' ')
function when(value: string | null) {
  if (!value) return 'Unknown time'
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Unknown time'
}
function listener(service: ServiceRecord) {
  // The listener is what identifies the row. The address is extra: only literal IPs are
  // retained, so a hostname-based observation has none, and leading every row with
  // "Address not retained" made an absence the loudest text on the page.
  return `${service.transport.toUpperCase()}/${service.port}`
}
function listenerWithAddress(service: ServiceRecord) {
  return service.address ? `${service.address} · ${listener(service)}` : listener(service)
}
function ago(value: string | null) {
  if (!value) return null
  const at = new Date(value).getTime()
  if (!Number.isFinite(at)) return null
  const minutes = Math.round((Date.now() - at) / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}
// Rows an operator should look at first: linked findings, then candidate weaknesses, then
// a stable listener order. Sorting by consequence is what makes the table worth scanning.
function byConsequence(a: ServiceRecord, b: ServiceRecord) {
  return b.findings.length - a.findings.length
    || b.cve_candidates.length - a.cve_candidates.length
    || a.transport.localeCompare(b.transport)
    || a.port - b.port
}
const STATUS: Record<string, string> = {
  review_in_hunt: 'Review in Hunt', manual_review: 'Manual review', unsupported: 'Not implemented',
  refresh_evidence_first: 'Refresh evidence first', no_match_in_snapshot: 'No match in curated snapshot',
  snapshot_unavailable: 'Intelligence unavailable', identity_unknown: 'Product identity needed',
  candidates_found: 'Candidates require validation',
}

function ServiceDetails({ service, target, onClose }: { service: ServiceRecord; target: ServiceTarget; onClose: () => void }) {
  const [tab, setTab] = useState('overview')
  const panel = useRef<HTMLDivElement>(null)
  useEffect(() => { panel.current?.focus({ preventScroll: true }); panel.current?.scrollIntoView({ block: 'nearest' }) }, [service.id])
  const tabs = ['overview', 'weaknesses', 'activities', 'evidence']
  return (
    <div ref={panel} tabIndex={-1} aria-label="Selected service" className="outline-none">
    <Card className="mt-4 p-5" data-testid="service-details">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="break-all text-xs text-gray-400">{target.root_domain || 'Device inventory'} → {target.locator || target.label} → {listenerWithAddress(service)}</p>
          <h3 className="mt-2 text-lg font-semibold text-white">{service.product || service.service} {service.version || '· version unknown'}</h3>
          <p className="mt-1 text-sm text-gray-400">Observation relationship—not a proven attack path.</p>
        </div>
        <Button onClick={onClose}>Close details</Button>
      </div>
      {service.binding_status === 'historical_locator' && <p role="status" className="mt-3 rounded border border-amber-500/30 p-3 text-sm text-amber-200">Historical or unbound target locator. These observations are not rebound to the current target address.</p>}
      <div className="mt-4 flex flex-wrap gap-2" role="tablist" aria-label="Service details">
        {tabs.map((item) => <button key={item} type="button" role="tab" aria-selected={tab === item} id={`service-tab-${item}`} aria-controls={`service-panel-${item}`} onClick={() => setTab(item)} className={`rounded px-3 py-2 text-sm focus-visible:outline focus-visible:outline-2 ${tab === item ? 'bg-teal-500/15 text-teal-200' : 'text-gray-400 hover:bg-gray-800'}`}>{item === 'evidence' ? 'Evidence / history' : item[0].toUpperCase() + item.slice(1)}</button>)}
      </div>
      <div role="tabpanel" id={`service-panel-${tab}`} aria-labelledby={`service-tab-${tab}`} className="mt-4 space-y-3 text-sm">
        {tab === 'overview' && <>
          <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {[
              ['Presence', `${readable(service.presence)} (${service.state})`],
              ['Identity evidence', readable(service.identity_basis)],
              ['Origin / Host context', service.application_origin || 'Not established; a port scan does not prove a virtual host'],
              ['Freshness', `${readable(service.freshness)}${service.identity_stale ? ' · identity needs refresh' : ''}`],
              ['Detection', `${service.detection_method || 'Method not retained'}${service.detection_confidence !== null ? ` · Nmap confidence ${service.detection_confidence}/10` : ''}`],
              ['Encryption', service.encrypted === null ? 'Not established' : service.encrypted ? 'Observed encrypted' : 'Observed cleartext'],
              ['Last observed', when(service.last_seen_at)],
              ['Identity observed', when(service.identity_observed_at)],
              ['Source execution', readable(service.observation_status)],
            ].map(([label, value]) => <div key={label}><dt className="text-xs text-gray-500">{label}</dt><dd className="mt-1 break-words text-gray-200">{value}</dd></div>)}
          </dl>
          {service.cpes.length > 0 && <p className="break-all text-xs text-gray-500">Observed CPE hints: {service.cpes.join(', ')}</p>}
          <p className="text-gray-400">{service.cve_candidates.length} CVE candidates · {service.cve_candidates.reduce((sum, candidate) => sum + candidate.exploit_references.length, 0)} public exploit references · {service.findings.length} exactly linked active findings.</p>
          <p className="text-xs text-gray-500">A supported generic capability is not a registered validator for a particular CVE. The evidence below determines what was actually demonstrated.</p>
        </>}
        {tab === 'weaknesses' && <>
          <p className="text-gray-400">{STATUS[service.intelligence_status] || readable(service.intelligence_status)}. Matching a banner or version never verifies a vulnerability.</p>
          {service.candidates_truncated && <p className="text-amber-300">Candidate list truncated; inspect the pinned snapshot for further matches.</p>}
          {service.cve_candidates.map((candidate) => <div key={candidate.id} className="rounded border border-gray-800 p-3">
            <a href={candidate.advisory_url} target="_blank" rel="noopener noreferrer" className="font-medium text-blue-300 hover:underline">{candidate.id}</a>
            <span className="ml-2 rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-200">Candidate · {candidate.severity}</span>
            <p className="mt-2 text-gray-200">{candidate.title}</p>
            <p className="mt-1 text-xs text-gray-400">{readable(candidate.match_type)} · identity confidence: {candidate.confidence} · {readable(candidate.local_validation)}</p>
            <p className="mt-2 text-gray-400">Prerequisites: {candidate.prerequisites.join('; ')}.</p>
            {candidate.identity_stale && <p className="text-amber-300">Product evidence is stale or undated.</p>}
            {candidate.exploit_references.length === 0 ? <p className="mt-2 text-xs text-gray-500">No exploit reference in this snapshot. This is not evidence that none exists.</p> : <div className="mt-2 space-y-1">{candidate.exploit_references.map((ref) => <p key={ref.url}><a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-blue-300 hover:underline">{ref.source} · {readable(ref.kind)}</a><span className="ml-2 text-xs text-gray-500">Reference only; never executed here</span></p>)}</div>}
          </div>)}
          <h4 className="pt-2 font-medium text-white">Exactly linked active findings</h4>
          {service.findings.length === 0 && <p className="text-gray-500">No active finding could be unambiguously linked to this service. This is not a clean assessment.</p>}
          {service.findings.map((finding) => <p key={finding.id}><Link href={`/findings/${encodeURIComponent(finding.id)}`} className="text-blue-300 hover:underline">{finding.title}</Link><span className="ml-2 text-xs text-gray-500">{finding.severity} · {finding.proof_state || finding.last_verification_verdict || 'Proof not supplied'}</span></p>)}
        </>}
        {tab === 'activities' && <>
          <p className="text-gray-400">Suggestions only. Opening Hunt does not start testing or approve any action. Hunt requires an active planner session.</p>
          {service.activities.map((activity) => <div key={activity.id} className="rounded border border-gray-800 p-3">
            <div className="flex flex-wrap justify-between gap-2"><h4 className="font-medium text-gray-200">{activity.title}</h4><span className="text-xs text-amber-200">{STATUS[activity.status] || readable(activity.status)}</span></div>
            <p className="mt-1 text-gray-400">{activity.reason}</p>
            {activity.capability && <p className="mt-2 text-xs text-gray-500">Canonical capability: {activity.capability} · risk: {activity.risk_tier} · approval: {activity.required_approval || 'Current run policy'}</p>}
          </div>)}
          {service.hunt_href && <Link href={service.hunt_href} className="inline-block rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-500">Prepare investigation in Hunt</Link>}
        </>}
        {tab === 'evidence' && <>
          {service.evidence_truncated && <p className="text-amber-300">Only the most recent evidence/history entries are shown.</p>}
          {service.evidence.map((evidence, index) => <div key={`${evidence.ref}:${index}`} className="rounded border border-gray-800 p-3">
            <p className="break-all font-mono text-xs text-gray-300">{evidence.ref}</p>
            <p className="mt-1 text-gray-500">{when(evidence.observed_at)} · {evidence.vantage || 'Runner not retained'} · {evidence.status}</p>
            {evidence.sha256 && <p className="mt-1 break-all text-xs text-gray-500">SHA-256: {evidence.sha256}</p>}
            {evidence.hunt_id && <Link href={`/hunt?target=${encodeURIComponent(target.id)}&run=${encodeURIComponent(evidence.hunt_id)}`} className="mt-2 inline-block text-blue-300 hover:underline">Open source Hunt</Link>}
            {evidence.scan_id && <Link href={`/scans/${encodeURIComponent(evidence.scan_id)}`} className="mt-2 inline-block text-blue-300 hover:underline">Open source scan</Link>}
          </div>)}
          <h4 className="pt-2 font-medium text-white">Observed history</h4>
          {service.history.map((item, index) => <p key={`${item.evidence_ref}:${index}`} className="text-gray-400">{when(item.observed_at)} · {item.service} {item.product || ''} {item.version || 'version unknown'} · {item.state}</p>)}
        </>}
      </div>
    </Card>
    </div>
  )
}

export function ServicesView({ rootDomain, revision, onBusyChange }: { rootDomain?: string; revision: number; onBusyChange: (busy: boolean) => void }) {
  const { filters, setFilters } = useUrlFilters()
  const kind = filters.service_kind === 'web' || filters.service_kind === 'device' ? filters.service_kind : 'all'
  const query = typeof filters.service_query === 'string' ? filters.service_query : ''
  const pageValue = Number(filters.service_page)
  const page = Number.isInteger(pageValue) && pageValue >= 1 && pageValue <= 100001 ? pageValue : 1
  const selectedId = typeof filters.service_id === 'string' ? filters.service_id : ''
  const [search, setSearch] = useState(query)
  const [data, setData] = useState<ServicePage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retry, setRetry] = useState(0)
  useEffect(() => { setSearch(query) }, [query])
  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setData(null)
    setError(null)
    onBusyChange(true)
    getServiceIntelligence({ rootDomain, targetKind: kind, search: query, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setData(result) })
      .catch((cause) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Failed to load services') })
      .finally(() => { if (!controller.signal.aborted) { setLoading(false); onBusyChange(false) } })
    return () => { controller.abort(); onBusyChange(false) }
  }, [rootDomain, kind, query, page, revision, retry, onBusyChange])
  const selectedTarget = data?.targets.find((target) => target.services.some((service) => service.id === selectedId))
  const selected = selectedTarget?.services.find((service) => service.id === selectedId)
  const updateFilters = (updates: Record<string, string | undefined>) => setFilters({ service_page: undefined, service_id: undefined, ...updates })
  return (
    <section className="space-y-4" aria-label="Service Intelligence">
      <Card className="p-4">
        <h2 className="font-semibold text-white">Service Intelligence</h2>
        <p className="mt-1 text-sm text-gray-400">Domain → target → listener → service/version → candidate weaknesses → investigation activities.</p>
        <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); updateFilters({ service_query: search.trim() || undefined }) }}>
          <label className="text-xs text-gray-400">Target kind<select aria-label="Service target kind" value={kind} onChange={(event) => updateFilters({ service_kind: event.target.value === 'all' ? undefined : event.target.value })} className="mt-1 block rounded border border-gray-700 bg-gray-900 p-2 text-sm text-white"><option value="all">Web and devices</option><option value="web">Web targets</option><option value="device">Devices</option></select></label>
          <label className="text-xs text-gray-400">Target name or locator<input aria-label="Search service targets" value={search} maxLength={200} onChange={(event) => setSearch(event.target.value)} className="mt-1 block w-64 rounded border border-gray-700 bg-gray-900 p-2 text-sm text-white" placeholder="Search targets" /></label>
          <Button type="submit">Search</Button>
        </form>
      </Card>
      {loading && <p role="status" className="text-sm text-gray-400">Loading retained service evidence…</p>}
      {error && <ErrorState message={error} onRetry={() => setRetry((value) => value + 1)} />}
      {data && <>
        <p className="text-sm text-gray-400">{data.total_targets} matching targets · {data.targets.reduce((sum, target) => sum + target.services.length, 0)} service observations on this page. Counts are separate from web vulnerability scores.</p>
        <details className="rounded border border-gray-800 p-3 text-xs text-gray-400"><summary className="cursor-pointer">Intelligence: {data.intelligence.status} · {data.intelligence.record_count} curated records · snapshot {when(data.intelligence.generated_at)}</summary><div className="mt-2 space-y-1">{[...data.intelligence.limitations, ...data.limitations].map((item) => <p key={item}>{item}</p>)}</div></details>
        {data.intelligence.status !== 'available' && <p role="status" className="text-sm text-amber-200">Intelligence is unavailable or failed integrity checks. Empty candidate lists must not be read as a clean result.</p>}
        {data.targets.length === 0 && <EmptyState message="No targets on this page" hint="Clear a filter or return to the first page. Missing service evidence is not a clean scan." />}
        {data.targets.map((target) => <Card key={`${target.kind}:${target.id}`} className="overflow-hidden">
          <div className="border-b border-gray-800 p-4"><h3 className="break-words font-medium text-white">{target.root_domain ? `${target.root_domain} → ` : ''}{target.label}</h3><p className="mt-1 break-all text-xs text-gray-500">{target.kind} · {target.locator} · {target.source_count} evidence sources</p>{target.warnings.map((warning) => <p key={warning} className="mt-2 text-xs text-amber-200">{warning}</p>)}{target.unlinked_findings_count > 0 && <p role="status" className="mt-2 rounded border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-200"><strong className="font-semibold">{target.unlinked_findings_count} active findings are not shown below.</strong> They are scoped to this target but could not be tied to one listener, so the table understates what is known. Open Findings for this target to see them.</p>}{target.findings_truncated && <p className="mt-2 text-xs text-amber-200">Active-finding association window is truncated.</p>}</div>
          {target.services.length === 0 ? <p className="p-4 text-sm text-gray-500">No positive service evidence retained in this window. Run an authorized Scan or Hunt with the relevant discovery policy to collect evidence.</p> : (() => {
            const services = [...target.services].sort(byConsequence)
            const notable = services.filter((service) => service.findings.length > 0 || service.cve_candidates.length > 0).length
            const addressed = services.filter((service) => service.address).length
            return <>
              <p className="border-b border-gray-800 px-4 py-2 text-xs text-gray-400">{services.length} listeners{notable > 0 ? <> · <span className="text-amber-200">{notable} with linked findings or candidates</span></> : ' · nothing linked to any of them'}{addressed === 0 && ' · no network address retained for this target'}</p>
              <div className="overflow-x-auto"><table className="w-full min-w-[740px] text-left text-sm"><thead className="border-b border-gray-800 text-xs text-gray-500"><tr>{['Listener', 'Identity', 'Linked', 'Last seen', ''].map((label, index) => <th key={index} scope="col" className="px-4 py-3">{label || 'Details'}</th>)}</tr></thead><tbody className="divide-y divide-gray-800">{services.map((service) => {
                const linked = service.findings.length
                const candidates = service.cve_candidates.length
                const quiet = linked === 0 && candidates === 0
                const seen = ago(service.last_seen_at)
                return <tr key={service.id} className={service.id === selectedId ? 'bg-teal-500/10' : 'hover:bg-gray-800/40'}>
                  <td className="px-4 py-3"><p className={quiet ? 'text-gray-400' : 'font-medium text-gray-100'}>{listener(service)} · {service.service}</p><p className="mt-1 text-xs text-gray-500">{readable(service.presence)}{service.address && <> · {service.address}</>}</p></td>
                  <td className="px-4 py-3 text-gray-300">{service.product ? <>{service.product}{service.version && <> {service.version}</>}</> : <span className="text-gray-600">&mdash;</span>}<p className="mt-1 text-xs text-gray-500">{readable(service.identity_basis)}{service.identity_stale && <> · <span className="text-gray-400">identity stale</span></>}</p></td>
                  <td className="px-4 py-3">{linked > 0 ? <span className="font-medium text-amber-200">{linked} finding{linked === 1 ? '' : 's'}</span> : <span className="text-gray-600">&mdash;</span>}<p className="mt-1 text-xs text-gray-500">{candidates > 0 ? `${candidates} CVE candidate${candidates === 1 ? '' : 's'}` : ''}</p></td>
                  <td className="px-4 py-3 text-gray-400">{seen || readable(service.freshness)}<p className="mt-1 text-xs text-gray-500">{readable(service.observation_status)}</p></td>
                  <td className="px-4 py-3"><button type="button" aria-label={`Inspect ${service.transport}/${service.port} on ${target.label}`} aria-expanded={selectedId === service.id} onClick={() => setFilters({ service_id: selectedId === service.id ? undefined : service.id })} className="rounded px-2 py-1 text-blue-300 hover:bg-gray-700 focus-visible:outline focus-visible:outline-2">Inspect</button></td>
                </tr>
              })}</tbody></table></div>
            </>
          })()}
        </Card>)}
        {selected && selectedTarget && <ServiceDetails key={selected.id} service={selected} target={selectedTarget} onClose={() => setFilters({ service_id: undefined })} />}
        {selectedId && !selected && <p role="status" className="text-sm text-amber-200">The selected service is not in this evidence window. Refresh or inspect its owning target; no stale details are displayed.</p>}
        <div className="flex items-center justify-between"><Button disabled={page <= 1} onClick={() => setFilters({ service_page: page <= 2 ? undefined : String(page - 1), service_id: undefined })}>Previous</Button><span className="text-sm text-gray-400">Target page {page}</span><Button disabled={!data.has_more} onClick={() => setFilters({ service_page: String(page + 1), service_id: undefined })}>Next</Button></div>
      </>}
    </section>
  )
}
