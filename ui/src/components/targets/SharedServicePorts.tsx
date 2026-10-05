import Link from '@/components/WorkspaceLink'
import { Card, EmptyState } from '@/components/ui'
import { partitionSharedServices, sharedServiceHuntHref } from '@/lib/sharedServicePorts.mjs'

export interface SharedServiceKnowledge {
  services: Array<{id:string; target_id:string; transport:string; port:number; address?:string|null;
    service?:string|null; application_origin?:string|null; binding_status?:string; observation_status?:string;
    /** Last nmap/receipt state, e.g. `open` or `open|filtered` (no reply). */
    state?:string
    /** API classification: `observed_open`, `inconclusive` or `not_observed`. */
    presence?:string
    evidence:Array<{hunt_id?:string|null; scan_id?:string|null; status?:string}>}>
  warnings: string[]
  sources_truncated: boolean
}

export function SharedServicePorts({knowledge,targetId}: {knowledge?:SharedServiceKnowledge;targetId:string}) {
  if (!knowledge) return null
  const {confirmed, unconfirmed, notObservedCount} = partitionSharedServices(knowledge.services)
  return <section className="mb-6">
    <h2 className="mb-3 text-lg font-semibold text-white">Ports discovered across Scans and Hunts</h2>
    {confirmed.length === 0 ? <EmptyState message={knowledge.services.length === 0 ? 'No retained service evidence' : 'No confirmed open ports'} hint="Port discovery in Hunt and network scans enrich this same target. Missing evidence does not establish closed ports." /> : <Card className="overflow-x-auto p-0"><table className="w-full text-left text-sm">
      <thead className="text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Port / address</th><th className="px-4 py-3">Service</th><th className="px-4 py-3">Evidence</th><th className="px-4 py-3">Investigate</th></tr></thead>
      <tbody className="divide-y divide-gray-800">{confirmed.map(service => {
        const huntHref = sharedServiceHuntHref(service, targetId)
        return <tr key={service.id}>
          <td className="px-4 py-3 font-mono text-gray-300">{service.port}/{service.transport}<div className="text-xs text-gray-500">{service.address || 'Address unattributed'}</div></td>
          <td className="px-4 py-3 text-gray-300">{service.service || 'Not identified'}<div className="text-xs text-gray-500">{service.application_origin || ''}</div></td>
          <td className="px-4 py-3 text-xs text-gray-400"><EvidenceRefs service={service} /></td>
          <td className="px-4 py-3">{huntHref ? <Link className="text-blue-300" href={huntHref}>Start Hunt</Link> : <span className="text-xs text-amber-300">Historical address</span>}</td>
        </tr>
      })}</tbody>
    </table></Card>}
    {unconfirmed.length > 0 && <details className="mt-3 rounded-sm border border-gray-800 bg-gray-900/40">
      <summary className="cursor-pointer p-4 text-left hover:bg-gray-900/70"><strong className="text-sm text-white">{unconfirmed.length} unconfirmed no-response probe{unconfirmed.length === 1 ? '' : 's'}</strong> <span className="text-xs text-gray-500">Not confirmed open · not offered for Hunt</span></summary>
      <p className="border-t border-gray-800 px-4 pt-3 text-xs text-gray-500">No reply was received; these ports may be open or filtered. They are not confirmed services and are not offered for Hunt.</p>
      <div className="divide-y divide-amber-500/10 bg-amber-950/10">{unconfirmed.map(service => <div key={service.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm">
        <span className="font-mono text-gray-200">{service.port}/{service.transport}</span>
        <span className="text-gray-400">Expected protocol: {service.service || 'unknown'}</span>
        <span className="rounded-sm bg-gray-800 px-2 py-0.5 text-xs text-gray-300">No response</span>
        <span className="text-xs font-medium text-amber-200">Not confirmed open</span>
        <span className="text-xs text-gray-500"><EvidenceRefs service={service} /></span>
      </div>)}</div>
    </details>}
    {notObservedCount > 0 && <p className="mt-2 text-xs text-gray-500">{notObservedCount} port{notObservedCount === 1 ? '' : 's'} last observed closed or filtered {notObservedCount === 1 ? 'is' : 'are'} not listed.</p>}
    {knowledge.warnings.map((warning,index) => <p key={index} className="mt-2 text-xs text-amber-200">{warning}</p>)}
    {knowledge.sources_truncated && <p className="mt-2 text-xs text-gray-500">This retained evidence view is bounded; absence is inconclusive.</p>}
  </section>
}

function EvidenceRefs({service}: {service: SharedServiceKnowledge['services'][number]}) {
  return <>{service.evidence.map((e,index) => <span key={index} className="mr-2">{e.hunt_id ? `Hunt ${e.hunt_id.slice(0,8)}` : e.scan_id ? `Scan ${e.scan_id.slice(0,8)}` : 'Observation'} · {e.status || service.observation_status}</span>)}</>
}
