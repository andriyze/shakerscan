import Link from '@/components/WorkspaceLink'
import { Card, EmptyState } from '@/components/ui'

export interface SharedServiceKnowledge {
  services: Array<{id:string; target_id:string; transport:string; port:number; address?:string|null;
    service?:string|null; application_origin?:string|null; binding_status?:string; observation_status?:string;
    evidence:Array<{hunt_id?:string|null; scan_id?:string|null; status?:string}>}>
  warnings: string[]
  sources_truncated: boolean
}

export function SharedServicePorts({knowledge,targetId}: {knowledge?:SharedServiceKnowledge;targetId:string}) {
  if (!knowledge) return null
  return <section className="mb-6">
    <h2 className="mb-3 text-lg font-semibold text-white">Ports discovered across Scans and Hunts</h2>
    {knowledge.services.length === 0 ? <EmptyState message="No retained service evidence" hint="Port discovery in Hunt and network scans enrich this same target. Missing evidence does not establish closed ports." /> : <Card className="overflow-x-auto p-0"><table className="w-full text-left text-sm">
      <thead className="text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Port / address</th><th className="px-4 py-3">Service</th><th className="px-4 py-3">Evidence</th><th className="px-4 py-3">Investigate</th></tr></thead>
      <tbody className="divide-y divide-gray-800">{knowledge.services.map(service => <tr key={service.id}>
        <td className="px-4 py-3 font-mono text-gray-300">{service.port}/{service.transport}<div className="text-xs text-gray-500">{service.address || 'Address unattributed'}</div></td>
        <td className="px-4 py-3 text-gray-300">{service.service || 'Not identified'}<div className="text-xs text-gray-500">{service.application_origin || ''}</div></td>
        <td className="px-4 py-3 text-xs text-gray-400">{service.evidence.map((e,index) => <span key={index} className="mr-2">{e.hunt_id ? `Hunt ${e.hunt_id.slice(0,8)}` : e.scan_id ? `Scan ${e.scan_id.slice(0,8)}` : 'Observation'} · {e.status || service.observation_status}</span>)}</td>
        <td className="px-4 py-3">{service.binding_status === 'historical_locator' ? <span className="text-xs text-amber-300">Historical address</span> : <Link className="text-blue-300" href={`/hunt?${new URLSearchParams({target:targetId,objective:`Investigate observed ${service.transport}/${service.port} on this target. Query existing service evidence before executing capabilities.`})}`}>Start Hunt</Link>}</td>
      </tr>)}</tbody>
    </table></Card>}
    {knowledge.warnings.map((warning,index) => <p key={index} className="mt-2 text-xs text-amber-200">{warning}</p>)}
    {knowledge.sources_truncated && <p className="mt-2 text-xs text-gray-500">This retained evidence view is bounded; absence is inconclusive.</p>}
  </section>
}
