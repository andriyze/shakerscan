import type { DetailEvidence } from '@/lib/findingDetailEvidence'

export function EvidenceDetails({ details }: { details: DetailEvidence }) {
  return <>
    {details.groups.map(group => <div key={group.title}>
      <h3 className="mb-2 text-sm font-medium text-gray-300">{group.title}</h3>
      <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {group.facts.map(fact => <div key={fact.label} className="min-w-0">
          <dt className="text-xs text-gray-500">{fact.label}</dt>
          <dd className="mt-0.5 whitespace-pre-wrap break-all text-sm text-gray-200">{fact.value}</dd>
        </div>)}
      </dl>
    </div>)}
    {details.severityReason && <div>
      <h3 className="mb-2 text-sm font-medium text-gray-300">Why this severity</h3>
      <p className="whitespace-pre-wrap wrap-break-word text-sm leading-6 text-gray-300">{details.severityReason}</p>
      <p className="mt-1 text-xs text-gray-500">Recorded by the scanner. Severity and technical proof are separate.</p>
    </div>}
  </>
}
