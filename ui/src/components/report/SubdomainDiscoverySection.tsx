'use client'

import Link from '@/components/WorkspaceLink'
import { subdomainDiscoverySummary, type SubdomainDiscoverySection as Section } from '@/lib/subdomainDiscovery'

// The names the Scan's subdomain discovery found. They are added as targets for their own scans;
// this scan stays bound to its own origin and does not test them.
export default function SubdomainDiscoverySection({ section }: { section: Section | null | undefined }) {
  const summary = subdomainDiscoverySummary(section)
  if (!summary || !section) return null
  return (
    <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
      <h2 className="text-2xl font-bold mb-2">Discovered subdomains</h2>
      <p className="text-sm text-gray-400">{summary}</p>
      <p className="mt-1 text-xs text-gray-500">
        This scan did not test them. Scan each from <Link href="/targets" className="text-blue-400 underline">Targets</Link>.
      </p>
      <div className="mt-3 max-h-48 overflow-y-auto rounded-sm bg-gray-700/30 p-3">
        {(section.hosts || []).map((host) => (
          <div key={host} className="py-0.5 font-mono text-xs text-gray-300">{host}</div>
        ))}
      </div>
    </div>
  )
}
