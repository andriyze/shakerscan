// The Scan option "Discover subdomains" lists what it found in report.discovery.subdomains and the
// worker records the names as targets for their own scans. This says both in one line.

export interface SubdomainDiscoverySection {
  root_domain?: string | null
  hosts?: string[]
  count?: number
  source?: string
  targets?: {
    status?: string
    added?: number
    scannable?: number
    unresolved_count?: number
    error?: string
    reason?: string
  } | null
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

export function subdomainDiscoverySummary(section: SubdomainDiscoverySection | null | undefined): string | null {
  const hosts = Array.isArray(section?.hosts) ? section!.hosts : []
  if (!section || hosts.length === 0) return null
  const count = typeof section.count === 'number' ? section.count : hosts.length
  const parts = [
    `${plural(count, 'subdomain')}${section.root_domain ? ` of ${section.root_domain}` : ''} found${section.source ? ` by ${section.source}` : ''}`,
  ]
  const targets = section.targets
  if (targets?.status === 'recorded') {
    parts.push(`${plural(targets.added ?? 0, 'new target')} added`)
    if ((targets.unresolved_count ?? 0) > 0) parts.push(`${targets.unresolved_count} without an address record, not added`)
  } else if (targets?.status === 'failed') {
    parts.push(`not added as targets (${targets.error || 'recording failed'})`)
  } else if (targets?.status === 'not_recorded') {
    parts.push('not added as targets')
  }
  return parts.join(' · ')
}
