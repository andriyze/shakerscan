// The Scan option "Discover subdomains" lists what it found in report.discovery.subdomains and the
// worker records the names as targets for their own scans. This says both in one line, and names
// every cap that left a name unlisted, unchecked or not added: a partial run never reads as whole.

export interface SubdomainDiscoverySection {
  root_domain?: string | null
  hosts?: string[]
  /** How many names are listed in `hosts`. */
  count?: number
  /** How many distinct names discovery returned; above `count` when the list was cut. */
  total?: number
  truncated?: boolean
  listed_limit?: number
  source?: string
  targets?: {
    status?: string
    added?: number
    scannable?: number
    unresolved_count?: number
    unknown_count?: number
    found?: number
    checked?: number
    not_checked?: number
    dns_deadline_skipped?: number
    target_limit?: number | null
    over_target_limit?: number
    insert_failed?: number
    partial?: boolean
    partial_reasons?: string[]
    error?: string
    reason?: string
  } | null
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

export function subdomainDiscoverySummary(section: SubdomainDiscoverySection | null | undefined): string | null {
  const hosts = Array.isArray(section?.hosts) ? section!.hosts : []
  if (!section || hosts.length === 0) return null
  const listed = count(section.count) ?? hosts.length
  const found = Math.max(listed, count(section.total) ?? listed)
  const head = `${plural(found, 'subdomain')}${section.root_domain ? ` of ${section.root_domain}` : ''} found${section.source ? ` by ${section.source}` : ''}`
  const parts = [found > listed || section.truncated ? `${head}; the first ${listed} are listed` : head]
  const targets = section.targets
  if (targets?.status === 'recorded') {
    const checked = count(targets.checked)
    if (checked !== null && checked < found) parts.push(`${checked} of ${found} checked in DNS`)
    parts.push(`${plural(targets.added ?? 0, 'new target')} added`)
    const overLimit = count(targets.over_target_limit) ?? 0
    if (overLimit > 0) {
      const limit = count(targets.target_limit)
      parts.push(`${plural(overLimit, 'resolving name')} not added${limit !== null ? ` (at most ${limit} per run)` : ''}`)
    }
    if ((targets.unresolved_count ?? 0) > 0) parts.push(`${targets.unresolved_count} without an address record, not added`)
    const failed = count(targets.insert_failed) ?? 0
    if (failed > 0) parts.push(`${failed} could not be stored`)
  } else if (targets?.status === 'failed') {
    parts.push(`not added as targets (${targets.error || 'recording failed'})`)
  } else if (targets?.status === 'not_recorded') {
    parts.push('not added as targets')
  }
  return parts.join(' · ')
}
