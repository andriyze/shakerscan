// Operator-facing wording for names that do not resolve in DNS: scan refusals, discovery runs that
// skipped such names, and targets registered under their www/apex twin.

export interface DnsFallbackLike {
  requested_host: string
  resolved_host: string
}

export interface DiscoveryOutcomeLike {
  status: string
  subdomains_found?: number | null
  new_subdomains?: number | null
  error_message?: string | null
  resolution?: { added: number; unresolved_count: number } | null
}

// The distinct reasons a batch of scan starts was refused, in first-seen order, capped so a
// domain with fifty subdomains does not produce a toast the size of the page.
export function scanStartFailureReasons(results: PromiseSettledResult<unknown>[], limit = 2): string[] {
  const reasons: string[] = []
  for (const result of results) {
    if (result.status !== 'rejected') continue
    const reason = result.reason instanceof Error ? result.reason.message : String(result.reason ?? '')
    const text = reason.trim() || 'Failed to start scan'
    if (!reasons.includes(text)) reasons.push(text)
  }
  if (reasons.length <= limit) return reasons
  return [...reasons.slice(0, limit), `and ${reasons.length - limit} other reason${reasons.length - limit === 1 ? '' : 's'}`]
}

// `target` with its host replaced by the twin the server registered, keeping scheme, port and
// path, so a scan is submitted for the name that resolves rather than the one that does not.
export function targetWithResolvedHost(target: string, fallback: DnsFallbackLike | null | undefined): string {
  if (!fallback?.resolved_host) return target
  const trimmed = target.trim()
  const schemeLess = !/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
  try {
    const parsed = new URL(schemeLess ? `https://${trimmed}` : trimmed)
    if (parsed.hostname.toLowerCase() !== fallback.requested_host.toLowerCase()) return target
    parsed.hostname = fallback.resolved_host
    const rebuilt = parsed.toString()
    const withoutRootSlash = /\/$/.test(rebuilt) && !/\/$/.test(trimmed) ? rebuilt.slice(0, -1) : rebuilt
    return schemeLess ? withoutRootSlash.replace(/^https:\/\//, '') : withoutRootSlash
  } catch {
    return target
  }
}

// Historical targets may retain their original hostname and ID. Submit that stored name so
// admission can keep its standing authorization; only a newly registered twin is submitted
// under the live hostname directly.
export function targetForRegisteredDnsFallback(
  submitted: string, registeredUrl: string, fallback: DnsFallbackLike,
): string {
  try {
    const registeredHost = new URL(registeredUrl).hostname.toLowerCase()
    if (registeredHost === fallback.requested_host.toLowerCase()) return submitted
    if (registeredHost === fallback.resolved_host.toLowerCase()) {
      return targetWithResolvedHost(submitted, fallback)
    }
  } catch { /* Leave the submitted name for server validation. */ }
  return submitted
}

// One sentence for a finished discovery run, naming names skipped for having no address record.
export function discoveryOutcomeMessage(rootDomain: string, run: DiscoveryOutcomeLike): { kind: 'success' | 'info' | 'error'; message: string } {
  if (run.status === 'failed') {
    return { kind: 'error', message: `Subdomain discovery failed for ${rootDomain}${run.error_message ? `: ${run.error_message}` : ''}` }
  }
  const found = Number(run.subdomains_found ?? 0)
  const added = Number(run.resolution?.added ?? run.new_subdomains ?? 0)
  const skipped = Number(run.resolution?.unresolved_count ?? 0)
  let message = `Discovery for ${rootDomain} found ${found} name${found === 1 ? '' : 's'}; ${added} new target${added === 1 ? '' : 's'} added`
  if (skipped > 0) {
    message += `. ${skipped} name${skipped === 1 ? '' : 's'} found but not resolving in DNS (no A/AAAA record) ${skipped === 1 ? 'was' : 'were'} skipped`
  }
  return { kind: skipped > 0 ? 'info' : 'success', message }
}
