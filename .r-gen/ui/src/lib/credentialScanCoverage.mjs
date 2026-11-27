// What an attached credential profile leaves anonymous in a Scan.
//
// Scan applies a profile per action, against the profile's allowed capabilities. A profile that
// only allows signing in signs the scan in and then crawls and verifies anonymously, so the
// picker must say so instead of presenting it as a fully usable identity.

const CRAWLERS = ['web.crawl', 'web.browser_crawl']
const VERIFIERS = {
  xss: { label: 'XSS', capabilities: ['xss.verify_batch', 'xss.verify', 'xss.request_verify_batch'] },
  sqli: { label: 'SQL injection', capabilities: ['sqli.verify_batch', 'sqli.verify', 'sqli.request_verify_batch'] },
}

export function credentialScanCoverageNote(allowedCapabilities, { families = [] } = {}) {
  const allowed = new Set(allowedCapabilities || [])
  // An empty allowlist and the historical whole-scan scope are not per-capability lists.
  if (!allowed.size || allowed.has('scan.execute')) return null
  const notes = []
  if (!CRAWLERS.some((name) => allowed.has(name))) {
    notes.push('does not allow the crawl, so pages behind the sign-in are discovered anonymously')
  }
  const anonymous = Object.entries(VERIFIERS)
    .filter(([family, item]) => families.includes(family) && !item.capabilities.some((name) => allowed.has(name)))
    .map(([, item]) => item.label)
  if (anonymous.length) {
    notes.push(`the ${anonymous.join(' and ')} verifiers run anonymously because the profile does not allow them`)
  }
  return notes.length ? notes.join('; ') : null
}
