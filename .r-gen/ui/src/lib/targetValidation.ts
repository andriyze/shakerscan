import { MAX_SCAN_TARGET_CHARS } from './targetLimits.mjs'

const HOSTNAME_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i
const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/

function targetHostname(value: string): string {
  const trimmed = value.trim()
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  try {
    return new URL(candidate).hostname.replace(/^\[|\]$/g, '').toLowerCase()
  } catch {
    return ''
  }
}

// Approval receipts are an internal Scan implementation detail. This only
// selects the server's scope policy for targets that are unmistakably local;
// ordinary DNS names stay production-scoped and cannot silently reach private
// destinations through DNS.
export function scanScopeEnvironment(value: string): 'production' | 'lab' {
  const host = targetHostname(value)
  if (!host) return 'production'
  if (
    host === 'localhost'
    || host.endsWith('.localhost')
    || host.endsWith('.internal')
    || host.endsWith('.local')
    || (!host.includes('.') && !host.includes(':'))
  ) return 'lab'

  if (IPV4_PATTERN.test(host)) {
    const octets = host.split('.').map(Number)
    const [first, second] = octets
    if (
      first === 0
      || first === 10
      || first === 127
      || (first === 100 && second >= 64 && second <= 127)
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 198 && (second === 18 || second === 19))
    ) return 'lab'
  }

  if (
    host === '::1'
    || host.startsWith('fc')
    || host.startsWith('fd')
    || /^fe[89ab]/.test(host)
  ) return 'lab'

  return 'production'
}

export function validateScanTarget(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Please enter a target URL'
  }
  if (trimmed.length > MAX_SCAN_TARGET_CHARS) {
    return `Target URL must be ${MAX_SCAN_TARGET_CHARS.toLocaleString()} characters or fewer`
  }
  if (/\s/.test(trimmed)) {
    return 'Target cannot contain spaces'
  }
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return 'Only http(s) targets are supported'
  }
  const host = url.hostname
  if (!host) {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  const isLocalhost = host === 'localhost'
  const isIPv6 = host.startsWith('[') || host.includes(':')
  const isIPv4 = IPV4_PATTERN.test(host)
  // Single-label DNS names are valid on Docker, Kubernetes, VPN, and lab
  // networks. The API remains the authority for target policy and scope.
  if (!isLocalhost && !isIPv4 && !isIPv6 && !HOSTNAME_PATTERN.test(host)) {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  return null
}
