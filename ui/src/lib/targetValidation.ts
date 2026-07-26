const HOSTNAME_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i
const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/

export function validateScanTarget(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Please enter a target URL'
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
