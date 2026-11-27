function sameAddressApiUrl(configured: string): string | null {
  // The configured API URL names one address. Opened at any other address that reaches the
  // same engine -- the public IP of the host, or a forwarded port -- the page kept fetching
  // the configured one, which the browser either cannot route to or refuses as a
  // private-network request from a public page, so every read and write failed.
  //
  // Only an address literal is followed, and only when the configured URL names one too. A
  // hostname is left alone: it may legitimately be a gateway in front of a different API
  // host, and following names would also be the shape a rebound DNS name relies on.
  try {
    const parsed = new URL(configured)
    const page = window.location.hostname
    const isLiteral = (value: string) =>
      /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':') || value.startsWith('[')
    if (!page || page === parsed.hostname) return null
    if (!isLiteral(page) || !isLiteral(parsed.hostname)) return null
    parsed.hostname = page
    return parsed.pathname === '/' && !parsed.search && !parsed.hash
      ? parsed.origin
      : parsed.toString()
  } catch {
    return null
  }
}

export function getApiUrl(): string {
  if (typeof window !== 'undefined') {
    const runtimeUrl = window.__SHAKERSCAN_API_URL__
    if (runtimeUrl) return sameAddressApiUrl(runtimeUrl) ?? runtimeUrl
    const host = window.location.hostname
    const pageProtocol = window.location.protocol
    if (host && !['localhost', '127.0.0.1', '::1'].includes(host)) {
      if (pageProtocol === 'https:') {
        // eslint-disable-next-line no-console
        console.warn(
          '[shakerscan] NEXT_PUBLIC_API_URL is not set on an HTTPS deploy. ' +
            'Falling back to same-origin API; set NEXT_PUBLIC_API_URL when the ' +
            'API is behind a different host or port.',
        )
        return window.location.origin
      }
      return `http://${host}:8080`
    }
  }
  return 'http://localhost:8080'
}

declare global {
  interface Window {
    __SHAKERSCAN_API_URL__?: string
  }
}

export const API_URL = getApiUrl()

export async function getApiErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const data = await response.json()
    const detail = data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      const messages = detail.map((item) => (typeof item?.msg === 'string' ? item.msg : null)).filter(Boolean)
      if (messages.length) return messages.join('; ')
    }
    if (detail && typeof detail === 'object') {
      if (typeof detail.message === 'string') return detail.message
      if (typeof detail.reason === 'string') return detail.reason
      if (typeof detail.error === 'string') return detail.error
    }
    if (typeof data?.message === 'string') return data.message
  } catch {
    // Intermediaries are not required to return JSON errors.
  }
  return fallback
}
