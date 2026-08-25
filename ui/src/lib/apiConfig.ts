export function getApiUrl(): string {
  if (typeof window !== 'undefined') {
    const runtimeUrl = window.__SHAKERSCAN_API_URL__
    if (runtimeUrl) return runtimeUrl
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
