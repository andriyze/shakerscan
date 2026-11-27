import type { Response } from '@playwright/test'


const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]'])


function sameApiOrigin(actual: URL, expected: URL): boolean {
  if (actual.origin === expected.origin) return true
  return (
    actual.protocol === expected.protocol
    && actual.port === expected.port
    && LOOPBACK_HOSTS.has(actual.hostname)
    && LOOPBACK_HOSTS.has(expected.hostname)
  )
}


/** Match the browser-facing API origin while treating loopback aliases equally. */
export function isApiResponse(
  response: Response,
  apiUrl: string,
  pathname: string,
  method = 'POST',
): boolean {
  const actual = new URL(response.url())
  const expected = new URL(apiUrl)
  return (
    sameApiOrigin(actual, expected)
    && actual.pathname === pathname
    && response.request().method() === method
  )
}
