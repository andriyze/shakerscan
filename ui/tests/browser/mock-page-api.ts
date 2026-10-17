import type { Page, Request } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

/** One scripted answer: a JSON body (200), or an explicit status with a body. */
export type MockAnswer = unknown | { status: number; json: unknown }
export type MockHandler = (url: URL, request: Request) => MockAnswer | Promise<MockAnswer>

export interface MockedApi {
  /** Every API request the page sent, as `METHOD /path?query`, in order. */
  requests: string[]
  /** Requests no handler answered (each got a 404): a populated page should leave this empty. */
  unhandled: string[]
}

function isExplicit(answer: MockAnswer): answer is { status: number; json: unknown } {
  return Boolean(answer && typeof answer === 'object' && 'status' in answer && 'json' in answer
    && typeof (answer as { status: unknown }).status === 'number' && Object.keys(answer as object).length === 2)
}

/**
 * Browser contract fixture for one page: pin the mock API origin and answer it from `routes`,
 * keyed by `METHOD /path` or bare `/path` (any method). A request no route answers gets a 404 and
 * is recorded in `unhandled`, so a spec can prove its fixture covers everything the page asks for.
 * The fixture is synthetic: no scan, Hunt or schedule ever runs.
 */
export async function mockPageApi(page: Page, routes: Record<string, MockHandler>): Promise<MockedApi> {
  const requests: string[] = []
  const unhandled: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const key = `${request.method()} ${url.pathname}`
    requests.push(`${key}${url.search}`)
    const handler = routes[key] ?? routes[url.pathname]
    if (!handler) {
      unhandled.push(`${key}${url.search}`)
      return route.fulfill({ status: 404, json: { detail: 'No fixture for this route' } })
    }
    const answer = await handler(url, request)
    if (isExplicit(answer)) return route.fulfill({ status: answer.status, json: answer.json })
    return route.fulfill({ json: answer })
  })
  return { requests, unhandled }
}

/** The query parameter names the page sent to `path` (for the gateway's allowlist review). */
export function queryNames(api: MockedApi, path: string): string[] {
  const names = new Set<string>()
  for (const entry of api.requests) {
    const [, target] = entry.split(' ')
    const url = new URL(target, MOCK_API_ORIGIN)
    if (url.pathname !== path) continue
    for (const name of url.searchParams.keys()) names.add(name)
  }
  return [...names].sort()
}

export const unavailable = (detail = 'fixture_unavailable'): { status: number; json: unknown } => ({ status: 503, json: { detail } })

/**
 * A plain server failure. Prefer it for error-state tests: heavy reads wait out 429/503 with
 * Retry-After (lib/busyRetry.mjs) before failing, so a 503 can outlast an assertion timeout.
 */
export const serverError = (detail = 'fixture_failure'): { status: number; json: unknown } => ({ status: 500, json: { detail } })
