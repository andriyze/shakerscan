import { expect, test, type Page } from '@playwright/test'

import { mockPageApi, queryNames } from './mock-page-api'

// Browser contract fixture for the 2.12 Targets page: bounded pages, a large domain paged on its
// own, and target liveness (column, filter, target page, Check now). Synthetic `.invalid` hosts;
// no scan or check runs.
const now = new Date().toISOString()
const minutesAgo = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString()
const STATUSES = ['live', 'reachable', 'unreachable', 'no_dns', 'dns_error', 'blocked', 'unchecked']
const liveness = (status: string) => ({
  status, dns: status === 'no_dns' ? 'no_record' : 'resolves', reachable: status === 'live' || status === 'reachable',
  live: status === 'live', checked_at: minutesAgo(5), trigger: 'schedule', addresses: ['203.0.113.10'],
  reason: status === 'live' ? null : status === 'no_dns' ? 'gone.big.invalid has no address record' : 'port 443: connection refused',
  ports: status === 'live' ? [{ port: 443, mode: 'https', address: '203.0.113.10', tcp: 'open', answered: true, http_status: 200 }]
    : [{ port: 443, mode: 'https', address: '203.0.113.10', tcp: 'refused', answered: false }],
})
const facets = (total: number) => ({ total, environment: { production: total }, authorization: { authorized: 0, unauthorized: total },
  findings: { any: 0, critical_high: 0, none: total }, activity: { scanned: 0, never: total, scanning: 0 },
  asset_type: { web: total, network: 0 },
  liveness: { live: 500, reachable: 20, unreachable: 180, no_dns: 90, dns_error: 2, blocked: 0, unchecked: 8 } })
const asset = (i: number, status = STATUSES[i % 3 === 0 ? 0 : i % 3 === 1 ? 2 : 3]) => {
  const host = `n${i}.big.invalid`
  return { id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, asset_id: `a-${i}`, name: null, url: `host://${host}`,
    locator: host, root_domain: 'big.invalid', is_active: true, environment: 'production', connected_device: false, origin_count: 1,
    origins: [{ id: `o-${i}`, url: `https://${host}`, name: null, is_active: true }], liveness: liveness(status),
    created_at: now, updated_at: now }
}

async function inventory(page: Page) {
  return mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': (url) => {
      const params = url.searchParams
      const status = params.get('liveness')
      if (params.get('domain') === 'big.invalid') {
        // One domain, 800 targets, 50 a page.
        const start = params.get('cursor') ? Number(params.get('cursor')) : 0
        const items = Array.from({ length: 50 }, (_, i) => asset(start + i + 1))
        return { items, has_more: start + 50 < 800, next_cursor: start + 50 < 800 ? String(start + 50) : null,
          ...(params.get('count') === 'exact' ? { total: 800, total_kind: 'exact' } : { total_kind: 'none' }),
          generated_at: now, facets: facets(800) }
      }
      const members = Array.from({ length: 20 }, (_, i) => asset(i + 1)).filter(item => !status || item.liveness.status === status)
      return {
        items: [{ root_domain: 'big.invalid', discoverable: true, targets: members, member_count: status ? 180 : 800,
          members_truncated: true }],
        has_more: false, next_cursor: null, total: 1, total_kind: 'exact', target_total: status ? 180 : 800,
        target_total_kind: 'exact', generated_at: now, facets: facets(800),
      }
    },
  })
}

test('TARGETS-SCALE-001 a large domain shows 20 targets and pages through all of them on its own', async ({ page }) => {
  const api = await inventory(page)
  await page.goto('/targets')
  const group = page.getByTestId('target-domain-group')
  await expect(group).toContainText('800 targets')
  // A group of more than five starts collapsed; open it.
  await group.getByRole('button', { name: 'Subdomains of big.invalid', exact: true }).click()
  await expect(group.getByTestId('target-asset-row')).toHaveCount(20)
  const first = new URL(api.requests.find(entry => entry.startsWith('GET /targets/inventory'))!.split(' ')[1], 'http://x').searchParams
  expect([first.get('member_limit'), first.get('limit'), first.get('group_by')]).toEqual(['20', '25', 'domain'])

  await group.getByRole('button', { name: 'Show all 800 targets in big.invalid' }).click()
  await expect(page.getByTestId('target-domain-view')).toContainText('All targets in big.invalid')
  await expect(page).toHaveURL(/[?&]domain=big\.invalid/)
  await expect(page.getByTestId('target-asset-row')).toHaveCount(50)
  await expect(page.getByTestId('target-page-position')).toHaveText('Targets 1–50 of 800 targets')
  const domainRead = api.requests.filter(entry => entry.includes('domain=big.invalid'))
  const params = new URL(domainRead[0].split(' ')[1], 'http://x').searchParams
  expect([params.get('group_by'), params.get('limit'), params.get('count')]).toEqual([null, '50', 'exact'])

  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(page.getByTestId('target-page-position')).toHaveText('Targets 51–100 of 800 targets')
  await expect(page.getByRole('link', { name: 'n51.big.invalid', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Previous', exact: true }).click()
  await expect(page.getByTestId('target-page-position')).toHaveText('Targets 1–50 of 800 targets')

  await page.getByRole('button', { name: 'All domains' }).click()
  await expect(page.getByTestId('target-domain-view')).toHaveCount(0)
  await expect(page.getByTestId('target-domain-group').getByTestId('target-asset-row')).toHaveCount(20)
  expect(queryNames(api, '/targets/inventory')).toEqual(
    ['count', 'cursor', 'domain', 'group_by', 'include_facets', 'limit', 'member_limit', 'sort'])
  expect(api.unhandled).toEqual([])
})

test('TARGETS-LIVENESS-001 the Liveness column says why, and the filter is applied by the server', async ({ page }) => {
  const api = await inventory(page)
  await page.goto('/targets')
  await page.getByRole('button', { name: 'Subdomains of big.invalid', exact: true }).click()
  const rows = page.getByTestId('target-asset-row')
  await expect(rows).toHaveCount(20)
  const down = rows.filter({ hasText: 'n1.big.invalid' }).getByTestId('target-liveness')
  await expect(down).toHaveText('Unreachable')
  await expect(down).toHaveAttribute('title', 'port 443: connection refused · checked 5m ago')
  await expect(rows.filter({ hasText: 'n3.big.invalid' }).getByTestId('target-liveness')).toHaveText('Live')
  await expect(rows.filter({ hasText: 'n2.big.invalid' }).getByTestId('target-liveness')).toHaveText('No DNS')

  const filter = page.getByLabel('Liveness', { exact: true })
  await expect(filter.locator('option[value="unreachable"]')).toHaveText('Unreachable (180)')
  await filter.selectOption('unreachable')
  await expect(page).toHaveURL(/[?&]liveness=unreachable/)
  await expect.poll(() => api.requests.some(entry => entry.includes('liveness=unreachable'))).toBe(true)
  await expect(rows.getByTestId('target-liveness')).not.toHaveText(['Live'])
  for (const pill of await rows.getByTestId('target-liveness').all()) await expect(pill).toHaveText('Unreachable')
  await expect(page.getByTestId('target-domain-group')).toContainText('180 targets')

  // The domain list keeps the filter.
  await page.getByRole('button', { name: 'Show all 180 targets in big.invalid' }).click()
  await expect.poll(() => api.requests.some(entry => entry.includes('domain=big.invalid') && entry.includes('liveness=unreachable'))).toBe(true)
  expect(api.unhandled).toEqual([])
})

test('TARGETS-LIVENESS-002 the target page shows DNS, reachable, live and the reason, and Check now updates it', async ({ page }) => {
  const target = asset(1, 'unreachable')
  let checks = 0
  const api = await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    [`/targets/${target.id}/asset`]: () => ({ target, requested_target_id: target.id, origins: [], services: [], credentials: [],
      request_collections: [], active_findings: {}, history: { asset_id: target.id, kind: 'scans', items: [], total: 0, limit: 25, offset: 0 },
      authorization: null }),
    [`/targets/${target.id}/history`]: () => ({ asset_id: target.id, kind: 'scans', items: [], total: 0, limit: 25, offset: 0 }),
    [`POST /targets/${target.id}/liveness`]: () => {
      checks += 1
      return { target_id: target.id, checked: true, liveness: { ...liveness('live'), checked_at: new Date().toISOString(), trigger: 'manual' } }
    },
  })
  await page.goto(`/targets/${target.id}/asset`)
  const card = page.getByTestId('target-liveness-card')
  await expect(card.getByTestId('target-liveness')).toHaveText('Unreachable')
  await expect(card.getByTestId('target-liveness-reason')).toHaveText('Reason: port 443: connection refused')
  await expect(card).toContainText('DNS')
  await expect(card).toContainText('Resolves')
  await expect(card).toContainText('5m ago · on schedule')
  await expect(card.getByRole('list', { name: 'Ports tried' })).toContainText('443 https: refused')

  await card.getByRole('button', { name: 'Check liveness now' }).click()
  await expect(card.getByTestId('target-liveness')).toHaveText('Live')
  await expect(card.getByRole('status')).toHaveText('Checked just now.')
  await expect(card).toContainText('just now · Check now')
  await expect(card.getByRole('list', { name: 'Ports tried' })).toContainText('443 https: opened, HTTP 200')
  await expect(card.getByTestId('target-liveness-reason')).toHaveCount(0)
  expect(checks).toBe(1)
  expect(api.requests).toContain(`POST /targets/${target.id}/liveness`)
})
