import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Investigation candidates (2.12.1): one server page of open candidates at a time, grouped by the
// target each concerns and named on every card; automatic advisory matches without a product
// version are hidden behind a toggle that says how many there are.
const web = '00000000-0000-4000-8000-000000000a01'
const host = '00000000-0000-4000-8000-000000000a02'

function candidate(index: number, unversioned: boolean) {
  const device = index % 2 === 1
  return {
    id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    plane: device ? 'device' : 'web',
    target_id: device ? null : web,
    device_target_id: device ? host : null,
    target_name: device ? 'Edge host' : 'Shop',
    target_url: device ? 'host://10.0.0.5' : 'https://shop.example.test',
    family: device ? 'device_firmware_advisory' : 'xss',
    canonical_locus: unversioned ? {advisory_id: `CVE-2026-${index}`} : {advisory_id: `CVE-2026-${index}`, version: '1.0'},
    title: `${unversioned ? 'Unversioned' : 'Candidate'} ${index}`,
    claim: `Claim ${index}`,
    claimed_severity: 'medium',
    evidence_refs: [],
    verification_context: {},
    status: 'new',
    authoritative: false,
    promotion_ready: false,
    observation_count: 1,
    last_seen_at: '2026-11-01T00:00:00Z',
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-01T00:00:00Z',
  }
}

const VERSIONED = Array.from({length: 120}, (_, i) => candidate(i, false))
const UNVERSIONED = Array.from({length: 300}, (_, i) => candidate(1000 + i, true))

async function mock(page: Page) {
  const requests: URLSearchParams[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const url = new URL(route.request().url())
    if (url.pathname === '/investigation/candidates') {
      requests.push(url.searchParams)
      const mode = url.searchParams.get('unversioned_advisories') || 'include'
      const rows = mode === 'only' ? UNVERSIONED : mode === 'exclude' ? VERSIONED : [...VERSIONED, ...UNVERSIONED]
      const limit = Number(url.searchParams.get('limit') || 100), offset = Number(url.searchParams.get('offset') || 0)
      return route.fulfill({json: {candidates: rows.slice(offset, offset + limit), total: rows.length, limit, offset}})
    }
    return route.fulfill({json: {status: 'healthy', workers: [], targets: [], total: 0}})
  })
  return requests
}

for (const width of [390, 1440]) {
  test.describe(`at ${width} px`, () => {
    test.use({viewport: {width, height: 900}})

    test('CANDIDATES-001 one page at a time, grouped by target, unversioned matches hidden', async ({page}) => {
      const requests = await mock(page)
      await page.goto('/findings/candidates')
      await expect(page.getByTestId('candidate-card')).toHaveCount(50)
      await expect(page.getByTestId('candidate-total')).toContainText('120 candidates · 300 advisory matches without a version hidden')
      const first = requests.find(r => r.get('unversioned_advisories') === 'exclude')!
      expect(first.get('status')).toBe('new,verification_queued,verifying,inconclusive,blocked')
      expect(first.get('limit')).toBe('50')
      await expect(page.getByRole('region', {name: 'Candidates on Shop'})).toBeVisible()
      await expect(page.getByRole('region', {name: 'Candidates on Edge host'})).toBeVisible()
      await expect(page.getByTestId('candidate-card').first()).toContainText('on Shop')
      await expect(page.getByText('Unversioned 1000')).toHaveCount(0)
      const pages = page.getByRole('navigation', {name: 'Candidate pages'}).first()
      await expect(pages).toContainText('Showing 1–50 of 120')
      await pages.getByRole('button', {name: 'Next'}).click()
      await expect(pages).toContainText('Showing 51–100 of 120')
      await expect(page.getByText('Candidate 50', {exact: true})).toBeVisible()
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    })

    test('CANDIDATES-002 the toggle shows the advisory matches without a version', async ({page}) => {
      await mock(page)
      await page.goto('/findings/candidates')
      await page.getByLabel('Show 300 advisory matches without a version').check()
      await expect(page.getByTestId('candidate-total')).toHaveText('420 candidates')
      await expect(page.getByRole('navigation', {name: 'Candidate pages'}).first()).toContainText('Showing 1–50 of 420')
    })
  })
}
