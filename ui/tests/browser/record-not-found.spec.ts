import { expect, test, type Page } from '@playwright/test'

import { mockPageApi, serverError, type MockHandler, type MockedApi } from './mock-page-api'

// Browser contract fixture: detail pages opened with an id the scripted API does not know (404),
// and once with a read that fails (500). Synthetic: nothing is stored and nothing runs.
const MISSING = '00000000-0000-4000-8000-00000000dead'
const health: Record<string, MockHandler> = { 'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }) }
const notFound = (detail: string) => () => ({ status: 404, json: { detail } })

interface MissingRecord {
  name: string
  path: string
  /** The read that says the record does not exist. */
  read: string
  detail: string
  title: string
  message: string
  list: { label: string; href: string }
  extra?: Record<string, MockHandler>
}

const records: MissingRecord[] = [
  {
    name: 'scan', path: `/scans/${MISSING}`, read: `GET /scans/${MISSING}`, detail: 'Scan not found',
    title: 'Scan not found', message: 'There is no scan at this address.', list: { label: 'Back to scans', href: '/scans' },
  },
  {
    name: 'finding', path: `/findings/${MISSING}`, read: `GET /findings/${MISSING}`, detail: 'Finding not found',
    title: 'Finding not found', message: 'There is no finding at this address.', list: { label: 'Back to findings', href: '/findings' },
  },
  {
    name: 'connected device', path: `/devices/${MISSING}`, read: `GET /devices/${MISSING}`, detail: 'Connected device not found',
    title: 'Device not found', message: 'There is no connected device at this address.',
    list: { label: 'Back to connected devices', href: '/devices' },
    extra: {
      'GET /device-agent/runs': () => ({ runs: [], count: 0 }),
      'GET /devices/readiness': () => ({ enabled: false, status: 'disabled' }),
    },
  },
  {
    name: 'campaign', path: `/campaigns/${MISSING}`, read: `GET /arsenal/campaigns/${MISSING}`, detail: 'Campaign not found',
    title: 'Campaign not found', message: 'There is no campaign at this address.', list: { label: 'Back to campaigns', href: '/campaigns' },
  },
  {
    name: 'target', path: `/targets/${MISSING}/asset`, read: `GET /targets/${MISSING}/asset`, detail: 'Target not found',
    title: 'Target not found', message: 'There is no target at this address.', list: { label: 'Back to targets', href: '/targets' },
  },
  {
    // The graph read answers an empty graph for any id; the target read says the target is missing.
    name: 'application graph', path: `/targets/${MISSING}/graph`, read: `GET /targets/${MISSING}`, detail: 'Target not found',
    title: 'Target not found',
    message: 'There is no target at this address, so there is no application graph to show.',
    list: { label: 'Back to targets', href: '/targets' },
    extra: {
      [`GET /targets/${MISSING}/graph`]: () => ({
        target_id: MISSING, nodes: [], edges: [], summary: { node_count: 0, edge_count: 0, by_node_type: {}, by_edge_type: {} },
      }),
    },
  },
]

const readsOf = (api: MockedApi, read: string) => api.requests.filter((entry) => entry.split('?')[0] === read)

async function open(page: Page, record: MissingRecord, answer: MockHandler): Promise<MockedApi> {
  const api = await mockPageApi(page, { ...health, ...(record.extra || {}), [record.read]: answer })
  await page.clock.install()
  await page.goto(record.path, { waitUntil: 'domcontentloaded' })
  return api
}

for (const record of records) {
  test(`MISSING-001 a ${record.name} id that does not exist says so and leads back to the list`, async ({ page }) => {
    const api = await open(page, record, notFound(record.detail))
    const main = page.locator('main')
    await expect(main.getByRole('heading', { level: 1, name: record.title, exact: true })).toBeVisible()
    await expect(main.getByText(record.message, { exact: true })).toBeVisible()
    await expect(main.getByText('It may have been deleted, or the link may be out of date.', { exact: true })).toBeVisible()
    // Not a failure to retry: no error banner and no Retry.
    await expect(main.getByRole('alert')).toHaveCount(0)
    await expect(main.getByRole('button', { name: 'Retry' })).toHaveCount(0)
    await expect(main.getByText(/Failed to load|Could not load/)).toHaveCount(0)
    await expect(main.getByRole('link', { name: record.list.label, exact: true })).toHaveAttribute('href', record.list.href)

    // The refused read is not repeated, however long the page stays open, and nothing stored
    // under the missing record is asked for.
    await page.clock.fastForward(60_000)
    await page.waitForTimeout(250)
    expect(readsOf(api, record.read)).toHaveLength(1)
    const refused = api.requests.filter((entry) => entry.includes(MISSING) && !(record.extra && entry.split('?')[0] in record.extra))
    expect(refused).toHaveLength(1)

    await main.getByRole('link', { name: record.list.label, exact: true }).click()
    await expect(page).toHaveURL(new RegExp(`${record.list.href}$`))
  })
}

// A read that failed is not "not found": the page keeps its error and Retry.
for (const record of records.filter((entry) => ['scan', 'finding', 'connected device', 'campaign', 'target'].includes(entry.name))) {
  test(`MISSING-002 a ${record.name} read that fails keeps the error with Retry`, async ({ page }) => {
    await open(page, record, () => serverError())
    const main = page.locator('main')
    await expect(main.getByRole('alert').first()).toBeVisible()
    await expect(main.getByRole('button', { name: 'Retry' })).toBeVisible()
    await expect(main.getByRole('heading', { level: 1, name: record.title, exact: true })).toHaveCount(0)
  })
}

test('MISSING-003 a target with no recorded graph says what fills it, and the page names the target', async ({ page }) => {
  const target = '11111111-1111-4111-8111-111111111111'
  await mockPageApi(page, {
    ...health,
    [`GET /targets/${target}`]: () => ({
      id: target, url: 'https://shop.fixture.example', name: 'Fixture shop', root_domain: 'fixture.example',
      is_root: true, discovery_source: 'manual', is_active: true, total_scans: 0, active_findings_count: 0,
    }),
    [`GET /targets/${target}/graph`]: () => ({
      target_id: target, nodes: [], edges: [], summary: { node_count: 0, edge_count: 0, by_node_type: {}, by_edge_type: {} },
    }),
  })
  await page.goto(`/targets/${target}/graph`, { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByRole('heading', { level: 1, name: 'Application Graph', exact: true })).toBeVisible()
  await expect(main.getByTestId('graph-target')).toHaveText('Fixture shop')
  await expect(main.getByText('No application graph has been recorded for this target yet.', { exact: true })).toBeVisible()
  await expect(main.getByRole('link', { name: 'Open the target', exact: true })).toHaveAttribute('href', `/targets/${target}/asset`)
})
