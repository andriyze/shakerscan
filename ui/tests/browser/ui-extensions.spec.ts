import { expect, test, type Locator, type Page } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture for ui-extensions/v1 (docs/ui-extensions.md): the real sidebar, the
// real /ext/<id> route and the real finding page over a scripted API, with a managed workspace
// policy injected the way a gateway publishes one. The "deployment pages" are served by this spec
// on the UI's own origin; nothing here is a real deployment, and nothing runs.
const findingId = '5c0b7c1e-1d8e-4b6a-9f3e-2a4d1e0c9b11'

const extensions = {
  schema: 'shakerscan.ui-extensions/v1',
  sections: [{ id: 'follow-up', label: 'Follow-up', after: 'Testing' }],
  pages: [
    { id: 'reports', title: 'Reports', src: '/deployment/embed/reports' },
    { id: 'gone', title: 'Gone', src: '/deployment/embed/gone' },
  ],
  nav: [
    { label: 'Reports', icon: 'file-text', page: 'reports', section: 'follow-up' },
    { label: 'Calendar', icon: 'calendar', href: '/deployment/calendar', section: 'Testing', after: '/scans' },
    // None of these may reach the page: another origin, a script URL, an undeclared page, markup.
    { label: 'Elsewhere', href: 'https://elsewhere.example/' },
    { label: 'Relative elsewhere', href: '//elsewhere.example/' },
    { label: 'Script', href: 'javascript:alert(1)' },
    { label: 'No such page', page: 'missing' },
    { label: 'Icon by name only', icon: '<svg onload=alert(1)>', href: '/deployment/plain', section: 'follow-up' },
  ],
  slots: {
    'finding.detail': [{ id: 'follow-up', title: 'Follow-up', src: '/deployment/embed/finding/{finding_id}' }],
  },
  account: {
    name: 'Dana Example',
    detail: 'Operator',
    links: [{ label: 'My account', href: '/deployment/account' }, { label: 'Elsewhere', href: 'https://elsewhere.example/' }],
    sign_out: '/deployment/sign-out',
  },
}

const managedPolicy = {
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  features: {
    dashboard: { state: 'enabled' }, docs: { state: 'enabled' }, scans: { state: 'enabled' },
    findings: { state: 'enabled' }, extensions: { state: 'enabled' },
  },
  navigation: { '/': 'dashboard', '/docs': 'docs', '/scans': 'scans', '/findings': 'findings', '/ext': 'extensions' },
  // `/ext/other` is deliberately not listed, and `/ext/undeclared` is listed but not declared.
  ui_routes: ['/', '/docs', '/scans', '/findings', '/findings/[0-9a-f-]{36}', '/ext/reports', '/ext/gone', '/ext/undeclared'],
  extensions,
}

const finding = {
  id: findingId, title: 'Reflected XSS in search', severity: 'high', status: 'active', tool: 'dalfox',
  url: 'http://extensions.fixture.test/search?q=1', target_url: 'http://extensions.fixture.test',
  first_seen_at: '2026-10-01T00:00:00Z', last_seen_at: '2026-10-10T00:00:00Z',
}

const api = {
  '/health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
  [`/findings/${findingId}`]: () => finding,
}

// A deployment page as the contract asks for one: dark colour scheme, no background, no page
// title, height from its content, and a target="_top" link to a page of the UI.
const framedPage = (name: string) => `<!doctype html>
<html lang="en" style="color-scheme: dark"><head><meta charset="utf-8"><title>${name}</title></head>
<body style="margin: 0; font: 14px system-ui; color: #e5e7eb">
<p id="name">${name}</p><p id="query"></p>
<a id="to-findings" target="_top" href="/findings">All findings</a>
<div style="height: 900px">content</div>
<script>document.getElementById('query').textContent = location.search</script>
</body></html>`

interface Deployment {
  /** Every deployment page the browser asked for, path and query. */
  requested: string[]
  /** Pages (by path) the deployment refuses to show in a frame. */
  refused: Set<string>
}

async function mockDeployment(page: Page): Promise<Deployment> {
  const deployment: Deployment = { requested: [], refused: new Set() }
  await page.route('**/deployment/**', async (route) => {
    const url = new URL(route.request().url())
    deployment.requested.push(`${url.pathname}${url.search}`)
    const headers: Record<string, string> = deployment.refused.has(url.pathname) ? { 'X-Frame-Options': 'DENY' } : {}
    await route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', headers, body: framedPage(url.pathname) })
  })
  return deployment
}

async function managed(page: Page, policy: unknown = managedPolicy): Promise<Deployment> {
  await page.addInitScript((value) => { window.__SHAKERSCAN_CAPABILITIES__ = value as never }, policy)
  await mockPageApi(page, api)
  return mockDeployment(page)
}

// The sidebar on a desktop viewport, or the drawer the mobile bar opens.
async function sidebar(page: Page): Promise<Locator> {
  const opener = page.getByLabel('Open navigation')
  if (await opener.isVisible()) {
    // A click before the client hydrates can be lost; retry the real drawer interaction.
    await expect(async () => {
      if (!(await page.getByRole('dialog', { name: 'Navigation' }).isVisible())) await opener.click()
      await expect(page.getByRole('dialog', { name: 'Navigation' })).toBeVisible()
    }).toPass({ timeout: 10_000 })
    return page.getByRole('dialog', { name: 'Navigation' })
  }
  return page.locator('aside:visible')
}

const hrefs = (nav: Locator) => nav.locator('a[href^="/"]').evaluateAll((links) => links.map((link) => link.getAttribute('href')))

async function noSidewaysScroll(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
}

test('EXT-001 declared entries and sections are placed in the sidebar; hostile entries are dropped', async ({ page }) => {
  await managed(page)
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  const nav = await sidebar(page)

  // A declared section after the heading it names, and an entry after the UI's entry it names.
  await expect(nav.getByText('Follow-up', { exact: true })).toBeVisible()
  await expect(nav.getByRole('link', { name: 'Reports', exact: true })).toHaveAttribute('href', '/ext/reports')
  await expect(nav.getByRole('link', { name: 'Calendar', exact: true })).toHaveAttribute('href', '/deployment/calendar')
  const order = await hrefs(nav)
  const at = (href: string) => order.indexOf(href)
  expect(at('/deployment/calendar')).toBe(at('/scans') + 1)
  expect(at('/findings')).toBeGreaterThan(at('/deployment/calendar'))
  expect(at('/ext/reports')).toBeGreaterThan(at('/findings'))

  // Another origin, a script URL and an undeclared page never become links.
  for (const name of ['Elsewhere', 'Relative elsewhere', 'Script', 'No such page']) {
    await expect(nav.getByRole('link', { name, exact: true })).toHaveCount(0)
  }
  expect(await nav.locator('a').evaluateAll((links) => links.map((link) => link.getAttribute('href') || '')
    .filter((href) => /^(?:javascript:|\/\/)|elsewhere/i.test(href)))).toEqual([])
  // An icon is chosen by name: an unknown name draws the default icon and no markup.
  const plain = nav.getByRole('link', { name: 'Icon by name only', exact: true })
  await expect(plain).toHaveAttribute('href', '/deployment/plain')
  await expect(plain.locator('svg')).toHaveCount(1)
  expect(await plain.locator('svg').getAttribute('onload')).toBeNull()

  // The account block: who is signed in, the deployment's links and its sign-out page.
  const account = nav.getByRole('region', { name: 'Account' })
  await expect(account).toContainText('Dana Example')
  await expect(account).toContainText('Operator')
  await expect(account.getByRole('link', { name: 'My account', exact: true })).toHaveAttribute('href', '/deployment/account')
  await expect(account.getByRole('link', { name: 'Sign out', exact: true })).toHaveAttribute('href', '/deployment/sign-out')
  await expect(account.getByRole('link', { name: 'Elsewhere' })).toHaveCount(0)
  await noSidewaysScroll(page)
})

test('EXT-002 a hosted page renders inside the shell under its declared title, at the linked item', async ({ page }) => {
  const deployment = await managed(page)
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  const nav = await sidebar(page)
  await nav.getByRole('link', { name: 'Reports', exact: true }).click()
  await expect(page).toHaveURL(/\/ext\/reports$/)

  // One heading (the UI's), the tab named after the page, and the deployment page framed below.
  await expect(page.getByRole('heading', { level: 1, name: 'Reports', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1)
  await expect(page).toHaveTitle('Reports · ShakerScan')
  const frame = page.locator('iframe[title="Reports"]')
  await expect(frame).toBeVisible()
  await expect(page.frameLocator('iframe[title="Reports"]').locator('#name')).toHaveText('/deployment/embed/reports')
  expect(deployment.requested).toContain('/deployment/embed/reports')

  // As tall as its content: the page keeps the only scrollbar, and nothing scrolls sideways.
  await expect(async () => {
    expect((await frame.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(900)
  }).toPass()
  await expect(frame).toHaveAttribute('scrolling', 'no')
  await noSidewaysScroll(page)

  // The query string of the outer address reaches the framed page: a link can open one item.
  await page.goto('/ext/reports?report=42&tab=open', { waitUntil: 'domcontentloaded' })
  await expect(page.frameLocator('iframe[title="Reports"]').locator('#query')).toHaveText('?report=42&tab=open')
  await expect(page).toHaveTitle('Reports · ShakerScan')

  // Back and forward keep working, and the tab is named after the page that is open.
  const shell = await sidebar(page)
  await shell.getByRole('link', { name: 'Docs', exact: true }).click()
  await expect(page).toHaveURL(/\/docs$/)
  await expect(page).toHaveTitle('Docs · ShakerScan')
  await page.goBack()
  await expect(page).toHaveURL(/\/ext\/reports\?report=42&tab=open$/)
  await expect(page.frameLocator('iframe[title="Reports"]').locator('#query')).toHaveText('?report=42&tab=open')
  await expect(page).toHaveTitle('Reports · ShakerScan')
  await page.goForward()
  await expect(page).toHaveURL(/\/docs$/)
  await expect(page).toHaveTitle('Docs · ShakerScan')
  await page.goBack()

  // A target="_top" link to a page of the UI is opened by the UI's router: no reload.
  await page.evaluate(() => { (window as unknown as { __stayed: boolean }).__stayed = true })
  await page.frameLocator('iframe[title="Reports"]').locator('#to-findings').click()
  await expect(page).toHaveURL(/\/findings$/)
  expect(await page.evaluate(() => (window as unknown as { __stayed?: boolean }).__stayed)).toBe(true)
})

test('EXT-003 a page that cannot be framed says so and can be tried again; unknown pages are refused', async ({ page }) => {
  const deployment = await managed(page)
  deployment.refused.add('/deployment/embed/gone')
  await page.goto('/ext/gone', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { level: 1, name: 'Gone', exact: true })).toBeVisible()
  const alert = page.getByRole('main').getByRole('alert')
  await expect(alert).toContainText('Gone could not be shown.', { timeout: 30_000 })
  await expect(page.locator('iframe[title="Gone"]')).toHaveCount(0)

  deployment.refused.clear()
  await alert.getByRole('button', { name: 'Try again' }).click()
  await expect(page.frameLocator('iframe[title="Gone"]').locator('#name')).toHaveText('/deployment/embed/gone')
  await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0)

  // A route the policy lists but the block does not declare has nothing to show.
  await page.goto('/ext/undeclared', { waitUntil: 'domcontentloaded' })
  await expect(page.getByText('This page is not part of this workspace.')).toBeVisible()
  await expect(page.locator('main iframe')).toHaveCount(0)
  // A route the policy does not list is refused like any other route outside the workspace.
  await page.goto('/ext/other', { waitUntil: 'domcontentloaded' })
  await expect(page.getByText('This feature is not available in this workspace.')).toBeVisible()
  await expect(page.locator('main iframe')).toHaveCount(0)
  expect(deployment.requested.filter((path) => path.includes('undeclared') || path.includes('other'))).toEqual([])
})

test('EXT-004 a finding panel sits first in the right-hand column and closes to one line when it fails', async ({ page }) => {
  const deployment = await managed(page)
  await page.goto(`/findings/${findingId}`, { waitUntil: 'domcontentloaded' })
  const column = page.getByRole('complementary', { name: 'Finding status and history' })
  await expect(column).toBeVisible()

  // A card like the page's own, titled by the UI, with the deployment page for this finding.
  const panel = column.locator('section#extension-follow-up')
  await expect(panel.getByRole('heading', { level: 2, name: 'Follow-up', exact: true })).toBeVisible()
  await expect(page.frameLocator('iframe[title="Follow-up"]').locator('#name')).toHaveText(`/deployment/embed/finding/${findingId}`)
  expect(await column.evaluate((aside) => aside.firstElementChild?.id)).toBe('extension-follow-up')
  expect(await column.evaluate((aside) => aside.children[1]?.id)).toBe('triage')
  await noSidewaysScroll(page)

  // The deployment refuses the frame: one quiet line, and Triage keeps its place right under it.
  deployment.refused.add(`/deployment/embed/finding/${findingId}`)
  await page.reload({ waitUntil: 'domcontentloaded' })
  const quiet = column.getByText('Follow-up is not available right now.')
  await expect(quiet).toBeVisible({ timeout: 30_000 })
  await expect(column.locator('section#extension-follow-up')).toHaveCount(0)
  await expect(column.locator('iframe')).toHaveCount(0)
  await expect(column.getByRole('alert')).toHaveCount(0)
  expect((await quiet.boundingBox())?.height ?? 99).toBeLessThan(40)
  expect(await column.evaluate((aside) => aside.children[1]?.id)).toBe('triage')
})

test('EXT-005 a standalone UI, and a managed one that declares nothing, are unchanged', async ({ page }) => {
  // Standalone: no policy at all.
  await mockPageApi(page, api)
  const deployment = await mockDeployment(page)
  await page.goto(`/findings/${findingId}`, { waitUntil: 'domcontentloaded' })
  const column = page.getByRole('complementary', { name: 'Finding status and history' })
  await expect(column.locator('section#triage')).toBeVisible()
  expect(await column.evaluate((aside) => aside.firstElementChild?.id)).toBe('triage')
  await expect(page.locator('iframe')).toHaveCount(0)
  const nav = await sidebar(page)
  await expect(nav.getByRole('region', { name: 'Account' })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Reports', exact: true })).toHaveCount(0)
  expect(await hrefs(nav)).not.toContain('/ext/reports')

  // A hosted page address in a standalone UI has nothing to show and asks the deployment nothing.
  await page.goto('/ext/reports', { waitUntil: 'domcontentloaded' })
  await expect(page.getByText('This page is not part of this workspace.')).toBeVisible()
  await expect(page.locator('iframe')).toHaveCount(0)
  expect(deployment.requested).toEqual([])

  // The UI says which optional contracts it reads, so a deployment can tell before declaring.
  const identity = await (await page.request.get('/api/build-identity')).json()
  expect(identity.ui_contracts).toContain('shakerscan.ui-extensions/v1')
})

test('EXT-006 a managed policy without the block, or with another schema, adds nothing', async ({ page }) => {
  const { extensions: _unused, ...bare } = managedPolicy
  void _unused
  await managed(page, { ...bare, extensions: { ...extensions, schema: 'shakerscan.ui-extensions/v9' } })
  await page.goto(`/findings/${findingId}`, { waitUntil: 'domcontentloaded' })
  const column = page.getByRole('complementary', { name: 'Finding status and history' })
  await expect(column.locator('section#triage')).toBeVisible()
  expect(await column.evaluate((aside) => aside.firstElementChild?.id)).toBe('triage')
  const nav = await sidebar(page)
  await expect(nav.getByText('Follow-up', { exact: true })).toHaveCount(0)
  await expect(nav.getByRole('region', { name: 'Account' })).toHaveCount(0)
  expect((await hrefs(nav)).filter((href) => href?.startsWith('/ext') || href?.startsWith('/deployment'))).toEqual([])
})
