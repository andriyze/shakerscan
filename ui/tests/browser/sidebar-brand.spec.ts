import { expect, test, type Page } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture: the real sidebar, tab title and icons over a scripted API that answers
// only the sidebar's health poll; no page data is needed and nothing runs.
const health = { '/health': () => ({ status: 'healthy', scanner_version: 'fixture' }) }

const enterprisePolicy = {
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  edition: 'Enterprise Edition',
  features: {
    dashboard: { state: 'enabled' }, docs: { state: 'enabled' }, schedules: { state: 'enabled' },
    settings: { state: 'enabled' }, evidence: { state: 'enabled' },
  },
  navigation: {
    '/': 'dashboard', '/docs': 'docs', '/schedules': 'schedules', '/settings': 'settings',
    '/evidence': 'evidence', '/model-intake': 'model_intake',
  },
  ui_routes: ['/', '/docs', '/schedules', '/settings/policy-profiles', '/evidence'],
}

// The server-rendered tab title: the first <title> in the document, which is the one a browser
// shows (a 404 also carries the not-found page's own <title> after it).
async function servedTitle(page: Page, path: string): Promise<{ status: number; title: string | undefined }> {
  const response = await page.request.get(path)
  const html = await response.text()
  return { status: response.status(), title: html.match(/<title>([^<]*)<\/title>/)?.[1] }
}

// The sidebar on a desktop viewport, or the drawer the mobile bar opens.
async function sidebar(page: Page) {
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

test('BRAND-001 the tab names the page first and shows the S mark', async ({ page }) => {
  await mockPageApi(page, health)
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('Docs · ShakerScan')

  const icons = await page.locator('link[rel="icon"], link[rel="apple-touch-icon"]').evaluateAll((links) =>
    links.map((link) => `${link.getAttribute('rel')} ${link.getAttribute('href')}`))
  expect(icons).toEqual(['icon /favicon.ico', 'icon /favicon.svg', 'apple-touch-icon /apple-touch-icon.png'])
  for (const [href, type] of [['/favicon.svg', 'image/svg+xml'], ['/favicon.ico', 'image/'], ['/apple-touch-icon.png', 'image/png']]) {
    const response = await page.request.get(href)
    expect(response.status(), href).toBe(200)
    expect(response.headers()['content-type'], href).toContain(type)
  }
  expect(await (await page.request.get('/favicon.svg')).text()).toContain('stroke="#3b82f6"')
})

test('BRAND-002 the sidebar lockup, the foot and the More row', async ({ page }) => {
  await mockPageApi(page, health)
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  const nav = await sidebar(page)

  const home = nav.getByRole('link', { name: 'ShakerScan dashboard', exact: true })
  await expect(home).toHaveText('ShakerScan')
  await expect(home.locator('svg path')).toHaveAttribute('stroke', '#3b82f6')
  // The corner is the logo and the primary action: the edition and the version are one quiet
  // line at the foot, and no build line sits under the logo while the builds agree.
  const newScan = nav.getByRole('link', { name: 'New Scan', exact: true })
  const firstPage = nav.getByRole('navigation').getByRole('link').first()
  const [homeBox, newScanBox, firstPageBox] = [await home.boundingBox(), await newScan.boundingBox(), await firstPage.boundingBox()]
  expect(newScanBox!.y).toBeGreaterThanOrEqual(homeBox!.y + homeBox!.height)
  expect(firstPageBox!.y).toBeGreaterThanOrEqual(newScanBox!.y + newScanBox!.height)
  await expect(nav.getByText('Open Source Edition', { exact: true })).toHaveCount(0)
  await expect(nav.getByText(/^Version /)).toHaveCount(0)
  await expect(nav.getByRole('status')).toHaveCount(0)
  const about = nav.getByText('Open Source fixture', { exact: true })
  await expect(about).toBeVisible()

  // The two ways out are icons with names, beside that line, below every page of the menu.
  const website = nav.getByRole('link', { name: 'shakerscan.com', exact: true })
  await expect(website).toHaveText('')
  await expect(website).toHaveAttribute('title', 'shakerscan.com')
  await expect(website).toHaveAttribute('href', 'https://shakerscan.com')
  await expect(website).toHaveAttribute('target', '_blank')
  await expect(website).toHaveAttribute('rel', /\bnoopener\b/)
  const github = nav.getByRole('link', { name: 'ShakerScan on GitHub' })
  await expect(github).toHaveAttribute('href', 'https://github.com/andriyze/shakerscan')
  await expect(github).toHaveAttribute('rel', /\bnoopener\b/)
  await expect(github).toHaveText('')
  await expect(github).toHaveAttribute('title', 'Source code on GitHub')
  const settings = nav.getByRole('link', { name: 'Settings', exact: true })
  await expect(settings).toHaveText('Settings')
  const [aboutBox, websiteBox, githubBox, settingsBox] = [
    await about.boundingBox(), await website.boundingBox(), await github.boundingBox(), await settings.boundingBox(),
  ]
  expect(aboutBox!.y).toBeGreaterThanOrEqual(settingsBox!.y + settingsBox!.height)
  for (const box of [websiteBox!, githubBox!]) {
    expect(box.x).toBeGreaterThanOrEqual(aboutBox!.x + aboutBox!.width)
    expect(Math.abs((box.y + box.height / 2) - (aboutBox!.y + aboutBox!.height / 2))).toBeLessThanOrEqual(2)
  }
  // OSS shows no way to a gateway console.
  await expect(nav.getByRole('link', { name: /console/i })).toHaveCount(0)

  // The Agentic badge is static.
  await expect(nav.getByText('Agentic', { exact: true })).toBeVisible()
  await expect(nav.locator('.animate-pulse')).toHaveCount(0)

  // The advanced pages wait behind the row that ends the menu. It says how many, opens them in
  // place, and the choice is kept.
  await expect(nav.getByRole('switch')).toHaveCount(0)
  const more = nav.getByRole('navigation').getByRole('button', { name: /^More/ })
  await expect(more).toHaveAccessibleName('More 5 pages')
  await expect(more).toBeInViewport({ ratio: 1 })
  await expect(more).toHaveAttribute('aria-expanded', 'false')
  await expect(nav.getByRole('link', { name: 'Evidence' })).toHaveCount(0)
  await more.click()
  await expect(more).toHaveAttribute('aria-expanded', 'true')
  await expect(more).toHaveAccessibleName('More')
  await expect(more).toBeInViewport({ ratio: 1 })
  const opened = nav.locator(`[id="${await more.getAttribute('aria-controls')}"]`).getByRole('link')
  await expect(opened).toHaveText(['Evidence', 'Timeline', 'Model Intake', 'Policy Profiles', 'Command Arsenal'])
  for (const link of await opened.all()) await expect(link).toBeInViewport({ ratio: 1 })
  expect(await page.evaluate(() => window.localStorage.getItem('shakerscan.sidebar.show_all'))).toBe('true')
  await more.click()
  await expect(more).toHaveAttribute('aria-expanded', 'false')
  await expect(nav.getByRole('link', { name: 'Evidence' })).toHaveCount(0)
  expect(await page.evaluate(() => window.localStorage.getItem('shakerscan.sidebar.show_all'))).toBe('false')
})

test('BRAND-003 a managed Enterprise edition names itself in the lockup and every tab title', async ({ page }) => {
  await page.addInitScript((policy) => { window.__SHAKERSCAN_CAPABILITIES__ = policy as never }, enterprisePolicy)
  await mockPageApi(page, health)
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('Docs · ShakerScan Enterprise')

  const nav = await sidebar(page)
  // The link's name contains the words it shows (WCAG 2.5.3, label in name).
  await expect(nav.getByRole('link', { name: 'ShakerScan Enterprise dashboard', exact: true })).toHaveText('ShakerScanEnterprise')
  await expect(nav.getByRole('link', { name: 'ShakerScan dashboard', exact: true })).toHaveCount(0)
  await expect(nav.getByText('Enterprise Edition', { exact: true })).toHaveCount(0)

  // A managed workspace has no More row: its navigation list decides. Evidence (allowed
  // here) is listed under Records without a click; Timeline and Model Intake (not allowed) are not.
  await expect(nav.getByRole('switch')).toHaveCount(0)
  await expect(nav.getByRole('button', { name: /^More/ })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Evidence' })).toBeVisible()
  await expect(nav.getByText('Records', { exact: true })).toBeVisible()
  await expect(nav.getByRole('link', { name: 'Timeline' })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Model Intake' })).toHaveCount(0)
  // A managed deployment links to neither the website nor the source code: nothing in its
  // sidebar leaves the deployment. With no account row, the foot says what is running; the engine
  // settings page and the scan form are not among this deployment's pages, so nothing leads to them.
  await expect(nav.locator('a[href^="http"]')).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Settings', exact: true })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'New Scan', exact: true })).toHaveCount(0)
  await expect(nav.getByText('Version fixture', { exact: true })).toBeVisible()

  // Next.js swaps the title on client navigation; the edition stays.
  await nav.getByRole('link', { name: 'Schedules' }).click()
  await expect(page).toHaveURL(/\/schedules$/)
  await expect(page).toHaveTitle('Schedules · ShakerScan Enterprise')
})

test('BRAND-004 nested routes keep the product name, and a missing page is not the dashboard', async ({ page }) => {
  // Each of these sits below a segment that names itself; Next.js hands a nested segment the
  // template only when its parent passes it on.
  const expected: Record<string, string> = {
    '/': 'Dashboard · ShakerScan',
    '/findings': 'Findings · ShakerScan',
    '/findings/fixture-finding': 'Finding · ShakerScan',
    '/findings/candidates': 'Investigation candidates · ShakerScan',
    '/scans/fixture-scan': 'Scan · ShakerScan',
    '/devices/fixture-device': 'Device · ShakerScan',
    '/devices/policies': 'Device service policies · ShakerScan',
    '/campaigns/fixture-campaign': 'Campaign · ShakerScan',
    '/deep-hunt/experiment': 'Test plan · ShakerScan',
    '/deep-hunt/leads': 'Leads · ShakerScan',
    '/deep-hunt/runs/fixture-run': 'Autonomous run · ShakerScan',
    '/ai-gate/boundary': 'Agent boundary verification · ShakerScan',
    '/settings/arsenal': 'Command arsenal · ShakerScan',
    '/settings/policy-profiles': 'Policy profiles · ShakerScan',
    '/targets/fixture-target/asset': 'Asset · ShakerScan',
    '/targets/fixture-target/graph': 'Application graph · ShakerScan',
  }
  const served: Record<string, string | undefined> = {}
  for (const path of Object.keys(expected)) served[path] = (await servedTitle(page, path)).title
  expect(served).toEqual(expected)

  for (const path of ['/nonexistent-page', '/settings/whatever']) {
    const missing = await servedTitle(page, path)
    expect(missing.status, path).toBe(404)
    expect(missing.title, path).toBe('ShakerScan')
  }

  await mockPageApi(page, health)
  await page.goto('/findings/fixture-finding', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('Finding · ShakerScan')
  await page.goto('/nonexistent-page', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('ShakerScan')
})

test('BRAND-005 a managed Enterprise edition names nested and missing pages too', async ({ page }) => {
  await page.addInitScript((policy) => { window.__SHAKERSCAN_CAPABILITIES__ = policy as never }, enterprisePolicy)
  await mockPageApi(page, health)
  await page.goto('/settings/policy-profiles', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('Policy profiles · ShakerScan Enterprise')
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('Dashboard · ShakerScan Enterprise')
  await page.goto('/nonexistent-page', { waitUntil: 'domcontentloaded' })
  await expect(page).toHaveTitle('ShakerScan Enterprise')
})

test('BRAND-006 the More row takes a click only once it can act on it', async ({ page }) => {
  // A loaded machine serves the page scripts late: the server-rendered row is on screen before
  // it has a handler. It must not look clickable then, and a click once it is must hold.
  test.skip(test.info().project.name !== 'chromium', 'desktop sidebar only')
  await mockPageApi(page, health)
  await page.route('**/_next/static/chunks/**', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500))
    await route.continue()
  })
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  const more = page.locator('aside:visible').getByRole('button', { name: /^More/ })
  await expect(more).toBeDisabled()
  await more.click()
  await expect(more).toHaveAttribute('aria-expanded', 'true')
  await page.waitForTimeout(1000)
  await expect(more).toHaveAttribute('aria-expanded', 'true')
  await expect(page.locator('aside:visible').getByRole('link', { name: 'Evidence' })).toBeVisible()
})
