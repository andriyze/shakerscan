import { expect, test, type Locator, type Page } from '@playwright/test'

import { mockPageApi, uiBuildVersion, type MockHandler } from './mock-page-api'

// Browser contract fixture: the real sidebar over a scripted API that answers only the sidebar's
// health poll; no page data is needed and nothing runs. The scripted engine reports the version
// the UI under test was built with, so the builds agree unless a test says otherwise.
let version = ''
test.beforeEach(async ({ page }) => { version = await uiBuildVersion(page) })
const health: Record<string, MockHandler> = { '/health': () => ({ status: 'healthy', scanner_version: version }) }

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

// True when nothing is drawn over the middle of the element: it can be seen and clicked.
function uncovered(target: Locator): Promise<boolean> {
  return target.evaluate((element) => {
    const box = element.getBoundingClientRect()
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2)
    return Boolean(hit && element.contains(hit))
  })
}

async function shortWindow(page: Page, allSections: boolean, path: string, routes = health): Promise<Locator> {
  await page.addInitScript((value) => window.localStorage.setItem('shakerscan.sidebar.show_all', value), String(allSections))
  await mockPageApi(page, routes)
  await page.setViewportSize({ width: page.viewportSize()!.width, height: 600 })
  await page.goto(path, { waitUntil: 'domcontentloaded' })
  return sidebar(page)
}

for (const allSections of [false, true]) {
  const sections = allSections ? 'every section shown' : 'the default sections'

  test(`NAV-SHORT-001 a short window keeps New Scan, Settings and the links out in view (${sections})`, async ({ page }) => {
    const nav = await shortWindow(page, allSections, '/docs')
    // The menu is taller than this window, so it has to scroll.
    const more = nav.getByRole('navigation').getByRole('button', { name: /^More/ })
    await expect(more).toBeEnabled()
    await expect(more).toHaveAttribute('aria-expanded', String(allSections))
    expect(await nav.getByRole('navigation').evaluate((list) => {
      const side = list.closest('aside')!
      return list.scrollHeight > list.clientHeight || side.scrollHeight > side.clientHeight
    })).toBe(true)

    for (const control of [
      nav.getByRole('link', { name: 'New Scan', exact: true }),
      nav.getByRole('link', { name: 'Settings', exact: true }),
      nav.getByRole('link', { name: 'shakerscan.com', exact: true }),
      nav.getByRole('link', { name: 'ShakerScan on GitHub' }),
      // Closed, the More row holds the foot of the menu: it is never below the fold.
      ...(allSections ? [] : [more]),
    ]) {
      await expect(control).toBeInViewport({ ratio: 1 })
      expect(await uncovered(control)).toBe(true)
    }

    // The closed row reaches the menu's lower edge: no sliver of a scrolled entry shows under it.
    if (!allSections) {
      expect(await more.evaluate((button) => {
        const list = button.closest('nav')!.getBoundingClientRect()
        return list.bottom - button.parentElement!.getBoundingClientRect().bottom
      })).toBeLessThan(1)
    }

    // Every page stays reachable: the last entry of the menu, focused from the keyboard, is
    // scrolled clear of the foot and of the closed More row above it. So is the More row, which
    // scrolls with the menu once it is open.
    for (const entry of [nav.getByRole('navigation').getByRole('link').last(), more]) {
      await entry.focus()
      await expect(entry).toBeInViewport({ ratio: 1 })
      expect(await uncovered(entry)).toBe(true)
    }
    await expect(nav.getByRole('link', { name: 'New Scan', exact: true })).toBeInViewport({ ratio: 1 })

    // Opening the row in a window this short brings the pages it adds into view.
    if (!allSections) {
      await more.click()
      const opened = nav.locator(`[id="${await more.getAttribute('aria-controls')}"]`).getByRole('link')
      await expect(opened).toHaveCount(5)
      for (const link of await opened.all()) {
        await expect(link).toBeInViewport({ ratio: 1 })
        expect(await uncovered(link)).toBe(true)
      }
    }
  })
}

test('NAV-SHORT-002 a short window opens with the current page visible in the menu', async ({ page }) => {
  const nav = await shortWindow(page, true, '/settings/arsenal')
  const current = nav.getByRole('navigation').getByRole('link', { name: 'Command Arsenal', exact: true })
  await expect(current).toHaveAttribute('aria-current', 'page')
  await expect(current).toBeInViewport({ ratio: 1 })
  expect(await uncovered(current)).toBe(true)
})

test('NAV-SHORT-003 a build mismatch line leaves the current page visible in the menu', async ({ page }) => {
  // The line appears under the logo once the engine has answered, and takes room from the menu.
  const nav = await shortWindow(page, true, '/settings/arsenal', {
    '/health': () => ({
      status: 'healthy', scanner_version: version,
      worker_build: { available: true, fleet_uniform: false, expected_count: 2, reported_count: 2, stale_count: 1, pending_count: 0 },
    }),
  })
  await expect(nav.getByRole('status')).toContainText('Build mismatch: ')
  const current = nav.getByRole('navigation').getByRole('link', { name: 'Command Arsenal', exact: true })
  await expect(current).toBeInViewport({ ratio: 1 })
  expect(await uncovered(current)).toBe(true)
})
