import { expect, test, type Locator, type Page } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture: the real sidebar over a scripted API that answers only the sidebar's
// health poll; no page data is needed and nothing runs.
const health = { '/health': () => ({ status: 'healthy', scanner_version: 'fixture' }) }

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

async function shortWindow(page: Page, allSections: boolean, path: string): Promise<Locator> {
  await page.addInitScript((value) => window.localStorage.setItem('shakerscan.sidebar.show_all', value), String(allSections))
  await mockPageApi(page, health)
  await page.setViewportSize({ width: page.viewportSize()!.width, height: 600 })
  await page.goto(path, { waitUntil: 'domcontentloaded' })
  return sidebar(page)
}

for (const allSections of [false, true]) {
  const sections = allSections ? 'every section shown' : 'the default sections'

  test(`NAV-SHORT-001 a short window keeps New Scan, the section switch and Settings in view (${sections})`, async ({ page }) => {
    const nav = await shortWindow(page, allSections, '/docs')
    // The menu is taller than this window, so it has to scroll.
    await expect(nav.getByRole('switch', { name: 'All sections' })).toBeEnabled()
    expect(await nav.getByRole('navigation').evaluate((list) => {
      const side = list.closest('aside')!
      return list.scrollHeight > list.clientHeight || side.scrollHeight > side.clientHeight
    })).toBe(true)

    for (const control of [
      nav.getByRole('link', { name: 'New Scan', exact: true }),
      nav.getByRole('switch', { name: 'All sections' }),
      nav.getByRole('link', { name: 'Settings', exact: true }),
    ]) {
      await expect(control).toBeInViewport({ ratio: 1 })
      expect(await uncovered(control)).toBe(true)
    }

    // Every page stays reachable: the last entry of the menu, focused from the keyboard, is
    // scrolled clear of the block that stays at the foot.
    const last = nav.getByRole('navigation').getByRole('link').last()
    await last.focus()
    await expect(last).toBeInViewport({ ratio: 1 })
    expect(await uncovered(last)).toBe(true)
    await expect(nav.getByRole('link', { name: 'New Scan', exact: true })).toBeInViewport({ ratio: 1 })
  })
}

test('NAV-SHORT-002 a short window opens with the current page visible in the menu', async ({ page }) => {
  const nav = await shortWindow(page, true, '/settings/arsenal')
  const current = nav.getByRole('navigation').getByRole('link', { name: 'Command Arsenal', exact: true })
  await expect(current).toHaveAttribute('aria-current', 'page')
  await expect(current).toBeInViewport({ ratio: 1 })
  expect(await uncovered(current)).toBe(true)
})
