import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture: the real shell over a scripted API that answers only the sidebar's
// health poll; nothing runs.
const health = { '/health': () => ({ status: 'healthy', scanner_version: 'fixture' }) }

// Relative luminance of a CSS colour as the browser computed it, 0 (black) to 1 (white).
function luminance(color: string): number {
  const [r, g, b] = (color.match(/[\d.]+/g) || []).slice(0, 3).map(Number)
  return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255
}

for (const path of ['/nonexistent-page', '/settings/whatever']) {
  test(`NOT-FOUND-001 ${path} says the page is missing in the product's own style, with a way back`, async ({ page }) => {
    await mockPageApi(page, health)
    const response = await page.goto(path, { waitUntil: 'domcontentloaded' })
    expect(response?.status()).toBe(404)

    const main = page.locator('main')
    const heading = main.getByRole('heading', { level: 1, name: 'Page not found', exact: true })
    await expect(heading).toBeVisible()
    await expect(main.getByText('There is no page at this address.', { exact: true })).toBeVisible()
    // Light text on the product's dark page, not the framework's black-on-white default.
    expect(luminance(await heading.evaluate((element) => getComputedStyle(element).color))).toBeGreaterThan(0.8)
    await expect(main.getByText('This page could not be found.')).toHaveCount(0)

    await main.getByRole('link', { name: 'Back to the dashboard', exact: true }).click()
    await expect(page).toHaveURL(/\/$/)
  })
}
