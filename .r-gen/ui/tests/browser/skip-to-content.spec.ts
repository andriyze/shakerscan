import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture (synthetic, nothing runs): the first tab stop of every page is a link
// that moves focus past the sidebar to the page content.
test('SKIP-001 the first tab stop is "Skip to content" and it moves focus into the page', async ({ page }) => {
  await mockPageApi(page, { 'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }) })
  await page.goto('/docs', { waitUntil: 'load' })
  const skip = page.getByRole('link', { name: 'Skip to content', exact: true })
  await expect(skip).toHaveAttribute('href', '#main-content')
  // Out of sight until it has focus.
  expect((await skip.boundingBox())!.width).toBeLessThanOrEqual(1)

  await page.keyboard.press('Tab')
  await expect(skip).toBeFocused()
  const box = (await skip.boundingBox())!
  expect(box.width).toBeGreaterThan(80)
  expect(box.height).toBeGreaterThan(20)
  expect(box.x).toBeGreaterThanOrEqual(0)
  expect(box.y).toBeGreaterThanOrEqual(0)

  await page.keyboard.press('Enter')
  await expect(page.locator('main#main-content')).toBeFocused()
  // The next tab stop is inside the page, not the sidebar.
  await page.keyboard.press('Tab')
  expect(await page.evaluate(() => Boolean(document.activeElement?.closest('main')))).toBe(true)
})
