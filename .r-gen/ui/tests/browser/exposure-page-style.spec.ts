import { expect, test, type Page } from '@playwright/test'

import fixture from './fixtures/service-intelligence.json'
import { mockPageApi } from './mock-page-api'

// Browser contract fixture: the Exposure page over a scripted service inventory. Synthetic:
// nothing is stored and nothing runs.
const scanned = { ...fixture.targets[0], locator: 'https://app.example.test', source_count: 6 }
const empty = {
  kind: 'web', services: [], listener_groups: [], source_count: 0, sources_truncated: false, findings_truncated: false,
  unlinked_findings_count: 0, warnings: [], root_domain: 'example.test',
}
// The host record the scanned target belongs to: no address and nothing recorded of its own.
const hostRecord = { ...empty, id: '99999999-9999-4999-8999-999999999999', label: 'app.example.test', locator: null }
const unscanned = { ...empty, id: '88888888-8888-4888-8888-888888888888', label: 'Other app', locator: 'https://other.example.test' }

async function open(page: Page, targets: unknown[]) {
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    'GET /domains': () => ({ domains: ['example.test'] }),
    'GET /exposure/services': () => ({ ...fixture, targets, total_targets: targets.length, has_more: false }),
  })
  await page.goto('/exposure', { waitUntil: 'domcontentloaded' })
  await expect(page.getByTestId('service-target').first()).toBeVisible()
}

test('EXPOSURE-001 the page uses the shared header and text style, and quiet page buttons', async ({ page }) => {
  await open(page, [scanned])
  const main = page.locator('main')
  const title = main.getByRole('heading', { level: 1, name: 'Exposure', exact: true })
  const style = await title.evaluate((heading) => {
    const text = heading.closest('main')!.querySelector('[data-testid="service-target-count"]')!
    return {
      transform: getComputedStyle(heading).textTransform,
      spacing: getComputedStyle(heading).letterSpacing,
      textFont: getComputedStyle(text).fontFamily,
      pageFont: getComputedStyle(document.body).fontFamily,
    }
  })
  expect(style.transform).toBe('none')
  expect(style.spacing).toBe('normal')
  expect(style.textFont).toBe(style.pageFont)
  expect(style.textFont).not.toMatch(/mono/i)

  // One page of targets: both page buttons are off, and not painted as the primary action.
  const primary = await main.getByRole('button', { name: 'Search', exact: true }).evaluate((button) => getComputedStyle(button).backgroundColor)
  for (const name of ['Previous', 'Next']) {
    const button = main.getByRole('button', { name, exact: true })
    await expect(button).toBeDisabled()
    expect(await button.evaluate((element) => getComputedStyle(element).backgroundColor)).not.toBe(primary)
  }
})

test('EXPOSURE-002 the host record of a listed target is not a second, empty card', async ({ page }) => {
  await open(page, [hostRecord, scanned])
  const main = page.locator('main')
  await expect(main.getByTestId('service-target')).toHaveCount(1)
  await expect(main.getByTestId('service-target-count')).toContainText('1 matching target ·')
  await expect(main.getByText('web · https://app.example.test · 6 evidence sources', { exact: true })).toBeVisible()
  await expect(main.getByText(/No positive service evidence retained/)).toHaveCount(0)
  await expect(main.getByText(/web · +·/)).toHaveCount(0)
})

test('EXPOSURE-003 a target with no evidence of its own keeps its card', async ({ page }) => {
  await open(page, [scanned, unscanned])
  const main = page.locator('main')
  await expect(main.getByTestId('service-target')).toHaveCount(2)
  await expect(main.getByTestId('service-target-count')).toContainText('2 matching targets ·')
  await expect(main.getByText('web · https://other.example.test · 0 evidence sources', { exact: true })).toBeVisible()
  await expect(main.getByText(/No positive service evidence retained/)).toHaveCount(1)
})
