import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Mocked spec (fixture data, not a live stack): GET /findings/{id} in the shape the API
// returns. Everything else the page asks for is refused so the spec stays hermetic.
const findingId = '5c0b7c1e-1d8e-4b6a-9f3e-2a4d1e0c9b11'

// A plain-HTTP, non-localhost host name is not a secure context, so the browser has no
// navigator.clipboard there -- the situation of a self-hosted install reached by LAN name.
const INSECURE_HOST = 'shakerscan-lan.test'

// Resolve the LAN-style name to the server under test (the secure tests ignore it).
test.use({ launchOptions: { args: [`--host-resolver-rules=MAP ${INSECURE_HOST} 127.0.0.1`] } })

async function mockApi(page: Page) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === `/findings/${findingId}`) {
      return route.fulfill({ json: {
        id: findingId, title: 'Reflected XSS in search', severity: 'high', status: 'active', tool: 'dalfox',
        url: 'http://copy.fixture.test/search?q=1', target_url: 'http://copy.fixture.test',
        first_seen_at: '2026-10-01T00:00:00Z', last_seen_at: '2026-10-10T00:00:00Z',
      } })
    }
    return route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } })
  })
}

/** Records what a document-level copy event carried, which is what execCommand('copy') puts on the clipboard. */
async function recordCopyEvents(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __copied: string[] }
    w.__copied = []
    document.addEventListener('copy', () => { w.__copied.push(String(document.getSelection() || '')) }, true)
  })
}

function insecureUrl(baseURL: string | undefined, path: string): string {
  const base = new URL(baseURL || 'http://127.0.0.1:3000')
  return `${base.protocol}//${INSECURE_HOST}:${base.port || '80'}${path}`
}

test.describe('secure context', () => {
  test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

  test('Copy link puts the absolute finding URL on the clipboard', async ({ page, baseURL }) => {
    await mockApi(page)
    await page.goto(`/findings/${findingId}`)
    const button = page.getByTestId('finding-copy-link')
    await expect(button).toBeVisible()
    expect(await page.evaluate(() => window.isSecureContext)).toBe(true)

    await button.click()
    await expect(button).toHaveAttribute('data-copy-state', 'copied')
    const origin = new URL(baseURL || 'http://127.0.0.1:3000').origin
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`${origin}/findings/${findingId}`)
    await expect(page.getByTestId('copy-fallback')).toHaveCount(0)
  })
})

test.describe('insecure context (plain HTTP on a LAN host name)', () => {
  test('Copy link still copies, through the execCommand fallback', async ({ page, baseURL }) => {
    await mockApi(page)
    await recordCopyEvents(page)
    const url = insecureUrl(baseURL, `/findings/${findingId}`)
    await page.goto(url)
    const button = page.getByTestId('finding-copy-link')
    await expect(button).toBeVisible()
    expect(await page.evaluate(() => ({ secure: window.isSecureContext, clipboard: typeof navigator.clipboard }))).toEqual({ secure: false, clipboard: 'undefined' })

    const scrollBefore = await page.evaluate(() => window.scrollY)
    await button.click()
    await expect(button).toHaveAttribute('data-copy-state', 'copied')
    const expected = `${new URL(url).origin}/findings/${findingId}`
    expect(await page.evaluate(() => (window as unknown as { __copied: string[] }).__copied)).toEqual([expected])
    // The temporary textarea is gone and the page did not move.
    expect(await page.locator('textarea[aria-hidden="true"]').count()).toBe(0)
    expect(await page.evaluate(() => window.scrollY)).toBe(scrollBefore)
    await expect(page.getByTestId('copy-fallback')).toHaveCount(0)
  })

  test('when the browser refuses every copy method the link is shown selected, not lost', async ({ page, baseURL }) => {
    await mockApi(page)
    await page.addInitScript(() => { document.execCommand = () => false })
    const url = insecureUrl(baseURL, `/findings/${findingId}`)
    await page.goto(url)
    await page.getByTestId('finding-copy-link').click()

    const fallback = page.getByTestId('copy-fallback')
    await expect(fallback).toBeVisible()
    await expect(fallback).toContainText('The browser blocked copying')
    const field = fallback.getByRole('textbox')
    const expected = `${new URL(url).origin}/findings/${findingId}`
    await expect(field).toHaveValue(expected)
    await expect(field).toBeFocused()
    expect(await field.evaluate((el: HTMLInputElement) => el.value.slice(el.selectionStart ?? 0, el.selectionEnd ?? 0))).toBe(expected)
    await field.press('Escape')
    await expect(fallback).toHaveCount(0)
  })
})
