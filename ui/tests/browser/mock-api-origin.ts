import type { Page } from '@playwright/test'


/** Origin a mocked spec serves its fake API on, and intercepts exactly. */
export const MOCK_API_ORIGIN = 'http://localhost:8080'


/**
 * Pin the browser-facing API origin for a spec that mocks the API.
 *
 * The app resolves its API origin from `window.__SHAKERSCAN_API_URL__`, which
 * `/api/runtime-config` publishes on every page load from the deployment's own
 * `NEXT_PUBLIC_API_URL`. An `addInitScript` override alone is therefore overwritten
 * before the app reads it, so a mocked spec only intercepted correctly when the
 * deployment happened to serve its API on this exact origin -- true for a default
 * install, false for any install on another port. Stubbing the runtime-config script
 * keeps these specs hermetic on any port, so they test the UI contract rather than
 * the port the stack under test happens to have been started on.
 */
export async function pinMockApiOrigin(page: Page, origin: string = MOCK_API_ORIGIN): Promise<void> {
  await page.addInitScript((url) => { window.__SHAKERSCAN_API_URL__ = url }, origin)
  await page.route('**/api/runtime-config', route => route.fulfill({
    status: 200,
    contentType: 'application/javascript; charset=utf-8',
    body: `window.__SHAKERSCAN_API_URL__=${JSON.stringify(origin)};\n`,
  }))
}
