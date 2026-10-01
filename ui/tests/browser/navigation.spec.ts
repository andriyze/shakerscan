import { expect, test } from '@playwright/test'
import routeManifest from '../../test-manifests/ui-route-action-manifest.json'
import { visitAndAuditPage } from './page-quality'


const STATIC_ROUTES = routeManifest.routes.flatMap((route) => route.smokePath ? [route.smokePath] : [])


for (const route of STATIC_ROUTES) {
  test(`${route} renders without an application exception`, async ({ page }) => {
    await visitAndAuditPage(page, route)
  })
}


test('sidebar links are internal, unique, and navigable', async ({ page }) => {
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  const openNavigation = page.getByLabel('Open navigation')
  if (await openNavigation.isVisible()) {
    // A click before the client hydrates can be lost. Retry the actual drawer
    // interaction instead of waiting for networkidle on a polling dashboard.
    await expect(async () => {
      if (await page.locator('nav:visible a[href]').count() === 0) await openNavigation.click()
      await expect(page.locator('nav:visible a[href]').first()).toBeVisible()
    }).toPass({ timeout: 10_000 })
  }
  // The responsive shell keeps the desktop sidebar in the DOM while the mobile
  // drawer is open. Audit the active navigation surface, not its hidden twin.
  const hrefs = await page.locator('aside:visible a[href], nav:visible a[href]').evaluateAll((links) => (
    links.map((link) => link.getAttribute('href')).filter((href): href is string => Boolean(href))
  ))
  const internal = hrefs.filter((href) => href.startsWith('/'))
  const external = hrefs.filter((href) => !href.startsWith('/'))

  expect(hrefs.length).toBeGreaterThan(15)
  expect(external).toEqual(['https://github.com/andriyze/shakerscan'])
  const duplicates = Array.from(new Set(
    internal.filter((href, index) => internal.indexOf(href) !== index),
  ))
  // The product logo and explicit Dashboard item intentionally share the home route.
  expect(duplicates).toEqual(['/'])
})


test('production shell sends browser security headers', async ({ page }) => {
  const response = await page.goto('/', { waitUntil: 'domcontentloaded' })
  expect(response).not.toBeNull()
  const headers = response!.headers()
  expect(headers['x-powered-by']).toBeUndefined()
  expect(headers['x-content-type-options']).toBe('nosniff')
  expect(headers['x-frame-options']).toBe('DENY')
  expect(headers['cross-origin-opener-policy']).toBe('same-origin')
  expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin')
  expect(headers['permissions-policy']).toContain('camera=()')
  expect(headers['content-security-policy']).toContain("frame-ancestors 'none'")
  expect(headers['content-security-policy']).toContain("object-src 'none'")
})


test('README badge links have accessible image names', async ({ page }) => {
  await page.goto('/docs', { waitUntil: 'domcontentloaded' })
  // The badge images are external (shields.io, GitHub, scorecard.dev). A link whose image has not
  // loaded yet has no box, so asserting visibility made this test wait on third-party latency (the
  // Scorecard badge redirect alone can take over 10 seconds). The accessible name is the contract:
  // each link exists once and its image carries the alt text that names it.
  for (const name of ['License: AGPL-3.0-only', 'Latest release', 'Python suite', 'CodeQL', 'OpenSSF Scorecard']) {
    const link = page.getByRole('link', { name })
    await expect(link).toHaveCount(1)
    await expect(link.locator('img')).toHaveAttribute('alt', name)
  }
})
