import { expect, test } from '@playwright/test'


const STATIC_ROUTES = [
  '/',
  '/docs',
  '/targets',
  '/scan/new',
  '/scans',
  '/findings',
  '/credentials',
  '/request-collections',
  '/devices',
  '/devices/policies',
  '/schedules',
  '/interactive',
  '/exposure',
  '/asm',
  '/hunt',
  '/deep-hunt/leads',
  '/deep-hunt/experiment',
  '/evidence',
  '/timeline',
  '/campaigns',
  '/ai-gate',
  '/model-intake',
  '/exceptions',
  '/fleet',
  '/settings',
  '/settings/policy-profiles',
  '/settings/arsenal',
  '/settings/ai-ops-router',
] as const


for (const route of STATIC_ROUTES) {
  test(`${route} renders without an application exception`, async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (error) => pageErrors.push(error.message))

    const response = await page.goto(route, { waitUntil: 'domcontentloaded' })

    expect(response, `no document response for ${route}`).not.toBeNull()
    expect(response?.status(), `HTTP status for ${route}`).toBeLessThan(500)
    await expect(page.locator('body')).not.toContainText('Application error')
    await expect(page.locator('body')).not.toContainText('Internal Server Error')
    expect(pageErrors, `page exceptions on ${route}`).toEqual([])
  })
}


test('sidebar links are internal, unique, and navigable', async ({ page }) => {
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  const hrefs = await page.locator('aside a[href], nav a[href]').evaluateAll((links) => (
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
