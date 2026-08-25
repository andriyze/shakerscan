import { expect, test } from '@playwright/test'
import routeManifest from '../../test-manifests/ui-route-action-manifest.json'


const STATIC_ROUTES = routeManifest.routes.flatMap((route) => route.smokePath ? [route.smokePath] : [])


for (const route of STATIC_ROUTES) {
  test(`${route} renders without an application exception`, async ({ page }) => {
    const pageErrors: string[] = []
    const consoleErrors: string[] = []
    page.on('pageerror', (error) => pageErrors.push(error.message))
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text())
    })

    const response = await page.goto(route, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(300)

    expect(response, `no document response for ${route}`).not.toBeNull()
    expect(response?.status(), `HTTP status for ${route}`).toBeLessThan(500)
    await expect(page.locator('main')).toHaveCount(1)
    await expect(page.locator('body')).not.toContainText('Application error')
    await expect(page.locator('body')).not.toContainText('Internal Server Error')
    expect(pageErrors, `page exceptions on ${route}`).toEqual([])
    expect(consoleErrors, `console errors on ${route}`).toEqual([])
    const layout = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      unnamed: [...document.querySelectorAll('button,input,select,textarea,a[href],summary')]
        .filter((control) => {
          const element = control as HTMLElement
          if (!(element.offsetWidth || element.offsetHeight || element.getClientRects().length)) return false
          if (control instanceof HTMLInputElement && control.type === 'hidden') return false
          const id = element.id
          const explicitLabel = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null
          const labelledBy = element.getAttribute('aria-labelledby')
          const labelledText = labelledBy
            ? labelledBy.split(/\s+/).map((labelId) => document.getElementById(labelId)?.textContent || '').join(' ')
            : ''
          const inputValue = control instanceof HTMLInputElement && ['button', 'submit', 'reset'].includes(control.type)
            ? control.value
            : ''
          const name = element.getAttribute('aria-label')
            || labelledText
            || explicitLabel?.textContent
            || element.closest('label')?.textContent
            || element.getAttribute('title')
            || inputValue
            || element.textContent
          return !name?.trim()
        })
        .map((control) => control.outerHTML.slice(0, 180)),
    }))
    expect(layout.scrollWidth, `horizontal page overflow on ${route}`).toBeLessThanOrEqual(layout.clientWidth)
    expect(layout.unnamed, `visible unnamed controls on ${route}`).toEqual([])
  })
}


test('sidebar links are internal, unique, and navigable', async ({ page }) => {
  await page.goto('/', { waitUntil: 'domcontentloaded' })
  const openNavigation = page.getByLabel('Open navigation')
  if (await openNavigation.isVisible()) await openNavigation.click()
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
