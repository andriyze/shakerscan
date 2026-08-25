import { expect, type ConsoleMessage, type Page } from '@playwright/test'


export async function visitAndAuditPage(page: Page, route: string, settleMs = 300) {
  const pageErrors: string[] = []
  const consoleErrors: string[] = []
  const onPageError = (error: Error) => pageErrors.push(error.message)
  const onConsole = (message: ConsoleMessage) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  }
  page.on('pageerror', onPageError)
  page.on('console', onConsole)

  try {
    const response = await page.goto(route, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(settleMs)

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
  } finally {
    page.off('pageerror', onPageError)
    page.off('console', onConsole)
  }
}
