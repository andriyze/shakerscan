// Browser contract fixture: a queued Scan says what it waits behind (2.12.1), and every link on a
// queued or running Scan page has a name. Scripted API; no Scan runs.
import { expect, test, type Page } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

const QUEUED = '77777777-7777-4777-8777-777777777777'
const RUNNING = '88888888-8888-4888-8888-888888888888'
const DISCOVERY = '99999999-9999-4999-8999-999999999999'
const TARGET = '55555555-5555-4555-8555-555555555555'

function scan(id: string, status: string, extra: Record<string, unknown> = {}) {
  return {
    id, status, target_id: TARGET, target_url: 'http://10.0.0.4:3000', target_name: 'Juice Shop (lab)',
    scan_type: 'scan', run_kind: 'web_dast', progress: status === 'running' ? 50 : 0,
    current_phase: status === 'running' ? 'verify.sqli.r02' : null, created_at: '2026-11-07T00:00:00Z',
    started_at: status === 'running' ? '2026-11-07T00:00:00Z' : null, options: { budget_profile: 'fast' }, ...extra,
  }
}

async function mock(page: Page, running: unknown[]) {
  return mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy' }),
    [`GET /scans/${QUEUED}`]: () => scan(QUEUED, 'queued'),
    [`GET /scans/${RUNNING}`]: () => scan(RUNNING, 'running'),
    [`GET /scans/${QUEUED}/logs`]: () => ({ logs: [], total: 0 }),
    [`GET /scans/${RUNNING}/logs`]: () => ({ logs: [{ raw: 'Started Verify SQLi R01 · 45%' }], total: 1 }),
    'GET /scans': (url) => {
      expect(url.searchParams.get('status')).toBe('running')
      return { scans: running, total: running.length, limit: 5, offset: 0 }
    },
  })
}

async function expectEveryLinkNamed(page: Page) {
  const unnamed = await page.evaluate(() => [...document.querySelectorAll('main a[href]')]
    .filter((el) => {
      const r = el.getBoundingClientRect()
      if (!r.width || !r.height) return false
      const name = (el.getAttribute('aria-label') || el.getAttribute('title') || (el as HTMLElement).innerText || '').trim()
      return !name
    })
    .map((el) => el.outerHTML.slice(0, 160)))
  expect(unnamed).toEqual([])
}

for (const width of [390, 1440]) {
  test(`QUEUE-WAIT-001 a queued Scan names the Scans it waits behind at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await mock(page, [
      scan(RUNNING, 'running'),
      scan(DISCOVERY, 'running', { target_name: 'host://10.0.0.4', target_url: 'host://10.0.0.4', run_kind: 'device_posture', scan_type: 'device_posture' }),
    ])
    await page.goto(`/scans/${QUEUED}`)
    const wait = page.getByTestId('queue-wait')
    await expect(wait).toContainText('Waiting behind 2 running Scans.')
    await expect(wait.getByRole('link', { name: 'Juice Shop (lab)' })).toHaveAttribute('href', `/scans/${RUNNING}`)
    await expect(wait).toContainText('10.0.0.4 · network discovery')
    await wait.getByRole('link', { name: 'Juice Shop (lab)' }).click()
    await expect(page).toHaveURL(new RegExp(`/scans/${RUNNING}$`))
    await expectEveryLinkNamed(page)
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })

  test(`QUEUE-WAIT-002 with nothing running the queued Scan says so at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await mock(page, [])
    await page.goto(`/scans/${QUEUED}`)
    await expect(page.getByTestId('queue-wait')).toContainText('No other Scan is running.')
    await expectEveryLinkNamed(page)
  })
}
