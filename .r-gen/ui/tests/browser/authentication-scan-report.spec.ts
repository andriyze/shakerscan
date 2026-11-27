import { expect, test } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

test('completed execution keeps credential interruption visible beside supported findings', async ({ page }, testInfo) => {
  const scanId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  await pinMockApiOrigin(page)
  // The installed-stack certification publishes the API on a free high port, never 8080, so
  // a port-literal pattern matches nothing there and the real API answers 404 for this fixture.
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } }))
  await page.route(`${MOCK_API_ORIGIN}/scans/${scanId}`, route => route.fulfill({ json: {
    id: scanId, target_url: 'https://fixture.example.test', status: 'completed',
    created_at: '2026-09-15T00:00:00Z', completed_at: '2026-09-15T00:01:00Z',
    options: {}, result: {
      authentication_assurance: { state: 'unknown', reason_code: 'authentication_gap', interrupted_action_count: 2 },
      coverage: { status: 'partial', reasons: ['authentication_uncertain'] },
      result: { risk_score: 40, risk_grade: 'F', assurance_score: 20, assurance_band: 'limited', grade_reliable: false },
      findings: [{ title: 'Previously confirmed fixture finding', severity: 'high',
        verified: true, proof_state: 'verified', url: 'https://fixture.example.test/account', tool: 'fixture' }],
    },
  } }))
  await page.goto(`/scans/${scanId}`)
  await expect(page.getByText('Credential authority unavailable', { exact: true })).toBeVisible()
  await expect(page.getByText(/2 planned actions were interrupted or blocked/)).toBeVisible()
  await expect(page.getByText(/Independently verified findings remain supported/)).toBeVisible()
  await expect(page.getByText(/1 confirmed material issue requires action/)).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('authentication-interruption.png'), fullPage: true })
})
