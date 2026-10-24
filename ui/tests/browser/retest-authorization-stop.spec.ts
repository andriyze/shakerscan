import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Fixture data in the shapes the API returns: a retest row from GET /retests/finding/{id}
// (api/retest_routes/router.py public_retest_row) and a failed Scan whose report the worker
// annotated (api/scan/action_authority_guard.py annotate).
const findingId = '77777777-7777-4777-8777-777777777777'
const scanId = '88888888-8888-4888-8888-888888888888'

const stoppedRetest = {
  id: '99999999-9999-4999-8999-999999999999',
  finding_id: findingId,
  status: 'failed',
  result_status: 'error',
  verdict: 'error',
  verdict_reason: "Retest stopped while it ran: the target's authorization was revoked. No verdict was recorded.",
  finding_type: 'xss',
  target_url: 'http://retest.fixture.test',
  retry_class: 'authorization',
  retryable: false,
  verification_mode: 'deterministic',
  deterministic_proof_state: 'not_proven',
  verdict_basis: 'execution_result',
  tested_endpoints: [],
  stop_reason: 'authorization_withdrawn',
  authority_stop: {
    stop_reason: 'authorization_withdrawn',
    reason_code: 'authorization_revoked',
    observed_at: '2026-10-10T10:00:00+00:00',
    before_start: false,
    interrupted_actions: ['finding.retest'],
    not_run_actions: [],
  },
  created_at: '2026-10-10T09:59:00Z',
  completed_at: '2026-10-10T10:00:03Z',
}

async function mockApi(page: Page, retestModes: string[] = ['tiered', 'deterministic']) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === `/findings/${findingId}`) {
      return route.fulfill({ json: {
        id: findingId, title: 'Reflected XSS', severity: 'high', status: 'active', tool: 'dalfox',
        url: 'http://retest.fixture.test/search?q=1', target_url: 'http://retest.fixture.test',
        last_verification_status: 'error', last_verification_verdict: 'error',
        retest_supported: true, retest_type: 'xss', retest_modes: retestModes,
        first_seen_at: '2026-10-01T00:00:00Z', last_seen_at: '2026-10-10T00:00:00Z',
      } })
    }
    if (path === `/retests/finding/${findingId}`) {
      return route.fulfill({ json: { finding_id: findingId, retests: [stoppedRetest], count: 1 } })
    }
    if (path === `/scans/${scanId}`) {
      return route.fulfill({ json: {
        id: scanId, status: 'failed', current_phase: 'failed', target_url: 'http://device.fixture.test',
        error_message: 'Scan stopped while it ran: target authorization check returned authorization_revoked',
        result: { scan_metadata: { stop_reason: 'authorization_withdrawn', status: 'partial',
          authority_stop: { stop_reason: 'authorization_withdrawn', reason_code: 'authorization_revoked',
            interrupted_actions: ['scan.run'], not_run_actions: [] } } },
        created_at: '2026-10-10T09:00:00Z',
      } })
    }
    return route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } })
  })
}

test('a retest stopped by its authorization says so and records no verdict', async ({ page }) => {
  await mockApi(page)
  await page.goto(`/findings/${findingId}`)
  const stop = page.getByTestId('retest-authorization-stop')
  await expect(stop).toBeVisible()
  await expect(stop).toContainText('Retest stopped: authorization withdrawn')
  await expect(stop).toContainText('authorization was revoked while this retest was running')
  await expect(stop).toContainText('No verdict was recorded')
})

test('a retest offers the prover tiers, never the AI tier alone', async ({ page }) => {
  // An AI verdict is at most inconclusive, so an AI-only retest could never conclude; the page
  // offers none even where the API (an earlier one) still lists the "ai" mode.
  await mockApi(page, ['tiered', 'deterministic', 'ai'])
  await page.goto(`/findings/${findingId}`)
  await expect(page.getByLabel('Retest mode').locator('option')).toHaveText(['Tiered', 'Deterministic only'])
})

test('a scan stopped by its authorization names why, not the failed phase', async ({ page }) => {
  await mockApi(page)
  await page.goto(`/scans/${scanId}`)
  await expect(page.getByText('This scan was stopped because the target’s authorization was revoked.')).toBeVisible()
  await expect(page.getByText(/stopped during the failed phase/)).toHaveCount(0)
})
