import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture: one completed scan with an execution record, unfinished steps and no
// triage summary, as the API answers it. Synthetic: nothing is stored and nothing runs.
const SCAN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa0011'
const TARGET = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbb0011'
const PLAN = 'b0b91a693ea4f299197ce3bcc6c117742d9765167e0c06df7b11fa07ddc9a2e0'
const CONTINUATION = '13a2815520c441c720134efe2e2d5bedfa4ab60f160e8c4acb75bf54a96c8601'

const steps = [
  { action_id: 'baseline.http', capability_name: 'http.request', label: 'Baseline HTTP', status: 'success', required: true },
  { action_id: 'verify.sqli.r01', capability_name: 'sqli.verify_batch', label: 'Verify SQLi R01', status: 'partial', required: true, reason_code: 'http_request_budget_exhausted' },
  { action_id: 'verify.sqli.r01.ext.r02', capability_name: 'sqli.verify_batch', label: 'Verify SQLi R01 Ext R02', status: 'timed_out', required: false, reason_code: 'timed_out' },
  { action_id: 'prove.xss.r01', capability_name: 'xss.browser_prove_batch', label: 'Prove XSS R01', status: 'skipped', required: false, reason_code: 'not_applicable' },
  { action_id: 'prove.sqli.r01', capability_name: 'sqli.prove_batch', label: 'Prove SQLi R01', status: 'skipped', required: true, reason_code: 'not_applicable' },
  { action_id: 'finalize.report', capability_name: 'scan.finalize', label: 'Finalize Report', status: 'success', required: true },
]
const matrix = { total: 5, completed: 1, partial: 2, skipped: 2, failed: 0, blocked: 0, required: 3, cancelled: 0, actions: steps }

function scan() {
  return {
    id: SCAN, target_id: TARGET, target_url: 'https://shop.fixture.example', status: 'completed', scan_type: 'standard',
    created_at: '2026-09-15T00:00:00Z', completed_at: '2026-09-15T00:10:00Z',
    options: { scan_execution_plan: { budget_profile: 'thorough', resolved_families: ['recon', 'nuclei_passive', 'sqli', 'sensitive_exposure'], policy: { active_testing: true } } },
    execution_explanation: {
      schema_version: 'scan-execution-explanation/v1', scan_id: SCAN, scan_status: 'completed', plan_digest: PLAN,
      plan_revision: { schema_version: 'scan-plan-revision/v1', revision: 4, plan_digest: PLAN, continuation_plan_digest: CONTINUATION },
      stage_timeline: [{ stage: 'verify', label: 'Verify Candidates', status: 'partial', action_count: 2 }],
      actions: steps.map((step) => ({ ...step, occurrence_id: step.action_id, placement: { backend: 'local' }, budget: {}, observation: { count: 0 } })),
      budget: { limit: { http_requests: 1000 }, allocated: { http_requests: 800 }, consumed: { http_requests: 700 }, unallocated: { http_requests: 200 } },
      coverage: { capability_coverage: matrix, grade_reliability: { reliable: true } },
      transport_parity: { contract: 'identical_canonical_action_graph/v1', consistent: true },
    },
    result: {
      result: { risk_score: 40, risk_grade: 'D', assurance_score: 70, assurance_band: 'adequate', grade_reliable: true },
      findings: [
        { title: 'SQL injection in search', severity: 'high', url: 'https://shop.fixture.example/search', tool: 'sqli', verified: true },
      ],
      verification_summary: { verified: 1, suspected: 0, unproven_critical_high: 0 },
      coverage: { status: 'partial', reasons: ['http_request_budget_exhausted'], capability_coverage: matrix, selected_family_gaps: ['sqli'] },
    },
  }
}

test('COVERAGE-001 the coverage tab names steps in plain words and keeps plan identifiers in a fold', async ({ page }) => {
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    [`GET /scans/${SCAN}`]: () => scan(),
  })
  await page.goto(`/scans/${SCAN}?tab=coverage`, { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByRole('heading', { name: 'What this scan ran' })).toBeVisible()

  // Plan identifiers and format names are there for support, behind a closed fold.
  const technical = main.getByTestId('plan-technical-details')
  await expect(technical.locator('summary')).toHaveText('Technical details')
  await expect(technical).not.toHaveAttribute('open', /.*/)
  await expect(main.getByText(PLAN)).toBeHidden()
  await expect(main.getByText(CONTINUATION)).toBeHidden()
  await expect(main.getByText(/scan-plan-revision\/v1/)).toBeHidden()
  await expect(main.getByText('Same local / fleet contract')).toBeHidden()
  await technical.locator('summary').click()
  await expect(technical.getByText(PLAN)).toBeVisible()
  await expect(technical.getByText('scan-plan-revision/v1 · revision 4')).toBeVisible()
  await expect(technical.getByText(CONTINUATION)).toBeVisible()

  // A scan that carries no triage summary shows no zero-filled triage tiles beside its findings.
  const gaps = main.getByTestId('coverage-gaps').filter({ has: page.getByRole('heading', { name: 'Coverage gaps', exact: true }) })
  await expect(gaps).toHaveCount(1)
  await expect(main.getByText('Suspected High', { exact: true })).toHaveCount(0)
  await expect(main.getByText('AI False Positives', { exact: true })).toHaveCount(0)

  // Unfinished work is named as a reader would name it; steps that did not apply are not gaps.
  await expect(gaps.getByRole('listitem')).toHaveCount(2)
  await expect(gaps.getByRole('listitem').nth(0)).toContainText('SQL injection checks: partly completed — ')
  await expect(gaps.getByRole('listitem').nth(1)).toContainText('SQL injection checks: timed out — ')
  await expect(gaps.getByText('2 planned steps did not apply to this target and were not needed.', { exact: true })).toBeVisible()
  await expect(main.getByText(/Sqli Verify Batch|Xss Browser Prove Batch|Sqli Prove Batch/)).toHaveCount(0)

  // Check families read as the New Scan page offers them.
  await expect(main.getByText('Recon, Nuclei (passive reviewed pack), SQL Injection, Sensitive Exposure', { exact: true })).toBeVisible()
  await expect(main.getByText('SQL Injection', { exact: true })).toBeVisible()

  // The step list keeps the step id beside the plain name.
  await main.getByText('Step details (6)', { exact: true }).click()
  const step = main.locator('[id="verify.sqli.r01.ext.r02"]')
  await expect(step.getByText('SQL injection checks', { exact: true })).toBeVisible()
  await expect(step.getByText('timed out', { exact: true })).toBeVisible()
  await expect(step.getByText('verify.sqli.r01.ext.r02', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

test('COVERAGE-002 a scan that carries a triage summary still shows it', async ({ page }) => {
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    [`GET /scans/${SCAN}`]: () => {
      const record = scan()
      return { ...record, result: { ...record.result, triage: { confirmed: { count: 3 }, suspected_high: { count: 1 } } } }
    },
  })
  await page.goto(`/scans/${SCAN}?tab=coverage`, { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByRole('heading', { name: 'Triage and coverage gaps', exact: true })).toBeVisible()
  await expect(main.getByText('Suspected High', { exact: true })).toBeVisible()
})
