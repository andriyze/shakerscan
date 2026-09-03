import { expect, test, type APIRequestContext } from '@playwright/test'

import { visitAndAuditPage } from './page-quality'


const REAL_STACK = process.env.PLAYWRIGHT_REAL_STACK === '1'
const API_URL = process.env.SHAKERSCAN_API_URL || 'http://localhost:8080'

async function readJson(request: APIRequestContext, path: string) {
  const response = await request.get(`${API_URL}${path}`)
  expect(response.ok(), `GET ${path}`).toBeTruthy()
  return response.json()
}

test('real dynamic detail routes remain usable and accessible', async ({ page, request }) => {
  test.skip(!REAL_STACK, 'release-only non-mutating dynamic UI acceptance')

  const [scanData, findingData, deviceData, huntData, campaignData, targetData] = await Promise.all([
    readJson(request, '/scans?limit=20'),
    readJson(request, '/findings?limit=50'),
    readJson(request, '/devices?limit=20'),
    readJson(request, '/hunts?limit=20'),
    readJson(request, '/arsenal/campaigns?limit=20'),
    readJson(request, '/targets?limit=20'),
  ])

  const scan = (scanData.scans || []).find((item: any) => item.scan_role !== 'shard' && item.run_kind === 'web_dast')
    || (scanData.scans || []).find((item: any) => item.scan_role !== 'shard')
  const finding = (findingData.findings || []).find((item: any) => item.target_id && !item.device_target_id)
    || (findingData.findings || [])[0]
  const device = (deviceData.devices || []).find((item: any) => item.is_active) || (deviceData.devices || [])[0]
  const hunt = (huntData.hunts || []).find((item: any) => item.target_id)
  const campaign = (campaignData.campaigns || []).find((item: any) => item.campaign_type !== 'autonomous_research')
  const target = (targetData.targets || []).find((item: any) => item.is_active) || (targetData.targets || [])[0]

  // The deterministic E2E areas always leave a scan, a finding, a Hunt, and a target behind on a
  // clean installed stack; those detail routes are required by name. Devices, campaigns, and legacy
  // research episodes exist only when their optional areas or an operator created them, so they are
  // audited when present rather than demanded by a record count that encoded a developer database.
  // Legacy research episodes are a compatibility surface and are not part of release acceptance.
  const required: Record<string, string | undefined> = {
    scan: scan?.id && `/scans/${scan.id}`,
    finding: finding?.id && `/findings/${finding.id}`,
    hunt: hunt?.hunt_id && hunt?.target_id
      && `/hunt?target=${encodeURIComponent(hunt.target_id)}&run=${encodeURIComponent(hunt.hunt_id)}`,
    target: target?.id && `/targets/${target.id}/graph`,
  }
  const missing = Object.entries(required).filter(([, route]) => !route).map(([name]) => name)
  // The pull-request smoke boots a stack without the DAST area, so it has no completed scan or
  // finding to audit; certification runs on an installed stack that always has them. Skip with
  // the reason instead of failing a stack that never produced the records.
  test.skip(
    !scan && missing.length > 0,
    `no completed DAST scan on this stack; missing dynamic records: ${missing.join(', ')}`,
  )
  expect(missing, `required dynamic records for UI acceptance are missing: ${missing.join(', ')}`).toEqual([])
  const optional = [
    device?.id && `/devices/${device.id}`,
    device?.id && `/devices/${device.id}/agent`,
    campaign?.id && `/campaigns/${campaign.id}`,
  ]
  const routes = [...Object.values(required), ...optional].filter((route): route is string => Boolean(route))
  for (const route of routes) await visitAndAuditPage(page, route, 700)
})

test('filtered scan history stays synchronized through Back and Forward', async ({ page, request }) => {
  test.skip(!REAL_STACK, 'release-only non-mutating navigation acceptance')

  const scanData = await readJson(request, '/scans?status=completed&limit=50')
  const scan = (scanData.scans || []).find((item: any) => (
    item.scan_role !== 'shard' && item.target_url && item.run_kind === 'web_dast'
  )) || (scanData.scans || []).find((item: any) => item.scan_role !== 'shard' && item.target_url)
  test.skip(!scan, 'no completed top-level scan on this stack (the pull-request smoke does not run the DAST area)')
  expect(scan, 'a completed top-level scan is available').toBeTruthy()

  const listUrl = `/scans?status=completed&search=${encodeURIComponent(scan.target_url)}`
  await page.goto(listUrl)
  await expect(page.getByLabel('Filter by scan status')).toHaveValue('completed')
  await expect(page.getByLabel('Search scans by target URL')).toHaveValue(scan.target_url)
  await page.locator(`a[href^="/scans/${scan.id}"]:visible`).first().click()
  await expect(page).toHaveURL(new RegExp(`/scans/${scan.id}`))

  await page.goBack()
  await expect.poll(() => {
    const current = new URL(page.url())
    return `${current.pathname}${current.search}`
  }).toBe(listUrl)
  await expect(page.getByRole('heading', { name: 'Scans', exact: true })).toBeVisible()
  await expect(page.getByLabel('Filter by scan status')).toHaveValue('completed')
  await expect(page.getByLabel('Search scans by target URL')).toHaveValue(scan.target_url)

  await page.goForward()
  await expect(page).toHaveURL(new RegExp(`/scans/${scan.id}`))
  await expect(page.getByRole('heading', { name: scan.target_url, exact: true })).toBeVisible()
})

test('internal scan visibility toggles immediately and follows browser history', async ({ page }) => {
  test.skip(!REAL_STACK, 'release-only non-mutating navigation acceptance')

  await page.goto('/scans')
  const checkbox = page.getByLabel('Show ASM and internal scans', { exact: true })
  await expect(checkbox).not.toBeChecked()

  await checkbox.check()
  await expect(checkbox).toBeChecked()
  await expect(page).toHaveURL(/include_internal=true/)

  await checkbox.uncheck()
  await expect(checkbox).not.toBeChecked()
  await expect(page).not.toHaveURL(/include_internal=true/)

  await page.goBack()
  await expect(checkbox).toBeChecked()
  await expect(page).toHaveURL(/include_internal=true/)

  await page.goForward()
  await expect(checkbox).not.toBeChecked()
  await expect(page).not.toHaveURL(/include_internal=true/)
})
