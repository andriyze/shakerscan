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

  const [scanData, findingData, deviceData, huntData, campaignData, targetData, episodeData] = await Promise.all([
    readJson(request, '/scans?limit=20'),
    readJson(request, '/findings?limit=50'),
    readJson(request, '/devices?limit=20'),
    readJson(request, '/hunts?limit=20'),
    readJson(request, '/arsenal/campaigns?limit=20'),
    readJson(request, '/targets?limit=20'),
    readJson(request, '/research/episodes?limit=20'),
  ])

  const scan = (scanData.scans || []).find((item: any) => item.scan_role !== 'shard' && item.run_kind === 'web_dast')
    || (scanData.scans || []).find((item: any) => item.scan_role !== 'shard')
  const finding = (findingData.findings || []).find((item: any) => item.target_id && !item.device_target_id)
    || (findingData.findings || [])[0]
  const device = (deviceData.devices || []).find((item: any) => item.is_active) || (deviceData.devices || [])[0]
  const hunt = (huntData.hunts || []).find((item: any) => item.target_id)
  const campaign = (campaignData.campaigns || []).find((item: any) => item.campaign_type !== 'autonomous_research')
  const target = (targetData.targets || []).find((item: any) => item.is_active) || (targetData.targets || [])[0]
  const episode = (episodeData.episodes || [])[0]

  const routes = [
    scan?.id && `/scans/${scan.id}`,
    finding?.id && `/findings/${finding.id}`,
    device?.id && `/devices/${device.id}`,
    device?.id && `/devices/${device.id}/agent`,
    hunt?.hunt_id && hunt?.target_id && `/hunt?target=${encodeURIComponent(hunt.target_id)}&run=${encodeURIComponent(hunt.hunt_id)}`,
    campaign?.id && `/campaigns/${campaign.id}`,
    target?.id && `/targets/${target.id}/graph`,
    episode?.id && `/deep-hunt/runs/${episode.id}`,
  ].filter((route): route is string => Boolean(route))

  expect(routes.length, 'dynamic records available for UI acceptance').toBeGreaterThanOrEqual(6)
  for (const route of routes) await visitAndAuditPage(page, route, 700)
})

test('filtered scan history stays synchronized through Back and Forward', async ({ page, request }) => {
  test.skip(!REAL_STACK, 'release-only non-mutating navigation acceptance')

  const scanData = await readJson(request, '/scans?status=completed&limit=50')
  const scan = (scanData.scans || []).find((item: any) => (
    item.scan_role !== 'shard' && item.target_url && item.run_kind === 'web_dast'
  )) || (scanData.scans || []).find((item: any) => item.scan_role !== 'shard' && item.target_url)
  expect(scan, 'a completed top-level scan is available').toBeTruthy()

  const listUrl = `/scans?status=completed&search=${encodeURIComponent(scan.target_url)}`
  await page.goto(listUrl)
  await expect(page.getByLabel('Filter by scan status')).toHaveValue('completed')
  await expect(page.getByLabel('Search scans by target URL')).toHaveValue(scan.target_url)
  await page.locator(`a[href^="/scans/${scan.id}"]`).first().click()
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
