import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture (synthetic; nothing is stored unless the test posts it): the Add
// device dialog names built-in service policies as a person reads them, and still sends the id.
const cameraPolicy = '00000000-0000-4000-8000-0000000004a1'
const ownPolicy = '00000000-0000-4000-8000-0000000004a2'
const policy = (id: string, name: string, description: string, builtIn: boolean) => ({
  id, name, description, device_class: 'camera', environment: 'production', rules: [], is_builtin: builtIn, is_active: true,
})

test('DEVICE-ADD-001 built-in service policies are offered by name, not by identifier', async ({ page }) => {
  const posted: Record<string, unknown>[] = []
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    'GET /devices': () => ({ devices: [], total: 0 }),
    'GET /devices/readiness': () => ({ enabled: true, status: 'ready', worker_count: 1 }),
    'GET /device-policies': () => ({ policies: [
      policy(cameraPolicy, 'camera-baseline-v1', 'IP camera and video endpoint baseline.', true),
      policy(ownPolicy, 'floor-3-cameras-v2', 'Cameras on the third floor.', false),
    ] }),
    'POST /devices': (_url, request) => {
      posted.push(request.postDataJSON() as Record<string, unknown>)
      return { device: { id: '00000000-0000-4000-8000-0000000004a3', name: 'Lobby camera', primary_locator: 'camera.example.test', device_class: 'camera', is_active: true, metadata_json: {}, active_findings_count: 0 } }
    },
  })
  await page.goto('/devices')
  await page.getByRole('button', { name: 'Add device' }).first().click()
  const dialog = page.getByRole('dialog')
  const select = dialog.getByLabel('Service policy')
  await expect(select.locator('option')).toHaveText([
    'Default connected-device policy', 'Camera baseline (version 1)', 'floor-3-cameras-v2',
  ])
  await expect(dialog.getByText('camera-baseline-v1')).toHaveCount(0)
  await select.selectOption({ label: 'Camera baseline (version 1)' })
  // The chosen policy says what it is for.
  await expect(dialog.getByText('IP camera and video endpoint baseline.', { exact: true })).toBeVisible()
  await dialog.getByLabel(/Hostname or IP address/).fill('camera.example.test')
  await dialog.getByRole('button', { name: 'Add device', exact: true }).click()
  await expect.poll(() => posted.length).toBe(1)
  expect(posted[0].policy_id).toBe(cameraPolicy)
})
