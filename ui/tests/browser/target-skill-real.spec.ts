import { randomInt } from 'node:crypto'
import { expect, test } from '@playwright/test'

const REAL_STACK = process.env.PLAYWRIGHT_REAL_STACK === '1'
const API = process.env.SHAKERSCAN_API_URL || 'http://localhost:8080'

test('target instructions persist through the real editor, proposals and opted-in Hunt CRUD', async ({ page, request }, testInfo) => {
  test.skip(!REAL_STACK, 'real-stack target instruction acceptance')
  const name = `Target skill acceptance ${testInfo.project.name} ${Date.now()}`
  const created = await request.post(`${API}/targets/hosts`, { data: {
    locator: `127.77.${randomInt(1, 250)}.${randomInt(1, 250)}`, name, environment: 'lab',
  } })
  expect(created.ok()).toBeTruthy()
  const { id } = await created.json()
  let huntId = ''
  try {
    await page.goto(`/targets/${id}/asset`)
    await page.getByRole('button', { name: `Create instructions for ${name}` }).click()
    const dialog = page.getByRole('dialog', { name: 'Target instructions', exact: true })
    const initialText = '## What to test\nInspect saved services.\n\n## What to skip\nDo not reboot.'
    await dialog.getByLabel('Skill title').fill('Local investigation guide')
    await dialog.getByLabel('Instructions', { exact: true }).fill(initialText)
    await dialog.getByRole('button', { name: 'Preview', exact: true }).click()
    await expect(dialog.getByRole('heading', { name: 'What to test' })).toBeVisible()
    await dialog.getByRole('button', { name: 'Save instructions', exact: true }).click()
    await expect(dialog).toBeHidden()
    const saved = await (await request.get(`${API}/targets/${id}/skill`)).json()
    expect(saved).toMatchObject({ revision: 1, skill: { methodology: initialText } })

    const started = await request.post(`${API}/hunts`, { data: {
      schema_version: 'hunt-start/v2', target_id: id, target_kind: 'network',
      goal: 'Maintain local target instructions without testing the network.', budget_profile: 'balanced',
      policy: { active_testing: false }, capabilities: [], credential_refs: {}, request_collection_ids: [],
    } })
    expect(started.ok()).toBeTruthy()
    const hunt = await started.json()
    huntId = hunt.hunt_id
    expect(hunt.target_skill).toMatchObject({ revision: 1, skill: { methodology: initialText }, loaded_at_start: true })
    const names = hunt.capabilities.map((item: { name: string }) => item.name)
    for (const operation of ['read', 'create', 'update', 'delete', 'propose']) expect(names).toContain(`targets.skill.${operation}`)
    expect(hunt.briefing.instructions).toMatchObject({ mode: 'full', text: initialText, more_available: false })
    expect(hunt.briefing.authority.target_delegation.instruction_changes).toBe(false)
    expect(names).not.toContain('ports.discover')

    async function call(operation: string, input: Record<string, unknown>) {
      const response = await request.post(`${API}/hunts/${huntId}/capabilities/targets.skill.${operation}`, {
        data: { idempotency_key: `real-skill-${operation}-${Date.now()}`, input },
      })
      expect(response.ok()).toBeTruthy()
      const action = await response.json()
      expect(action.action_result.status).toBe('success')
      expect(action.result.receipt_id).toBeTruthy()
      return action
    }
    await call('read', {})
    // Editing instructions is a separate permission, off by default: the Hunt proposes instead.
    const refused = await request.post(`${API}/hunts/${huntId}/capabilities/targets.skill.update`, {
      data: { idempotency_key: `real-skill-refused-${Date.now()}`, input: { expected_revision: 1, methodology: 'Not allowed yet.' } },
    })
    expect(refused.status()).toBe(403)
    expect((await refused.json()).detail.propose_with).toBe('targets.skill.propose')
    const proposed = await call('propose', { title: 'Mention the admin port', methodology: `${initialText}\n\n## Also\nCheck 8443.`,
      reason: 'The saved services include 8443.', base_revision: 1 })
    expect(proposed.result.applied).toBe(false)
    const pending = await (await request.get(`${API}/targets/${id}/instruction-proposals`)).json()
    expect(pending.proposals.map((item: { id: string }) => item.id)).toEqual([proposed.result.proposal.id])
    expect(pending.proposals[0].diff.text).toContain('+Check 8443.')
    expect((await request.post(`${API}/targets/${id}/instruction-proposals/${proposed.result.proposal.id}/reject`, { data: {} })).ok()).toBeTruthy()
    expect(await (await request.get(`${API}/targets/${id}/skill`)).json()).toMatchObject({ revision: 1, skill: { methodology: initialText } })
    // The operator opts in through the real permissions dialog.
    await page.getByRole('button', { name: 'Edit Hunt permissions', exact: true }).click()
    const permissions = page.getByRole('dialog', { name: 'Hunt permissions', exact: true })
    await permissions.getByRole('checkbox', { name: /Let Hunt edit these instructions/ }).check()
    await permissions.getByRole('button', { name: 'Save permissions', exact: true }).click()
    await expect(page.getByText(/Hunt permissions saved/)).toBeVisible()
    expect((await (await request.get(`${API}/targets/${id}/hunt-authority`)).json()).instruction_changes).toBe(true)
    await call('update', { operator_confirmed: true, expected_revision: 1, methodology: 'Instructions changed by Hunt.' })
    await call('delete', { operator_confirmed: true, expected_revision: 2 })
    await call('create', { operator_confirmed: true, expected_revision: 3, methodology: 'Instructions for the next Hunt.' })
    const current = await (await request.get(`${API}/targets/${id}/skill`)).json()
    expect(current).toMatchObject({ revision: 4, skill: { methodology: 'Instructions for the next Hunt.' } })
    const retained = await (await request.get(`${API}/hunts/${huntId}`)).json()
    expect(retained.target_skill).toMatchObject({ revision: 1, skill: { methodology: initialText } })

    await page.reload()
    await page.getByRole('button', { name: `Edit instructions for ${name}` }).click()
    await expect(dialog.getByLabel('Instructions', { exact: true })).toHaveValue('Instructions for the next Hunt.')
    await dialog.getByLabel('Instructions', { exact: true }).fill('Saved through the real UI again.')
    await dialog.getByRole('button', { name: 'Save instructions', exact: true }).click()
    await expect(dialog).toBeHidden()
    await page.getByRole('button', { name: `Edit instructions for ${name}` }).click()
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
    await dialog.getByRole('button', { name: 'Delete instructions', exact: true }).click()
    await expect(dialog).toBeHidden()
    expect(await (await request.get(`${API}/targets/${id}/skill`)).json()).toMatchObject({ revision: 6, skill: null })
    expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false)
    await page.screenshot({ path: testInfo.outputPath('target-skill-real.png') })
  } finally {
    if (huntId) await request.post(`${API}/hunts/${huntId}/finish`, { data: { summary: 'Real target skill acceptance finished.', next_actions: [] } })
    await request.post(`${API}/targets/${id}/archive`, { data: {} })
  }
})

test('connected-device view reuses real Hunt ports and opens the same target workflow', async ({ page, request }) => {
  const id = process.env.SHAKERSCAN_E2E_DEVICE_TARGET_ID || ''
  test.skip(!REAL_STACK || !id, 'requires the owned local network acceptance fixture')
  const response = await request.get(`${API}/targets/${id}/asset`)
  expect(response.ok()).toBeTruthy()
  const asset = await response.json()
  expect(asset.target.connected_device).toBe(true)
  await page.goto(`/devices/${id}`)
  await expect(page.getByRole('heading', { name: 'Ports discovered across Scans and Hunts' })).toBeVisible()
  for (const port of [22, 2222, 8081, 8443]) {
    await expect(page.getByRole('cell', { name: new RegExp(`^${port}/tcp`) }).first()).toBeVisible()
  }
  await page.getByRole('button', { name: 'Start network scan', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: `Scan ${asset.target.name}` })
  await expect(dialog.getByLabel('Known TCP ports (optional)')).toHaveValue('22, 2222, 8081, 8443')
  await expect(dialog.getByRole('button', { name: 'Queue scan', exact: true })).toBeEnabled()
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  await page.getByRole('link', { name: 'Start Hunt', exact: true }).first().click()
  await expect(page.getByLabel('Target', { exact: true })).toHaveAttribute('data-value', id)
})
