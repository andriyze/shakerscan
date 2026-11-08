import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'
import { mockPageApi } from './mock-page-api'

// Mocked API (fixture data, no live stack): the UI reads GET /session/capabilities
// (docs/session-capabilities.md) and hides what the person cannot do. A viewer-like answer hides
// every state-changing control and turns links to refused pages into text; an engine without the
// endpoint (404) keeps the whole surface, as before the contract.
const assetId = '00000000-0000-4000-8000-000000000910'
const findingId = '00000000-0000-4000-8000-000000000911'
const huntId = '00000000-0000-4000-8000-000000000912'
const now = '2026-11-01T00:00:00Z'

const VIEWER = {
  schema_version: 'session-capabilities/v1', source: 'gateway', role: 'viewer', default: 'deny',
  actions: {}, pages: { '/devices': false, '/credentials': false, '/scan/new': false, '/schedules': false },
  reasons: { 'targets.add': 'this action needs the operator role' },
}
type Mode = 'viewer' | 'absent'

const target = {
  id: assetId, asset_id: assetId, name: 'Capabilities fixture', url: 'host://caps.example.test', locator: 'caps.example.test',
  is_active: true, environment: 'lab', connected_device: true, device_class: 'router', origin_count: 1, service_count: 0,
  active_findings_count: 1, authorized: false, created_at: now, updated_at: now,
  origins: [{ id: '00000000-0000-4000-8000-000000000913', url: 'https://caps.example.test', is_active: true }],
}
const origin = { id: '00000000-0000-4000-8000-000000000913', url: 'https://caps.example.test', name: 'Web app', is_active: true,
  current_membership: true, authorized: false, last_scanned_at: null, active_findings_count: 0 }
const secret = { ref: 'secret://00000000-0000-4000-8000-000000000914', kind: 'password', label: 'DB_PASSWORD', length: 12,
  source: { kind: 'hunt_action' }, first_seen_at: now, last_seen_at: now, seen_count: 1, state: 'active', expires_at: null,
  uses: 0, reveals: 0, last_used_at: null, found_on: assetId, granted_to: [], promoted_profile_id: null }
const finding = {
  id: findingId, title: 'Reflected XSS in search', severity: 'high', status: 'active', tool: 'dalfox', target_id: assetId,
  url: 'https://caps.example.test/search?q=1', target_url: 'https://caps.example.test', first_seen_at: now, last_seen_at: now,
}
const hunt = {
  hunt_id: huntId, target_id: assetId, target_kind: 'web', objective: 'Review object access', status: 'active',
  budget_profile: 'balanced', budget_revision: 0, policy: { active_testing: false }, budget: {}, budget_used: {},
  capabilities: [], actions: [],
}

async function mock(page: Page, mode: Mode) {
  const requests: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const url = new URL(route.request().url()), path = url.pathname
    requests.push(`${route.request().method()} ${path}`)
    if (path === '/session/capabilities') {
      return mode === 'viewer' ? route.fulfill({ json: VIEWER }) : route.fulfill({ status: 404, json: { detail: 'Not Found' } })
    }
    if (path === '/targets/inventory') {
      return route.fulfill({ json: { targets: [target], total: 1, total_groups: 1,
        groups: [{ root_domain: 'caps.example.test', discoverable: false, targets: [target] }] } })
    }
    if (path === `/targets/${assetId}/asset`) {
      return route.fulfill({ json: { target, origins: [origin], services: [], service_intelligence: { services: [], warnings: [] },
        credentials: [], request_collections: [], history: { items: [], total: 0 }, active_findings: {}, authorization: null } })
    }
    if (path.endsWith('/discovered-secrets')) return route.fulfill({ json: { target_id: assetId, secrets: [secret], count: 1, values_visible: false } })
    if (path.endsWith('/skill')) return route.fulfill({ json: { target_id: assetId, revision: 0, skill: null, max_characters: 12000 } })
    if (path.endsWith('/actions')) return route.fulfill({ json: { target_id: assetId, revision: 0, actions: [] } })
    if (path.endsWith('/hunt-authority')) {
      return route.fulfill({ json: { target_id: assetId, revision: 0, metadata_changes: false, instruction_changes: false,
        credential_profile_ids: [], collection_ids: [], ssh_host_keys: [], ssh_trust_first_contact: false } })
    }
    if (path.endsWith('/history')) return route.fulfill({ json: { asset_id: assetId, kind: 'scans', items: [], total: 0, offset: 0, limit: 25 } })
    if (path.endsWith('/interpretations')) return route.fulfill({ json: { interpretations: [], count: 0, has_more: false } })
    if (path.endsWith('/negative-results')) return route.fulfill({ json: { rows: [], count: 0, has_more: false } })
    if (path === `/findings/${findingId}`) return route.fulfill({ json: finding })
    if (path === `/hunts/${huntId}`) return route.fulfill({ json: hunt })
    if (path === `/hunts/${huntId}/http-transactions`) {
      return route.fulfill({ json: { fidelity: 'complete', fidelity_detail: 'Synthetic', total: 0, archive_total: 0, transactions: [] } })
    }
    if (path === `/hunts/${huntId}/query`) return route.fulfill({ json: { rows: [], has_more: false, next_cursor: null, supported: true } })
    return route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } })
  })
  return requests
}

for (const width of [390, 1440]) {
  test.describe(`${width} px`, () => {
    test.use({ viewport: { width, height: 900 } })

    test('CAPS-001 targets: a viewer is offered no Add targets or Scan; without the endpoint both stay', async ({ page }) => {
      await mock(page, 'viewer')
      await page.goto('/targets')
      await expect(page.getByRole('link', { name: 'Capabilities fixture', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: /Add targets/ })).toHaveCount(0)
      await expect(page.getByRole('button', { name: /^Scan .*caps\.example\.test|^Discover services: caps/ })).toHaveCount(0)
      if (width >= 768) {
        const nav = page.getByRole('navigation').first()
        await expect(nav.getByRole('link', { name: 'Targets', exact: true })).toBeVisible()
        await expect(page.getByRole('link', { name: 'Credentials', exact: true })).toHaveCount(0)
        await expect(page.getByRole('link', { name: 'Connected Devices', exact: true })).toHaveCount(0)
        await expect(page.getByRole('link', { name: 'New Scan', exact: true })).toHaveCount(0)
      }

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'absent')
      await page.goto('/targets')
      await expect(page.getByRole('button', { name: /Add targets/ }).first()).toBeVisible()
      await expect(page.getByRole('button', { name: /^Scan .*caps\.example\.test|^Discover services: caps/ })).toBeVisible()
    })

    test('CAPS-002 target page: a viewer gets no edit, check, scan or secret controls, and no device link', async ({ page }) => {
      const requests = await mock(page, 'viewer')
      await page.goto(`/targets/${assetId}/asset`)
      await expect(page.getByRole('heading', { name: 'Capabilities fixture' })).toBeVisible()
      for (const name of ['Rename', 'Edit details', 'Start network scan', 'Network Hunt', 'Authorize asset', 'Edit Hunt permissions',
        'Add action', 'Edit learned knowledge']) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0)
      }
      await expect(page.getByRole('button', { name: 'Check liveness now' })).toHaveCount(0)
      await expect(page.getByRole('button', { name: /instructions for Capabilities fixture/ })).toHaveCount(0)
      await expect(page.getByRole('link', { name: 'Configure web scan' })).toHaveCount(0)
      // The device view link keeps its words, without a link to a page the viewer cannot open.
      await expect(page.getByText('Connected Devices view →')).toBeVisible()
      await expect(page.getByRole('link', { name: 'Connected Devices view →' })).toHaveCount(0)
      await expect(page.getByRole('heading', { name: 'Discovered secrets' })).toHaveCount(0)
      expect(requests.filter(entry => entry.includes('/discovered-secrets'))).toEqual([])

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      const allowed = await mock(page, 'absent')
      await page.goto(`/targets/${assetId}/asset`)
      await expect(page.getByRole('button', { name: 'Edit details', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Check liveness now' })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Create instructions for Capabilities fixture' })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Edit Hunt permissions', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Add action', exact: true })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Connected Devices view →' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Discovered secrets' }).first()).toBeVisible()
      for (const name of ['Reveal', 'Grant', 'Promote', 'Revoke', 'Expiry']) {
        await expect(page.getByRole('button', { name, exact: true }).first()).toBeVisible()
      }
      expect(allowed.some(entry => entry.endsWith('/discovered-secrets'))).toBe(true)
    })

    test('CAPS-003 finding page: a viewer reads status and verdict but gets no Retest, Verify, triage or Accept risk', async ({ page }) => {
      await mock(page, 'viewer')
      await page.goto(`/findings/${findingId}`)
      await expect(page.getByRole('heading', { name: 'Reflected XSS in search' }).first()).toBeVisible()
      await expect(page.getByTestId('finding-status-readonly')).toContainText('Active')
      await expect(page.getByTestId('finding-verdict-readonly')).toContainText('No verdict recorded')
      await expect(page.getByLabel('Retest mode')).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Retest', exact: true })).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Verify finding' })).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Accept risk…' })).toHaveCount(0)
      await expect(page.getByRole('combobox', { name: /Status|Analyst verdict/ })).toHaveCount(0)

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'absent')
      await page.goto(`/findings/${findingId}`)
      await expect(page.getByRole('button', { name: 'Retest', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Accept risk…' })).toBeVisible()
      await expect(page.getByRole('combobox', { name: 'Status' })).toBeVisible()
      await expect(page.getByRole('combobox', { name: 'Analyst verdict' })).toBeVisible()
      await expect(page.getByTestId('finding-status-readonly')).toHaveCount(0)
    })

    test('CAPS-004 Hunt page: a viewer gets no Stop or Delete', async ({ page }) => {
      await mock(page, 'viewer')
      await page.goto(`/hunt?run=${huntId}`)
      await expect(page.getByText('Review object access').first()).toBeVisible()
      await expect(page.getByRole('button', { name: 'Stop', exact: true })).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Delete this Hunt', exact: true })).toHaveCount(0)

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'absent')
      await page.goto(`/hunt?run=${huntId}`)
      await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Delete this Hunt', exact: true })).toBeVisible()
    })

    test('CAPS-005 dashboard: an empty install offers "Add a target" only to someone who may add one', async ({ page }) => {
      const empty = {
        '/health': () => ({ status: 'healthy' }),
        '/dashboard': () => ({ metrics: { total_targets: 0, total_scans: 0, running_scans: 0, active_findings: 0, critical_findings: 0,
          high_findings: 0, avg_score: null }, recent_scans: [], recent_findings: [], action_center: [] }),
        '/queue/stats': () => ({ pending: 0, queued: 0, running: 0, completed: 0, failed: 0 }),
        '/exposure/assets': () => ({ assets: [], count: 0, total: 0, new_count: 0, cohort: 'operational', cohort_counts: {},
          metrics: { asset_count: 0, active_critical: 0, active_high: 0, active_verified: 0, active_needs_verification: 0,
            ai_surfaces: 0, verified_assets: 0, unverified_high_assets: 0, fresh_scans: 0, p1_count: 0 } }),
        '/targets/grouped': () => ({ items: [], next_cursor: null, has_more: false, total: 0, total_kind: 'exact', generated_at: now }),
        '/timeline': () => ({ events: [], upcoming: [] }),
      }
      await mockPageApi(page, { ...empty, '/session/capabilities': () => VIEWER })
      await page.goto('/')
      await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible()
      await expect(page.getByRole('link', { name: /Add a target/ })).toHaveCount(0)

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mockPageApi(page, empty)
      await page.goto('/')
      await expect(page.getByRole('link', { name: /Add a target/ })).toBeVisible()
    })
  })
}
