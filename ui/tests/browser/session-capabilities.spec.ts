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
// The answers an Enterprise gateway gives (fixtures copied from its session_capabilities.answer):
// an operator on an installation with Hunt and network scans off, and an administrator with Hunt on.
const OPERATOR = {
  schema_version: 'session-capabilities/v1', source: 'gateway', role: 'operator', default: 'allow',
  actions: { 'targets.add': true, 'targets.edit': true, 'targets.check': true, 'scans.start': true, 'findings.retest': true,
    'findings.verify': false, 'findings.triage': true, 'findings.accept_risk': true, 'hunts.manage': false,
    'secrets.read': true, 'secrets.manage': true, 'secrets.decide': true, 'records.delete': false },
  pages: { '/': true, '/scan/new': true, '/credentials': true, '/hunt': false, '/hunts': false, '/deep-hunt': false,
    '/devices': false, '/schedules': true, '/settings': false },
  reasons: { 'findings.verify': 'Hunt is not enabled on this installation', 'hunts.manage': 'Hunt is not enabled on this installation' },
}
const ADMIN = {
  schema_version: 'session-capabilities/v1', source: 'gateway', role: 'admin', default: 'allow',
  actions: { 'targets.add': true, 'targets.edit': true, 'targets.check': true, 'scans.start': true, 'findings.retest': true,
    'findings.verify': true, 'findings.triage': true, 'findings.accept_risk': true, 'hunts.manage': true,
    'secrets.read': true, 'secrets.manage': true, 'secrets.decide': true, 'records.delete': true },
  pages: { '/': true, '/scan/new': true, '/credentials': true, '/hunt': true, '/devices': false, '/schedules': true },
  reasons: {},
}
// An operator with Hunt on: Stop is theirs, deleting the Hunt's record is an administrator's.
const OPERATOR_HUNT = { ...ADMIN, role: 'operator', actions: { ...ADMIN.actions, 'records.delete': false } }
type Mode = 'viewer' | 'operator' | 'operator-hunt' | 'admin' | 'absent' | 'malformed'
const ANSWERS = { viewer: VIEWER, operator: OPERATOR, 'operator-hunt': OPERATOR_HUNT, admin: ADMIN }

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
      if (mode === 'absent') return route.fulfill({ status: 404, json: { detail: 'Not Found' } })
      // Another schema (or any answer that is not this contract) means everything is allowed.
      if (mode === 'malformed') return route.fulfill({ json: { schema_version: 'session-capabilities/v9', default: 'deny', actions: {} } })
      return route.fulfill({ json: ANSWERS[mode] })
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
    if (path === '/scans') {
      const scan = (id: string, status: string) => ({ id, target_url: 'https://caps.example.test', target_id: assetId, status,
        progress: status === 'running' ? 40 : 100, created_at: now, scan_type: 'standard' })
      return route.fulfill({ json: { scans: [scan('00000000-0000-4000-8000-000000000921', 'running'),
        scan('00000000-0000-4000-8000-000000000922', 'completed')], total: 2, limit: 50, offset: 0 } })
    }
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

      // Opened by address, New Scan shows a viewer the form without Run Scan, and says why.
      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'viewer')
      await page.goto('/scan/new')
      await expect(page.getByTestId('scan-start-refused')).toBeVisible()
      await expect(page.getByRole('button', { name: 'Run Scan' })).toHaveCount(0)
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

    test('CAPS-011 dashboard: without ct_monitor.toggle the CT monitor switch is locked and says why when pressed', async ({ page }) => {
      // A gateway may keep the switch for administrators. The reason was in the hover text
      // only, so pressing the control looked like a dead button (2026-11 evaluation).
      let running = true
      const dashboard = {
        '/health': () => ({ status: 'healthy' }),
        '/dashboard': () => ({ metrics: { total_targets: 0, total_scans: 0, running_scans: 0, active_findings: 0, critical_findings: 0,
          high_findings: 0, avg_score: null }, recent_scans: [], recent_findings: [], action_center: [] }),
        '/queue/stats': () => ({ pending: 0, queued: 0, running: 0, completed: 0, failed: 0 }),
        '/gungnir/status': () => ({ running, domains_monitored: 4, subdomains_found: 0, session_found: 0, last_discovery: '',
          started_at: now, uptime_seconds: 60 }),
        '/targets/grouped': () => ({ items: [], next_cursor: null, has_more: false, total: 0, total_kind: 'exact', generated_at: now }),
        '/timeline': () => ({ events: [], upcoming: [] }),
      }
      const locked = { ...ADMIN, actions: { ...ADMIN.actions, 'ct_monitor.toggle': false },
        reasons: { 'ct_monitor.toggle': 'only an administrator turns the CT monitor on or off' } }
      const lockedApi = await mockPageApi(page, { ...dashboard, '/session/capabilities': () => locked })
      await page.goto('/')
      const lockedSwitch = page.getByRole('switch', { name: 'CT monitor' })
      await expect(lockedSwitch).toBeVisible()
      await expect(lockedSwitch).toHaveAttribute('aria-checked', 'true')
      await expect(lockedSwitch).toHaveAttribute('aria-readonly', 'true')
      await expect(lockedSwitch).toHaveAttribute('aria-description', 'only an administrator turns the CT monitor on or off')
      await expect(page.getByTestId('ct-monitor-state')).toHaveText('on')
      await lockedSwitch.click()
      await expect(page.getByText('Only an administrator turns the CT monitor on or off')).toBeVisible()
      // The keyboard reaches it and gets the same answer; no request to change the monitor is sent.
      await lockedSwitch.focus()
      await page.keyboard.press('Enter')
      await expect(page.getByText('Only an administrator turns the CT monitor on or off').first()).toBeVisible()
      expect(lockedApi.requests.filter((entry) => entry.startsWith('POST /gungnir/'))).toEqual([])

      // A session that may switch it: the label follows the request, then the monitor's state.
      await page.unrouteAll({ behavior: 'ignoreErrors' })
      let release: () => void = () => {}
      const held = new Promise<void>((resolve) => { release = resolve })
      const openApi = await mockPageApi(page, {
        ...dashboard,
        'POST /gungnir/stop': async () => { await held; running = false; return { status: 'stopped' } },
        'POST /gungnir/start': () => { running = true; return { status: 'started' } },
      })
      await page.goto('/')
      const open = page.getByRole('switch', { name: 'CT monitor' })
      await expect(open).toHaveAttribute('aria-checked', 'true')
      await expect(open).not.toHaveAttribute('aria-readonly', 'true')
      await open.click()
      await expect(page.getByTestId('ct-monitor-state')).toHaveText('stopping…')
      await expect(open).toBeDisabled()
      release()
      await expect(page.getByTestId('ct-monitor-state')).toHaveText('off')
      await expect(open).toHaveAttribute('aria-checked', 'false')
      await expect(open).toBeEnabled()
      await open.click()
      await expect(page.getByTestId('ct-monitor-state')).toHaveText('on')
      await expect(open).toHaveAttribute('aria-checked', 'true')
      expect(openApi.requests.filter((entry) => entry.startsWith('POST /gungnir/'))).toEqual(['POST /gungnir/stop', 'POST /gungnir/start'])
    })

    test('CAPS-012 dashboard: a refused CT monitor change leaves the switch showing the monitor as it is', async ({ page }) => {
      const dashboard = {
        '/health': () => ({ status: 'healthy' }),
        '/dashboard': () => ({ metrics: { total_targets: 0, total_scans: 0, running_scans: 0, active_findings: 0, critical_findings: 0,
          high_findings: 0, avg_score: null }, recent_scans: [], recent_findings: [], action_center: [] }),
        '/queue/stats': () => ({ pending: 0, queued: 0, running: 0, completed: 0, failed: 0 }),
        '/gungnir/status': () => ({ running: false, domains_monitored: 0, subdomains_found: 0, session_found: 0, last_discovery: '',
          started_at: '', uptime_seconds: 0 }),
        '/targets/grouped': () => ({ items: [], next_cursor: null, has_more: false, total: 0, total_kind: 'exact', generated_at: now }),
        '/timeline': () => ({ events: [], upcoming: [] }),
        'POST /gungnir/start': () => ({ status: 503, json: { detail: 'the CT monitor was not changed: fixture' } }),
      }
      await mockPageApi(page, dashboard)
      await page.goto('/')
      const toggle = page.getByRole('switch', { name: 'CT monitor' })
      await expect(toggle).toHaveAttribute('aria-checked', 'false')
      await toggle.click()
      await expect(page.getByText('the CT monitor was not changed: fixture')).toBeVisible()
      await expect(page.getByTestId('ct-monitor-state')).toHaveText('off')
      await expect(toggle).toHaveAttribute('aria-checked', 'false')
      await expect(toggle).toBeEnabled()
    })

    test('CAPS-006 an operator without Hunt keeps scans, edits, triage and secrets but gets no Verify or Hunt link', async ({ page }) => {
      await mock(page, 'operator')
      await page.goto('/targets')
      await expect(page.getByRole('button', { name: /Add targets/ }).first()).toBeVisible()
      await expect(page.getByRole('button', { name: /^Scan .*caps\.example\.test|^Discover services: caps/ })).toBeVisible()
      if (width >= 768) await expect(page.getByRole('link', { name: 'New Scan', exact: true })).toBeVisible()

      await page.goto(`/targets/${assetId}/asset`)
      await expect(page.getByRole('heading', { name: 'Capabilities fixture' })).toBeVisible()
      for (const name of ['Rename', 'Edit details', 'Authorize asset', 'Add action']) {
        await expect(page.getByRole('button', { name, exact: true })).toBeVisible()
      }
      await expect(page.getByRole('button', { name: 'Check liveness now' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Configure web scan' })).toBeVisible()
      // Network scans are off for this installation: no network scan, and the device view is text.
      await expect(page.getByRole('button', { name: 'Start network scan', exact: true })).toHaveCount(0)
      await expect(page.getByRole('link', { name: 'Connected Devices view →' })).toHaveCount(0)
      for (const name of ['Reveal', 'Grant', 'Promote', 'Revoke', 'Expiry']) {
        await expect(page.getByRole('button', { name, exact: true }).first()).toBeVisible()
      }

      await page.goto(`/findings/${findingId}`)
      await expect(page.getByRole('button', { name: 'Retest', exact: true })).toBeVisible()
      await expect(page.getByRole('combobox', { name: 'Status' })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Accept risk…' })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Verify finding' })).toHaveCount(0)
    })

    test('CAPS-007 an administrator with Hunt gets every control, Verify and Stop included', async ({ page }) => {
      await mock(page, 'admin')
      await page.goto(`/findings/${findingId}`)
      await expect(page.getByRole('button', { name: 'Retest', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Verify finding' })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Accept risk…' })).toBeVisible()
      await page.goto(`/hunt?run=${huntId}`)
      await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Delete this Hunt', exact: true })).toBeVisible()
      await page.goto(`/targets/${assetId}/asset`)
      await expect(page.getByRole('button', { name: 'Edit details', exact: true })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Discovered secrets' }).first()).toBeVisible()
    })

    test('CAPS-009 an operator with Hunt can Stop it but is not offered Delete (records.delete)', async ({ page }) => {
      await mock(page, 'operator-hunt')
      await page.goto(`/hunt?run=${huntId}`)
      await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeVisible()
      await expect(page.getByRole('button', { name: 'Delete this Hunt', exact: true })).toHaveCount(0)
    })

    test('CAPS-010 Scans list: Cancel, Scan again and New Scan follow scans.start', async ({ page }) => {
      await mock(page, 'viewer')
      await page.goto('/scans')
      await expect(page.getByText('Showing 2 scans').first()).toBeVisible()
      for (const name of ['Cancel', 'Scan again', 'New Scan']) {
        await expect(page.getByRole('main').getByRole(name === 'New Scan' ? 'link' : 'button', { name, exact: true })).toHaveCount(0)
      }

      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'operator')
      await page.goto('/scans')
      await expect(page.getByRole('main').getByRole('button', { name: 'Cancel', exact: true }).first()).toBeVisible()
      await expect(page.getByRole('main').getByRole('link', { name: 'New Scan', exact: true })).toBeVisible()
      if (width >= 1440) await expect(page.getByRole('main').getByRole('button', { name: 'Scan again', exact: true })).toBeVisible()
    })

    test('CAPS-011 Targets row menu: the Hunt command and Start Hunt follow hunts.manage', async ({ page }) => {
      const managed = { schema: 'shakerscan.workspace-capabilities/v1', mode: 'managed', edition: 'Enterprise Edition',
        features: { hunt: { state: 'enabled' }, targets: { state: 'enabled' } }, navigation: { '/hunt': 'hunt', '/targets': 'targets' },
        ui_routes: ['/hunt', '/targets', '/targets/[^/]+/asset'] }
      const menu = async () => {
        await page.goto('/targets')
        await page.getByRole('button', { name: 'More actions for caps.example.test', exact: true }).click()
        await expect(page.getByRole('menuitem', { name: /Open details/ })).toBeVisible()
      }
      // Open-source edition: the menu links to the Hunt page.
      await mock(page, 'viewer')
      await menu()
      await expect(page.getByRole('menuitem', { name: /Start Hunt/ })).toHaveCount(0)
      await page.unrouteAll({ behavior: 'ignoreErrors' })
      await mock(page, 'absent')
      await menu()
      await expect(page.getByRole('menuitem', { name: /Start Hunt/ })).toBeVisible()

      // A managed workspace copies the terminal command instead; a viewer cannot start a Hunt.
      await page.addInitScript(policy => { (window as unknown as { __SHAKERSCAN_CAPABILITIES__: unknown }).__SHAKERSCAN_CAPABILITIES__ = policy }, managed)
      for (const [mode, count] of [['viewer', 0], ['operator', 0], ['operator-hunt', 1]] as const) {
        await page.unrouteAll({ behavior: 'ignoreErrors' })
        await mock(page, mode)
        await menu()
        await expect(page.getByRole('menuitem', { name: /Copy the Hunt command/ })).toHaveCount(count)
      }
    })

    test('CAPS-008 an answer that is not this contract keeps the whole surface (fail open)', async ({ page }) => {
      await mock(page, 'malformed')
      await page.goto(`/targets/${assetId}/asset`)
      await expect(page.getByRole('button', { name: 'Edit details', exact: true })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Connected Devices view →' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Discovered secrets' }).first()).toBeVisible()
      await page.goto('/scan/new')
      await expect(page.getByRole('button', { name: 'Run Scan' })).toBeVisible()
      await expect(page.getByTestId('scan-start-refused')).toHaveCount(0)
    })
  })
}
