// Browser contract fixture: the real /deep-hunt pages, a scripted API; no Hunt, episode or scan ever runs.
import { expect, test, type Page } from '@playwright/test'

import type {
  Campaign, CampaignDetailResponse, Finding, ResearchBudget, ResearchEpisode, ResearchEpisodeDetail,
} from '../../src/lib/api'
import type { HuntV2 } from '../../src/lib/huntV2'
import { mockPageApi, queryNames, unavailable, type MockHandler, type MockedApi } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

const RUN = '11111111-1111-4111-8111-111111111111'
const EPISODE = '22222222-2222-4222-8222-222222222222'
const TARGET = '33333333-3333-4333-8333-333333333333'
const FINDING = '44444444-4444-4444-8444-444444444444'

const budget = (value: number): ResearchBudget => ({
  steps: value, actions: value, active_actions: value, requests: value, seconds: value, model_tokens: value,
})

function campaign(status: string, activeFindings = 0): Campaign {
  return {
    id: RUN, name: 'Synthetic fixture run', objective: 'Review app.example.test', campaign_type: 'autonomous_research',
    target_id: TARGET, target_scope: { url: 'https://app.example.test' }, risk_tier: 'low', planner: {},
    status, deployment_impact: { active_finding_count: activeFindings },
    metadata_json: { autonomous_research: { intensity: 'hunt', max_episodes: 3, planner_mode: 'configured_ai' } },
    created_at: '2026-01-01T00:00:00Z', execution_enabled: false,
  }
}

function campaignDetail(status: string, withYield: boolean, activeFindings = 0): CampaignDetailResponse {
  return {
    campaign: campaign(status, activeFindings), actions: [], action_count: 0, total_action_count: 0,
    status_rollup: {}, deployment_impact: { active_finding_count: activeFindings }, execution_enabled: false,
    research_yield: withYield ? {
      episodes: 1, decisions: 1, model_units: 1200, experiments: 4, falsified_experiments: 2,
      experiment_outcomes: { supported_unverified: 1 }, non_scientific_experiments: 1,
      semantic_dimensions_tested: 2, exhausted_dimensions: 0, recon_actions: 3, novelty_suppressions: 0,
      verified_autonomous_findings: 1, net_new_verified_findings: 1, finding_yield_per_experiment: 0.25,
      stop_recommended: false,
    } : null,
  }
}

function episode(terminal: boolean): ResearchEpisode {
  return {
    id: EPISODE, target_id: TARGET, campaign_id: RUN, objective: 'Review app.example.test', episode_version: 'v1',
    planner: { mode: 'configured_ai' }, execution_mode: 'gated', status: terminal ? 'completed' : 'awaiting_planner',
    version: 1, max_risk_tier: 'low', allowed_families: [], budget_limits: budget(10), budget_used: budget(2),
    remaining_budget: budget(8), step_count: 2, cancel_requested: false, autopilot_enabled: !terminal,
    autopilot_consecutive_failures: 0, terminal, execution_enabled: false,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:05:00Z',
  }
}

function episodeDetail(terminal: boolean): ResearchEpisodeDetail {
  return {
    episode: episode(terminal), current_observation: null, observations: [],
    decisions: [{
      id: '55555555-5555-4555-8555-555555555555', sequence: 1, decision_type: 'command',
      action: { command: 'experiment.workflow', parameters: { proof_family: 'idor', method: 'GET', path: '/orders/11' } },
      reason: 'Synthetic fixture reason.', confidence: 0.5, status: 'accepted', validation_errors: [],
      validation_warnings: [], policy_result: {}, created_at: '2026-01-01T00:04:00Z',
    }],
    events: [{ id: '66666666-6666-4666-8666-666666666666', event_type: 'note', status: 'ok', summary: 'Synthetic fixture event', details: {} }],
  }
}

const finding: Finding = {
  id: FINDING, title: 'Synthetic fixture IDOR', severity: 'high', status: 'active',
  first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
} as Finding

interface RunFixture { status: string; terminal: boolean; episodes: boolean; withYield: boolean; findings: Finding[] }

async function mockRun(page: Page, fixture: RunFixture): Promise<MockedApi> {
  const routes: Record<string, MockHandler> = {
    'GET /health': () => ({ status: 'healthy' }),
    [`GET /arsenal/campaigns/${RUN}`]: () => campaignDetail(fixture.status, fixture.withYield, fixture.findings.length),
    'GET /research/episodes': () => {
      const episodes = fixture.episodes ? [episode(fixture.terminal)] : []
      return { episodes, count: episodes.length }
    },
    [`GET /research/episodes/${EPISODE}`]: () => episodeDetail(fixture.terminal),
    'GET /findings': () => ({
      findings: fixture.findings, total: fixture.findings.length, limit: 25, offset: 0,
      details_included: false, omitted_detail_fields: [],
    }),
  }
  return mockPageApi(page, routes)
}

const finished: RunFixture = { status: 'completed', terminal: true, episodes: true, withYield: true, findings: [finding] }
const live: RunFixture = { status: 'active', terminal: false, episodes: true, withYield: true, findings: [finding] }
const empty: RunFixture = { status: 'completed', terminal: true, episodes: false, withYield: false, findings: [] }

const episodeReads = (api: MockedApi) => api.requests.filter((entry) => entry.startsWith(`GET /research/episodes/${EPISODE}`)).length

async function expectNoHorizontalOverflow(page: Page) {
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }))
  expect(layout.scrollWidth, 'horizontal page overflow').toBeLessThanOrEqual(layout.clientWidth)
}

test.describe('/deep-hunt/runs/<id>', () => {
  test('a finished run shows its outcome, findings and activity', async ({ page }) => {
    const api = await mockRun(page, finished)
    await visitAndAuditPage(page, `/deep-hunt/runs/${RUN}`)
    await expect(page.getByRole('heading', { name: 'Synthetic fixture run', level: 1 })).toBeVisible()
    await expect(page.getByText('https://app.example.test', { exact: true })).toBeVisible()
    await expect(page.getByText('Done', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('1 net-new verified finding produced by this run.')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Findings from this run' })).toBeVisible()
    await expect(page.getByRole('link', { name: /Synthetic fixture IDOR/ })).toHaveAttribute('href', `/findings/${FINDING}`)
    await expect(page.getByText('1 active finding linked to this run')).toBeVisible()
    await expect(page.getByText('Testing for idor')).toBeVisible()
    await expect(page.getByText('1/3')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Stop' })).toHaveCount(0)
    await expect(page.getByRole('link', { name: 'All hunts' })).toHaveAttribute('href', '/deep-hunt')
    expect(api.unhandled).toEqual([])
    expect(queryNames(api, `/arsenal/campaigns/${RUN}`)).toEqual(['action_limit'])
    expect(queryNames(api, '/research/episodes')).toEqual(['campaign_id', 'limit'])
    expect(queryNames(api, `/research/episodes/${EPISODE}`)).toEqual([])
    expect(queryNames(api, '/findings')).toEqual(['limit', 'research_campaign_id', 'sort_by', 'sort_order'])
  })

  test('a run without episodes says it has no activity yet', async ({ page }) => {
    const api = await mockRun(page, empty)
    await visitAndAuditPage(page, `/deep-hunt/runs/${RUN}`)
    await expect(page.getByRole('heading', { name: 'Synthetic fixture run', level: 1 })).toBeVisible()
    await expect(page.getByText('This run has no episode activity yet.')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Findings from this run' })).toHaveCount(0)
    await expect(page.getByRole('heading', { name: 'Run outcome' })).toHaveCount(0)
    expect(api.unhandled).toEqual([])
  })

  test('an unreadable run shows the error state without crashing', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    await mockPageApi(page, {
      'GET /health': () => ({ status: 'healthy' }),
      [`GET /arsenal/campaigns/${RUN}`]: () => unavailable('Synthetic campaign unavailable'),
      [`GET /research/episodes/${RUN}`]: () => unavailable('Synthetic run unavailable'),
    })
    await page.goto(`/deep-hunt/runs/${RUN}`)
    await expect(page.getByRole('alert').filter({ hasText: 'Synthetic run unavailable' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Autonomous run', level: 1 })).toBeVisible()
    await expect(page.locator('body')).not.toContainText('Application error')
    expect(errors).toEqual([])
  })

  test('a live run follows its episode every 2.5 s', async ({ page }) => {
    await page.clock.install()
    const api = await mockRun(page, live)
    await page.goto(`/deep-hunt/runs/${RUN}`)
    await expect(page.getByText('Working', { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Stop' })).toBeVisible()
    const before = episodeReads(api)
    await page.clock.fastForward(3_000)
    await expect.poll(() => episodeReads(api)).toBeGreaterThan(before)
    expect(api.unhandled).toEqual([])
  })

  test('a finished run stops polling', async ({ page }) => {
    await page.clock.install()
    const api = await mockRun(page, finished)
    await page.goto(`/deep-hunt/runs/${RUN}`)
    await expect(page.getByText('Testing for idor')).toBeVisible()
    await page.waitForTimeout(300)
    // The sidebar re-reads /health on its own 30 s cadence; only the run's own reads count here.
    const runReads = () => api.requests.filter((entry) => !entry.startsWith('GET /health'))
    const before = runReads()
    await page.clock.fastForward(30_000)
    await page.waitForTimeout(300)
    expect(runReads()).toEqual(before)
    expect(api.unhandled).toEqual([])
  })

  test('a run fits a phone viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    const api = await mockRun(page, finished)
    await page.goto(`/deep-hunt/runs/${RUN}`)
    await expect(page.getByRole('heading', { name: 'Synthetic fixture run', level: 1 })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Run outcome' })).toBeVisible()
    await expect(page.getByText('Testing for idor')).toBeVisible()
    await expectNoHorizontalOverflow(page)
    expect(api.unhandled).toEqual([])
  })
})

const savedHunt = {
  hunt_id: '77777777-7777-4777-8777-777777777777', target_id: TARGET, target_kind: 'web',
  target_url: 'https://app.example.test', objective: 'Synthetic fixture objective', status: 'completed',
  budget_profile: 'fast', policy: {}, budget: {}, budget_used: { http_requests: 4 },
  created_at: '2026-01-01T00:00:00Z', completed_at: '2026-01-01T00:10:00Z',
} as HuntV2

async function mockHunts(page: Page, answer: MockHandler): Promise<MockedApi> {
  return mockPageApi(page, { 'GET /health': () => ({ status: 'healthy' }), 'GET /hunts': answer })
}

test.describe('/deep-hunt (redirects to /hunt)', () => {
  test('redirects to the Hunt list keeping its query and lists saved Hunts', async ({ page }) => {
    const api = await mockHunts(page, () => ({ hunts: [savedHunt], count: 1, total: 1, limit: 50, offset: 0 }))
    await page.goto('/deep-hunt?status=completed')
    await expect(page).toHaveURL(/\/hunt\?status=completed$/)
    await expect(page.getByRole('heading', { name: 'Hunts', level: 1 })).toBeVisible()
    await expect(page.getByText('Showing 1 hunt')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Synthetic fixture objective' })).toBeVisible()
    expect(api.unhandled).toEqual([])
    expect(queryNames(api, '/hunts')).toEqual(['limit', 'sort_by', 'sort_order', 'status'])
  })

  test('populated Hunt list passes the page audit', async ({ page }) => {
    const api = await mockHunts(page, () => ({ hunts: [savedHunt], count: 1, total: 1, limit: 50, offset: 0 }))
    await visitAndAuditPage(page, '/deep-hunt')
    await expect(page).toHaveURL(/\/hunt$/)
    await expect(page.getByRole('link', { name: 'Synthetic fixture objective' })).toBeVisible()
    expect(api.unhandled).toEqual([])
    expect(queryNames(api, '/hunts')).toEqual(['limit', 'sort_by', 'sort_order'])
  })

  test('empty Hunt list says there are none yet', async ({ page }) => {
    const api = await mockHunts(page, () => ({ hunts: [], count: 0, total: 0, limit: 50, offset: 0 }))
    await visitAndAuditPage(page, '/deep-hunt')
    await expect(page.getByText('No hunts yet')).toBeVisible()
    expect(api.unhandled).toEqual([])
  })

  test('a failed Hunt list read shows the error state', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (error) => errors.push(error.message))
    await mockHunts(page, () => unavailable('Synthetic Hunt list unavailable'))
    await page.goto('/deep-hunt')
    await expect(page.getByRole('alert').filter({ hasText: 'Synthetic Hunt list unavailable' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Hunts', level: 1 })).toBeVisible()
    expect(errors).toEqual([])
  })

  test('the Hunt list fits a phone viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    const api = await mockHunts(page, () => ({ hunts: [savedHunt], count: 1, total: 1, limit: 50, offset: 0 }))
    await page.goto('/deep-hunt')
    await expect(page.getByRole('link', { name: 'Synthetic fixture objective' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'New Hunt' })).toBeVisible()
    await expectNoHorizontalOverflow(page)
    expect(api.unhandled).toEqual([])
  })
})
