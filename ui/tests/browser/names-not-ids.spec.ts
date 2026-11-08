import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Mocked API (fixture data, not a live stack). Lists people work from name things and say why a
// control is unavailable in visible text: a credential's owner by its name or address (never its
// id), one copyable terminal Hunt command per target (not one per port), repeated evidence as one
// counted label, and a disabled Retest's reason on the page, not only in a tooltip.
const hostId = '73caec63-0000-4000-8000-000000000501'
const huntId = '79d5443a-0000-4000-8000-000000000502'
const profileId = '00000000-0000-4000-8000-000000000503'
const findingId = '00000000-0000-4000-8000-000000000504'
const host = {id:hostId,asset_id:hostId,name:'Lab host',url:'host://10.0.0.5',locator:'10.0.0.5',is_active:true,environment:'lab',
  connected_device:true,origin_count:0,service_count:2,active_findings_count:0,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z'}
const port = (id: string, number: number) => ({id,target_id:hostId,transport:'tcp',port:number,address:'10.0.0.5',service:'http',
  presence:'observed_open',state:'open',binding_status:'current',observation_status:'observed',
  evidence:[...Array(12)].map(() => ({hunt_id:huntId,status:'succeeded'}))})
const profile = {id:profileId,target_kind:'web',target_id:hostId,home_target_id:hostId,name:'Shop login',auth_kind:'bearer_token',
  principal_slot:'primary',configuration:{schema_version:'1',auth_kind:'bearer_token',username_configured:false,secret_configured:true,
    secondary_secret_configured:false,endpoint_configured:false,client_id_configured:false,scope_count:0,custom_header_names:[],
    interactive_exchange_required:false,secret_values_visible:false},
  current_version:1,record_version:1,is_active:true,rotated_at:'2026-01-01T00:00:00Z',created_at:'2026-01-01T00:00:00Z',
  updated_at:'2026-01-01T00:00:00Z',allowed_capabilities:[],secret_configured:true,secret_values_visible:false,status:'active',
  refresh_required:false,execution_compatible:true,storage_encrypted:true,encryption_available:true,
  home_target_name:null,home_target_locator:'http://10.0.0.5:3000'}
const managedPolicy = {schema:'shakerscan.workspace-capabilities/v1',mode:'managed',edition:'Enterprise Edition',
  features:{hunt:{state:'enabled'},targets:{state:'enabled'}},navigation:{'/hunt':'hunt','/targets':'targets'},
  ui_routes:['/hunt','/targets','/targets/[^/]+/asset','/credentials','/findings/[^/]+','/evidence']}

async function mock(page: Page, {managed = false} = {}) {
  if (managed) await page.addInitScript((policy) => { window.__SHAKERSCAN_CAPABILITIES__ = policy as never }, managedPolicy)
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === `/targets/${hostId}/asset`) return route.fulfill({json:{target:host,origins:[],services:[],
      service_intelligence:{services:[port('p1', 80), port('p2', 8080)],warnings:[],sources_truncated:false},
      credentials:[],request_collections:[],history:{items:[],total:0},active_findings:{},authorization:{approved_by:'fixture'}}})
    if (path === '/credential-profiles') return route.fulfill({json:{profiles:[profile],total:1}})
    if (path === `/findings/${findingId}`) return route.fulfill({json:{id:findingId,title:'Sensitive exposure: configuration secret file',
      severity:'high',status:'active',tool:'exposure',url:'http://shop.fixture.test/.env',target_url:'http://shop.fixture.test',
      first_seen_at:'2026-10-01T00:00:00Z',last_seen_at:'2026-10-10T00:00:00Z',retest_supported:false,
      retest_unsupported_reason:'retest_exposure_by_rescan'}})
    if (path.endsWith('/discovered-secrets')) return route.fulfill({json:{secrets:[],count:0,values_visible:false}})
    return route.fulfill({json:{status:'healthy',profiles:[],targets:[],rows:[],items:[],instances:[],total:0,has_more:false}})
  })
}

for (const width of [390, 1440]) test.describe(`at ${width} px`, () => {
  test.use({viewport: {width, height: 900}})

  test('NAMES-001 a credential names its owner by name or address, never its id', async ({page}) => {
    await mock(page)
    await page.goto('/credentials')
    await expect(page.getByRole('heading', {name: 'Shop login'})).toBeVisible()
    await expect(page.getByRole('button', {name: 'http://10.0.0.5:3000'})).toBeVisible()
    await expect(page.locator('main')).not.toContainText(hostId)
  })

  test('NAMES-002 ports show one copyable Hunt command and counted evidence', async ({page}) => {
    await mock(page, {managed: true})
    await page.goto(`/targets/${hostId}/asset`)
    await expect(page.getByRole('heading', {name: 'Ports discovered across Scans and Hunts'})).toBeVisible()
    await expect(page.getByTestId('terminal-hunt-start')).toHaveCount(1)
    await expect(page.getByTestId('terminal-hunt-start')).toContainText(`shakerscan agent --target ${hostId}`)
    await expect(page.getByRole('button', {name: 'Copy the Hunt command'})).toBeVisible()
    const evidence = page.getByTestId('port-evidence')
    await expect(evidence).toHaveCount(2)
    await expect(evidence.first()).toHaveText('Hunt 79d5443a · succeeded ×12')
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  })

  test('NAMES-003 a disabled Retest states its reason on the page', async ({page}) => {
    await mock(page)
    await page.goto(`/findings/${findingId}`)
    const retest = page.getByRole('button', {name: 'Retest', exact: true})
    await expect(retest).toBeDisabled()
    const reason = page.getByTestId('retest-blocked-reason')
    await expect(reason).toBeVisible()
    await expect(reason).toContainText('Retest unavailable: Run a new Scan to check this exposure again.')
    await expect(retest).toHaveAttribute('aria-describedby', 'retest-blocked-reason')
  })

  test('NAMES-004 every button on the Evidence page has an accessible name', async ({page}) => {
    // Guard, not a regression test: the audit that reported an unnamed button there read
    // innerText, which is empty for buttons inside a closed <details> (Chrome lays them out with
    // content-visibility). Their accessible names were never empty.
    await mock(page)
    await page.goto('/evidence')
    await expect(page.getByRole('heading', {name: 'Evidence', level: 1})).toBeVisible()
    const buttons = page.getByRole('main').getByRole('button')
    expect(await buttons.count()).toBeGreaterThan(3)
    for (const button of await buttons.all()) await expect(button).toHaveAccessibleName(/\S/)
  })
})
