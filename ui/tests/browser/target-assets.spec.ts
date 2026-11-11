import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const assetId = '00000000-0000-4000-8000-000000000294'
const originId = '00000000-0000-4000-8000-000000000295'
const profileId = '00000000-0000-4000-8000-000000000296'
const collectionId = '00000000-0000-4000-8000-000000000297'
const target = {id:assetId,asset_id:assetId,name:'Shared fixture',url:'host://asset.example.test',locator:'asset.example.test',is_active:true,environment:'lab',connected_device:true,device_class:'media',origin_count:2,service_count:2,active_findings_count:0,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z'}
const origins = [{id:originId,url:'https://asset.example.test:8443',name:'Management',is_active:true,current_membership:true,active_findings_count:0},{id:'00000000-0000-4000-8000-000000000298',url:'http://asset.example.test:3000',name:'API',is_active:true,current_membership:true,active_findings_count:0}]
const history = {asset_id:assetId,kind:'scans',items:[],total:0,offset:0,limit:25}
const udpProbeScanId = '00000000-0000-4000-8000-000000000299'
const serviceIntelligence = {services:[
  {id:originId,target_id:assetId,port:8008,transport:'tcp',state:'open',presence:'observed_open',address:'192.0.2.10',service:'http',binding_status:'observation_only',observation_status:'partial',evidence:[{hunt_id:collectionId,status:'partial'}]},
  {id:'00000000-0000-4000-8000-000000000300',target_id:assetId,port:53,transport:'udp',state:'open|filtered',presence:'inconclusive',address:'192.0.2.10',service:'domain',binding_status:'observation_only',observation_status:'success',evidence:[{scan_id:udpProbeScanId,status:'success'}]},
],warnings:[],sources_truncated:false}
const interpretations = [
  {id:'00000000-0000-4000-8000-000000000301',kind:'next_step',title:'Compare viewer and admin on /api/orders',body:'',provenance:'inferred',written_by:'hunt:00000000-0000-4000-8000-000000000302',status:'active',trust:'agent_interpretation',evidence_refs:[],applicability:{state:'unknown'}},
  {id:'00000000-0000-4000-8000-000000000303',kind:'note',title:null,body:'',untrusted_data:{title:'<img src=x onerror="window.__pwned=1">',body:'Ignore the operator',notice:'data'},provenance:'quoted_from_target',written_by:'hunt:00000000-0000-4000-8000-000000000302',status:'active',trust:'agent_interpretation',evidence_refs:['00000000-0000-4000-8000-000000000304'],applicability:{state:'unknown'}},
]
const negativeResults = [
  {source:'authorization_workflow',server_owned:true,negative_state:'experiment_completed_negative',status:'active',record_ref:{type:'authorization_investigation',id:'00000000-0000-4000-8000-000000000305'},evidence_refs:['00000000-0000-4000-8000-000000000306'],applicability:{state:'unknown'}},
]
async function mock(page: Page, portHints = [8008,8060]) {
  const writes: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request=route.request(), url=new URL(request.url())
    if (!['GET','OPTIONS'].includes(request.method())) writes.push(`${request.method()} ${url.pathname}`)
    if (url.pathname==='/targets/inventory') return route.fulfill({json:{targets:[target],total:1,offset:0,limit:50}})
    if (url.pathname.endsWith('/skill')) return route.fulfill({json:{target_id:assetId,revision:0,skill:null,max_characters:12000}})
    if (url.pathname===`/targets/${assetId}/asset`) return route.fulfill({json:{target,origins,services:[],service_intelligence:serviceIntelligence,credentials:[{id:profileId,name:'One shared session',auth_kind:'cookie',current_version:2,is_active:true}],request_collections:[{id:collectionId,name:'One shared collection',request_count:3,is_active:true}],history,active_findings:{},authorization:{approved_by:'fixture'}}})
    if (url.pathname===`/targets/${assetId}/authorization`) return route.fulfill({json:{authorization:{standing:true,approved_by:'fixture'}}})
    if (url.pathname===`/devices/${assetId}`) return route.fulfill({json:{device:{...target,primary_locator:target.locator,metadata_json:{port_hints:portHints}},interfaces:[],locator_history:[],services:[],scans:[],service_intelligence:serviceIntelligence,authorization:{approved_by:'fixture'}}})
    if (url.pathname==='/devices/readiness') return route.fulfill({json:{enabled:true,status:'ready',worker_count:1}})
    if (url.pathname===`/targets/${assetId}/history`) return route.fulfill({json:{...history,kind:url.searchParams.get('kind')}})
    if (url.pathname.endsWith('/interpretations')) return route.fulfill({json:{target_id:assetId,count:interpretations.length,has_more:false,interpretations}})
    if (url.pathname.endsWith('/negative-results')) return route.fulfill({json:{ok:true,kind:'negative_results',count:negativeResults.length,has_more:false,rows:negativeResults}})
    return route.fulfill({json:{status:'healthy',workers:[],devices:[],targets:[],total:0}})
  })
  return writes
}

async function expectNoResponseProbeIsNotADiscoveredPort(page: Page) {
  const discovered = page.getByRole('table')
  await expect(discovered.getByRole('cell',{name:/8008\/tcp/})).toBeVisible()
  await expect(discovered.getByRole('cell',{name:/^53\/udp/})).toHaveCount(0)
  await expect(page.getByRole('link',{name:'Start Hunt',exact:true})).toHaveCount(1)
  await expect(page.locator('a[href*="udp%2F53"], a[href*="udp/53"]')).toHaveCount(0)
  const probes = page.getByText('1 unconfirmed no-response probe',{exact:true})
  await expect(probes).toBeVisible()
  await expect(page.getByText('53/udp',{exact:true})).toBeHidden()
  await probes.click()
  await expect(page.getByText('53/udp',{exact:true})).toBeVisible()
  await expect(page.getByText('No response',{exact:true})).toBeVisible()
  await expect(page.getByText('Expected protocol: domain',{exact:true})).toBeVisible()
}

test('ASSET-001 one asset owns service origins and shared IDs without executing on navigation', async ({page}) => {
  const writes=await mock(page)
  await page.goto('/targets')
  await expect(page.getByTestId('target-asset-row')).toHaveCount(1)
  await page.getByRole('link',{name:'Shared fixture',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Shared fixture',exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'https://asset.example.test:8443',exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'https://asset.example.test:8443',exact:true})).toHaveAttribute('href',`/targets/${originId}/asset`)
  await expect(page.getByRole('link',{name:'http://asset.example.test:3000',exact:true})).toBeVisible()
  await expect(page.getByText(profileId,{exact:true})).toBeVisible()
  await expect(page.getByText(collectionId,{exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'Connected Devices view →'})).toHaveAttribute('href',`/devices/${assetId}`)
  const manage=page.getByRole('link',{name:'Manage',exact:true})
  await expect(manage.nth(0)).toHaveAttribute('href',new RegExp(`target_id=${assetId}`))
  await expect(manage.nth(1)).toHaveAttribute('href',new RegExp(`target_id=${assetId}`))
  expect(writes).toEqual([])
  expect(await page.evaluate(() => document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
})

test('ASSET-002 retained Hunt ports open the same target without duplicate device choices', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  await expect(page.getByRole('heading',{name:'Ports discovered across Scans and Hunts'})).toBeVisible()
  await expect(page.getByRole('cell',{name:/8008\/tcp.*192\.0\.2\.10/})).toBeVisible()
  await expect(page.getByText('Hunt 00000000 · partial',{exact:true})).toBeVisible()
  await page.getByRole('link',{name:'Start Hunt',exact:true}).click()
  const targetPicker = page.getByLabel('Target',{exact:true})
  await expect(targetPicker).toHaveAttribute('data-value',assetId)
  await targetPicker.click()
  await expect(page.getByRole('listbox').getByRole('option')).toHaveCount(1)
  await page.keyboard.press('Escape')
  await expect(page.getByLabel('Objective',{exact:true})).toHaveValue(/observed tcp\/8008/)
  expect(writes).toEqual([])
})

test('ASSET-003 adding a host preserves explicit port hints', async ({page}) => {
  await mock(page)
  let submitted: Record<string,unknown> = {}
  await page.route(`${MOCK_API_ORIGIN}/targets/hosts`,async route => {
    submitted = route.request().postDataJSON()
    return route.fulfill({json:{id:assetId,status:'created'}})
  })
  await page.goto('/targets')
  await page.getByRole('button',{name:'Add targets',exact:true}).first().click()
  const dialog = page.getByRole('dialog',{name:'Add targets'})
  await dialog.getByLabel('What do you want to test?').fill('tv.test')
  await dialog.getByLabel('Extra ports to check (optional)').fill('8008, 8060, 8008')
  await page.getByRole('button',{name:'Add target',exact:true}).click()
  await dialog.getByRole('link',{name:'Open'}).click()
  await expect(page.getByRole('heading',{name:'Shared fixture',exact:true})).toBeVisible()
  expect(submitted).toMatchObject({locator:'tv.test',port_hints:[8008,8060]})
})

test('ASSET-004 connected-device view shows Hunt ports and reuses saved scan hints', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/devices/${assetId}`)
  await expect(page.getByRole('heading',{name:'Ports discovered across Scans and Hunts'})).toBeVisible()
  await expect(page.getByRole('cell',{name:/8008\/tcp.*192\.0\.2\.10/})).toBeVisible()
  await expect(page.getByRole('link',{name:'Start Hunt',exact:true})).toHaveAttribute('href',new RegExp(`target=${assetId}`))
  await page.getByRole('button',{name:'Start network scan',exact:true}).click()
  const dialog = page.getByRole('dialog',{name:'Scan Shared fixture'})
  await expect(dialog.getByLabel('Known TCP ports (optional)')).toHaveValue('8008, 8060')
  await expect(dialog.getByRole('button',{name:'Queue scan',exact:true})).toBeEnabled()
  expect(writes).toEqual([])
})

test('ASSET-005 Hunt-discovered ports populate scan hints without saved metadata', async ({page}) => {
  const writes = await mock(page, [])
  await page.goto(`/devices/${assetId}`)
  await page.getByRole('button',{name:'Start network scan',exact:true}).click()
  const dialog = page.getByRole('dialog',{name:'Scan Shared fixture'})
  const hints = dialog.getByLabel('Known TCP ports (optional)')
  await expect(hints).toHaveValue('8008')
  await hints.fill('8008, 9000')
  await expect(hints).toHaveValue('8008, 9000')
  await hints.fill('')
  await expect(hints).toHaveValue('')
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click()
  await page.getByRole('button',{name:'Start network scan',exact:true}).click()
  await expect(hints).toHaveValue('8008')
  expect(writes).toEqual([])
})

test('ASSET-006 no-response UDP probes are not listed as discovered ports or offered for Hunt', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  await expect(page.getByRole('heading',{name:'Ports discovered across Scans and Hunts'})).toBeVisible()
  await expectNoResponseProbeIsNotADiscoveredPort(page)
  await page.goto(`/devices/${assetId}`)
  await expect(page.getByRole('heading',{name:'Ports discovered across Scans and Hunts'})).toBeVisible()
  await expectNoResponseProbeIsNotADiscoveredPort(page)
  expect(writes).toEqual([])
})

test('ASSET-INTERP-001 the asset page lists interpretations and negative results read-only, quoted text as text', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  const panel = page.locator('section, div').filter({has: page.getByRole('heading',{name:'Interpretations and negative results'})}).last()
  await expect(page.getByRole('heading',{name:'Interpretations and negative results'})).toBeVisible()
  await expect(panel.getByText('Compare viewer and admin on /api/orders',{exact:true})).toBeVisible()
  await expect(panel.getByText('Quoted from the target: “<img src=x onerror="window.__pwned=1">”',{exact:true})).toBeVisible()
  await expect(panel.getByText(/Experiment ran, nothing found \(these conditions only\)/)).toBeVisible()
  await expect(panel.getByText('Server record',{exact:true})).toBeVisible()
  await expect(panel.getByRole('button')).toHaveCount(0)
  expect(await page.evaluate(() => (window as unknown as {__pwned?: number}).__pwned)).toBeUndefined()
  expect(writes).toEqual([])
})

const changeReport = {ok:true,kind:'changes',target_id:assetId,since:{kind:'last_hunt',at:'2026-01-02T03:04:05+00:00',resolved:true},sends_traffic:false,
  sections:{endpoints:{added:{count:1,at_least:false,items:[{method:'GET',path:'/api/orders/<b>new</b>',auth_state:'authenticated'}]},removed:{count:0,at_least:false,items:[]},auth_surface:{significant:false}},
    deployment:{compared:true,changes:[{field:'technology_version',before:'nginx 1.24',after:'nginx 1.26',significance:'significant'}]},responses:{changed:[]},services:{added:[],no_longer_observed:[]},findings:{new:{count:2,at_least:false}},subdomains:{new_targets:[]}},
  knowledge:{active_by_applicability:{applicable:1,needs_revalidation:1},affected:[{id:'00000000-0000-4000-8000-000000000301',kind:'next_step',applicability:'needs_revalidation',caused_by:[{type:'deployment',key:'scan',field:'technology_version'}]}],affected_truncated:false}}

test('ASSET-CHANGES-001 what changed on a target is read and shown on its page, on request', async ({page}) => {
  const writes = await mock(page)
  const reads: string[] = []
  await page.route(`${MOCK_API_ORIGIN}/targets/${assetId}/knowledge/changes*`, async route => {
    reads.push(new URL(route.request().url()).search)
    return route.fulfill({json:changeReport})
  })
  await page.goto(`/targets/${assetId}/asset`)
  const card = page.getByTestId('target-changes')
  await expect(card.getByRole('heading',{name:'What changed',exact:true})).toBeVisible()
  await expect(card.getByText(/Nothing is sent to the target/)).toBeVisible()
  // Nothing is read until the person asks.
  expect(reads).toEqual([])
  await card.getByRole('button',{name:'See what changed',exact:true}).click()
  await expect(card.getByText(/^Since the last Hunt \(.+\):$/)).toBeVisible()
  await expect(card.getByRole('heading',{name:'Routes added (1)',exact:true})).toBeVisible()
  // A path observed from the target is text, not markup.
  await expect(card.getByText('GET /api/orders/<b>new</b> (authenticated)',{exact:true})).toBeVisible()
  await expect(card.getByText('technology version: nginx 1.24 → nginx 1.26 (significant)',{exact:true})).toBeVisible()
  await expect(card.getByText('2 new findings',{exact:true})).toBeVisible()
  await expect(card.getByText('Next step: needs re-testing (deployment scan technology version)',{exact:true})).toBeVisible()
  await expect(card.getByText('Active interpretations: 1 still applies, 1 needs re-testing.',{exact:true})).toBeVisible()
  expect(reads).toEqual(['?since=last_hunt&limit=25'])
  await card.getByLabel('Compare with').selectOption('release')
  await card.getByRole('button',{name:'See what changed',exact:true}).click()
  await expect(card.getByRole('heading',{name:'Routes added (1)',exact:true})).toBeVisible()
  expect(reads).toEqual(['?since=last_hunt&limit=25','?since=release&limit=25'])
  // The terminal command stays as an alternative, and dismissing a finding is pointed at its page.
  await expect(card.getByText('shakerscan knowledge changes',{exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:"this target's findings",exact:true}))
    .toHaveAttribute('href',`/findings?target_id=${assetId}&status=all&freshness=all`)
  expect(writes).toEqual([])
  expect(await page.evaluate(() => document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
})

test('ASSET-CHANGES-002 with nothing to compare with, and when the read fails, the card says so', async ({page}) => {
  await mock(page)
  let fail = false
  await page.route(`${MOCK_API_ORIGIN}/targets/${assetId}/knowledge/changes*`, async route => fail
    ? route.fulfill({status:422,json:{detail:{error:'invalid_since',message:'No release is recorded for this target.'}}})
    : route.fulfill({json:{...changeReport,since:{kind:'last_hunt',at:null,resolved:false,note:'No earlier Hunt on this target; nothing to compare with.'},sections:{},knowledge:{active_by_applicability:{},affected:[]}}}))
  await page.goto(`/targets/${assetId}/asset`)
  const card = page.getByTestId('target-changes')
  await card.getByRole('button',{name:'See what changed',exact:true}).click()
  await expect(card.getByText('No earlier Hunt on this target; nothing to compare with.',{exact:true})).toBeVisible()
  fail = true
  await card.getByRole('button',{name:'See what changed',exact:true}).click()
  await expect(card.getByRole('alert')).toBeVisible()
  await expect(card.getByText('No earlier Hunt on this target; nothing to compare with.',{exact:true})).toHaveCount(0)
})

test('ASSET-007 target details (owner, environment, cohort) are edited on the target page', async ({page}) => {
  // Moved from the removed Exposure triage drawer in 2.10: the only place to set these after creation.
  await mock(page)
  const patches: unknown[] = []
  await page.route(`${MOCK_API_ORIGIN}/targets/${assetId}`, async route => {
    if (route.request().method() === 'PATCH') {
      patches.push(route.request().postDataJSON())
      return route.fulfill({json:{id:assetId,status:'updated'}})
    }
    return route.fallback()
  })
  await page.goto(`/targets/${assetId}/asset`)
  await page.getByRole('button', {name: 'Edit details'}).click()
  const dialog = page.getByRole('dialog', {name: 'Edit target details'})
  await dialog.getByPlaceholder('team or person').fill('  platform team  ')
  await dialog.getByLabel('Environment').selectOption('staging')
  await dialog.getByLabel('Reporting cohort').selectOption('lab')
  await dialog.getByRole('button', {name: 'Save'}).click()
  await expect(dialog).toBeHidden()
  expect(patches).toEqual([{metadata_json:{owner:'platform team',environment:'staging'},cohort:'lab'}])
})

for (const width of [390, 1440]) {
  test(`ASSET-008 a web app added on a known host keeps its display name (${width} px)`, async ({page}) => {
    await page.setViewportSize({width, height: 900})
    await mock(page)
    let web: Record<string,unknown> = {}
    await page.route(`${MOCK_API_ORIGIN}/targets/hosts`,async route => route.fulfill({json:{id:assetId,status:'already_exists'}}))
    await page.route(`${MOCK_API_ORIGIN}/targets`,async route => {
      if (route.request().method() !== 'POST') return route.fallback()
      web = route.request().postDataJSON()
      return route.fulfill({json:{id:originId,url:'http://asset.example.test:3000',status:'already_exists'}})
    })
    await page.goto('/targets')
    await page.getByRole('button',{name:'Add targets',exact:true}).first().click()
    const dialog = page.getByRole('dialog',{name:'Add targets'})
    await dialog.getByLabel('What do you want to test?').fill('http://asset.example.test:3000/')
    await dialog.getByLabel('Display name (optional)').fill('Shop (lab)')
    await page.getByRole('button',{name:'Add target',exact:true}).click()
    await expect(dialog.getByRole('list',{name:'Results'})).toBeVisible()
    expect(web.name).toBe('Shop (lab)')
    expect(String(web.url)).toMatch(/^http:\/\/asset\.example\.test:3000/)
  })
}

test('ASSET-HISTORY-001 the history names what each record is in words', async ({page}) => {
  await mock(page)
  await page.route(`${MOCK_API_ORIGIN}/targets/${assetId}/history*`, route => route.fulfill({json:{asset_id:assetId,kind:'scans',total:2,offset:0,limit:25,items:[
    {id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',target_id:assetId,target_url:'https://fixture.example.test',run_kind:'web_dast',status:'completed',created_at:'2026-01-02T03:04:05Z'},
    {id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2',target_id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',target_url:'https://fixture.example.test:8443',run_kind:'device_posture',status:'completed',created_at:'2026-01-02T03:04:05Z'},
  ]}}))
  await page.goto(`/targets/${assetId}/asset`, {waitUntil:'domcontentloaded'})
  const history = page.locator('section', {has: page.getByRole('heading', {name:'Asset history', exact:true})})
  await expect(history.getByText('Web scan · Host', {exact:true})).toBeVisible()
  await expect(history.getByText('Network discovery · Application service', {exact:true})).toBeVisible()
  await expect(history).not.toContainText('web_dast')
  await expect(history).not.toContainText('device_posture')
})

test('ASSET-009 a Targets row shows the whole host name at laptop width', async ({page}) => {
  await mock(page)
  const host = 'app.staging.example.test'
  await page.route(`${MOCK_API_ORIGIN}/targets/inventory*`, route => route.fulfill({json:{targets:[{...target,name:host,url:`host://${host}`,locator:host}],total:1,offset:0,limit:50}}))
  await page.setViewportSize({width:1280,height:800})
  await page.goto('/targets')
  const name = page.getByTestId('target-asset-row').getByRole('link',{name:host,exact:true})
  await expect(name).toBeVisible()
  // Nothing of the name is cut off sideways or clamped away below.
  expect(await name.evaluate(element => element.scrollWidth <= element.clientWidth && element.scrollHeight <= element.clientHeight + 1)).toBe(true)
  expect(await page.evaluate(() => document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
})

test('ASSET-010 a very long target label stays inside its row', async ({page}) => {
  await mock(page)
  const label = 'a'.repeat(120)
  await page.route(`${MOCK_API_ORIGIN}/targets/inventory*`, route => route.fulfill({json:{targets:[{...target,name:label,url:`host://${label}`,locator:label}],total:1,offset:0,limit:50}}))
  await page.setViewportSize({width:1280,height:800})
  await page.goto('/targets')
  const row = page.getByTestId('target-asset-row')
  const name = row.getByRole('link',{name:label,exact:true})
  await expect(name).toBeVisible()
  // Two lines at most, inside the row, and the page does not scroll sideways.
  expect(await name.evaluate(element => element.clientHeight <= 2 * parseFloat(getComputedStyle(element).lineHeight) + 1)).toBe(true)
  expect(await row.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true)
  expect(await page.evaluate(() => document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
})
