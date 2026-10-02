import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const assetId = '00000000-0000-4000-8000-000000000294'
const originId = '00000000-0000-4000-8000-000000000295'
const profileId = '00000000-0000-4000-8000-000000000296'
const collectionId = '00000000-0000-4000-8000-000000000297'
const target = {id:assetId,asset_id:assetId,name:'Shared fixture',url:'host://asset.example.test',locator:'asset.example.test',is_active:true,environment:'lab',connected_device:true,device_class:'media',origin_count:2,service_count:2,active_findings_count:0,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z'}
const origins = [{id:originId,url:'https://asset.example.test:8443',name:'Management',is_active:true,current_membership:true,active_findings_count:0},{id:'00000000-0000-4000-8000-000000000298',url:'http://asset.example.test:3000',name:'API',is_active:true,current_membership:true,active_findings_count:0}]
const history = {asset_id:assetId,kind:'scans',items:[],total:0,offset:0,limit:25}
const serviceIntelligence = {services:[{id:originId,target_id:assetId,port:8008,transport:'tcp',address:'192.0.2.10',service:'http',binding_status:'observation_only',observation_status:'partial',evidence:[{hunt_id:collectionId,status:'partial'}]}],warnings:[],sources_truncated:false}
async function mock(page: Page) {
  const writes: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request=route.request(), url=new URL(request.url())
    if (!['GET','OPTIONS'].includes(request.method())) writes.push(`${request.method()} ${url.pathname}`)
    if (url.pathname==='/targets/inventory') return route.fulfill({json:{targets:[target],total:1,offset:0,limit:50}})
    if (url.pathname.endsWith('/skill')) return route.fulfill({json:{target_id:assetId,revision:0,skill:null,max_characters:12000}})
    if (url.pathname===`/targets/${assetId}/asset`) return route.fulfill({json:{target,origins,services:[],service_intelligence:serviceIntelligence,credentials:[{id:profileId,name:'One shared session',auth_kind:'cookie',current_version:2,is_active:true}],request_collections:[{id:collectionId,name:'One shared collection',request_count:3,is_active:true}],history,active_findings:{},authorization:{approved_by:'fixture'}}})
    if (url.pathname===`/targets/${assetId}/authorization`) return route.fulfill({json:{authorization:{standing:true,approved_by:'fixture'}}})
    if (url.pathname===`/devices/${assetId}`) return route.fulfill({json:{device:{...target,primary_locator:target.locator,metadata_json:{port_hints:[8008,8060]}},interfaces:[],locator_history:[],services:[],scans:[],service_intelligence:serviceIntelligence,authorization:{approved_by:'fixture'}}})
    if (url.pathname==='/devices/readiness') return route.fulfill({json:{enabled:true,status:'ready',worker_count:1}})
    if (url.pathname===`/targets/${assetId}/history`) return route.fulfill({json:{...history,kind:url.searchParams.get('kind')}})
    return route.fulfill({json:{status:'healthy',workers:[],devices:[],targets:[],total:0}})
  })
  return writes
}

test('ASSET-001 one asset owns service origins and shared IDs without executing on navigation', async ({page}) => {
  const writes=await mock(page)
  await page.goto('/targets')
  await expect(page.getByTestId('target-asset-row')).toHaveCount(1)
  await page.getByRole('link',{name:'Open asset',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Shared fixture',exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'https://asset.example.test:8443',exact:true})).toBeVisible()
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
  await expect(page.getByLabel('Target',{exact:true})).toHaveValue(assetId)
  await expect(page.getByLabel('Target',{exact:true}).locator('option')).toHaveCount(2)
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
  await page.getByRole('button',{name:'Add target',exact:true}).click()
  const dialog = page.getByRole('dialog',{name:'Add target asset'})
  await dialog.getByLabel('Hostname, IP address, or application URL').fill('tv.test')
  await dialog.getByLabel('Known TCP ports (optional)').fill('8008, 8060, 8008')
  await dialog.getByRole('button',{name:'Add target',exact:true}).click()
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
