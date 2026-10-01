import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const assetId = '00000000-0000-4000-8000-000000000294'
const originId = '00000000-0000-4000-8000-000000000295'
const profileId = '00000000-0000-4000-8000-000000000296'
const collectionId = '00000000-0000-4000-8000-000000000297'
const target = {id:assetId,asset_id:assetId,name:'Shared fixture',url:'host://asset.example.test',locator:'asset.example.test',is_active:true,environment:'lab',connected_device:true,device_class:'media',origin_count:2,service_count:2,active_findings_count:0,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z'}
const origins = [{id:originId,url:'https://asset.example.test:8443',name:'Management',is_active:true,current_membership:true,active_findings_count:0},{id:'00000000-0000-4000-8000-000000000298',url:'http://asset.example.test:3000',name:'API',is_active:true,current_membership:true,active_findings_count:0}]
const history = {asset_id:assetId,kind:'scans',items:[],total:0,offset:0,limit:25}
async function mock(page: Page) {
  const writes: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request=route.request(), url=new URL(request.url())
    if (!['GET','OPTIONS'].includes(request.method())) writes.push(`${request.method()} ${url.pathname}`)
    if (url.pathname==='/targets/inventory') return route.fulfill({json:{targets:[target],total:1,offset:0,limit:50}})
    if (url.pathname===`/targets/${assetId}/asset`) return route.fulfill({json:{target,origins,services:[],credentials:[{id:profileId,name:'One shared session',auth_kind:'cookie',current_version:2,is_active:true}],request_collections:[{id:collectionId,name:'One shared collection',request_count:3,is_active:true}],history,active_findings:{},authorization:{approved_by:'fixture'}}})
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
