import { expect, test } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const hostId = '00000000-0000-4000-8000-000000000391'
const serviceId = '00000000-0000-4000-8000-000000000392'
const host = {id:hostId,asset_id:hostId,name:'Home router',url:'host://router.test',locator:'router.test',
  is_active:true,environment:'lab',connected_device:true,created_at:'2026-01-01',updated_at:'2026-01-01'}
const service = {id:serviceId,url:'https://router.test:8443',name:'Management service',
  is_active:true,current_membership:true,active_findings_count:0}

for (const link of ['id','url']) {
  test(`credential ${link} link preserves exact service identity`,async ({page}) => {
    const consumers: string[] = []
    await pinMockApiOrigin(page)
    await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
      const url = new URL(route.request().url())
      if (url.pathname === '/targets/inventory') return route.fulfill({json:{
        targets:link === 'id' ? [host] : [host,{...host,...service,asset_id:hostId}],
        total:link === 'id' ? 1 : 2,offset:0,limit:500}})
      if (url.pathname === `/targets/${serviceId}/asset`) return route.fulfill({json:{target:host,origins:[service]}})
      if (url.pathname === '/credential-profiles') {
        consumers.push(url.searchParams.get('target_id') || '')
        return route.fulfill({json:{profiles:[],total:0}})
      }
      return route.fulfill({json:{profiles:[],targets:[],total:0}})
    })
    const params: Record<string,string> = link === 'id' ? {target_id:serviceId} : {target:service.url}
    await page.goto(`/credentials?${new URLSearchParams(params)}`)
    await expect(page.getByRole('combobox').first()).toHaveValue('web')
    await expect(page.getByRole('combobox').nth(1)).toHaveValue(serviceId)
    await expect.poll(() => consumers).toContain(serviceId)
    expect(consumers).not.toContain(hostId)
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  })
}
