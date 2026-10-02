import { test, expect } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id='00000000-0000-4000-8000-000000000721'
const source='00000000-0000-4000-8000-000000000722'
const profile='00000000-0000-4000-8000-000000000723'
const collection='00000000-0000-4000-8000-000000000724'
const targets=[{id,asset_id:id,locator:'example.test',name:'example.test',url:'host://example.test',is_active:true,environment:'lab',connected_device:false,origin_count:1},
  {id:source,asset_id:source,locator:'192.0.2.8',name:'Home TV',url:'host://192.0.2.8',is_active:true,environment:'lab',connected_device:true,service_count:3}]
const permission={target_id:id,revision:0,metadata_changes:false,credential_profile_ids:[],collection_ids:[],ssh_host_keys:[],ssh_trust_first_contact:false}

test('TARGET-FILTERS-001 server filters select Web and IP/network without losing canonical actions',async ({page}) => {
  await pinMockApiOrigin(page)
  const filters:string[]=[]
  await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
    const url=new URL(route.request().url())
    if(url.pathname==='/targets/inventory') {
      const kind=url.searchParams.get('asset_type') || 'all'
      filters.push(kind)
      expect(url.searchParams.get('offset')).toBe('0')
      const matching=kind==='web' ? [targets[0]] : kind==='network' ? [targets[1]] : targets
      return route.fulfill({json:{targets:matching,total:matching.length,total_groups:matching.length,
        groups:matching.map(target=>({root_domain:target.locator,targets:[target]}))}})
    }
    return route.fulfill({json:{skill:null,revision:0}})
  })
  await page.goto('/targets')
  await expect(page.getByRole('link',{name:'example.test',exact:true})).toBeVisible()
  await page.getByRole('button',{name:'Web',exact:true}).click()
  await expect(page.getByRole('button',{name:'Web',exact:true})).toHaveAttribute('aria-pressed','true')
  await expect(page.getByRole('link',{name:'Home TV',exact:true})).toHaveCount(0)
  await expect(page.getByRole('button',{name:'Discover subdomains of example.test',exact:true})).toBeVisible()
  await page.getByRole('button',{name:'IP / network',exact:true}).click()
  await expect(page.getByRole('link',{name:'Home TV',exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'example.test',exact:true})).toHaveCount(0)
  await expect(page.getByRole('button',{name:'Start network scan',exact:true})).toHaveCount(1)
  await page.getByRole('button',{name:'All targets',exact:true}).click()
  await expect(page.getByTestId('target-domain-group')).toHaveCount(2)
  expect(filters).toContain('web');expect(filters).toContain('network')
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
  expect(await page.getByTestId('target-domain-group').evaluateAll(cards =>
    cards.every(card => card.scrollWidth <= card.clientWidth))).toBe(true)
  const scan=page.getByRole('button',{name:'Start network scan',exact:true}).last()
  expect(await scan.evaluate(button => {
    const row=button.closest('[data-testid="target-domain-group"]')!
    const control=button.getBoundingClientRect(),bounds=row.getBoundingClientRect()
    return control.left >= bounds.left && control.right <= bounds.right
  })).toBe(true)
})

test('TARGET-PERMISSIONS-001 operator delegates metadata, named inputs and an SSH key through target API',async ({page}) => {
  await pinMockApiOrigin(page)
  let submitted:Record<string,unknown>|undefined
  let grants=0
  await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
    const request=route.request(),path=new URL(request.url()).pathname
    if(path.includes('/grants') || path.includes('/capabilities/')) grants++
    if(path===`/targets/${id}/hunt-authority`) {
      if(request.method()==='PUT') {submitted=request.postDataJSON();return route.fulfill({json:{...permission,...submitted,revision:1}})}
      return route.fulfill({json:permission})
    }
    if(path===`/targets/${id}/asset`) return route.fulfill({json:{target:targets[0],origins:[],services:[],credentials:[],request_collections:[],active_findings:{},history:{items:[],total:0}}})
    if(path==='/targets/inventory') return route.fulfill({json:{targets,total:targets.length}})
    if(path==='/credential-profiles') return route.fulfill({json:{profiles:[{id:profile,name:'TV SSH identity'}]}})
    if(path==='/request-collections') return route.fulfill({json:{collections:[{id:collection,name:'TV API collection'}]}})
    return route.fulfill({json:{skill:null,revision:0,max_characters:12000,items:[],total:0}})
  })
  await page.goto(`/targets/${id}/asset`)
  await page.getByRole('button',{name:'Edit Hunt permissions',exact:true}).click()
  const dialog=page.getByRole('dialog',{name:'Hunt permissions',exact:true})
  await dialog.getByRole('checkbox',{name:/Let Hunt manage targets/}).check()
  await dialog.getByLabel('Source target').selectOption(source)
  await dialog.getByRole('checkbox',{name:'TV SSH identity',exact:true}).check()
  await dialog.getByRole('checkbox',{name:'TV API collection',exact:true}).check()
  await dialog.getByRole('button',{name:'Add SSH host key',exact:true}).click()
  await dialog.getByLabel('SSH port 1',{exact:true}).fill('2222')
  await dialog.getByLabel('SSH fingerprint 1',{exact:true}).fill('SHA256:'+'a'.repeat(43))
  await dialog.getByRole('button',{name:'Save permissions',exact:true}).click()
  await expect(page.getByText(/Hunt permissions saved/)).toBeVisible()
  expect(submitted).toEqual({expected_revision:0,metadata_changes:true,credential_profile_ids:[profile],collection_ids:[collection],ssh_host_keys:[{port:2222,fingerprint:'SHA256:'+'a'.repeat(43)}],ssh_trust_first_contact:false})
  expect(grants).toBe(0)
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth)).toBe(false)
})
