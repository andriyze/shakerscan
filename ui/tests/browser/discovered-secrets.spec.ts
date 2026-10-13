import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// The target page's Discovered secrets card (2.10). Mocked API: the list never carries a value; a
// reveal does, only after the person asks; on Enterprise the gateway answers a step-up decision with
// 403 and x-shakerscan-step-up: required, and the card names the terminal command instead.
const assetId = '00000000-0000-4000-8000-000000000410'
const otherId = '00000000-0000-4000-8000-000000000411'
const secretId = '00000000-0000-4000-8000-000000000412'
const ref = `secret://${secretId}`
const VALUE = 'synthetic-db-password-7f3a9c'
const target = {id:assetId,asset_id:assetId,name:'Secrets fixture',url:'https://app.example.test',locator:'app.example.test',is_active:true,environment:'lab',connected_device:false,origin_count:0,service_count:0,active_findings_count:0,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z'}
const secret = {ref,kind:'password',label:'DB_PASSWORD',length:VALUE.length,source:{kind:'hunt_action'},first_seen_at:'2026-10-12T00:00:00Z',last_seen_at:'2026-10-13T00:00:00Z',seen_count:2,state:'active',expires_at:'2026-11-12T00:00:00Z',uses:1,reveals:0,last_used_at:null,found_on:assetId,granted_to:[],promoted_profile_id:null}

async function mock(page: Page, opts: {stepUp?: boolean} = {}) {
  const writes: {method: string; path: string; body: unknown}[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request(), url = new URL(request.url())
    if (!['GET','OPTIONS'].includes(request.method())) writes.push({method:request.method(),path:url.pathname,body:request.postDataJSON()})
    if (url.pathname === `/targets/${assetId}/asset`) return route.fulfill({json:{target,origins:[],services:[],service_intelligence:{services:[],warnings:[]},credentials:[],request_collections:[],history:{items:[],total:0},active_findings:{},authorization:{approved_by:'fixture'}}})
    if (url.pathname === `/targets/${assetId}/discovered-secrets`) return route.fulfill({json:{target_id:assetId,secrets:[secret],count:1,values_visible:false}})
    if (url.pathname.endsWith('/reveal') || url.pathname.endsWith('/grants') || url.pathname.endsWith('/promote')) {
      if (opts.stepUp) return route.fulfill({status:403,headers:{'x-shakerscan-step-up':'required','access-control-expose-headers':'x-shakerscan-step-up'},json:{detail:'revealing, granting or promoting a discovered secret needs your step-up'}})
      if (url.pathname.endsWith('/reveal')) return route.fulfill({json:{value:VALUE}})
      return route.fulfill({status:201,json:{status:'ok',profile:{id:'p-1'}}})
    }
    if (url.pathname.endsWith('/state') || url.pathname.endsWith('/expiry')) return route.fulfill({json:{status:'ok'}})
    if (url.pathname.endsWith('/skill')) return route.fulfill({json:{target_id:assetId,revision:0,skill:null,max_characters:12000}})
    if (url.pathname.endsWith('/history')) return route.fulfill({json:{asset_id:assetId,kind:'scans',items:[],total:0,offset:0,limit:25}})
    if (url.pathname.endsWith('/interpretations')) return route.fulfill({json:{interpretations:[],count:0,has_more:false}})
    if (url.pathname.endsWith('/negative-results')) return route.fulfill({json:{rows:[],count:0,has_more:false}})
    return route.fulfill({json:{status:'healthy',workers:[],devices:[],targets:[],total:0}})
  })
  return writes
}

test('SECRETS-001 the card lists metadata, never a value, and revoke is an operator write', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  await expect(page.getByRole('heading', {name: 'Discovered secrets'})).toBeVisible()
  await expect(page.getByText('DB_PASSWORD')).toBeVisible()
  await expect(page.getByText(ref)).toBeVisible()
  await expect(page.locator('body')).not.toContainText(VALUE)
  await page.getByRole('button', {name: 'Revoke'}).click()
  await expect.poll(() => writes.map(w => `${w.method} ${w.path}`)).toContain(`POST /targets/${assetId}/discovered-secrets/${secretId}/state`)
  expect(writes[0].body).toEqual({state:'revoked_by_operator'})
})

test('SECRETS-002 a reveal shows the value only after asking, and closing hides it', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  await page.getByRole('button', {name: 'Reveal'}).click()
  const dialog = page.getByRole('dialog', {name: 'Reveal the value'})
  await expect(dialog).toBeVisible()
  expect(writes).toEqual([])
  await dialog.getByRole('button', {name: 'Reveal'}).click()
  await expect(dialog.getByTestId('revealed-value')).toHaveText(VALUE)
  await dialog.getByRole('button', {name: 'Hide'}).click()
  await expect(dialog).toBeHidden()
  await expect(page.locator('body')).not.toContainText(VALUE)
  expect(writes.map(w => w.path)).toEqual([`/targets/${assetId}/discovered-secrets/${secretId}/reveal`])
})

test('SECRETS-003 on Enterprise a step-up decision names the terminal command and shows no value', async ({page}) => {
  await mock(page, {stepUp: true})
  await page.goto(`/targets/${assetId}/asset`)
  await page.getByRole('button', {name: 'Reveal'}).click()
  await page.getByRole('dialog', {name: 'Reveal the value'}).getByRole('button', {name: 'Reveal'}).click()
  const notice = page.getByRole('status').filter({hasText: 'needs your step-up'})
  await expect(notice).toContainText(`shakerscan secrets reveal ${assetId} ${ref}`)
  await expect(page.locator('body')).not.toContainText(VALUE)
})

test('SECRETS-004 grant sends exactly the other target id', async ({page}) => {
  const writes = await mock(page)
  await page.goto(`/targets/${assetId}/asset`)
  await page.getByRole('button', {name: 'Grant'}).click()
  const dialog = page.getByRole('dialog', {name: 'Let another target use this secret'})
  await expect(dialog.getByRole('button', {name: 'Grant'})).toBeDisabled()
  await dialog.getByPlaceholder('target id').fill(otherId)
  await dialog.getByRole('button', {name: 'Grant'}).click()
  await expect(dialog).toBeHidden()
  expect(writes).toEqual([{method:'POST',path:`/targets/${assetId}/discovered-secrets/${secretId}/grants`,body:{target_id:otherId}}])
})
