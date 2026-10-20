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
    const searches: string[] = []
    await pinMockApiOrigin(page)
    await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
      const url = new URL(route.request().url())
      if (url.pathname === '/targets/inventory') searches.push(url.searchParams.get('search') || '')
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
    await expect(page.getByLabel('Target type', {exact:true})).toHaveValue('web')
    await expect(page.getByLabel('Target', {exact:true})).toHaveAttribute('data-value', serviceId)
    await expect.poll(() => consumers).toContain(serviceId)
    expect(consumers).not.toContain(hostId)
    // A URL link is resolved with one bounded search for its origin, not by loading every target.
    if (link === 'url') expect(searches).toContain('router.test:8443')
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  })
}

// A ?target=URL link must find its exact origin even when it sorts after the first page of
// substring matches for its host (an apex domain with many discovered subdomains). Reading only
// the first page reported "not found" and fell back to every credential.
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
type Row = {id: string; asset_id: string; name: string; url: string; locator: string; is_active: boolean
  environment: string; connected_device: boolean; created_at: string; updated_at: string}
const assetRow = (n: number, name: string, url: string): Row => ({id:uuid(n),asset_id:uuid(n),name,url,
  locator:url.replace(/^[a-z]+:\/\//,''),is_active:true,environment:'production',connected_device:false,
  created_at:'2026-01-01',updated_at:'2026-01-01'})
const exactId = uuid(1)
const exactUrl = 'https://corp.example'

/** Subdomains that sort before the apex by name, each a host asset plus its web service. */
function apexInventory(subdomains: number, {withExact = true} = {}): Row[] {
  const rows: Row[] = withExact ? [assetRow(1, 'corp.example', exactUrl)] : []
  // The same host on another port or scheme is another origin, and sorts first.
  rows.push(assetRow(2, 'admin corp.example', 'https://corp.example:8443'), assetRow(3, 'plain corp.example', 'http://corp.example'))
  for (let i = 0; i < subdomains; i++) {
    const host = `app${String(i).padStart(4, '0')}.corp.example`
    rows.push(assetRow(1000 + i, host, `host://${host}`), assetRow(100000 + i, host, `https://${host}`))
  }
  return rows
}

/** The inventory's list/v1 semantics: substring search on name/url, web_only, name order, cursor pages. */
function servePage(rows: Row[], url: URL, {endless = false} = {}) {
  const term = (url.searchParams.get('search') || '').toLowerCase()
  const webOnly = url.searchParams.get('web_only') === 'true'
  const limit = Math.min(200, Number(url.searchParams.get('limit') || 50))
  const start = Number(url.searchParams.get('cursor') || 0)
  const matches = rows
    .filter((item) => !term || item.name.toLowerCase().includes(term) || item.url.toLowerCase().includes(term))
    .filter((item) => !webOnly || /^https?:\/\//.test(item.url))
    .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || a.id.localeCompare(b.id))
  const items = endless
    ? Array.from({length: limit}, (_, i) => assetRow(500000 + start + i, `x${start + i}.corp.example`, `https://x${start + i}.corp.example`))
    : matches.slice(start, start + limit)
  const hasMore = endless || start + limit < matches.length
  return {items, has_more: hasMore, next_cursor: hasMore ? String(start + limit) : null,
    total: null, total_kind: 'none', generated_at: '2026-10-19T00:00:00Z'}
}

type LinkFailure = 'server error' | 'refused cursor' | 'lost connection'

async function routeApex(page: import('@playwright/test').Page, rows: Row[],
  options: {endless?: boolean; failCursorPage?: LinkFailure} = {}) {
  const linkSearches: {cursor: string | null; webOnly: string | null; hasMore: boolean | null}[] = []
  const consumers: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const url = new URL(route.request().url())
    if (url.pathname === '/targets/inventory') {
      const linkSearch = url.searchParams.get('search') === 'corp.example'
      const cursor = url.searchParams.get('cursor')
      if (linkSearch && cursor !== null && options.failCursorPage) {
        linkSearches.push({cursor, webOnly: url.searchParams.get('web_only'), hasMore: null})
        if (options.failCursorPage === 'lost connection') return route.abort('failed')
        if (options.failCursorPage === 'refused cursor') return route.fulfill({status: 400, json: {detail: {
          error: 'invalid_cursor', message: 'the cursor is malformed or was not issued by this server'}}})
        return route.fulfill({status: 500, json: {detail: 'the inventory database is unavailable'}})
      }
      const body = servePage(rows, url, options)
      if (linkSearch) linkSearches.push({cursor, webOnly: url.searchParams.get('web_only'), hasMore: body.has_more})
      return route.fulfill({json: body})
    }
    if (url.pathname === `/targets/${exactId}/asset`) return route.fulfill({json: {target: rows[0], origins: []}})
    if (url.pathname === '/credential-profiles') {
      consumers.push(url.searchParams.get('target_id') || '')
      return route.fulfill({json: {profiles: [], total: 0}})
    }
    return route.fulfill({json: {profiles: [], targets: [], items: [], has_more: false, next_cursor: null, total: 0}})
  })
  return {linkSearches, consumers}
}

/** The distinct link-search cursors in the order they were first read (dev mode runs effects twice). */
const cursorsRead = (searches: {cursor: string | null}[]) => [...new Set(searches.map((search) => search.cursor))]

test('credential URL link finds its exact origin beyond the first search page', async ({page}) => {
  // 300 subdomains: 600 rows (300 web) sort ahead of the apex, so it is not on the first page.
  const rows = apexInventory(300)
  const {linkSearches, consumers} = await routeApex(page, rows)
  await page.goto(`/credentials?${new URLSearchParams({target: `${exactUrl}/`})}`)
  await expect(page.getByLabel('Target', {exact: true})).toHaveAttribute('data-value', exactId)
  await expect(page).toHaveURL(new RegExp(`[?&]target_id=${exactId}`))
  expect(new URL(page.url()).searchParams.get('target')).toBeNull()
  await expect.poll(() => consumers).toContain(exactId)
  // 301 web rows sort ahead of the apex: the second page (from the first page's cursor) holds it,
  // and nothing is read after it.
  expect(cursorsRead(linkSearches), 'the next page is requested with its cursor').toEqual([null, '200'])
  await expect(page.getByText('was not found', {exact: false})).toHaveCount(0)
  await expect(page.getByText('Could not find the linked target', {exact: false})).toHaveCount(0)
})

test('credential URL link reports not found only after every matching page was read', async ({page}) => {
  // 500 subdomains: 502 web rows match the host, three pages of 200.
  const rows = apexInventory(500, {withExact: false})
  const {linkSearches, consumers} = await routeApex(page, rows)
  await page.goto(`/credentials?${new URLSearchParams({target: `${exactUrl}/`})}`)
  await expect(page.getByText(`The linked target ${exactUrl}/ was not found`, {exact: false})).toBeVisible()
  // Every page, in order, each from the cursor of the one before, until the inventory said no more.
  expect(cursorsRead(linkSearches), 'every page was read before "not found"').toEqual([null, '200', '400'])
  expect(linkSearches.every((search) => search.webOnly === 'true')).toBe(true)
  expect(linkSearches.filter((search) => search.cursor === '400').map((search) => search.hasMore)).toContain(false)
  expect(linkSearches.filter((search) => search.cursor !== '400').every((search) => search.hasMore === true)).toBe(true)
  await expect(page.getByLabel('Target', {exact: true})).toHaveAttribute('data-value', '')
  expect(consumers).not.toContain(exactId)
})

test('credential URL link that the bounded search cannot settle says so instead of "not found"', async ({page}) => {
  const {linkSearches} = await routeApex(page, apexInventory(0, {withExact: false}), {endless: true})
  await page.goto(`/credentials?${new URLSearchParams({target: `${exactUrl}/`})}`)
  await expect(page.getByText(`Could not find the linked target ${exactUrl}/ among the first`, {exact: false})).toBeVisible()
  await expect(page.getByText('was not found', {exact: false})).toHaveCount(0)
  await expect(page.getByLabel('Target', {exact: true})).toHaveAttribute('data-value', '')
  // Bounded: the reading stops rather than walking an endless inventory.
  expect(new Set(linkSearches.map((search) => search.cursor)).size).toBeLessThanOrEqual(10)
})

// A page read that fails proves nothing about the target: the page says the search failed and keeps
// the link, instead of claiming the target does not exist.
const failureReasons: Record<LinkFailure, string | null> = {
  'server error': 'the inventory database is unavailable',
  'refused cursor': 'the cursor is malformed or was not issued by this server',
  'lost connection': null,
}
for (const failure of Object.keys(failureReasons) as LinkFailure[]) {
  test(`credential URL link whose search read fails (${failure}) says so instead of "not found"`, async ({page}) => {
    const {linkSearches, consumers} = await routeApex(page, apexInventory(300), {failCursorPage: failure})
    await page.goto(`/credentials?${new URLSearchParams({target: `${exactUrl}/`})}`)
    const notice = page.getByText(`Could not finish searching for the linked target ${exactUrl}/`, {exact: false})
    await expect(notice).toBeVisible()
    const reason = failureReasons[failure]
    if (reason) await expect(notice).toContainText(reason)
    await expect(page.getByText('was not found', {exact: false})).toHaveCount(0)
    await expect(page.getByText('among the first', {exact: false})).toHaveCount(0)
    expect(cursorsRead(linkSearches), 'the failed read was the second page').toEqual([null, '200'])
    await expect(page.getByLabel('Target', {exact: true})).toHaveAttribute('data-value', '')
    // The link stays as it was, so a reload tries again.
    expect(new URL(page.url()).searchParams.get('target')).toBe(`${exactUrl}/`)
    expect(consumers).not.toContain(exactId)
  })
}
