import { expect, test } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const hosts = ['example.test', 'api.example.test', 'tv.example.test', '192.0.2.10', '2001:db8::1']
const targets = hosts.map((locator, index) => ({ id: `00000000-0000-4000-8000-${String(index + 400).padStart(12,'0')}`,
  asset_id: `00000000-0000-4000-8000-${String(index + 400).padStart(12,'0')}`, name: locator,
  locator, url: `host://${locator}`, root_domain: locator.includes('example.test') ? 'example.test' : locator,
  is_active: true, environment: 'lab', connected_device: false, origin_count: index === 1 ? 2 : 0, service_count: 0, active_findings_count: 0 }))

test('HIERARCHY-001 root domains expand to subdomains while IPv4 and IPv6 stay independent', async ({page}) => {
  await pinMockApiOrigin(page)
  let writes = 0
  await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
    const request = route.request(), url = new URL(request.url())
    if (!['GET','OPTIONS'].includes(request.method())) writes++
    if (url.pathname === '/targets/inventory') {
      expect(url.searchParams.get('group_by')).toBe('domain')
      const search = url.searchParams.get('search') || ''
      const matching = targets.filter(target => !search || target.locator.includes(search))
      const domains = [...new Set(matching.map(target => target.root_domain))]
      return route.fulfill({json:{targets:matching,total:matching.length,total_groups:domains.length,
        groups:domains.map(root_domain => ({root_domain,targets:matching.filter(target => target.root_domain===root_domain)}))}})
    }
    return route.fulfill({json:{status:'healthy',skill:null,revision:0,targets:[],total:0}})
  })
  await page.goto('/targets')
  // Registrable domains group their subdomains; addresses gather in one network group.
  await expect(page.getByTestId('target-domain-group')).toHaveCount(1)
  await expect(page.getByTestId('target-network-group')).toHaveCount(1)
  // Domain discovery lives in the domain group's menu; addresses offer no discovery at all.
  await page.getByRole('button',{name:'Actions for example.test',exact:true}).click()
  await expect(page.getByRole('menuitem',{name:'Discover subdomains of example.test',exact:true})).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menuitem',{name:/Discover subdomains of (192|2001)/,includeHidden:true})).toHaveCount(0)
  await expect(page.getByRole('link',{name:'192.0.2.10',exact:true})).toBeVisible()
  await expect(page.getByRole('link',{name:'2001:db8::1',exact:true})).toBeVisible()
  const domain = page.getByRole('button',{name:'Subdomains of example.test',exact:true})
  // A small group opens with its subdomains visible; collapsing hides them.
  await expect(domain).toHaveAttribute('aria-expanded','true')
  await expect(page.getByRole('link',{name:'api.example.test',exact:true})).toHaveAttribute('href',`/targets/${targets[1].id}/asset`)
  await domain.click()
  await expect(domain).toHaveAttribute('aria-expanded','false')
  await expect(page.getByRole('link',{name:'api.example.test',exact:true})).toHaveCount(0)
  await domain.click()
  await expect(page.getByRole('link',{name:'tv.example.test',exact:true})).toBeVisible()
  await expect(page.getByTestId('target-asset-row')).toHaveCount(5)
  await page.getByRole('button',{name:'More actions for api.example.test'}).click()
  await expect(page.getByRole('menuitem',{name:'Create instructions for api.example.test'})).toBeVisible()
  await expect(page.getByRole('menuitem',{name:/^Network scan/})).toBeVisible()
  await page.keyboard.press('Escape')
  await page.getByLabel('Search targets by URL or domain').fill('api.example.test')
  await expect(page.getByRole('link',{name:'api.example.test',exact:true})).toBeVisible()
  await expect(page.getByTestId('target-domain-group')).toHaveCount(1)
  expect(writes).toBe(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false)
})

for (const locator of ['new.example.test','192.0.2.40','2001:db8::40']) {
  test(`HIERARCHY-002 add ${locator} without assuming HTTP`, async ({page}) => {
    await pinMockApiOrigin(page)
    let submitted: Record<string,unknown> = {}
    const web: Array<Record<string,unknown>> = []
    const id = targets[0].id
    await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/targets/hosts') {
        submitted = route.request().postDataJSON()
        return route.fulfill({json:{id,status:'created'}})
      }
      if (path === '/targets' && route.request().method() === 'POST') {
        const body = route.request().postDataJSON()
        web.push(body)
        return route.fulfill({json:{id:'00000000-0000-4000-8000-000000000498',url:`https://${body.url}`}})
      }
      if (path === `/targets/${id}/asset`) return route.fulfill({json:{target:{...targets[0],locator,name:locator},origins:[],services:[],credentials:[],request_collections:[],history:{items:[],total:0},active_findings:{}}})
      return route.fulfill({json:{targets:[],groups:[],total:0,total_groups:0,skill:null,revision:0,items:[]}})
    })
    await page.goto('/targets')
    await page.getByRole('button',{name:'Add targets',exact:true}).first().click()
    const dialog = page.getByRole('dialog',{name:'Add targets'})
    await dialog.getByLabel('What do you want to test?').fill(locator)
    await dialog.getByLabel('Extra ports to check (optional)').fill('22, 8443')
    await page.getByRole('button',{name:'Add target',exact:true}).click()
    await expect(dialog.getByText('Added',{exact:true})).toBeVisible()
    await expect(dialog.getByRole('link',{name:'Open'})).toHaveAttribute('href',`/targets/${id}/asset`)
    expect(submitted).toMatchObject({locator,port_hints:[22,8443]})
    // HTTP is never assumed: a domain's web app is registered without a scheme for the first
    // scan to detect, and a bare address registers no web app at all.
    expect(web).toEqual(locator.includes('example') ? [{url:locator,cohort:'production'}] : [])
  })
}

test('HIERARCHY-003 root-domain discovery tracks completion and reveals new canonical targets', async ({page}) => {
  await pinMockApiOrigin(page)
  let completed = false
  const submitted: string[] = []
  const found = {...targets[1],id:'00000000-0000-4000-8000-000000000499',locator:'new.example.test',name:'new.example.test'}
  await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
    const request=route.request(),url=new URL(request.url())
    if (url.pathname === '/discovery' && request.method() === 'POST') {
      submitted.push(url.searchParams.get('root_domain') || '')
      return route.fulfill({json:{discovery_id:'discovery-fixture',status:'pending'}})
    }
    if (url.pathname === '/discovery/discovery-fixture') {
      completed=true
      return route.fulfill({json:{id:'discovery-fixture',root_domain:'example.test',status:'completed',subdomains_found:1,new_subdomains:1,resolution:{added:1,unresolved_count:0}}})
    }
    if (url.pathname === '/targets/inventory') {
      const members = completed ? [targets[0],targets[1],found] : [targets[0],targets[1]]
      return route.fulfill({json:{targets:members,groups:[{root_domain:'example.test',targets:members}],total:members.length,total_groups:1}})
    }
    return route.fulfill({json:{status:'healthy',skill:null,revision:0,targets:[],total:0}})
  })
  await page.goto('/targets')
  const actions=page.getByRole('button',{name:'Actions for example.test',exact:true})
  const discover=page.getByRole('menuitem',{name:'Discover subdomains of example.test',exact:true})
  await actions.click()
  await discover.click()
  // The menu closes on selection; reopened, it shows the running discovery as unavailable.
  await actions.click()
  await expect(discover).toBeDisabled()
  await page.keyboard.press('Escape')
  await expect(page.getByText(/Subdomain discovery started for example.test/)).toBeVisible()
  await expect(page.getByRole('link',{name:'new.example.test',exact:true})).toBeVisible({timeout:10_000})
  await expect(page.getByText(/1 new target added/)).toBeVisible()
  await actions.click()
  await expect(discover).toBeEnabled()
  expect(submitted).toEqual(['example.test'])
})

test('HIERARCHY-004 discovery refusal reports the server reason and re-enables the root action', async ({page}) => {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`,async route => {
    const url=new URL(route.request().url())
    if (url.pathname === '/discovery') return route.fulfill({status:403,json:{detail:'Discovery is disabled by the operator'}})
    if (url.pathname === '/targets/inventory') return route.fulfill({json:{targets:[targets[0]],groups:[{root_domain:'example.test',targets:[targets[0]]}],total:1,total_groups:1}})
    return route.fulfill({json:{status:'healthy',skill:null,revision:0,targets:[],total:0}})
  })
  await page.goto('/targets')
  // A root domain without subdomains carries discovery in its own menu.
  const menu=page.getByRole('button',{name:'More actions for example.test'})
  await menu.click()
  await page.getByRole('menuitem',{name:'Discover subdomains of example.test',exact:true}).click()
  await expect(page.getByText('Discovery is disabled by the operator',{exact:true})).toBeVisible()
  await menu.click()
  await expect(page.getByRole('menuitem',{name:'Discover subdomains of example.test',exact:true})).toBeEnabled()
})
