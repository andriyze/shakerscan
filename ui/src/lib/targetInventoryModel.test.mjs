import assert from 'node:assert/strict'
import test from 'node:test'

import {
  activeFilterCount, filtersFromQuery, groupSections, inventoryParams, isDomainGroup, latestGrade,
  originLabel, parsePortList, parseTargetInput, parseTargetLines, queryFromFilters, relativeTime,
  severitySummary,
} from './targetInventoryModel.mjs'

test('a bare domain becomes a host and a web app whose scheme is detected on first scan', () => {
  const parsed = parseTargetInput('Example.com.')
  assert.equal(parsed.ok, true)
  assert.deepEqual([parsed.host, parsed.kind, parsed.scheme, parsed.port], ['example.com', 'domain', null, null])
  assert.equal(parsed.webUrl, 'example.com')
  assert.match(parsed.webLabel, /HTTP\/HTTPS detected on first scan/)
  assert.equal(parsed.webDefault, true)
})

test('an explicit URL keeps its scheme and non-default port and drops the path', () => {
  const parsed = parseTargetInput('https://app.example.com:8443/login?next=/')
  assert.deepEqual([parsed.host, parsed.scheme, parsed.port, parsed.pathIgnored], ['app.example.com', 'https', 8443, true])
  assert.equal(parsed.webUrl, 'https://app.example.com:8443')
  assert.equal(parseTargetInput('http://example.com:80').webUrl, 'http://example.com')
  assert.equal(parseTargetInput('https://example.com:443/').pathIgnored, false)
})

test('addresses, ports and LAN names are read without inventing a website', () => {
  const printer = parseTargetInput('printer.local:9100')
  assert.deepEqual([printer.kind, printer.port, printer.webUrl, printer.webDefault], ['local', 9100, 'printer.local:9100', false])
  const ip = parseTargetInput('192.168.1.20')
  assert.deepEqual([ip.kind, ip.webDefault], ['ipv4', false])
  assert.equal(parseTargetInput('192.168.1.20:8080').webDefault, true)
  const v6 = parseTargetInput('[2001:DB8::1]:8443')
  assert.deepEqual([v6.kind, v6.host, v6.port, v6.webUrl], ['ipv6', '2001:db8::1', 8443, '[2001:db8::1]:8443'])
  assert.equal(parseTargetInput('2001:db8::5').kind, 'ipv6')
  assert.equal(parseTargetInput('nas').kind, 'local')
})

test('malformed input explains itself', () => {
  assert.match(parseTargetInput('').error, /Enter/)
  assert.match(parseTargetInput('ftp://example.com').error, /Only http/)
  assert.match(parseTargetInput('example.com:99999').error, /1 to 65535/)
  assert.match(parseTargetInput('https://user:pass@example.com').error, /user name/)
  assert.match(parseTargetInput('exa mple.com').error, /One target/)
  assert.match(parseTargetInput('bad_host.example').error, /hostname/)
  assert.match(parseTargetInput('[2001:db8::1').error, /Close/)
})

test('several lines are split, de-duplicated by what they create, and bounded', () => {
  const { entries } = parseTargetLines('example.com\nexample.com, https://example.com\n\nnot a host\n10.0.0.1')
  assert.deepEqual(entries.map(entry => entry.ok ? entry.webUrl : `!${entry.input}`),
    ['example.com', 'https://example.com', '!not a host', '10.0.0.1'])
  assert.match(entries[2].error, /One target per line/)
  const many = parseTargetLines(Array.from({ length: 60 }, (_, index) => `host${index}.example.com`).join('\n'))
  assert.equal(many.entries.length, 50)
  assert.equal(many.truncated, true)
})

test('port lists accept commas and spaces, reject junk, and de-duplicate', () => {
  assert.deepEqual(parsePortList('80, 443 8080,80'), { ports: [80, 443, 8080], error: null })
  assert.match(parsePortList('80, http').error, /http is not a port/)
  assert.match(parsePortList('0').error, /1 to 65535/)
  assert.deepEqual(parsePortList(''), { ports: [], error: null })
})

test('web app chips show scheme and the effective port', () => {
  assert.deepEqual(originLabel('https://app.example.com'), { scheme: 'https', secure: true, port: 443, host: 'app.example.com', label: 'https :443' })
  assert.equal(originLabel('http://[2001:db8::1]:8080').label, 'http :8080')
  assert.equal(originLabel('host://example.com').scheme, null)
})

test('severity summaries keep non-zero counts in severity order', () => {
  assert.deepEqual(severitySummary({ low: 2, critical: 1, medium: 0 }), [
    { severity: 'critical', count: 1 }, { severity: 'low', count: 2 }])
  assert.deepEqual(severitySummary(null), [])
})

test('relative times are short and stable', () => {
  const now = Date.parse('2026-10-02T12:00:00Z')
  assert.equal(relativeTime('2026-10-02T11:59:30Z', now), 'just now')
  assert.equal(relativeTime('2026-10-02T11:45:00Z', now), '15m ago')
  assert.equal(relativeTime('2026-10-02T09:00:00Z', now), '3h ago')
  assert.equal(relativeTime('2026-09-29T12:00:00Z', now), '3d ago')
  assert.equal(relativeTime('2026-01-02T12:00:00Z', now), '2026-01-02')
  assert.equal(relativeTime(null, now), null)
})

test('domains form groups while addresses and LAN hosts gather into one network group', () => {
  assert.equal(isDomainGroup('example.co.uk'), true)
  for (const value of ['192.0.2.1', '2001:db8::1', 'router.local', 'nas', '2852039166']) assert.equal(isDomainGroup(value), false)
  const sections = groupSections([
    { root_domain: '192.0.2.1', targets: [{ id: 'ip' }] },
    { root_domain: 'example.com', targets: [{ id: 'root' }, { id: 'api' }] },
    { root_domain: 'tv.local', targets: [{ id: 'tv' }] },
  ])
  assert.deepEqual(sections.domains.map(group => group.root_domain), ['example.com'])
  assert.deepEqual(sections.network.map(asset => asset.id), ['ip', 'tv'])
})

test('the newest scan grade wins across the network view and web apps', () => {
  assert.equal(latestGrade({ network_grade: 'C', network_last_scanned_at: '2026-10-01T00:00:00Z',
    origins: [{ last_grade: 'A', last_scanned_at: '2026-10-02T00:00:00Z' }] }), 'A')
  assert.equal(latestGrade({ origins: [] }), null)
})

test('filters round-trip through the URL and drop unknown values', () => {
  const filters = filtersFromQuery(new URLSearchParams('search=api&authorization=authorized&findings=bogus&sort=risk&archived=1&type=network'))
  assert.deepEqual(filters, { search: 'api', environment: '', authorization: 'authorized', findings: '', activity: '',
    asset_type: 'network', sort: 'risk', archived: true })
  assert.equal(queryFromFilters(filters), 'search=api&authorization=authorized&asset_type=network&sort=risk&archived=1')
  assert.equal(queryFromFilters(filtersFromQuery(new URLSearchParams(''))), '')
  assert.equal(activeFilterCount(filters), 3)
  assert.deepEqual(inventoryParams(filters, 50, 25), { group_by: 'domain', include_facets: true, offset: 50, limit: 25,
    sort: 'risk', search: 'api', authorization: 'authorized', asset_type: 'network', include_inactive: true })
})

test('a scan covers live web apps, else a bare domain, and New Scan opens prefilled', async () => {
  const { configureScanHref, scanUrls } = await import('./targetInventoryModel.mjs')
  assert.deepEqual(scanUrls({ locator: 'example.com', origins: [
    { url: 'https://example.com', is_active: true }, { url: 'http://example.com:8080', is_active: false }] }), ['https://example.com'])
  assert.deepEqual(scanUrls({ locator: 'example.com', origins: [] }), ['example.com'])
  assert.deepEqual(scanUrls({ locator: '192.0.2.1', origins: [] }), [])
  assert.equal(configureScanHref(['https://example.com']), '/scan/new?target=https%3A%2F%2Fexample.com')
  assert.equal(configureScanHref(['a.example.com', 'b.example.com', 'a.example.com']), '/scan/new?targets=a.example.com%0Ab.example.com')
  assert.equal(configureScanHref(['only.example.com'], true), '/scan/new?targets=only.example.com')
})

// UI audit 2.11 #2: at 10k targets a domain's "Customize batch" link listed every URL (450 KB) and
// /scan/new answered HTTP 431. A large domain now travels by reference and New Scan reads it.
test('a large domain group opens New Scan by reference, capped at one batch', async () => {
  const { SCAN_BATCH_MAX, batchCapNotice, capBatchTargets, domainBatchHref, domainBatchTargets } = await import('./targetInventoryModel.mjs')
  assert.equal(SCAN_BATCH_MAX, 50)
  const small = ['https://a.example.com', 'https://b.example.com']
  assert.equal(domainBatchHref('example.com', small), '/scan/new?targets=https%3A%2F%2Fa.example.com%0Ahttps%3A%2F%2Fb.example.com')
  const many = Array.from({ length: 10_000 }, (_, i) => `https://app-${String(i).padStart(5, '0')}.scale-seed.invalid`)
  const href = domainBatchHref('scale-seed.invalid', many)
  assert.equal(href, '/scan/new?domain=scale-seed.invalid')
  assert.ok(href.length < 100)
  // At exactly one batch the URLs still travel in the link (well under any header limit).
  assert.ok(domainBatchHref('scale-seed.invalid', many.slice(0, 50)).startsWith('/scan/new?targets='))

  const page = { groups: [
    { root_domain: 'other.invalid', targets: [{ is_active: true, locator: 'x.other.invalid', origins: [{ url: 'https://x.other.invalid', is_active: true }] }] },
    { root_domain: 'Scale-Seed.invalid', targets: [
      ...many.slice(0, 120).map(url => ({ is_active: true, locator: new URL(url).host, origins: [{ url, is_active: true }] })),
      { is_active: false, locator: 'gone.scale-seed.invalid', origins: [{ url: 'https://gone.scale-seed.invalid', is_active: true }] },
    ] },
  ] }
  const resolved = domainBatchTargets('scale-seed.invalid', page)
  assert.equal(resolved.found, true)
  assert.equal(resolved.total, 120)
  assert.equal(resolved.targets.length, 50)
  assert.ok(!resolved.targets.includes('https://gone.scale-seed.invalid'))
  assert.deepEqual(domainBatchTargets('missing.invalid', page), { targets: [], total: 0, found: false, moreMembers: false })
  assert.match(batchCapNotice(120, 'scale-seed.invalid'), /120 web apps; a batch scans at most 50 at once\. The first 50 are filled in/)
  assert.equal(batchCapNotice(50, 'x'), null)
  assert.deepEqual(capBatchTargets([...many.slice(0, 60), many[0]]), { targets: many.slice(0, 50), total: 60 })
})

// UI audit 2.11 #12: /targets took 4.1-4.5 s at 10k targets because the legacy grouping read every
// asset and returned whole groups (one of 10,000 members). The page now reads list/v1 pages.
test('the Targets page reads list/v1 group pages with a member cap, and still reads a legacy answer', async () => {
  const { INVENTORY_MEMBER_LIMIT, inventoryPageFromBody, inventoryPageParams, filtersFromQuery } = await import('./targetInventoryModel.mjs')
  const filters = filtersFromQuery(new URLSearchParams('search=api&sort=risk&archived=1&findings=critical_high'))
  assert.deepEqual(inventoryPageParams(filters, null, 40), { group_by: 'domain', include_facets: true, limit: 40,
    member_limit: INVENTORY_MEMBER_LIMIT, sort: '-risk', count: 'exact', search: 'api', findings: 'critical_high', include_inactive: true })
  const next = inventoryPageParams(filtersFromQuery(new URLSearchParams('')), 'c2', 40)
  assert.equal(next.cursor, 'c2')
  assert.equal(next.count, undefined, 'a later page carries the cursor, not a recount')
  assert.equal(next.sort, 'name')
  assert.equal(next.offset, undefined)

  const v1 = inventoryPageFromBody({ items: [{ root_domain: 'scale-seed.invalid', targets: [{ id: 'a' }], member_count: 10000, members_truncated: true }],
    has_more: true, next_cursor: 'c2', total: 3, facets: { total: 10002 } })
  assert.equal(v1.listV1, true)
  assert.equal(v1.totalGroups, 3)
  assert.equal(v1.nextCursor, 'c2')
  assert.equal(v1.groups[0].member_count, 10000)
  assert.equal(v1.facets.total, 10002)
  assert.equal(inventoryPageFromBody({ items: [], has_more: false, next_cursor: 'stale' }).nextCursor, null)

  const legacy = inventoryPageFromBody({ targets: [{ id: 'a', locator: 'a.example' }], groups: [{ root_domain: 'example', targets: [] }], total: 1, total_groups: 1 })
  assert.deepEqual([legacy.listV1, legacy.totalGroups, legacy.hasMore, legacy.groups.length], [false, 1, false, 1])
  const flat = inventoryPageFromBody({ targets: [{ id: 'a', locator: 'a.example' }], total: 1 })
  assert.deepEqual(flat.groups, [{ root_domain: 'a.example', targets: [{ id: 'a', locator: 'a.example' }] }])
})

test('a domain group loaded in part always opens New Scan by reference', async () => {
  const { domainBatchHref, domainBatchTargets, batchCapNotice } = await import('./targetInventoryModel.mjs')
  assert.equal(domainBatchHref('scale-seed.invalid', ['https://a.scale-seed.invalid', 'https://b.scale-seed.invalid'], true), '/scan/new?domain=scale-seed.invalid')
  const page = { items: [{ root_domain: 'scale-seed.invalid', member_count: 10000, members_truncated: true,
    targets: Array.from({ length: 200 }, (_, i) => ({ is_active: true, locator: `app-${i}.scale-seed.invalid`, origins: [{ url: `https://app-${i}.scale-seed.invalid`, is_active: true }] })) }], has_more: false }
  const resolved = domainBatchTargets('scale-seed.invalid', page)
  assert.deepEqual([resolved.targets.length, resolved.total, resolved.moreMembers, resolved.memberCount], [50, 200, true, 10000])
  assert.equal(batchCapNotice(resolved.total, 'scale-seed.invalid', resolved),
    'scale-seed.invalid has 10,000 targets; a batch scans at most 50 at once. The first 50 are filled in below; queue the rest in further batches.')
})

// Review of the 2.11 audit fixes: the Targets count said "1,200 targets in 3 groups" under
// authorization=unauthorized because it read the facets' total (the search scope only).
test('the Targets count applies every filter, never the facets\' search-scope total', async () => {
  const { inventoryPageFromBody, inventoryTargetTotal, targetTotalLabel } = await import('./targetInventoryModel.mjs')
  const groups = [{ root_domain: 'a.invalid', targets: [{ id: '1' }], member_count: 2 }, { root_domain: 'b.invalid', targets: [{ id: '2' }], member_count: 1 }]
  const served = inventoryPageFromBody({ items: groups, has_more: false, total: 2, target_total: 3, target_total_kind: 'exact', facets: { total: 1200 } })
  assert.deepEqual(inventoryTargetTotal(served, true), { count: 3, kind: 'exact' })
  assert.equal(targetTotalLabel(inventoryTargetTotal(served, true)), '3 targets')
  const capped = inventoryPageFromBody({ items: groups, has_more: true, next_cursor: 'c', total: 2, target_total: 10000, target_total_kind: 'at_least' })
  assert.equal(targetTotalLabel(inventoryTargetTotal(capped, false)), '10,000+ targets')
  // An engine without target_total: the loaded groups' member counts, labelled when partial.
  const older = inventoryPageFromBody({ items: groups, has_more: false, total: 2, facets: { total: 1200 } })
  assert.equal(older.targetTotal, null)
  assert.deepEqual(inventoryTargetTotal(older, true), { count: 3, kind: 'exact' })
  assert.equal(targetTotalLabel(inventoryTargetTotal(older, false)), '3 targets on this page')
  assert.equal(targetTotalLabel({ count: 1, kind: 'exact' }), '1 target')
  // The legacy answer's total is already filtered.
  assert.deepEqual(inventoryPageFromBody({ targets: [], groups: [], total: 7, total_groups: 2 }).targetTotal, { count: 7, kind: 'exact' })
})
