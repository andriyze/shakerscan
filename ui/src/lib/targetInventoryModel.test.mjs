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
