// Pure presentation and input logic for the Targets inventory. No React, no network.

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/
const LOCAL_SUFFIX = /\.(local|internal|localhost|lan|home\.arpa)$/
const MAX_LINES = 50
// Ports that usually serve a web UI; other explicit ports on a device are not assumed to be web.
const WEB_PORTS = new Set([80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443])

/** What an operator typed, read as host, optional scheme, optional port. */
export function parseTargetInput(raw) {
  const text = String(raw ?? '').trim()
  if (!text) return { ok: false, error: 'Enter a domain, URL, IP address or hostname' }
  if (/\s/.test(text)) return { ok: false, error: 'One target per line' }
  let scheme = null
  let rest = text
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text)
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase()
    if (scheme !== 'http' && scheme !== 'https') return { ok: false, error: `Only http:// and https:// are supported, not ${scheme}://` }
    rest = text.slice(schemeMatch[0].length)
  }
  const authority = rest.split(/[/?#]/, 1)[0]
  const path = rest.slice(authority.length)
  if (!authority) return { ok: false, error: 'Missing host' }
  if (authority.includes('@')) return { ok: false, error: 'Remove the user name or password from the address' }
  let host = authority
  let portText = null
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']')
    if (close < 0) return { ok: false, error: 'Close the IPv6 address with ]' }
    host = authority.slice(1, close)
    const after = authority.slice(close + 1)
    if (after) {
      if (!after.startsWith(':')) return { ok: false, error: 'Unexpected text after the IPv6 address' }
      portText = after.slice(1)
    }
  } else if ((authority.match(/:/g) || []).length > 1) {
    host = authority // bare IPv6 without a port
  } else if (authority.includes(':')) {
    ;[host, portText] = authority.split(':')
  }
  host = host.toLowerCase().replace(/\.$/, '')
  let port = null
  if (portText !== null) {
    if (!/^\d{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) {
      return { ok: false, error: 'Ports are numbers from 1 to 65535' }
    }
    port = Number(portText)
  }
  let kind
  if (IPV4.test(host)) kind = 'ipv4'
  else if (host.includes(':')) {
    if (!/^[0-9a-f:.]+$/.test(host)) return { ok: false, error: 'Not a valid IPv6 address' }
    kind = 'ipv6'
  } else {
    if (host.length > 253 || !host.split('.').every(label => LABEL.test(label))) {
      return { ok: false, error: 'Not a valid hostname' }
    }
    kind = !host.includes('.') || LOCAL_SUFFIX.test(host) ? 'local' : 'domain'
  }
  if (scheme && port === (scheme === 'https' ? 443 : 80)) port = null
  const hostText = kind === 'ipv6' ? `[${host}]` : host
  const authorityText = port ? `${hostText}:${port}` : hostText
  return {
    ok: true,
    input: text,
    host,
    kind,
    scheme,
    port,
    pathIgnored: Boolean(path && path !== '/'),
    // Without a scheme the scanner detects HTTP or HTTPS itself on the first scan.
    webUrl: scheme ? `${scheme}://${authorityText}` : authorityText,
    webLabel: scheme ? `${scheme}://${authorityText}` : `${authorityText} · HTTP/HTTPS detected on first scan`,
    // A bare domain is usually a website; an address or LAN name is usually a device.
    webDefault: Boolean(scheme) || kind === 'domain' || (port !== null && WEB_PORTS.has(port)),
  }
}

/** Several targets, one per line (commas also separate), de-duplicated by what they create. */
export function parseTargetLines(raw) {
  const lines = String(raw ?? '').split(/[\n,]+/).map(line => line.trim()).filter(Boolean)
  const seen = new Set()
  const entries = []
  for (const line of lines) {
    const parsed = parseTargetInput(line)
    const key = parsed.ok ? `${parsed.host}|${parsed.scheme || ''}|${parsed.port || ''}` : `!${line}`
    if (seen.has(key)) continue
    seen.add(key)
    entries.push(parsed.ok ? parsed : { ...parsed, input: line })
  }
  return { entries: entries.slice(0, MAX_LINES), truncated: entries.length > MAX_LINES }
}

/** "80, 443 8080" -> [80, 443, 8080]; at most 128 ports. */
export function parsePortList(raw) {
  const parts = String(raw ?? '').split(/[\s,]+/).filter(Boolean)
  const ports = []
  for (const part of parts) {
    if (!/^\d{1,5}$/.test(part) || Number(part) < 1 || Number(part) > 65535) {
      return { ports: [], error: `${part} is not a port from 1 to 65535` }
    }
    if (!ports.includes(Number(part))) ports.push(Number(part))
  }
  if (ports.length > 128) return { ports: [], error: 'Enter at most 128 ports' }
  return { ports, error: null }
}

/** A web app origin as a short chip: scheme, explicit port, TLS. */
export function originLabel(url) {
  const match = /^(https?):\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i.exec(String(url || ''))
  if (!match) return { scheme: null, secure: false, port: null, label: String(url || ''), host: '' }
  const scheme = match[1].toLowerCase()
  const port = match[3] ? Number(match[3]) : scheme === 'https' ? 443 : 80
  return { scheme, secure: scheme === 'https', port, host: match[2].toLowerCase(), label: `${scheme} :${port}` }
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** Non-zero severity counts, most severe first. */
export function severitySummary(counts) {
  const source = counts && typeof counts === 'object' ? counts : {}
  return SEVERITY_ORDER.map(severity => ({ severity, count: Number(source[severity] || 0) }))
    .filter(item => item.count > 0)
}

/** "just now", "5m ago", "3h ago", "2d ago", or a date for anything older than a month. */
export function relativeTime(value, now = Date.now()) {
  if (!value) return null
  const time = new Date(value).getTime()
  if (!Number.isFinite(time)) return null
  const seconds = Math.max(0, Math.round((now - time) / 1000))
  if (seconds < 60) return 'just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  if (days <= 30) return `${days}d ago`
  return new Date(time).toISOString().slice(0, 10)
}

/** Whether an inventory group is a registrable domain (vs an address or LAN host). */
export function isDomainGroup(rootDomain) {
  const value = String(rootDomain || '').toLowerCase()
  if (!value || IPV4.test(value) || value.includes(':') || /^\d+$/.test(value)) return false
  return value.includes('.') && !LOCAL_SUFFIX.test(value)
}

/** Domains first as their own groups; addresses and LAN names gathered into one group. */
export function groupSections(groups) {
  const domains = []
  const network = []
  for (const group of groups || []) {
    if (isDomainGroup(group.root_domain)) domains.push(group)
    else network.push(...(group.targets || []))
  }
  return { domains, network }
}

/** The best grade to show for an asset: its own network grade, else its web apps' latest. */
export function latestGrade(asset) {
  const candidates = [
    { grade: asset?.network_grade, at: asset?.network_last_scanned_at },
    ...((asset?.origins || []).map(origin => ({ grade: origin.last_grade, at: origin.last_scanned_at }))),
  ].filter(item => item.grade && item.at)
  candidates.sort((left, right) => new Date(right.at).getTime() - new Date(left.at).getTime())
  return candidates[0]?.grade || null
}

export const FILTER_KEYS = ['search', 'environment', 'authorization', 'findings', 'activity', 'asset_type', 'sort', 'archived']
export const FILTER_DEFAULTS = { search: '', environment: '', authorization: '', findings: '', activity: '', asset_type: '', sort: 'name', archived: false }
const ALLOWED = {
  authorization: ['authorized', 'unauthorized'],
  findings: ['any', 'critical_high', 'none'],
  activity: ['never', 'scanned', 'scanning'],
  asset_type: ['web', 'network'],
  sort: ['name', 'risk', 'recent', 'created'],
}

/** URL query -> validated filter state (unknown values fall back to defaults). */
export function filtersFromQuery(params) {
  const read = key => (params && typeof params.get === 'function' ? params.get(key) : null) || ''
  const filters = { ...FILTER_DEFAULTS }
  filters.search = read('search').slice(0, 500)
  filters.environment = /^[a-z0-9_-]{1,40}$/.test(read('environment')) ? read('environment') : ''
  for (const [key, values] of Object.entries(ALLOWED)) {
    const value = read(key)
    if (values.includes(value)) filters[key] = value
  }
  // The retired single-type views map onto the one inventory.
  if (!filters.asset_type && ['web', 'network'].includes(read('type'))) filters.asset_type = read('type')
  filters.archived = read('archived') === '1'
  return filters
}

/** Filter state -> query string, omitting defaults so URLs stay short. */
export function queryFromFilters(filters) {
  const params = new URLSearchParams()
  for (const key of FILTER_KEYS) {
    const value = filters[key]
    if (key === 'archived') { if (value) params.set('archived', '1'); continue }
    if (value && value !== FILTER_DEFAULTS[key]) params.set(key, String(value))
  }
  return params.toString()
}

/** Inventory API parameters for a filter state. */
export function inventoryParams(filters, offset, limit) {
  const params = { group_by: 'domain', include_facets: true, offset, limit, sort: filters.sort || 'name' }
  if (filters.search.trim()) params.search = filters.search.trim()
  for (const key of ['environment', 'authorization', 'findings', 'activity', 'asset_type']) {
    if (filters[key]) params[key] = filters[key]
  }
  if (filters.archived) params.include_inactive = true
  return params
}

/** Members per domain group on the Targets page; larger groups say how many are not shown. */
export const INVENTORY_MEMBER_LIMIT = 200

const V1_SORT = { name: 'name', risk: '-risk', recent: '-recent', created: '-created' }

/**
 * One Targets page as list/v1 (keyset `cursor`, `member_limit` members per group, exact group
 * count). The legacy grouping read every asset of the install into the API and returned whole
 * groups: 3.5 s and a 10,000-member group at the 10k-target scale seed.
 */
export function inventoryPageParams(filters, cursor, limit, memberLimit = INVENTORY_MEMBER_LIMIT) {
  const params = { group_by: 'domain', include_facets: true, limit, member_limit: memberLimit,
    sort: V1_SORT[filters.sort] || 'name' }
  if (cursor) params.cursor = cursor
  else params.count = 'exact'
  if (filters.search.trim()) params.search = filters.search.trim()
  for (const key of ['environment', 'authorization', 'findings', 'activity', 'asset_type']) {
    if (filters[key]) params[key] = filters[key]
  }
  if (filters.archived) params.include_inactive = true
  return params
}

/**
 * A Targets page from either answer: list/v1 (`items`, `next_cursor`, groups carrying
 * `member_count` / `members_truncated`) or an older engine's legacy shape.
 */
export function inventoryPageFromBody(body) {
  const item = body && typeof body === 'object' ? body : {}
  if (Array.isArray(item.items)) {
    return {
      groups: item.items.map(group => ({ ...group, targets: Array.isArray(group.targets) ? group.targets : [] })),
      totalGroups: Number.isFinite(item.total) ? item.total : null,
      // Every filtered target (an engine without `target_total` leaves it null).
      targetTotal: Number.isFinite(item.target_total)
        ? { count: item.target_total, kind: item.target_total_kind === 'at_least' ? 'at_least' : 'exact' } : null,
      hasMore: Boolean(item.has_more), nextCursor: item.has_more ? item.next_cursor || null : null,
      facets: item.facets || null, listV1: true,
    }
  }
  const targets = Array.isArray(item.targets) ? item.targets : []
  const groups = Array.isArray(item.groups) ? item.groups : targets.map(asset => ({ root_domain: asset.locator, targets: [asset] }))
  // The legacy `total` counts every filtered asset.
  const targetTotal = Number.isFinite(item.total) ? { count: item.total, kind: 'exact' } : null
  return { groups, totalGroups: item.total_groups ?? item.total ?? groups.length, targetTotal, hasMore: false, nextCursor: null,
    facets: item.facets || null, listV1: false }
}

/**
 * The Targets count to show, with every filter applied. The facets' `total` counts the search
 * scope before the other filters, so it is never used here. Without a server total (an older
 * engine), the loaded groups' `member_count` is summed: the whole answer when every group is on
 * this page, otherwise only this page's targets, and the label says so.
 * Returns `{ count, kind }` with kind `exact`, `at_least` or `page`.
 */
export function inventoryTargetTotal(view, allGroupsLoaded) {
  if (view?.targetTotal) return view.targetTotal
  const count = (view?.groups || []).reduce((sum, group) => sum
    + (Number.isFinite(group.member_count) ? group.member_count : (group.targets || []).length), 0)
  return { count, kind: allGroupsLoaded ? 'exact' : 'page' }
}

/** "1,200 targets", "10,000+ targets" or "40 targets on this page". */
export function targetTotalLabel(total) {
  const count = Number(total?.count) || 0
  const noun = `target${count === 1 && total?.kind !== 'at_least' ? '' : 's'}`
  if (total?.kind === 'at_least') return `${count.toLocaleString('en-US')}+ ${noun}`
  if (total?.kind === 'page') return `${count.toLocaleString('en-US')} ${noun} on this page`
  return `${count.toLocaleString('en-US')} ${noun}`
}

export function activeFilterCount(filters) {
  return ['environment', 'authorization', 'findings', 'activity', 'asset_type'].filter(key => filters[key]).length
    + (filters.archived ? 1 : 0)
}

/** The web addresses a scan of this asset covers: its live web apps, else a bare domain. */
export function scanUrls(asset) {
  const origins = (asset?.origins || []).filter(origin => origin.is_active).map(origin => origin.url)
  if (origins.length) return origins
  const locator = String(asset?.locator || '')
  return isDomainGroup(locator) ? [locator] : []
}

/** POST /scans/batch takes at most this many targets (api.py `_BatchRequestBase.targets`). */
export const SCAN_BATCH_MAX = 50

function uniqueScanTargets(targets) {
  return Array.from(new Set((targets || []).map(target => String(target).trim()).filter(Boolean)))
}

/** New Scan, prefilled with one target or, for several, in batch mode. */
export function configureScanHref(targets, forceBatch = false) {
  const uniqueTargets = uniqueScanTargets(targets)
  const params = new URLSearchParams()
  if (forceBatch || uniqueTargets.length > 1) params.set('targets', uniqueTargets.join('\n'))
  else if (uniqueTargets[0]) params.set('target', uniqueTargets[0])
  return `/scan/new?${params.toString()}`
}

/**
 * New Scan for a whole domain group. Up to one batch of web apps travels in the link; a larger
 * domain is passed by reference (`domain=`), and New Scan reads its web apps from the inventory.
 * Listing every URL made a 450 KB link that the UI server refused (HTTP 431) at 10k targets.
 */
export function domainBatchHref(rootDomain, targets, membersTruncated = false) {
  const uniqueTargets = uniqueScanTargets(targets)
  if (!membersTruncated && uniqueTargets.length <= SCAN_BATCH_MAX) return configureScanHref(uniqueTargets, true)
  return `/scan/new?${new URLSearchParams({ domain: String(rootDomain || '').trim() })}`
}

/**
 * The web apps of `rootDomain` in an inventory answer (group_by=domain), capped at one batch.
 * `total` counts every web app found, so New Scan can say how many were left for later batches.
 */
export function domainBatchTargets(rootDomain, page) {
  const wanted = String(rootDomain || '').trim().toLowerCase()
  const group = inventoryPageFromBody(page).groups.find(item => String(item.root_domain || '').toLowerCase() === wanted)
  if (!group) return { targets: [], total: 0, found: false, moreMembers: false }
  const urls = uniqueScanTargets((group.targets || []).filter(asset => asset.is_active).flatMap(asset => scanUrls(asset)))
  // A list/v1 group lists at most member_limit members; the rest exist but were not read.
  const moreMembers = Boolean(group.members_truncated)
  return { targets: urls.slice(0, SCAN_BATCH_MAX), total: urls.length, found: true, moreMembers,
    memberCount: Number(group.member_count) || (group.targets || []).length }
}

/** Domain-group pages New Scan reads, at most, to find a `domain=` reference (10 groups each). */
export const DOMAIN_LOOKUP_PAGE = 10
export const DOMAIN_LOOKUP_MAX_PAGES = 5

/**
 * Find one domain group by exact name. The inventory search is a substring match, so groups such
 * as `aapp.io` sort before `app.io` and can fill the first page; this follows `next_cursor` until
 * the exact group appears, the matches end, or `maxPages` pages were read.
 * `fetchPage(cursor)` returns one list/v1 answer (`cursor` is null for the first page).
 * `exhausted` is true when every matching group was read, so "not found" is definitive.
 */
export async function findDomainGroup(rootDomain, fetchPage, maxPages = DOMAIN_LOOKUP_MAX_PAGES) {
  let cursor = null
  for (let read = 0; read < maxPages; read += 1) {
    const page = await fetchPage(cursor)
    const resolved = domainBatchTargets(rootDomain, page)
    if (resolved.found) return { ...resolved, exhausted: false }
    cursor = inventoryPageFromBody(page).nextCursor
    if (!cursor) return { ...resolved, exhausted: true }
  }
  return { targets: [], total: 0, found: false, moreMembers: false, exhausted: false }
}

/** Explicit `targets=` beyond one batch are cut to the batch size (the API refuses more). */
export function capBatchTargets(targets) {
  const uniqueTargets = uniqueScanTargets(targets)
  return { targets: uniqueTargets.slice(0, SCAN_BATCH_MAX), total: uniqueTargets.length }
}

export function batchCapNotice(total, source, { memberCount = 0, moreMembers = false } = {}) {
  if (total <= SCAN_BATCH_MAX && !moreMembers) return null
  const size = moreMembers
    ? `${Number(memberCount).toLocaleString('en-US')} targets`
    : `${total.toLocaleString('en-US')} web apps`
  return `${source} has ${size}; a batch scans at most ${SCAN_BATCH_MAX} at once. `
    + `The first ${Math.min(total, SCAN_BATCH_MAX)} are filled in below; queue the rest in further batches.`
}
