/** Evidence-only network coverage. Tool-stage counts and the final inventory are different populations. */
const record = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {}
const rows = (value) => Array.isArray(value) ? value.map(record) : []
const transportOf = (row) => String(row.transport || 'tcp').toLowerCase()
const TCP_SCOPE_LABELS = {
  all_tcp: 'All 65,535 TCP ports',
  all_65535: 'All 65,535 TCP ports',
  top_100_plus_priority: 'Top 100 + device priority TCP ports',
  top_100: 'Top 100 TCP ports',
}

function count(value) {
  if (typeof value !== 'number' && typeof value !== 'string') return null
  if (typeof value === 'string' && !/^\d+$/.test(value.trim())) return null
  const number = Number(value)
  return Number.isSafeInteger(number) && number >= 0 ? number : null
}

function uniqueServices(value) {
  const result = new Map()
  for (const row of rows(value)) {
    const port = count(row.port)
    const transport = transportOf(row)
    if (port === null || port < 1 || port > 65535 || !['tcp', 'udp'].includes(transport) || row.state !== 'open') continue
    result.set(`${transport}/${port}`, row)
  }
  return [...result.values()]
}

/** Retries describe the same stage, not additional ports. Keep the last attempt. */
function finalReceipts(receipts) {
  const stages = new Map()
  for (const receipt of receipts) {
    const stage = String(receipt.stage || '')
    if (!stage) continue
    const previous = stages.get(stage)
    if (!previous || (count(receipt.attempt) ?? 0) >= (count(previous.attempt) ?? 0)) stages.set(stage, receipt)
  }
  return [...stages.values()]
}

function stateCounts(receipts) {
  const totals = {}
  let recorded = false
  for (const receipt of receipts) {
    for (const [state, value] of Object.entries(record(receipt.port_state_counts))) {
      const number = count(value)
      if (number === null) continue
      totals[state] = (totals[state] || 0) + number
      recorded = true
    }
  }
  return { totals, recorded, total: recorded ? Object.values(totals).reduce((sum, value) => sum + value, 0) : null }
}

/** Numeric port specs are bounded before expansion; a top-N spec is never a port number. */
function numericPorts(spec) {
  if (typeof spec !== 'string' || spec.length > 400000) return null
  const ports = new Set()
  for (const item of spec.split(',')) {
    const match = item.trim().match(/^(\d{1,5})(?:-(\d{1,5}))?$/)
    if (!match) return null
    const first = Number(match[1])
    const last = Number(match[2] || match[1])
    if (first < 1 || last > 65535 || first > last) return null
    for (let port = first; port <= last; port += 1) ports.add(port)
  }
  return ports
}

function tcpCoverage(completeness, receipts, services) {
  const scope = completeness.tcp_scope ? String(completeness.tcp_scope) : null
  const full = ['all_tcp', 'all_65535'].includes(scope)
  const complete = completeness.tcp_discovery_complete === true
  const scopeReceipt = receipts.find((row) => row.stage === 'tcp_scope_discovery')
  const children = finalReceipts([
    ...rows(scopeReceipt?.chunk_receipts),
    ...receipts.filter((row) => row.stage === 'tcp_priority_discovery' || String(row.stage || '').startsWith('tcp_scope_range_') || row.stage === 'tcp_scope_top_100'),
  ])
  const completedPorts = new Set()
  let unknownCompletedScope = false
  for (const receipt of children) {
    if (receipt.complete !== true) continue
    // Naabu's top-N receipt stores "100", not the identities of those 100 ports.
    const ports = receipt.stage === 'tcp_scope_top_100' ? null : numericPorts(receipt.port_spec)
    if (!ports) { unknownCompletedScope = true; continue }
    for (const port of ports) completedPorts.add(port)
  }
  // Legacy aggregate counters count completed batches (including overlapping priority/top-N
  // scopes), not unique examined ports. They cannot be subtracted from the unique inventory.
  const examined = full && complete ? 65535 : null
  const open = services.filter((row) => transportOf(row) === 'tcp').length
  const classified = completeness.tcp_closed_filtered_classification_complete === true && examined !== null
  const filtered = classified ? count(completeness.tcp_filtered_ports_count) : null
  const notOpen = examined !== null && open <= examined ? examined - open : null
  const closed = classified && filtered !== null && notOpen !== null && filtered <= notOpen ? notOpen - filtered : null
  return {
    scope,
    scopeLabel: scope ? (TCP_SCOPE_LABELS[scope] || scope.replace(/_/g, ' ')) : 'TCP ports',
    examined,
    examinedLowerBound: Math.max(completedPorts.size, open),
    required: full ? 65535 : null,
    open,
    notOpen,
    classified: closed !== null,
    closed,
    filtered: closed !== null ? filtered : null,
    complete,
    unknownCompletedScope,
    completedScopePortCount: count(completeness.tcp_completed_required_port_count),
    note: examined === null
      ? 'Exact unique-port examination was not recorded. Confirmed services and completed explicit ranges provide a lower bound; requested scope and overlapping batch counts are not examination totals.'
      : 'Scope completed from this scanner’s network vantage point; an unconfirmed port is not necessarily closed.',
    stages: children.map((row) => ({
      stage: String(row.stage),
      portSpec: typeof row.port_spec === 'string' ? row.port_spec : null,
      complete: row.complete === true,
      attempt: count(row.attempt),
      reasons: Array.isArray(row.incomplete_reasons) ? row.incomplete_reasons.map(String) : [],
    })),
  }
}

export function devicePortCoverage(scan) {
  const posture = record(record(record(scan).result).device_posture)
  const completeness = record(posture.completeness)
  if (!Object.keys(completeness).length) return null
  const receipts = finalReceipts(rows(completeness.tool_receipts))
  const services = uniqueServices(posture.services)
  const tcp = tcpCoverage(completeness, receipts, services)
  const udpReceipts = receipts.filter((row) => row.stage === 'udp_service_discovery')
  let udp = null
  if (udpReceipts.length) {
    const states = stateCounts(udpReceipts)
    const value = (key) => states.recorded ? (states.totals[key] ?? 0) : null
    // Preserve Nmap's original stage rather than combining its no-response count with
    // services promoted by later SSDP/mDNS probes. The final inventory is shown separately.
    udp = {
      basis: 'Nmap UDP discovery stage',
      examined: states.total,
      open: value('open'),
      closed: value('closed'),
      noResponse: value('open|filtered'),
      filtered: value('filtered'),
      other: states.recorded ? Object.entries(states.totals).filter(([state]) => !['open', 'closed', 'open|filtered', 'filtered'].includes(state)).reduce((sum, [, n]) => sum + n, 0) : null,
      confirmedOpen: services.filter((row) => transportOf(row) === 'udp').length,
      requestedPorts: Array.isArray(completeness.udp_ports_requested)
        ? [...new Set(completeness.udp_ports_requested.map(count).filter((port) => port !== null && port > 0 && port <= 65535))].sort((a, b) => a - b)
        : [],
      complete: udpReceipts.every((row) => row.complete === true),
    }
  }
  const fingerprintReceipts = receipts.filter((row) => String(row.stage || '').startsWith('tcp_service_fingerprint_'))
  let fingerprint = null
  if (fingerprintReceipts.length || count(completeness.tcp_fingerprint_truncated_count) > 0) {
    const states = stateCounts(fingerprintReceipts)
    fingerprint = {
      ports: states.total,
      open: states.recorded ? (states.totals.open ?? 0) : null,
      truncated: count(completeness.tcp_fingerprint_truncated_count),
      complete: completeness.tcp_fingerprinting_complete === true,
      stages: fingerprintReceipts.length,
    }
  }
  const tcpServices = services.filter((row) => transportOf(row) === 'tcp')
  const identification = {
    total: tcpServices.length,
    identified: tcpServices.filter((row) => row.product || (row.service_name && !['unknown', 'tcpwrapped'].includes(String(row.service_name).toLowerCase()))).length,
    withVersion: tcpServices.filter((row) => row.version).length,
    basis: 'Final TCP inventory, after all identification methods',
  }
  return { tcp, udp, fingerprint, identification }
}

export function deviceServiceDetails(service) {
  const row = record(service)
  const productVersion = [row.product, row.version].filter(Boolean).map(String).join(' ')
  const name = String(row.service_name || '').toLowerCase()
  return {
    productVersion: productVersion || null,
    extraInfo: row.extra_info ? String(row.extra_info) : null,
    // "Encrypted" alone includes SSH; it is not evidence of TLS.
    tls: ['ssl', 'tls'].includes(String(row.tunnel || '').toLowerCase()) || ['https', 'ssl/http'].includes(name),
    cpe: row.cpe ? String(row.cpe) : null,
    unidentified: !productVersion && ['unknown', 'tcpwrapped', ''].includes(name),
  }
}
