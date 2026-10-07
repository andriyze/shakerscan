/**
 * Classify retained service knowledge the way the API does
 * (api/exposure/service_inventory.py `presence`): only a port a probe saw
 * answer is a discovered port. An nmap `open|filtered` result means no reply
 * was received, so it is an unconfirmed probe, never a service to Hunt.
 */
export function presenceOf(service) {
  if (typeof service?.presence === 'string' && service.presence) return service.presence
  const state = String(service?.state || 'unknown').toLowerCase()
  if (state === 'open') return 'observed_open'
  if (state === 'open|filtered' || state === 'unknown') return 'inconclusive'
  return 'not_observed'
}

/**
 * One row per port. A Hunt and a network scan each retain their own record of the same service,
 * so 22/tcp was listed twice (once attributed to an address, once "Address unattributed"). Records
 * of one transport/port merge when they name the same address, or when one names none and the
 * port was seen at only one address; their evidence is kept together.
 */
function mergeSamePort(records) {
  const byPort = new Map()
  for (const record of records) {
    const key = `${String(record.transport || '').toLowerCase()}/${record.port}`
    if (!byPort.has(key)) byPort.set(key, [])
    byPort.get(key).push(record)
  }
  const merged = []
  for (const group of byPort.values()) {
    const addresses = [...new Set(group.map((item) => item.address).filter(Boolean))]
    const rows = new Map()
    for (const record of group) {
      const address = record.address || (addresses.length === 1 ? addresses[0] : '')
      const existing = rows.get(address)
      if (!existing) {
        rows.set(address, { ...record, address: address || record.address, evidence: [...(record.evidence || [])] })
        continue
      }
      existing.evidence.push(...(record.evidence || []))
      existing.service ||= record.service
      existing.application_origin ||= record.application_origin
      // A current binding from either record keeps the row investigable.
      if (existing.binding_status === 'historical_locator' && record.binding_status !== 'historical_locator') {
        existing.binding_status = record.binding_status
      }
    }
    merged.push(...rows.values())
  }
  return merged
}

/** Split records into confirmed ports, unconfirmed probes and a count of closed/filtered ones. */
export function partitionSharedServices(services) {
  const confirmed = []
  const unconfirmed = []
  let notObservedCount = 0
  for (const service of Array.isArray(services) ? services : []) {
    const presence = presenceOf(service)
    if (presence === 'observed_open') confirmed.push(service)
    else if (presence === 'inconclusive') unconfirmed.push(service)
    else notObservedCount += 1
  }
  // A port another probe saw answer is confirmed; a no-reply record of it is not a second entry.
  const open = new Set(confirmed.map((item) => `${String(item.transport || '').toLowerCase()}/${item.port}`))
  const pending = unconfirmed.filter((item) => !open.has(`${String(item.transport || '').toLowerCase()}/${item.port}`))
  return { confirmed: mergeSamePort(confirmed), unconfirmed: mergeSamePort(pending), notObservedCount }
}

/** Hunt link for a confirmed open port at a current address; null otherwise. */
export function sharedServiceHuntHref(service, targetId) {
  if (presenceOf(service) !== 'observed_open' || service?.binding_status === 'historical_locator') return null
  const params = new URLSearchParams({
    target: targetId,
    objective: `Investigate observed ${service.transport}/${service.port} on this target. Query existing service evidence before executing capabilities.`,
  })
  return `/hunt?${params}`
}
