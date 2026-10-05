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
  return { confirmed, unconfirmed, notObservedCount }
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
