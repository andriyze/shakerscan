/** Reuse the target's retained TCP knowledge when opening a network scan. */
export function networkScanTcpHints(detail) {
  const ports = new Set()
  const add = port => {
    if (Number.isInteger(port) && port >= 1 && port <= 65535) ports.add(port)
  }
  const savedHints = detail?.device?.metadata_json?.port_hints
  for (const port of Array.isArray(savedHints) ? savedHints : []) add(port)
  for (const service of [...(detail?.services || []), ...(detail?.service_intelligence?.services || [])]) {
    if (!service || typeof service !== 'object') continue
    if (String(service.transport || 'tcp').toLowerCase() !== 'tcp') continue
    if (service.binding_status === 'historical_locator') continue
    if (service.state && service.state !== 'open') continue
    add(service.port)
  }
  return [...ports].sort((left, right) => left - right).slice(0, 128).join(', ')
}
