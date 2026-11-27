import assert from 'node:assert/strict'
import test from 'node:test'
import { devicePortCoverage, deviceServiceDetails } from '../src/lib/networkScanCoverage.mjs'
const scan = (completeness, services = []) => ({ result: { device_posture: { completeness, services } } })
const tcp = (port, extra = {}) => ({ transport: 'tcp', state: 'open', port, service_name: 'unknown', ...extra })
const udp = (port, extra = {}) => ({ transport: 'udp', state: 'open', port, service_name: 'unknown', ...extra })

test('no device completeness means no coverage', () => {
  assert.equal(devicePortCoverage(null), null)
  assert.equal(devicePortCoverage({ result: { findings: [] } }), null)
})
test('full completed scope has an exact unique denominator, not a false closed count', () => {
  const { tcp: result } = devicePortCoverage(scan({ tcp_scope: 'all_tcp', tcp_discovery_complete: true }, [tcp(22), tcp(443)]))
  assert.equal(result.examined, 65535)
  assert.equal(result.notOpen, 65533)
  assert.equal(result.closed, null)
  assert.equal(result.filtered, null)
})
test('priority and top-N batch counts are not unique examined port counts', () => {
  const { tcp: result } = devicePortCoverage(scan({
    tcp_scope: 'top_100_plus_priority', tcp_discovery_complete: true,
    tcp_required_port_count: 140, tcp_completed_required_port_count: 140,
    tool_receipts: [
      { stage: 'tcp_priority_discovery', complete: true, port_spec: '22,80,443' },
      { stage: 'tcp_scope_top_100', complete: true, port_spec: '100' },
    ],
  }, [tcp(22)]))
  assert.equal(result.examined, null)
  assert.equal(result.required, null)
  assert.equal(result.notOpen, null)
  assert.equal(result.examinedLowerBound, 3)
  assert.equal(result.unknownCompletedScope, true)
})
test('partial scan preserves open evidence without pretending that zero ports were examined', () => {
  const { tcp: result } = devicePortCoverage(scan({
    tcp_scope: 'all_tcp', tcp_discovery_complete: false,
    tcp_completed_required_port_count: 0, tcp_required_port_count: 65535,
    tool_receipts: [{ stage: 'tcp_priority_discovery', complete: true, port_spec: '22,443' }],
  }, [tcp(22), tcp(443)]))
  assert.equal(result.examined, null)
  assert.equal(result.examinedLowerBound, 2)
  assert.equal(result.open, 2)
  assert.equal(result.complete, false)
})
test('completed explicit ranges are deduplicated across priority scopes and retries', () => {
  const receipts = [
    { stage: 'tcp_priority_discovery', complete: true, port_spec: '22,80,443' },
    { stage: 'tcp_scope_range_1_of_8', attempt: 1, complete: false, port_spec: '1-8192' },
    { stage: 'tcp_scope_range_1_of_8', attempt: 2, complete: true, port_spec: '1-8192' },
  ]
  const { tcp: result } = devicePortCoverage(scan({ tcp_scope: 'all_tcp', tool_receipts: [
    ...receipts, { stage: 'tcp_scope_discovery', chunk_receipts: receipts },
  ] }))
  assert.equal(result.examinedLowerBound, 8192)
  assert.equal(result.stages.length, 2)
})
test('null, booleans, blanks and fractional counts remain unknown', () => {
  for (const invalid of [null, undefined, false, true, '', ' ', [], {}, 1.5, -1]) {
    const result = devicePortCoverage(scan({ tcp_scope: 'all_tcp', tcp_completed_required_port_count: invalid, tcp_required_port_count: 65535 }))
    assert.equal(result.tcp.examined, null)
    assert.equal(result.tcp.completedScopePortCount, null)
  }
})
test('UDP promotion does not add final inventory counts to original no-response counts', () => {
  const result = devicePortCoverage(scan({ tool_receipts: [{
    stage: 'udp_service_discovery', complete: true,
    port_state_counts: { closed: 7, 'open|filtered': 1 },
  }] }, [udp(1900, { service_name: 'upnp' })]))
  assert.deepEqual([result.udp.examined, result.udp.open, result.udp.closed, result.udp.noResponse], [8, 0, 7, 1])
  assert.equal(result.udp.confirmedOpen, 1)
  assert.equal(result.udp.basis, 'Nmap UDP discovery stage')
})
test('missing UDP evidence is unknown, not zero; requested ports are validated and deduplicated', () => {
  const result = devicePortCoverage(scan({ udp_ports_requested: [53, '53', 1900, null, true, 0, 65536], tool_receipts: [{ stage: 'udp_service_discovery', complete: false }] }))
  assert.equal(result.udp.examined, null)
  assert.equal(result.udp.open, null)
  assert.equal(result.udp.closed, null)
  assert.equal(result.udp.noResponse, null)
  assert.deepEqual(result.udp.requestedPorts, [53, 1900])
})
test('fingerprint failure and successful HTTP detection are distinct outcomes', () => {
  const result = devicePortCoverage(scan({
    tcp_fingerprinting_complete: false,
    tool_receipts: [{ stage: 'tcp_service_fingerprint_1', complete: false, port_state_counts: {} }],
  }, [tcp(8080, { service_name: 'http' })]))
  assert.equal(result.fingerprint.ports, null)
  assert.equal(result.fingerprint.complete, false)
  assert.equal(result.identification.identified, 1)
  assert.equal(result.fingerprint.identified, undefined)
})
test('fingerprinting counts returned states independently of final identified services', () => {
  const result = devicePortCoverage(scan({
    tcp_fingerprinting_complete: true, tcp_fingerprint_truncated_count: 0,
    tool_receipts: [{ stage: 'tcp_service_fingerprint_1', complete: true, port_state_counts: { open: 1, closed: 1 } }],
  }, [tcp(22, { service_name: 'ssh', product: 'OpenSSH', version: '9.6' }), tcp(8080, { service_name: 'http' })]))
  assert.equal(result.fingerprint.ports, 2)
  assert.equal(result.fingerprint.open, 1)
  assert.equal(result.identification.identified, 2)
  assert.equal(result.identification.withVersion, 1)
})
test('invalid services and duplicate ports cannot inflate observed open counts', () => {
  const result = devicePortCoverage(scan({ tcp_scope: 'all_tcp' }, [tcp(22), tcp(22), tcp(0), tcp(65536), tcp(443, { state: 'filtered' }), tcp(80, { state: undefined })]))
  assert.equal(result.tcp.open, 1)
})
test('TLS must not be inferred from an encrypted non-TLS protocol', () => {
  assert.equal(deviceServiceDetails({ service_name: 'ssh', encrypted: true }).tls, false)
  assert.equal(deviceServiceDetails({ service_name: 'http', tunnel: 'ssl' }).tls, true)
  assert.equal(deviceServiceDetails({ service_name: 'https' }).tls, true)
  assert.equal(deviceServiceDetails({ service_name: 'tcpwrapped' }).unidentified, true)
})
test('invalid and out-of-range port specifications never create examined coverage', () => {
  for (const port_spec of ['0-65535', '65536', '8192-1', '22;touch /tmp/x', '1-999999999']) {
    const result = devicePortCoverage(scan({ tool_receipts: [{ stage: 'tcp_priority_discovery', port_spec, complete: true }] }))
    assert.equal(result.tcp.examinedLowerBound, 0)
  }
})
test('UDP retries are not additional examined ports', () => {
  const result = devicePortCoverage(scan({ tool_receipts: [
    { stage: 'udp_service_discovery', attempt: 1, complete: false, port_state_counts: { open: 1 } },
    { stage: 'udp_service_discovery', attempt: 2, complete: true, port_state_counts: { open: 1, closed: 7 } },
  ] }))
  assert.equal(result.udp.examined, 8)
})
