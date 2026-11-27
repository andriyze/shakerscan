import assert from 'node:assert/strict'
import test from 'node:test'

import { devicePortCoverage, deviceServiceDetails } from '../src/lib/deviceScanPresentation.mjs'

function scanWith(posture) {
  return { id: 'scan-1', result: { device_posture: posture } }
}

const openTcp = (port, extra = {}) => ({ transport: 'tcp', port, state: 'open', service_name: 'http', ...extra })

test('overlapping batch counters are not a unique examination total', () => {
  const coverage = devicePortCoverage(scanWith({
    services: [openTcp(80), openTcp(443), openTcp(8080)],
    completeness: {
      tcp_scope: 'top_100_plus_priority',
      tcp_required_port_count: 130,
      tcp_completed_required_port_count: 130,
      tcp_closed_filtered_classification_complete: false,
      tcp_discovery_complete: true,
      tool_receipts: [{ stage: 'tcp_scope_discovery', port_state_counts: { open: 3 } }],
    },
  }))
  assert.equal(coverage.tcp.scopeLabel, 'Top 100 + device priority TCP ports')
  assert.deepEqual(
    [coverage.tcp.examined, coverage.tcp.open, coverage.tcp.notOpen, coverage.tcp.closed, coverage.tcp.filtered],
    [null, 3, null, null, null],
  )
  assert.equal(coverage.tcp.complete, true)
})

test('a classified scan separates closed from filtered', () => {
  const coverage = devicePortCoverage(scanWith({
    services: [openTcp(22, { service_name: 'ssh' }), openTcp(443)],
    completeness: {
      tcp_scope: 'all_tcp',
      tcp_discovery_complete: true,
      tcp_required_port_count: 65535,
      tcp_completed_required_port_count: 65535,
      tcp_closed_filtered_classification_complete: true,
      tcp_filtered_ports_count: 10,
      tool_receipts: [],
    },
  }))
  assert.equal(coverage.tcp.scopeLabel, 'All 65,535 TCP ports')
  assert.deepEqual([coverage.tcp.open, coverage.tcp.closed, coverage.tcp.filtered], [2, 65523, 10])
})

test('UDP counts open, closed and no-response probes from the UDP stage', () => {
  const coverage = devicePortCoverage(scanWith({
    services: [{ transport: 'udp', port: 1900, state: 'open', service_name: 'upnp' }],
    inconclusive_observations: [{ transport: 'udp', port: 5353, state: 'open|filtered' }],
    completeness: {
      tool_receipts: [{
        stage: 'udp_service_discovery', complete: true,
        port_state_counts: { open: 1, closed: 6, 'open|filtered': 1 },
      }],
    },
  }))
  assert.deepEqual(
    [coverage.udp.examined, coverage.udp.open, coverage.udp.closed, coverage.udp.noResponse, coverage.udp.complete],
    [8, 1, 6, 1, true],
  )
})

test('fingerprinting reports how many open ports were identified and versioned', () => {
  const coverage = devicePortCoverage(scanWith({
    services: [
      openTcp(22, { service_name: 'ssh', product: 'OpenSSH', version: '9.6' }),
      openTcp(3000, { service_name: 'tcpwrapped' }),
      openTcp(3001, { service_name: 'https', product: 'Example TV http service' }),
    ],
    completeness: {
      tcp_fingerprinting_complete: true,
      tool_receipts: [
        { stage: 'tcp_service_fingerprint_1', port_state_counts: { open: 3 } },
      ],
    },
  }))
  assert.deepEqual(
    [coverage.fingerprint.ports, coverage.identification.identified, coverage.identification.withVersion],
    [3, 2, 1],
  )
})

test('a scan without device posture has no port coverage', () => {
  assert.equal(devicePortCoverage({ id: 'web-scan', result: { findings: [] } }), null)
  assert.equal(devicePortCoverage(null), null)
})

test('service details show product and version, extra detail, TLS and CPE', () => {
  assert.deepEqual(
    deviceServiceDetails({
      service_name: 'http', product: 'lighttpd', version: '1.4.76', extra_info: 'device admin UI',
      tunnel: 'ssl', cpe: 'cpe:/a:lighttpd:lighttpd:1.4.76',
    }),
    {
      productVersion: 'lighttpd 1.4.76', extraInfo: 'device admin UI', tls: true,
      cpe: 'cpe:/a:lighttpd:lighttpd:1.4.76', unidentified: false,
    },
  )
  const wrapped = deviceServiceDetails({ service_name: 'tcpwrapped' })
  assert.equal(wrapped.productVersion, null)
  assert.equal(wrapped.unidentified, true)
  assert.equal(deviceServiceDetails({ service_name: 'https' }).tls, true)
})
