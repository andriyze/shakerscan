import assert from 'node:assert/strict'
import test from 'node:test'
import { networkScanTcpHints } from './networkScanHints.mjs'

test('network scan hints combine saved ports with Scan and Hunt TCP observations', () => {
  assert.equal(networkScanTcpHints({
    device: { metadata_json: { port_hints: [8443, 2222] } },
    services: [{ port: 22, transport: 'tcp', state: 'open' }],
    service_intelligence: { services: [{ port: 8081, transport: 'tcp' }, { port: 2222, transport: 'tcp' }] },
  }), '22, 2222, 8081, 8443')
})

test('network scan hints exclude UDP, old locators, unconfirmed states and invalid ports', () => {
  assert.equal(networkScanTcpHints({ service_intelligence: { services: [
    { port: 161, transport: 'udp' }, { port: 23, binding_status: 'historical_locator' },
    { port: 25, state: 'open|filtered' }, { port: 0 }, { port: 65536 }, { port: '22' },
    { port: 443, transport: 'TCP' },
  ] } }), '443')
  assert.equal(networkScanTcpHints(null), '')
  assert.equal(networkScanTcpHints({ device: { metadata_json: { port_hints: {} } } }), '')
})

test('automatic hints fit the network scan request limit', () => {
  const hints = networkScanTcpHints({ services: Array.from({ length: 200 }, (_, index) => ({ port: index + 1 })) })
  assert.equal(hints.split(', ').length, 128)
})
