import assert from 'node:assert/strict'
import test from 'node:test'
import { partitionSharedServices, presenceOf, sharedServiceHuntHref } from './sharedServicePorts.mjs'

const targetId = '00000000-0000-4000-8000-000000000294'
const ssh = { id: 'a', port: 22, transport: 'tcp', presence: 'observed_open', state: 'open', evidence: [] }
const dns = { id: 'b', port: 53, transport: 'udp', presence: 'inconclusive', state: 'open|filtered', service: 'domain', evidence: [] }
const snmpLegacy = { id: 'c', port: 161, transport: 'udp', state: 'open|filtered', evidence: [] }
const huntReceipt = { id: 'd', port: 9000, transport: 'tcp', evidence: [] }
const smtpClosed = { id: 'e', port: 25, transport: 'tcp', presence: 'not_observed', state: 'closed', evidence: [] }

test('presence follows the API rule, falling back to state when presence is absent', () => {
  assert.equal(presenceOf(ssh), 'observed_open')
  assert.equal(presenceOf(dns), 'inconclusive')
  assert.equal(presenceOf(snmpLegacy), 'inconclusive')
  assert.equal(presenceOf(huntReceipt), 'inconclusive')
  assert.equal(presenceOf({ state: 'OPEN' }), 'observed_open')
  assert.equal(presenceOf({ state: 'filtered' }), 'not_observed')
  assert.equal(presenceOf(smtpClosed), 'not_observed')
})

test('only confirmed open ports are listed as discovered; no-response probes are separate and nothing is dropped uncounted', () => {
  const { confirmed, unconfirmed, notObservedCount } = partitionSharedServices([ssh, dns, snmpLegacy, huntReceipt, smtpClosed])
  assert.deepEqual(confirmed.map(s => s.id), ['a'])
  assert.deepEqual(unconfirmed.map(s => s.id), ['b', 'c', 'd'])
  assert.equal(notObservedCount, 1)
  assert.deepEqual(partitionSharedServices(undefined), { confirmed: [], unconfirmed: [], notObservedCount: 0 })
})

test('Hunt is offered only for confirmed open ports at a current address', () => {
  for (const service of [dns, snmpLegacy, huntReceipt, smtpClosed]) assert.equal(sharedServiceHuntHref(service, targetId), null)
  const href = sharedServiceHuntHref(ssh, targetId)
  assert.ok(href && href.startsWith('/hunt?'))
  const params = new URLSearchParams(href.slice('/hunt?'.length))
  assert.equal(params.get('target'), targetId)
  assert.match(params.get('objective'), /Investigate observed tcp\/22 on this target/)
  assert.equal(sharedServiceHuntHref({ ...ssh, binding_status: 'historical_locator' }, targetId), null)
})

test('one port seen by a Hunt and by a scan is listed once, with both as evidence', () => {
  // Soak N25: 22/tcp was listed twice on the device page, once per source.
  const fromScan = { id: 's', port: 22, transport: 'tcp', presence: 'observed_open', address: '2.28.1.228',
    service: 'ssh', binding_status: 'current', evidence: [{ scan_id: 'c2e71720-0000' }] }
  const fromHunt = { id: 'h', port: 22, transport: 'TCP', presence: 'observed_open', address: null,
    evidence: [{ hunt_id: 'a1b2c3d4-0000' }] }
  const noReply = { id: 'n', port: 22, transport: 'tcp', presence: 'inconclusive', evidence: [{ hunt_id: 'x' }] }
  const { confirmed, unconfirmed } = partitionSharedServices([fromScan, fromHunt, noReply])
  assert.equal(confirmed.length, 1)
  assert.equal(confirmed[0].address, '2.28.1.228')
  assert.equal(confirmed[0].service, 'ssh')
  assert.deepEqual(confirmed[0].evidence, [{ scan_id: 'c2e71720-0000' }, { hunt_id: 'a1b2c3d4-0000' }])
  assert.deepEqual(unconfirmed, [])
  // Distinct addresses stay distinct rows.
  const other = { ...fromScan, id: 'o', address: '10.0.0.9', evidence: [] }
  assert.equal(partitionSharedServices([fromScan, other]).confirmed.length, 2)
  // The input records are not mutated.
  assert.deepEqual(fromScan.evidence, [{ scan_id: 'c2e71720-0000' }])
})
