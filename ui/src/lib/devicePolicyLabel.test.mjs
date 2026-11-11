import assert from 'node:assert/strict'
import test from 'node:test'
import { devicePolicyLabel } from './devicePolicyLabel.mjs'

test('built-in policy identifiers read as names with their version', () => {
  assert.equal(devicePolicyLabel({ name: 'camera-baseline-v1', is_builtin: true }), 'Camera baseline (version 1)')
  assert.equal(devicePolicyLabel({ name: 'connected-device-default-v2', is_builtin: true }), 'Connected device default (version 2)')
  assert.equal(devicePolicyLabel({ name: 'network-appliance-baseline-v12', is_builtin: true }), 'Network appliance baseline (version 12)')
})

test('a policy a person named keeps its name exactly', () => {
  assert.equal(devicePolicyLabel({ name: 'floor-3-printers-v2', is_builtin: false }), 'floor-3-printers-v2')
  assert.equal(devicePolicyLabel({ name: 'Lobby cameras', is_builtin: true }), 'Lobby cameras')
  assert.equal(devicePolicyLabel({ name: '', is_builtin: false }), 'Unnamed policy')
  assert.equal(devicePolicyLabel(null), 'Unnamed policy')
})
