import assert from 'node:assert/strict'
import test from 'node:test'

import { filterOptions, groupOptions, matches, moveActive, normalize } from './comboboxModel.mjs'

const options = [
  { value: '1', label: 'Partner API admin', description: 'bearer token · primary · v3', meta: 'api.example.test', group: 'This target' },
  { value: '2', label: 'Storefront shopper', description: 'form login · secondary', meta: 'shop.example.test', group: 'Shared' },
  { value: '3', label: 'Router SSH', description: 'ssh private key', meta: '192.0.2.1', keywords: 'device', group: 'Shared', disabled: true },
  { value: '4', label: 'Admin console', description: 'cookie', meta: 'admin.example.test', group: 'This target' },
]

test('every query word must appear somewhere in the option', () => {
  assert.equal(matches(options[0], 'partner bearer'), true)
  assert.equal(matches(options[0], 'partner cookie'), false)
  assert.equal(matches(options[2], 'DEVICE'), true)
  assert.equal(matches(options[1], ''), true)
  assert.equal(normalize('Café'), 'cafe')
})

test('label matches rank first, prefix before substring, stable otherwise', () => {
  assert.deepEqual(filterOptions(options, 'admin').map(item => item.value), ['4', '1'])
  assert.deepEqual(filterOptions(options, 'example.test').map(item => item.value), ['1', '2', '4'])
  assert.deepEqual(filterOptions(options, '').map(item => item.value), ['1', '2', '3', '4'])
})

test('arrow keys skip disabled options and wrap around', () => {
  assert.equal(moveActive(options, -1, 1), 0)
  assert.equal(moveActive(options, 1, 1), 3)
  assert.equal(moveActive(options, 3, 1), 0)
  assert.equal(moveActive(options, 0, -1), 3)
  assert.equal(moveActive(options, -1, -1), 3)
  assert.equal(moveActive([], 0, 1), -1)
  assert.equal(moveActive([{ value: 'x', label: 'x', disabled: true }], 0, 1), -1)
})

test('groups keep first-seen order', () => {
  assert.deepEqual(groupOptions(options).map(group => [group.name, group.options.map(item => item.value)]),
    [['This target', ['1', '4']], ['Shared', ['2', '3']]])
})
