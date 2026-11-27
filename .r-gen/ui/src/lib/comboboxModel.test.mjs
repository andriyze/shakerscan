import assert from 'node:assert/strict'
import test from 'node:test'

import { canChooseActive, clampActive, filterOptions, groupOptions, initialActive, matches, moveActive, normalize } from './comboboxModel.mjs'

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

// Review of the server-search picker: the highlight was computed against the previous query's
// results, so Enter could choose a different target, or an index past the end of a shorter list.
test('a new result list gets a fresh highlight: the selection when shown, else the first enabled', () => {
  const answer = [{ value: 'a', label: 'A', disabled: true }, { value: 'b', label: 'B' }, { value: 'c', label: 'C' }]
  assert.equal(initialActive(answer, 'c'), 2)
  assert.equal(initialActive(answer, 'zzz'), 1, 'selection absent: first enabled option')
  assert.equal(initialActive(answer, 'a'), 1, 'a disabled selection is not highlighted')
  assert.equal(initialActive([], 'c'), -1)
})

test('an index from an older, longer list is never used', () => {
  const shorter = [{ value: 'x', label: 'X' }, { value: 'y', label: 'Y', disabled: true }]
  assert.equal(clampActive(shorter, 5), -1, 'past the end')
  assert.equal(clampActive(shorter, 1), -1, 'disabled')
  assert.equal(clampActive(shorter, 0), 0)
  assert.equal(clampActive(shorter, -1), -1)
})

test('Enter in server search waits for the answer to the text in the box', () => {
  assert.equal(canChooseActive({ remote: false, loading: true, query: 'x' }), true, 'a local list answers its own filter')
  assert.equal(canChooseActive({ remote: true, loading: true, query: 'shop', optionsQuery: 'shop' }), false, 'still searching')
  assert.equal(canChooseActive({ remote: true, loading: false, query: 'shop', optionsQuery: 'sh' }), false, 'an older query\'s results')
  assert.equal(canChooseActive({ remote: true, loading: false, query: ' shop ', optionsQuery: 'shop' }), true)
  assert.equal(canChooseActive({ remote: true, loading: false, query: '', optionsQuery: null }), false, 'nothing answered yet')
  assert.equal(canChooseActive({ remote: true, loading: false, query: 'shop' }), true, 'a caller that does not say which query: loading alone decides')
})
