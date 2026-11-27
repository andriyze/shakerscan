import assert from 'node:assert/strict'
import test from 'node:test'

import { cleanTargetLocator, huntActivity, huntTargetTitle, targetRetired } from './huntListModel.mjs'

test('internal locators lose their scheme and retirement marker', () => {
  assert.equal(cleanTargetLocator('host://127.77.75.209#retired=1911cceb-96ad-476c-a733-10dbc8903fc6'), '127.77.75.209')
  assert.equal(cleanTargetLocator('http://shakerscan-fixtures.internal:18099/'), 'http://shakerscan-fixtures.internal:18099')
  assert.equal(cleanTargetLocator(null), '')
  assert.equal(targetRetired('host://a.test#retired=abc-123'), true)
  assert.equal(targetRetired('https://a.test'), false)
})

test('a Hunt is titled by its target name, then its cleaned locator', () => {
  assert.equal(huntTargetTitle({ target_name: 'Partner API', target_url: 'https://api.example.test' }), 'Partner API')
  assert.equal(huntTargetTitle({ target_name: '  ', target_url: 'host://tv.local#retired=ab12' }), 'tv.local')
  assert.equal(huntTargetTitle({ target_id: 'abc' }), 'abc')
})

test('activity reads the settled budget usage', () => {
  assert.deepEqual(huntActivity({ budget_used: { http_requests: 10, agent_actions: 5, candidates: 1, tcp_ports_attempted: 3, udp_ports_attempted: 2 } }),
    { requests: 10, actions: 5, candidates: 1, browser: 0, ports: 5 })
  assert.deepEqual(huntActivity(null), { requests: 0, actions: 0, candidates: 0, browser: 0, ports: 0 })
})
