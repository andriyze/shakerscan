import assert from 'node:assert/strict'
import test from 'node:test'

import {
  effectiveStatusView,
  findingCountSummary,
  findingGroupKey,
  findingHost,
  findingLocation,
  findingSubject,
  groupFindings,
  retestSignal,
  statusViewParam,
} from './findingGroups.ts'

const honey = 'https://honey.example.test'
const exposure = (id, path, extra = {}) => ({
  id,
  title: 'Sensitive exposure: cloud credential material',
  severity: 'critical',
  status: 'active',
  proof_state: 'verified',
  target_id: 't-honey',
  url: `${honey}${path}`,
  last_seen_at: '2026-09-29T10:00:00Z',
  ...extra,
})

test('repeats of one issue on one subject collapse into a group, in server order', () => {
  const findings = [
    exposure('a', '/.aws/credentials'),
    { id: 'b', title: 'Sensitive exposure: private key material', severity: 'critical', status: 'active', proof_state: 'verified', target_id: 't-honey', url: `${honey}/id_rsa` },
    exposure('c', '/settings.py', { last_seen_at: '2026-09-30T04:28:45Z' }),
    exposure('d', '/phpinfo.php', { last_seen_at: 'not a date' }),
  ]
  const groups = groupFindings(findings)
  assert.deepEqual(groups.map((group) => group.members.map((member) => member.id)), [['a', 'c', 'd'], ['b']])
  assert.equal(groups[0].lead.id, 'a')
  assert.equal(groups[0].lastSeenAt, '2026-09-30T04:28:45Z')
})

test('a different subject, proof, or triage state is a different group', () => {
  const base = exposure('a', '/x')
  const key = findingGroupKey(base)
  assert.notEqual(findingGroupKey({ ...base, target_id: 't-other' }), key)
  assert.notEqual(findingGroupKey({ ...base, proof_state: 'suspected' }), key)
  assert.notEqual(findingGroupKey({ ...base, status: 'resolved' }), key)
  assert.notEqual(findingGroupKey({ ...base, is_candidate: true }), key)
  assert.equal(findingGroupKey({ ...base, title: '  sensitive EXPOSURE: cloud credential material ' }), key)
})

test('the location names the route and parameter names, never their values', () => {
  assert.equal(findingLocation({ id: 'x', url: 'https://app.test/rest/search?q=secret-value&lang=en&q=again' }), '/rest/search?q&lang')
  assert.equal(findingLocation({ id: 'x', url: 'https://app.test' }), '/')
  assert.equal(findingLocation({ id: 'x' }), '')
  assert.equal(findingHost({ id: 'x', url: 'https://app.test:8443/a' }), 'app.test:8443')
  assert.equal(findingSubject({ id: 'x', ai_target_name: 'support-bot' }), 'support-bot')
  // Two AI targets on one endpoint host are told apart by name, not by the shared host.
  assert.equal(findingSubject({ id: 'x', ai_target_id: 'a1', ai_target_name: 'support-bot', url: 'https://ai.test/chat' }), 'support-bot')
})

test('open work is the default view, except for a scan-scoped view of its evidence', () => {
  assert.equal(effectiveStatusView(undefined, false), 'active')
  assert.equal(effectiveStatusView(undefined, true), 'all')
  assert.equal(effectiveStatusView('resolved', true), 'resolved')
  assert.equal(effectiveStatusView('bogus', false), 'active')
  assert.equal(statusViewParam('active', false), undefined)
  assert.equal(statusViewParam('all', false), 'all')
  assert.equal(statusViewParam('active', true), 'active')
  assert.equal(statusViewParam('all', true), undefined)
})

test('a retest shows only when it tells the row something new', () => {
  assert.equal(retestSignal('exploited', 'active'), null)
  assert.equal(retestSignal(null, 'active'), null)
  assert.equal(retestSignal('exploited', 'resolved')?.label, 'Still vulnerable')
  assert.equal(retestSignal('exploited', 'resolved')?.tone, 'danger')
  assert.equal(retestSignal('likely_fixed', 'active')?.tone, 'success')
  assert.equal(retestSignal('likely_fixed', 'resolved'), null)
  assert.equal(retestSignal('inconclusive', 'active')?.tone, 'muted')
  assert.match(retestSignal('inconclusive', 'active')?.title || '', /does not change the triage status/)
})

test('the count line never presents a partial load as complete', () => {
  assert.equal(findingCountSummary({ total: 144, loaded: 144, offset: 0, groups: 37, statusLabel: 'open' }), '144 open findings in 37 groups')
  assert.equal(findingCountSummary({ total: 1, loaded: 1, offset: 0, groups: 1, statusLabel: '' }), '1 finding in 1 group')
  assert.equal(
    findingCountSummary({ total: 2117, loaded: 500, offset: 0, groups: 180, statusLabel: '' }),
    '2,117 findings · showing 1–500 in 180 groups (groups cover the loaded rows only)',
  )
  assert.equal(findingCountSummary({ total: 120, loaded: 50, offset: 50, groups: null, statusLabel: 'open' }), '120 open findings · showing 51–100')
})
