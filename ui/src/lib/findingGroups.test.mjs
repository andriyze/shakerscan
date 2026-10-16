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
  groupSize,
  groupedCountSummary,
  groupsFromServer,
  isGroupingTooBroadError,
  isServerGroupsPage,
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

const serverGroup = (lead, memberIds, extra = {}) => ({
  title_key: 'sensitive exposure: cloud credential material', severity: 'critical', subject: 't-honey',
  proof_state: 'verified', status: 'active', count: memberIds.length, first_seen_at: null,
  last_seen_at: '2026-09-30T04:28:45Z', lead, member_ids: memberIds, member_ids_truncated: false,
  members: memberIds.map((id) => ({ id, url: `${honey}/${id}`, last_seen_at: '2026-09-29T10:00:00Z', latest_retest_verdict: id === 'c' ? 'likely_fixed' : null })),
  ...extra,
})

test('server groups keep the server order, list members by location, and count the whole group', () => {
  const lead = exposure('a', '/.aws/credentials')
  const groups = groupsFromServer([
    serverGroup(lead, ['a', 'c', 'd'], { count: 80, member_ids_truncated: true }),
    serverGroup(exposure('b', '/id_rsa'), ['b']),
  ])
  assert.deepEqual(groups.map((group) => group.lead.id), ['a', 'b'])
  const [first, second] = groups
  assert.equal(first.lead, lead)
  assert.deepEqual(first.members.map((member) => member.id), ['a', 'c', 'd'])
  // A listed member is its own location, retest and sighting; the rest is the group's.
  assert.equal(first.members[1].url, `${honey}/c`)
  assert.equal(first.members[1].latest_retest_verdict, 'likely_fixed')
  assert.equal(first.members[1].title, lead.title)
  assert.equal(first.lastSeenAt, '2026-09-30T04:28:45Z')
  assert.equal(groupSize(first), 80)
  assert.equal(groupSize(second), 1)
  // A browser group has no server count: its size is its members.
  assert.equal(groupSize(groupFindings([lead, exposure('e', '/x')])[0]), 2)
  assert.notEqual(first.key, second.key)
})

test('only a page of groups is taken for server grouping; rows mean the engine cannot group', () => {
  const page = { items: [serverGroup(exposure('a', '/'), ['a'])], next_cursor: null, has_more: false, total: 1, total_kind: 'exact', generated_at: 'x' }
  assert.equal(isServerGroupsPage(page), true)
  assert.equal(isServerGroupsPage({ ...page, items: [] }), true)
  // An older engine: the legacy shape, or list/v1 rows (no count, member ids or lead).
  assert.equal(isServerGroupsPage({ findings: [exposure('a', '/')], total: 1 }), false)
  assert.equal(isServerGroupsPage({ ...page, items: [exposure('a', '/')] }), false)
  assert.equal(isServerGroupsPage(null), false)
})

test('the count line for server groups states complete groups and the groups shown', () => {
  assert.equal(groupedCountSummary({ findings: 428572, groups: 10000, start: 1, shown: 50, statusLabel: 'open' }),
    '428,572 open findings in 10,000 groups · showing groups 1–50')
  assert.equal(groupedCountSummary({ findings: 3, groups: 2, start: 1, shown: 2, statusLabel: '' }), '3 findings in 2 groups')
  assert.equal(groupedCountSummary({ findings: 1, groups: 1, start: 1, shown: 1, statusLabel: 'open' }), '1 open finding in 1 group')
  assert.equal(groupedCountSummary({ findings: 120, groups: 75, start: 51, shown: 25, statusLabel: '' }),
    '120 findings in 75 groups · showing groups 51–75')
})

test('only the engine refusing these filters as too broad falls back for one request', () => {
  const tooBroad = { status: 422, detail: { error: 'proof_filter_too_broad', message: 'more than 10000 …' } }
  assert.equal(isGroupingTooBroadError(tooBroad), true)
  assert.equal(isGroupingTooBroadError({ ...tooBroad, status: 400 }), false)
  assert.equal(isGroupingTooBroadError({ status: 422, detail: { error: 'invalid_group_by' } }), false)
  assert.equal(isGroupingTooBroadError({ status: 422, detail: 'proof_filter_too_broad' }), false)
  assert.equal(isGroupingTooBroadError(null), false)
})
