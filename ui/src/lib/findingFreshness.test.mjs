import assert from 'node:assert/strict'
import test from 'node:test'

import { findingFreshness, relativeAge, STALE_AFTER_DAYS } from './findingFreshness.ts'

const NOW = new Date('2026-09-19T21:00:00Z')
const ago = (days) => new Date(NOW.getTime() - days * 86_400_000).toISOString()

test('a finding observed by a recent scan is unremarkably current', () => {
  const state = findingFreshness(
    { status: 'active', first_seen_at: ago(1), last_seen_at: ago(1) }, NOW,
  )
  assert.equal(state.state, 'current')
  assert.equal(state.badge, null, 'a current finding needs no badge')
  assert.match(state.detail, /Last seen/)
})

test('the shakerscan.com case: a critical last observed in May reads as not recent', () => {
  // first_seen == last_seen, four months back: three later scans never
  // re-observed it, and the list rendered it identically to a fresh finding.
  const state = findingFreshness(
    {
      status: 'active',
      first_seen_at: '2026-05-24T15:00:06Z',
      last_seen_at: '2026-05-24T15:00:06Z',
    },
    NOW,
  )
  assert.equal(state.state, 'stale')
  assert.equal(state.tone, 'amber')
  assert.match(state.detail, /Last seen 4mo ago/)
  // It is not evidence the issue is gone, so it must never say so.
  assert.doesNotMatch(state.badge, /fixed|gone|resolved/i)
})

test('first seen is only repeated when it differs from last seen', () => {
  const same = findingFreshness(
    { status: 'active', first_seen_at: ago(90), last_seen_at: ago(90) }, NOW,
  )
  assert.doesNotMatch(same.detail, /first seen/)

  const drifted = findingFreshness(
    { status: 'active', first_seen_at: ago(200), last_seen_at: ago(90) }, NOW,
  )
  assert.match(drifted.detail, /first seen/)
})

test('a finding that came back after being resolved says so', () => {
  const state = findingFreshness(
    { status: 'active', first_seen_at: ago(200), last_seen_at: ago(1), resurfaced_count: 2 },
    NOW,
  )
  assert.match(state.detail, /returned 2/)
})

test('a resolved finding reports when it was resolved', () => {
  const state = findingFreshness(
    { status: 'resolved', first_seen_at: ago(90), last_seen_at: ago(60), resolved_at: ago(3) },
    NOW,
  )
  assert.equal(state.state, 'resolved')
  assert.equal(state.tone, 'emerald')
  assert.match(state.badge, /resolved 3d ago/)
})

test('a finding no scan ever observed is flagged, not treated as current', () => {
  const state = findingFreshness({ status: 'active', last_seen_at: null }, NOW)
  assert.equal(state.state, 'unknown')
  assert.equal(state.ageDays, null)
  assert.match(state.detail, /Never observed/)
})

test('the staleness boundary is the documented threshold', () => {
  const inside = findingFreshness(
    { status: 'active', last_seen_at: ago(STALE_AFTER_DAYS - 1) }, NOW,
  )
  const outside = findingFreshness(
    { status: 'active', last_seen_at: ago(STALE_AFTER_DAYS + 1) }, NOW,
  )
  assert.equal(inside.state, 'current')
  assert.equal(outside.state, 'stale')
})

test('relative age stays readable across the ranges it spans', () => {
  assert.equal(relativeAge(new Date(NOW.getTime() - 30_000), NOW), 'just now')
  assert.equal(relativeAge(new Date(NOW.getTime() - 5 * 60_000), NOW), '5m ago')
  assert.equal(relativeAge(new Date(NOW.getTime() - 3 * 3_600_000), NOW), '3h ago')
  assert.equal(relativeAge(new Date(NOW.getTime() - 5 * 86_400_000), NOW), '5d ago')
  assert.equal(relativeAge(new Date(NOW.getTime() - 120 * 86_400_000), NOW), '4mo ago')
})
