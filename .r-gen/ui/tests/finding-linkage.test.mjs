import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildFindingLinkageIndex,
  linkedPersistedFinding,
  observedReportFinding,
} from '../src/lib/findingLinkage.ts'

test('raw scanner results link to persisted findings by stable fingerprint', () => {
  const persisted = { id: 'finding-db-id', fingerprint: 't:abc', title: 'Finding', url: 'https://example.test/a' }
  const index = buildFindingLinkageIndex([persisted])
  assert.equal(linkedPersistedFinding({ fingerprint: 't:abc' }, index), persisted)
})

test('legacy raw results without IDs link by normalized title and URL', () => {
  const persisted = {
    id: '615521d8-f97b-4cbc-b6f3-7abfd96faff5',
    fingerprint: 't:8bf5d646fa92a220',
    title: 'Git Credentials - Detect',
    tool: 'nuclei',
    url: 'https://honey.shakerscan.com/.git-credentials',
  }
  const raw = {
    title: '  Git Credentials   - Detect ',
    tool: 'nuclei',
    url: 'https://honey.shakerscan.com/.git-credentials',
  }
  const index = buildFindingLinkageIndex([persisted])
  assert.equal(linkedPersistedFinding(raw, index), persisted)
})

test('same title on a different endpoint remains unlinked', () => {
  const persisted = { id: 'one', title: 'Missing authorization', url: 'https://example.test/a' }
  const index = buildFindingLinkageIndex([persisted])
  assert.equal(linkedPersistedFinding({ title: 'Missing authorization', url: 'https://example.test/b' }, index), null)
})

test('tool-specific identity wins when legacy records share a title and endpoint', () => {
  const nuclei = { id: 'nuclei', title: 'Exposed metadata', tool: 'nuclei', url: 'https://example.test/info' }
  const custom = { id: 'custom', title: 'Exposed metadata', tool: 'custom_check', url: 'https://example.test/info' }
  const index = buildFindingLinkageIndex([nuclei, custom])
  assert.equal(linkedPersistedFinding({ title: custom.title, tool: custom.tool, url: custom.url }, index), custom)
})

test('probe-local AI finding IDs resolve only inside the current scan index', () => {
  const sourceId = 'smoke.prompt-leakage:pii'
  const honeyFinding = {
    id: 'honey-finding-uuid',
    source_finding_id: sourceId,
    title: 'Honey prompt leakage',
  }
  const fixtureFinding = {
    id: 'fixture-finding-uuid',
    source_finding_id: sourceId,
    title: 'Fixture prompt leakage',
  }

  const rawFinding = { id: sourceId }
  assert.equal(
    linkedPersistedFinding(rawFinding, buildFindingLinkageIndex([honeyFinding])),
    honeyFinding,
  )
  assert.equal(
    linkedPersistedFinding(rawFinding, buildFindingLinkageIndex([fixtureFinding])),
    fixtureFinding,
  )
})

test('a report result is shown as observed by the scan that reported it', () => {
  // The honey report marked every proven critical "never observed": a raw result has no
  // last_seen_at of its own.
  const raw = { title: 'Sensitive exposure: private key material', url: 'https://example.test/id_rsa', severity: 'critical' }
  const linked = observedReportFinding(raw, {
    id: 'f1', status: 'active', first_seen_at: '2026-09-04T06:16:14Z', last_seen_at: '2026-09-30T04:28:45Z',
  }, '2026-09-30T04:28:50Z')
  assert.equal(linked.first_seen_at, '2026-09-04T06:16:14Z')
  assert.equal(linked.last_seen_at, '2026-09-30T04:28:45Z')
  assert.equal(linked.status, 'active')
  const candidate = observedReportFinding(raw, null, '2026-09-30T04:28:50Z')
  assert.equal(candidate.last_seen_at, '2026-09-30T04:28:50Z')
  assert.equal(candidate.first_seen_at, '2026-09-30T04:28:50Z')
  assert.equal(candidate.title, raw.title)
})
