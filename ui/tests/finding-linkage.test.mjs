import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildFindingLinkageIndex,
  linkedPersistedFinding,
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
