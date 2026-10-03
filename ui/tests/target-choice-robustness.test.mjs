import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

import { boundedDisplayText, boundedTargetDisplay, usableWebTargets } from '../src/lib/targetChoices.ts'

const credentialsPage = fs.readFileSync(new URL('../src/app/credentials/page.tsx', import.meta.url), 'utf8')
const collectionsPage = fs.readFileSync(new URL('../src/app/request-collections/page.tsx', import.meta.url), 'utf8')
const evidencePanel = fs.readFileSync(new URL('../src/components/EvidenceRetentionPanel.tsx', import.meta.url), 'utf8')
const timelinePage = fs.readFileSync(new URL('../src/app/timeline/page.tsx', import.meta.url), 'utf8')
const schedulesPage = fs.readFileSync(new URL('../src/app/schedules/page.tsx', import.meta.url), 'utf8')
const targetsPage = fs.readFileSync(new URL('../src/components/targets/inventory/TargetRow.tsx', import.meta.url), 'utf8')
const targetGroups = fs.readFileSync(new URL('../src/components/targets/inventory/TargetGroups.tsx', import.meta.url), 'utf8')

test('target-bound forms hide inactive and unnamed web targets', () => {
  const usable = usableWebTargets([
    { id: 'blank', url: '', is_active: true },
    { id: 'spaces', url: '   ', is_active: true },
    { id: 'oversized', url: `https://${'a'.repeat(2048)}.example`, is_active: true },
    { id: 'unsupported', url: 'ftp://files.example', is_active: true },
    { id: 'inactive', url: 'https://inactive.example', is_active: false },
    { id: 'ready', url: 'https://ready.example', is_active: true },
  ])
  assert.deepEqual(usable.map((target) => target.id), ['ready'])
})

test('secret-bearing forms require an explicit target choice', () => {
  assert.match(collectionsPage, /<Button onClick=\{openUploader\} disabled=\{!targetId\}>/)
  // Credentials without a target is the library; creating one still needs an explicit target.
  assert.match(credentialsPage, /noneLabel="All targets"/)
  assert.match(credentialsPage, /onClick=\{openCreate\} disabled=\{!targetId\}/)
  // A target ID from the URL is used only once it is one of the choices.
  assert.match(credentialsPage, /choices\.some\(\(item\) => item\.id === targetId\) \? targetId : ''/)
  assert.match(collectionsPage, /if \(loading \|\| !targetId \|\| assets\.some\(\(asset\) => asset\.id === targetId\)\) return/)
  // With no target chosen the credentials page is the library, and says how to create one.
  assert.match(credentialsPage, /Choose a target to create a credential/)
  assert.match(collectionsPage, /Choose a collection owner/)
})

test('historical malformed target labels stay bounded in read-only selectors', () => {
  const label = boundedTargetDisplay({
    name: 'Historical fuzz target',
    url: `https://${'a'.repeat(65_000)}.example`,
  })
  assert.equal(label.length, 160)
  assert.ok(label.endsWith('…'))
  assert.equal(boundedDisplayText(`target-${'x'.repeat(500)}`, 40).length, 40)
  assert.equal(boundedDisplayText('  normal target  '), 'normal target')
  assert.equal(boundedTargetDisplay({ url: 'https://example.test' }, { stripScheme: true }), 'example.test')
  for (const surface of [evidencePanel, timelinePage, schedulesPage, targetsPage]) {
    assert.match(surface, /boundedTargetDisplay/)
  }
  assert.match(targetGroups, /boundedDisplayText\(group\.root_domain/)
})
