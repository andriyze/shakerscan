import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

import { boundedDisplayText, boundedTargetDisplay, usableWebTargets } from '../src/lib/targetChoices.ts'

const credentialsPage = fs.readFileSync(new URL('../src/app/credentials/page.tsx', import.meta.url), 'utf8')
const collectionsPage = fs.readFileSync(new URL('../src/app/request-collections/page.tsx', import.meta.url), 'utf8')
const evidencePanel = fs.readFileSync(new URL('../src/components/EvidenceRetentionPanel.tsx', import.meta.url), 'utf8')
const timelinePage = fs.readFileSync(new URL('../src/app/timeline/page.tsx', import.meta.url), 'utf8')
const schedulesPage = fs.readFileSync(new URL('../src/app/schedules/page.tsx', import.meta.url), 'utf8')

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
  for (const page of [credentialsPage, collectionsPage]) {
    assert.match(page, /targetId && !choices\.some/)
    assert.match(page, /Choose a target…/)
  }
  assert.match(credentialsPage, /Choose a bound target/)
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
  for (const surface of [evidencePanel, timelinePage, schedulesPage]) {
    assert.match(surface, /boundedTargetDisplay/)
  }
})
