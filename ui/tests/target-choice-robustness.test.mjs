import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

import { usableWebTargets } from '../src/lib/targetChoices.ts'

const credentialsPage = fs.readFileSync(new URL('../src/app/credentials/page.tsx', import.meta.url), 'utf8')
const collectionsPage = fs.readFileSync(new URL('../src/app/request-collections/page.tsx', import.meta.url), 'utf8')

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
