import assert from 'node:assert/strict'
import test from 'node:test'

import { usableWebTargets } from '../src/lib/targetChoices.ts'

test('target-bound forms hide inactive and unnamed web targets', () => {
  const usable = usableWebTargets([
    { id: 'blank', url: '', is_active: true },
    { id: 'spaces', url: '   ', is_active: true },
    { id: 'inactive', url: 'https://inactive.example', is_active: false },
    { id: 'ready', url: 'https://ready.example', is_active: true },
  ])
  assert.deepEqual(usable.map((target) => target.id), ['ready'])
})
