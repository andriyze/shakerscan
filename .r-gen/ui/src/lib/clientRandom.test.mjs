import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRandomUUID } from './clientRandom.ts'

test('generates distinct version 4 UUIDs when randomUUID is absent', () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  const actual = globalThis.crypto
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { getRandomValues: actual.getRandomValues.bind(actual) },
  })
  try {
    const first = createRandomUUID()
    const second = createRandomUUID()
    assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    assert.notEqual(first, second)
  } finally {
    if (original) Object.defineProperty(globalThis, 'crypto', original)
    else delete globalThis.crypto
  }
})
