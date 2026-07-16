// Dependency-free regression test for the array normalizer behind the Command
// Arsenal crash fix. Run: `node --test ui/src/lib/safe.test.mjs`
// (Node >= 23 strips the types from the imported .ts automatically.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { asArray } from './safe.ts'

test('asArray returns real arrays unchanged', () => {
  assert.deepEqual(asArray([1, 2, 3]), [1, 2, 3])
  assert.deepEqual(asArray([]), [])
})

test('asArray coerces undefined / null (missing key) to []', () => {
  assert.deepEqual(asArray(undefined), [])
  assert.deepEqual(asArray(null), [])
})

test('asArray coerces a malformed / version-skewed non-array to []', () => {
  // The exact shapes that used to reach a `.map()` and crash the page.
  assert.deepEqual(asArray(/** @type {any} */ ({ detail: 'not found' })), [])
  assert.deepEqual(asArray(/** @type {any} */ ('oops')), [])
  assert.deepEqual(asArray(/** @type {any} */ (42)), [])
})
