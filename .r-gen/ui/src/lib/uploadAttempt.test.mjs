import { test } from 'node:test'
import assert from 'node:assert/strict'
import { UploadAttempt } from './uploadAttempt.ts'

test('ambiguous upload retries reuse the key without retaining source documents', async () => {
  const attempt = new UploadAttempt()
  const payload = { target_id: 'fixture', document: { secret: 'synthetic-secret' } }
  const first = await attempt.keyFor(payload)
  assert.equal(await attempt.keyFor(payload), first)
  assert.equal(JSON.stringify(attempt).includes('synthetic-secret'), false)
  assert.notEqual(await attempt.keyFor({ ...payload, target_id: 'another' }), first)
})

test('new successful upload intent gets a new key even for identical content', async () => {
  const attempt = new UploadAttempt()
  const first = await attempt.keyFor({ document: 'fixture' })
  attempt.reset()
  assert.notEqual(await attempt.keyFor({ document: 'fixture' }), first)
})

test('insecure standalone contexts retain upload support without a weak fingerprint', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined })
  try {
    assert.equal(await new UploadAttempt().keyFor({ document: 'fixture' }), undefined)
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor)
  }
})
