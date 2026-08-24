import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(new URL('../src/app/credentials/page.tsx', import.meta.url), 'utf8')

test('credential editor keeps validation visible beside required fields', () => {
  assert.match(page, /function validateDraft\(/)
  assert.match(page, /error=\{draftErrors\.name\}/)
  assert.match(page, /error=\{draftErrors\.username\}/)
  assert.match(page, /error=\{draftErrors\.secret\}/)
})

test('credential editor exposes a persistent validation summary', () => {
  assert.match(page, /role="alert"/)
  assert.match(page, /Complete the highlighted required fields before saving this credential\./)
})
