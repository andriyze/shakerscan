import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const source = fs.readFileSync(new URL('../src/app/hunt/page.tsx', import.meta.url), 'utf8')

test('Hunt action UI separates reservation ceilings from settled actual use', () => {
  assert.match(source, /Settled charge:/)
  assert.match(source, /conservative upper bound; measured consumption was unavailable/)
  assert.match(source, /Temporarily reserved:/)
  assert.match(source, /Released after settlement:/)
  assert.match(source, /Legacy reported charge:/)
  assert.doesNotMatch(source, />\s*Used \{budget/)
})

test('Hunt detail shows persisted completion time and elapsed duration', () => {
  assert.match(source, /Completed \{new Date\(hunt\.completed_at\)\.toLocaleString\(\)\}/)
  assert.match(source, /formatHuntDuration\(hunt\.created_at, hunt\.completed_at\)/)
})
