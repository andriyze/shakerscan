import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL('../src/app/scan/new/page.tsx', import.meta.url),
  'utf8',
)

test('Scan exposes independent host and state-changing request ceilings', () => {
  assert.match(page, /max_state_changing_requests/)
  assert.match(page, /Maximum state-changing requests/)
  assert.match(page, /max_hosts/)
  assert.match(page, /Maximum hosts/)
})
