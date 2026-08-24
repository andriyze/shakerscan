import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL('../src/app/scan/new/page.tsx', import.meta.url),
  'utf8',
)

test('New Scan labels target entry and exposes selected budget state', () => {
  assert.match(page, /<Field label="Target URL or hostname" required>/)
  assert.match(page, /<Field label="Target URLs \(one per line\)" required>/)
  assert.match(page, /role="group" aria-label="Scan budget"/)
  assert.match(page, /aria-pressed=\{budgetProfile === budget\.value\}/)
})

test('New Scan exposes disclosure and validation state to assistive technology', () => {
  assert.match(page, /aria-expanded=\{showAdvanced\}/)
  assert.match(page, /aria-controls="advanced-scan-options"/)
  assert.match(page, /id="advanced-scan-options"/)
  assert.match(page, /<p role="alert"/)
})
