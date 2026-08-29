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
  assert.match(page, /<form\s+noValidate\s+onSubmit=\{handleSubmit\}/)
  assert.match(page, /aria-expanded=\{showAdvanced\}/)
  assert.match(page, /aria-controls="advanced-scan-options"/)
  assert.match(page, /id="advanced-scan-options"/)
  assert.match(page, /<p role="alert"/)
})

test('New Scan clears stale validation when the operator edits the form', () => {
  assert.match(page, /onChange=\{\(\) => \{ if \(error\) setError\(null\) \}\}/)
  assert.match(page, /setBudgetProfile\(budget\.value\); setError\(null\)/)
})

test('ordinary active scans need one runnable worker, not release-fleet uniformity', () => {
  assert.match(page, /execution_capacity\?\.total_available \?\? currentWorkerCount/)
  assert.match(page, /require_current_workers: false/)
  assert.match(page, /placementPreviewLabel\(topology, currentWorkerCount\)/)
  assert.match(page, /Expected build:/)
  assert.match(page, /Reported running builds:/)
  assert.match(page, /disabled=\{activeTesting && !activeWorkerAvailable\}/)
  assert.doesNotMatch(page, /Active testing is paused until the worker fleet is uniformly current/)
})
