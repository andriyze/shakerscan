import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const controls = fs.readFileSync(new URL('../src/components/targets/inventory/InventoryControls.tsx', import.meta.url), 'utf8')

test('target search has a stable accessible name', () => {
  assert.match(controls, /aria-label="Search targets by URL or domain"/)
})
