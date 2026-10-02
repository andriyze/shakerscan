import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(root, file), 'utf8')
const row = read('src/components/targets/inventory/TargetRow.tsx')
const groups = read('src/components/targets/inventory/TargetGroups.tsx')
const inventory = read('src/components/targets/TargetInventory.tsx')
const controls = read('src/components/targets/inventory/InventoryControls.tsx')

test('target rows describe the latest scan instead of counting all linked history', () => {
  // The inventory reports when the asset was last examined and its observed grade, never a raw
  // count of every linked run, and it says so plainly when nothing has been scanned.
  assert.match(row, /relativeTime\(asset\.last_scanned_at\)/)
  assert.match(row, /Never scanned/)
  assert.match(row, /Scanning…/)
})

test('each row links to its own asset history, and each web app to its own record', () => {
  // Exact target history: the asset page shows the asset's own scans, not a URL substring across hosts.
  assert.match(row, /href=\{`\/targets\/\$\{asset\.id\}\/asset`\}/)
  assert.match(row, /href=\{`\/targets\/\$\{origin\.id\}\/asset`\}/)
  assert.doesNotMatch(row, /\/scans\?domain=/)
})

test('finding counters have an accessible text label', () => {
  assert.match(row, /title=\{`\$\{item\.count\} \$\{item\.severity\}`\}/)
  assert.match(row, /No open findings/)
})

test('pathological domain labels stay inside their row', () => {
  assert.match(row, /block truncate font-medium text-gray-100/)
  assert.match(groups, /<span className="truncate">\{domain\}<\/span>/)
})

test('archived targets can be listed, restored and deleted from the Targets page', () => {
  // Archive sets is_active=false and the default inventory hides such rows; without these
  // controls an archived target could be neither deleted nor restored.
  assert.match(controls, /Show archived/)
  assert.match(read('src/lib/targetInventoryModel.mjs'), /if \(filters\.archived\) params\.include_inactive = true/)
  assert.match(row, /Archived<\/Pill>/)
  assert.match(row, /actions\.restore\(asset\)/)
  assert.match(row, /archived=\{!asset\.is_active\}/)
  assert.match(inventory, /await restoreTarget\(asset\.id\)/)
})
