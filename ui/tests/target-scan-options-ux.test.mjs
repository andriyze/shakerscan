import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { configureScanHref } from '../src/lib/targetInventoryModel.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const row = readFileSync(path.join(root, 'src/components/targets/inventory/TargetRow.tsx'), 'utf8')
// The row menu is the shared overflow menu primitive.
const menu = readFileSync(path.join(root, 'src/components/ui/ActionMenu.tsx'), 'utf8')
const groups = readFileSync(path.join(root, 'src/components/targets/inventory/TargetGroups.tsx'), 'utf8')
const newScan = readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')

test('single-target menus offer both the safe shortcut and full configuration', () => {
  assert.match(row, /Balanced budget · passive policy/)
  assert.match(row, /Customize Scan…/)
  assert.match(row, /Choose budget, permissions, credentials, and coverage/)
  assert.match(menu, /aria-haspopup="menu"/)
})

test('domain-wide customization opens New Scan in prefilled batch mode', () => {
  assert.match(groups, /Customize batch…/)
  assert.match(groups, /configureScanHref\(batch, true\)/)
  assert.equal(configureScanHref(['https://a.example.test', 'b.example.test'], true),
    '/scan/new?targets=https%3A%2F%2Fa.example.test%0Ab.example.test')
  assert.match(newScan, /requestedParams\.get\('targets'\)/)
  assert.match(newScan, /setBatchMode\(true\)/)
  assert.match(newScan, /setBatchTargets\(Array\.from\(new Set\(requestedTargets\)\)\.join\('\\n'\)\)/)
})
