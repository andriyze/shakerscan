import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const targets = readFileSync(path.join(root, 'src/app/targets/page.tsx'), 'utf8')
const newScan = readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')

test('single-target menus offer both the safe shortcut and full configuration', () => {
  assert.match(targets, /Balanced budget · passive policy/)
  assert.match(targets, /Customize Scan…/)
  assert.match(targets, /Choose budget, permissions, credentials, and coverage/)
  assert.match(targets, /aria-haspopup="menu"/)
})

test('domain-wide customization opens New Scan in prefilled batch mode', () => {
  assert.match(targets, /Customize batch…/)
  assert.match(targets, /params\.set\('targets', uniqueTargets\.join\('\\n'\)\)/)
  assert.match(newScan, /requestedParams\.get\('targets'\)/)
  assert.match(newScan, /setBatchMode\(true\)/)
  assert.match(newScan, /setBatchTargets\(Array\.from\(new Set\(requestedTargets\)\)\.join\('\\n'\)\)/)
})
