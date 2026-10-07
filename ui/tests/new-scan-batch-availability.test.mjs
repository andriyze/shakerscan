import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')
const capabilities = fs.readFileSync(path.join(root, 'src/lib/workspaceCapabilities.ts'), 'utf8')

test('New Scan offers Multiple targets only where batch submission is available', () => {
  // Soak N26: Enterprise refuses POST /scans/batch, yet New Scan offered "Multiple targets".
  // A managed deployment must list batch_scan as enabled; a standalone engine has no policy and
  // keeps the full surface.
  assert.match(page, /\{featureEnabled\('batch_scan'\) && <label className="flex items-center gap-2 text-sm text-gray-300">\s*<input type="checkbox" checked=\{batchMode\}/)
  assert.match(page, /if \(requestedTargets\.length > 0 && featureEnabled\('batch_scan'\)\) \{\s*setBatchMode\(true\)/)
  assert.match(capabilities, /if \(!policy\) return true/)
  assert.match(capabilities, /policy\.features\?\.\[feature\]\?\.state === 'enabled'/)
})
