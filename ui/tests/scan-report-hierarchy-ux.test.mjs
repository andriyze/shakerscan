import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const report = fs.readFileSync(new URL('../src/components/ReportView.tsx', import.meta.url), 'utf8')

test('detailed report does not repeat the target as a second page title', () => {
  assert.match(report, /<h2 className="text-2xl font-bold mb-2">Detailed scan report<\/h2>/)
  assert.doesNotMatch(report, /<h1 className="text-3xl font-bold mb-2 break-words">/)
})

test('unlinked scan evidence is described in user-facing language', () => {
  assert.match(report, /Findings reported by this scan/)
  assert.doesNotMatch(report, /Raw Scan Findings/)
  assert.match(report, /do not yet have saved finding records/)
})
