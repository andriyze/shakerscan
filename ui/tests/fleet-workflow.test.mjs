import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(new URL('../src/app/fleet/page.tsx', import.meta.url), 'utf8')

test('fleet access failure does not render an empty fleet as authoritative state', () => {
  assert.match(page, /Enter the fleet operator token to load remote nodes and controls\./)
  assert.match(page, /if \(!loading && error && nodes\.length === 0\)/)
  assert.match(page, /<OperatorAccessCard/)
  assert.match(page, /<ErrorState message=\{error\}/)
  assert.match(page, /catch \(err\) \{[\s\S]*setNodes\(\[\]\)[\s\S]*setSummary\(EMPTY_SUMMARY\)/)
})
