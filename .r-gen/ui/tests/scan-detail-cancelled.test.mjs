import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('a cancelled scan says it was cancelled and has no conclusion', () => {
  // Soak N12: the cancelled scan b2a63faa rendered as a report with no cancelled state.
  assert.match(page, /\{scan\.status === 'cancelled' && \(/)
  assert.match(page, /Scan cancelled\{scan\.error_message \? `: \$\{scan\.error_message\}` : ''\}/)
  assert.match(page, /no final grade or conclusion/)
})
