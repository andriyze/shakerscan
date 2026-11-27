import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('the canonical workflow is presented as a DAST scan, never Scan scan', () => {
  assert.match(detail, /scan\?\.scan_type === 'scan' \|\| scan\?\.run_kind === 'web_dast'/)
  assert.match(detail, /return 'DAST'/)
  assert.doesNotMatch(detail, /return 'Scan'/)
})
