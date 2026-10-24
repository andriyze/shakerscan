import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { activeScanLinkLabel, activeScanNote } from './asmActiveScan.ts'

const page = fs.readFileSync(path.join(import.meta.dirname, '../app/asm/page.tsx'), 'utf8')

test('E1-N4: an ordinary DAST scan blocking the target is not called an ASM batch/recon scan', () => {
  assert.equal(activeScanNote({ kind: 'active_scan', scan_id: 's', scan_kind: 'scan', hidden_from_scans_list: false }), null)
  assert.equal(activeScanLinkLabel('scan'), 'View active scan')
})

test('an ASM batch/recon scan keeps its hidden-from-the-Scans-list note', () => {
  assert.equal(
    activeScanNote({ kind: 'active_scan', scan_id: 's', scan_kind: 'asm', hidden_from_scans_list: true }),
    'ASM batch/recon — hidden from the Scans list',
  )
  assert.equal(activeScanLinkLabel('asm'), 'View active ASM scan')
})

test('an engine that does not say which kind gets no ASM claim', () => {
  assert.equal(activeScanNote({ kind: 'active_scan', scan_id: 's' }), null)
  assert.equal(activeScanLinkLabel(undefined), 'View active scan')
})

test('the ASM page takes its active-scan wording from the helper only', () => {
  assert.doesNotMatch(page, /\(ASM batch\/recon — hidden from the Scans list\)/)
  assert.doesNotMatch(page, />\s*View active ASM scan\s*</)
  assert.match(page, /activeScanNote\(b\)/)
  assert.match(page, /activeScanLinkLabel\(/)
})
