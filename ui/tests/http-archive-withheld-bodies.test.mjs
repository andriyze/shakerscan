import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

// External release audit, 2026-10-09 (R2): a masked export leaves a body out past its masking
// budget or size limit and lists it under payload_omitted. Both archive views must say so rather
// than read a withheld body as "No body recorded".
const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(uiRoot, file), 'utf8')
const helper = read('src/lib/archiveBodies.ts')
const hunt = read('src/components/hunt/HuntRequestsPanel.tsx')
const scan = read('src/components/HttpArchiveExport.tsx')

test('a body listed under payload_omitted is labelled withheld', () => {
  assert.match(helper, /BODY_WITHHELD_LABEL = 'Body withheld from this export \(size\/budget limit\)'/)
  assert.match(helper, /payload_omitted \|\| \[\]\)\.includes\(`\$\{side\}_body`\)/)
})

test('the Hunt request panel shows the withheld label instead of "No body recorded"', () => {
  assert.match(hunt, /payload_omitted\?: string\[\] \| null/)
  assert.match(hunt, /withheld \? BODY_WITHHELD_LABEL : 'No body recorded'/)
  assert.match(hunt, /withheld=\{bodyWithheld\(row, 'request'\)\}/)
  assert.match(hunt, /withheld=\{bodyWithheld\(row, 'response'\)\}/)
})

test('the scan and Hunt archive browser marks a withheld body on each side', () => {
  assert.match(scan, /payload_omitted\?: string\[\] \| null/)
  assert.match(scan, /bodyWithheld\(transaction, 'request'\) \? ` · \$\{BODY_WITHHELD_LABEL\}`/)
  assert.match(scan, /bodyWithheld\(transaction, 'response'\) \? ` · \$\{BODY_WITHHELD_LABEL\}`/)
})
