import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = readFileSync(path.join(uiRoot, 'src/components/HttpArchiveExport.tsx'), 'utf8')

test('request archive is browsable as well as downloadable', () => {
  assert.match(source, /Browse recorded calls/)
  assert.match(source, /archive\.transactions\.map/)
  assert.match(source, /Request/)
  assert.match(source, /Response/)
})

test('archive browser supports server-side search, method, status and pagination', () => {
  assert.match(source, /params\.set\('search'/)
  assert.match(source, /params\.set\('method'/)
  assert.match(source, /params\.set\('status_code'/)
  assert.match(source, /void load\(offset \+ PAGE_SIZE\)/)
})

test('archive viewer explains historical and partial capture instead of implying completeness', () => {
  assert.match(source, /archive\.fidelity_detail/)
  assert.match(source, /No request archive is available for this historical run/)
  assert.match(source, /archive\.archive_total/)
})
