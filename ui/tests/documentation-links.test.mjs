import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const docs = readFileSync(path.join(root, 'src/app/docs/page.tsx'), 'utf8')
const fleet = readFileSync(path.join(root, 'src/app/fleet/page.tsx'), 'utf8')
const repository = readFileSync(path.join(root, 'src/lib/repository.ts'), 'utf8')

test('installed V2 documentation links do not drift to the moving main branch', () => {
  assert.match(repository, /blob\/v2/)
  assert.doesNotMatch(`${docs}\n${fleet}\n${repository}`, /github\.com\/andriyze\/shakerscan\/blob\/main/)
  assert.match(docs, /SHAKERSCAN_DOCUMENTATION_BLOB_URL/)
  assert.match(fleet, /SHAKERSCAN_DOCUMENTATION_BLOB_URL/)
})
