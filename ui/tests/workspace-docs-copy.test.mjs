import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = readFileSync(path.join(uiRoot, 'src/components/WorkspaceDocs.tsx'), 'utf8')

test('the managed workspace guide holds for a self-hosted deployment', () => {
  // A managed deployment can be self-hosted: no hosted-SaaS or subscription wording.
  assert.doesNotMatch(source, /hosted workspace/i)
  assert.doesNotMatch(source, /No local Docker installation/i)
  assert.doesNotMatch(source, /subscription/i)
  assert.doesNotMatch(source, /tenant/i)
  assert.match(source, /Work in this managed workspace/)
})
