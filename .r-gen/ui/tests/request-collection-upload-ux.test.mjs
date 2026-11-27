import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(new URL('../src/app/request-collections/page.tsx', import.meta.url), 'utf8')

test('collection upload keeps JSON errors visible in the modal', () => {
  assert.match(page, /error=\{uploadErrors\.document\}/)
  assert.match(page, /error=\{uploadErrors\.environment\}/)
  assert.match(page, /role="alert"/)
})

test('collection JSON is parsed before the upload request starts', () => {
  assert.match(page, /document = parseJson\(documentText, 'Collection document'\)/)
  assert.match(page, /environment = parseJson\(environmentText, 'Environment document'\)/)
})
