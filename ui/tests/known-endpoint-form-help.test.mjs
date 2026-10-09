import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL('../src/app/scan/new/page.tsx', import.meta.url),
  'utf8',
)

// Soak N54: the help said a field list was "body or query field names" without saying a POST
// field list is a JSON body, so an HTML sign-in form seeded that way was probed as a JSON API.
test('New Scan says a field list is JSON and how to declare an HTML form', () => {
  assert.match(page, /a JSON body on POST, PUT and PATCH, a query on GET/)
  assert.match(page, /For an HTML form, which posts form-encoded, prefix the fields with <code>form:<\/code>/)
  assert.match(page, /<code>form:username,password<\/code>/)
  assert.match(page, /POST \/login form:username,password'\}/)
})
