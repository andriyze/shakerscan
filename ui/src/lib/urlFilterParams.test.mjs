import { test } from 'node:test'
import assert from 'node:assert/strict'

import { parseFilterParams, parseReturnParams } from './urlFilterParams.mjs'

// A shared link's query names were written as properties of the filter object, so
// "?__proto__=..." reached the prototype setter and "?constructor=x" shadowed a built-in.
test('reserved names in the query string never become filter properties', () => {
  const params = new URLSearchParams('__proto__=polluted&constructor=x&prototype=y&severity=high&page=0')
  const filters = parseFilterParams(params, { status: 'active' })
  assert.deepEqual(Object.keys(filters).sort(), ['page', 'severity', 'status'])
  assert.equal(Object.getPrototypeOf(filters), Object.prototype)
  assert.equal(filters.constructor, Object)
  assert.equal(filters.page, 1)
  assert.equal(filters.severity, 'high')
  assert.equal({}.polluted, undefined)
})

test('return_ parameters drop reserved names and keep the rest', () => {
  const params = new URLSearchParams('return___proto__=a&return_constructor=b&return_q=login&other=1')
  const result = parseReturnParams(params)
  assert.deepEqual(result, { q: 'login' })
  assert.equal(Object.getPrototypeOf(result), Object.prototype)
})

test('URL values override defaults; a valid page is kept', () => {
  const filters = parseFilterParams(new URLSearchParams('status=resolved&page=3'), { status: 'active', page: 1 })
  assert.deepEqual(filters, { status: 'resolved', page: 3 })
})
