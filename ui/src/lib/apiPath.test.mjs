import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { pathSegment } from './apiPath.mjs'

const BASE = 'https://engine.example'

function resolved(template) {
  return new URL(template, BASE).pathname
}

// An ID taken from the address bar or a link reached fetch() unencoded. "../../settings" (or
// "%2e%2e") moved a credentialed request to another API route, and "x?y" started a query.
test('a hostile ID stays inside its path segment or is refused', () => {
  for (const hostile of ['../admin', 'a/b', 'x?scope=all', 'x#frag', '%2e%2e', 'a\\b']) {
    const path = resolved(`/targets/${pathSegment(hostile)}/asm/policy`)
    assert.ok(path.startsWith('/targets/'), `${hostile} -> ${path}`)
    assert.ok(path.endsWith('/asm/policy'), `${hostile} -> ${path}`)
    assert.equal(path.split('/').length, 5, `${hostile} -> ${path}`)
  }
  for (const dot of ['.', '..', '']) {
    assert.throws(() => pathSegment(dot), /dot path segment/)
  }
})

test('ordinary IDs are unchanged', () => {
  assert.equal(pathSegment('5f0c2b1e-3a4d-4e5f-9a8b-7c6d5e4f3a2b'), '5f0c2b1e-3a4d-4e5f-9a8b-7c6d5e4f3a2b')
  assert.equal(pathSegment(42), '42')
  assert.equal(pathSegment('scan.v2'), 'scan.v2')
})

// Every value interpolated into a path position of an API URL in api.ts goes through
// pathSegment(); a new call site that interpolates an ID directly fails here.
test('api.ts builds every API path segment with pathSegment', () => {
  const source = readFileSync(new URL('./api.ts', import.meta.url), 'utf8')
  const raw = []
  for (const [index, line] of source.split('\n').entries()) {
    if (!line.includes('${API_URL}')) continue
    const path = line.split('?')[0]
    for (const match of path.matchAll(/\/\$\{([^}]*)\}/g)) {
      if (match[1] === 'API_URL' || /^pathSegment\([\w.]+\)$/.test(match[1])) continue
      raw.push(`${index + 1}: ${match[0]}`)
    }
  }
  assert.deepEqual(raw, [])
})
