import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

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


// Review sweep L3: the rule held only in api.ts; about forty API calls elsewhere used plain
// encodeURIComponent (".." passes) or interpolated an ID raw. Every API URL in the UI's sources --
// a line that builds on API_URL, and every relative API path an src/lib helper passes to fetch --
// builds each interpolated path segment with pathSegment(), and query values with URLSearchParams.
const SRC = fileURLToPath(new URL('..', import.meta.url))
// Path segments the code chooses itself, never a value from the address bar, a link or a record.
const CODE_CHOSEN = new Set(['API_URL', 'ownerPath'])

function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return sources(path)
    return /\.(ts|tsx|mjs)$/.test(entry.name) && !/\.test\./.test(entry.name) && !entry.name.endsWith('.d.ts')
      ? [path] : []
  })
}

export function rawApiPathSegments(file, source) {
  const inLib = relative(SRC, file).startsWith('lib/')
  const raw = []
  for (const [index, line] of source.split('\n').entries()) {
    const templates = line.match(/`[^`]*`/g) || []
    for (const template of templates) {
      const api = template.includes('${API_URL}') || template.startsWith('`${runPath(')
        || (inLib && template.startsWith('`/'))
      if (!api) continue
      const path = template.split('?')[0]
      for (const match of path.matchAll(/\/\$\{([^}]*)\}/g)) {
        if (CODE_CHOSEN.has(match[1]) || /^pathSegment\(.+\)$/.test(match[1])) continue
        raw.push(`${relative(SRC, file)}:${index + 1}: ${match[0]}`)
      }
      // An ID interpolated as a query value without encoding (`?scan_id=${scanId}`) can add
      // parameters; numbers and booleans the code computes cannot.
      for (const match of template.slice(path.length).matchAll(/=\$\{([^}]*)\}/g)) {
        if (!/^[\w.]*(Id|ID|_id)$/.test(match[1])) continue
        raw.push(`${relative(SRC, file)}:${index + 1}: ${match[0]}`)
      }
    }
  }
  return raw
}

test('every API URL in the UI builds its path segments with pathSegment', () => {
  const raw = sources(SRC).flatMap((file) => rawApiPathSegments(file, readFileSync(file, 'utf8')))
  assert.deepEqual(raw, [])
})

test('the source rule catches the shapes the review found', () => {
  const lib = join(SRC, 'lib', 'example.ts')
  const component = join(SRC, 'components', 'Example.tsx')
  const flagged = (file, line) => rawApiPathSegments(file, line).length
  assert.equal(flagged(component, 'fetch(`${API_URL}/devices/${encodeURIComponent(deviceId)}`)'), 1)
  assert.equal(flagged(component, 'const url = `${API_URL}/findings/${findingId}?scan_id=${scanId}`'), 2)
  assert.equal(flagged(lib, "request(`/targets/${encodeURIComponent(id)}/asset`)"), 1)
  assert.equal(flagged(lib, "fetch(`${runPath(huntId)}/investigations/${proposalId}`)"), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/findings/${pathSegment(id)}?${new URLSearchParams({ a: b })}`)'), 0)
  assert.equal(flagged(component, '<Link href={`/targets/${encodeURIComponent(id)}/asset`}>'), 0)  // a UI link
})
