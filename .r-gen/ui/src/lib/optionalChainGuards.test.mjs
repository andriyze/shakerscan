// A guard of the form `obj?.field !== null` is TRUE when `obj` is absent -- undefined
// is not null -- so JSX behind it renders and any unguarded `obj.field` inside throws.
// In React that is not a blank card: the exception propagates and the whole page dies.
//
// This happened for real. `tls.testssl?.supports_tls13 !== null` sat dormant for as long
// as the report carried no `tls` section at all; the moment TLS posture was restored the
// guard started passing, `tls.testssl.supports_tls13` threw, and the entire scan report
// rendered as "This page couldn't load".
//
// `!= null` (loose) is correct and stays allowed: it covers null and undefined both.
// So is `?.field !== undefined`: that comparison is FALSE when the parent is absent, so
// the body never renders. Only the strict `!== null` form inverts into a crash.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')

function* sourceFiles(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      yield* sourceFiles(full)
    } else if (/\.(tsx?|mjs)$/.test(entry) && !entry.endsWith('.test.mjs')) {
      yield full
    }
  }
}

// `?.name !== null` — a strict null comparison after an optional chain.
const STRICT_NULL_AFTER_OPTIONAL = /\?\.[\w$]+(?:\??\.[\w$]+)*\s*!==\s*null\b/
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*|\{\/\*)/

test('no strict null-comparison directly after an optional chain', () => {
  const offenders = []
  for (const file of sourceFiles(SRC)) {
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, index) => {
      if (COMMENT_LINE.test(line)) return
      if (!STRICT_NULL_AFTER_OPTIONAL.test(line)) return
      // Comparing against undefined as well on the same line is exhaustive.
      if (/!==\s*undefined\b/.test(line)) return
      offenders.push(`${file.slice(SRC.length + 1)}:${index + 1}: ${line.trim().slice(0, 120)}`)
    })
  }
  assert.deepEqual(
    offenders,
    [],
    'use `!= null` (covers null and undefined) or compare against both:\n' + offenders.join('\n')
  )
})
