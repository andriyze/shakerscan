import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const panel = readFileSync(new URL('../src/components/AISettingsPanel.tsx', import.meta.url), 'utf8')

test('example values in the provider fields read as examples, not as saved values', () => {
  const literal = [...panel.matchAll(/placeholder="([^"]*)"/g)].map((match) => match[1])
  assert.ok(literal.length >= 4)
  for (const text of literal) assert.match(text, /^e\.g\. /, text)
})
