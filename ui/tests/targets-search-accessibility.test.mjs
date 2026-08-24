import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(new URL('../src/app/targets/page.tsx', import.meta.url), 'utf8')

test('target search has a stable accessible name', () => {
  assert.match(page, /aria-label="Search targets by URL or domain"/)
})
