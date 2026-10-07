import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL('../src/app/findings/[id]/page.tsx', import.meta.url),
  'utf8',
)

test('finding detail gives its icon-only return link an accessible name', () => {
  assert.match(page, /href=\{backUrl\}[\s\S]*?aria-label="Back to findings"/)
  // The chevron is decorative; the link's name comes from aria-label, not the icon.
  assert.match(page, /aria-label="Back to findings"[\s\S]*?<svg aria-hidden="true" className="[^"]+"/)
})
