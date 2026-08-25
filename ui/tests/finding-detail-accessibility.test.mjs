import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(
  new URL('../src/app/findings/[id]/page.tsx', import.meta.url),
  'utf8',
)

test('finding detail gives its icon-only return link an accessible name', () => {
  assert.match(page, /href=\{backUrl\}[\s\S]*?aria-label="Back to findings"/)
  assert.match(page, /<svg aria-hidden="true" className="w-5 h-5"/)
})
