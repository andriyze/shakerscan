import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
// A run renders through the run-view components the page mounts.
const source = [
  fs.readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8'),
  ['HuntRunView', 'HuntResults', 'HuntTimeline', 'HuntDetails', 'huntFormat'].map((name) => {
    const file = name === 'huntFormat' ? `${name}.ts` : `${name}.tsx`
    return fs.readFileSync(path.join(root, 'src/components/hunt', file), 'utf8')
  }).join('\n'),
].join('\n')

test('Hunt action UI separates reservation ceilings from settled actual use', () => {
  assert.match(source, /Settled charge:/)
  assert.match(source, /conservative upper bound; measured consumption was unavailable/)
  assert.match(source, /Temporarily reserved:/)
  assert.match(source, /Released after settlement:/)
  assert.match(source, /Legacy reported charge:/)
  assert.match(source, /Budget settlement failed; no released amount is asserted/)
  assert.match(source, /No durable reservation existed/)
  assert.doesNotMatch(source, />\s*Used \{budget/)
})

test('Hunt detail shows persisted completion time and elapsed duration', () => {
  assert.match(source, />Completed<\/dt><dd[^>]*>\{new Date\(hunt\.completed_at\)\.toLocaleString\(\)\}/)
  assert.match(source, /formatHuntDuration\(hunt\.created_at, hunt\.completed_at\)/)
})

test('Hunt debrief leads with immutable action and evidence facts', () => {
  assert.match(source, /Factual run record/)
  assert.match(source, /hunt\.outcome_summary\??\.observation_count/)
  assert.match(source, /hunt\.outcome_summary\??\.finding_ids\.length/)
  assert.match(source, /hunt\.outcome_summary\??\.evidence_ids\.length/)
  assert.match(source, /Planner debrief:/)
  assert.match(source, /total_capability_calls/)
})
