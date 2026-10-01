import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(root, file), 'utf8')
const toolbar = read('src/app/findings/FindingsToolbar.tsx')
const list = read('src/app/findings/page.tsx')
const api = read('src/lib/api.ts')
const detail = read('src/app/findings/[id]/page.tsx')
const howToFix = read('src/components/findings/detail/HowToFix.tsx')

test('severity and proof pills select several values, sent as the comma lists the API takes', () => {
  assert.match(toolbar, /toggleListFilterValue\(values\.severity, sev, SEVERITY_LEVELS\)/)
  assert.match(toolbar, /toggleListFilterValue\(values\.proofState, proof\.key, PROOF_ORDER\)/)
  assert.match(toolbar, /aria-label="Filter by proof"/)
  // The proof pills use the badge words and the server's projection values.
  assert.match(toolbar, /key: 'verified', label: 'Proven'/)
  assert.match(toolbar, /key: 'suspected', label: 'Suspected'/)
  assert.match(api, /if \(params\?\.proof_state\) searchParams\.set\('proof_state', params\.proof_state\)/)
})

test('the proof filter narrows the list, its older-findings count, and the way back from a finding', () => {
  // The list and the count of what its freshness window hides use one set of filters.
  assert.equal(list.match(/proof_state: proofFilter \|\| undefined/g)?.length, 1)
  assert.match(list, /getFindings\(\{\s*\.\.\.scope,\s*seen_within_days: undefined,\s*not_seen_within_days: STALE_AFTER_DAYS,/)
  // The way back from a finding carries every filter in effect, proof_state included.
  assert.match(list, /detailUrlWithReturn\(`\/findings\/\$\{finding\.id\}`, filters, FINDINGS_FILTER_DEFAULTS\)/)
  assert.match(list, /severityFilter \|\| proofFilter \|\|/)
})

test('a finding shows the server fix guidance, says when it is general, and keeps tool steps', () => {
  assert.match(detail, /<HowToFix remediation=\{finding\.remediation\} toolSteps=\{evidence\.remediation\} \/>/)
  assert.match(howToFix, /remediation\.matched_by === 'title'/)
  assert.match(howToFix, />General guidance</)
  assert.match(howToFix, /remediation\?\.steps\?\.length \? remediation\.steps : toolSteps/)
  assert.match(howToFix, /Check the fix/)
})
