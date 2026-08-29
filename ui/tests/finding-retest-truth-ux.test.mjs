import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const detail = fs.readFileSync(path.join(root, 'src/app/findings/[id]/page.tsx'), 'utf8')
const list = fs.readFileSync(path.join(root, 'src/app/findings/page.tsx'), 'utf8')

test('finding surfaces distinguish canonical proof from latest retest', () => {
  assert.match(list, /finding\.latest_retest_verdict/)
  assert.doesNotMatch(list, /<RetestVerdictBadge verdict=\{finding\.last_verification_verdict\}/)
  assert.match(detail, /const latestRetestVerdict = latestRetest\?\.verdict/)
  assert.match(detail, /deterministic proof:/)
  assert.match(detail, /verdict basis: advisory AI assessment/)
  assert.match(detail, /AI assessment — advisory, cannot override deterministic proof:/)
})
