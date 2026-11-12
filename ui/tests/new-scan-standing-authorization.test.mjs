import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const scan = fs.readFileSync(new URL('../src/app/scan/new/page.tsx', import.meta.url), 'utf8')

// After "Authorize testing" on the target, New Scan with active testing asked again for "I own or
// have explicit authorization..." before it would submit.
test('a target with a valid standing authorization needs no second confirmation for active testing', () => {
  assert.match(scan, /getTargetAuthorization\(selectedRegisteredTarget\.id\)/)
  assert.match(scan, /if \(cancelled \|\| !authorization\?\.standing\) return/)
  assert.match(scan, /authorization\.expires_at \? Date\.parse\(authorization\.expires_at\) <= Date\.now\(\) : false/)
  assert.match(scan, /const standingCoversScan = Boolean\(standingAuthorization\) && !credentialUse && !batchMode/)
  assert.match(scan, /const confirmationNeeded = \(activeTesting \|\| credentialUse\) && !standingCoversScan/)
  assert.match(scan, /if \(confirmationNeeded && !authorized\) \{/)
  assert.match(scan, /\(confirmationNeeded && !authorized\) \|\|/)
  assert.match(scan, /\{confirmationNeeded && \(/)
  assert.match(scan, /data-testid="standing-authorization"/)
  assert.doesNotMatch(scan, /\(\(activeTesting \|\| credentialUse\) && !authorized\)/)
})

test('credential use still asks for the confirmation', () => {
  assert.match(scan, /standingCoversScan = Boolean\(standingAuthorization\) && !credentialUse/)
})
