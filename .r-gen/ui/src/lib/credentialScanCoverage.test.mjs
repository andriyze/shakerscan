import assert from 'node:assert/strict'
import test from 'node:test'

import { credentialScanCoverageNote } from './credentialScanCoverage.mjs'

const SIGN_IN_ONLY = ['auth.session.establish', 'auth.session.refresh', 'auth.session.revoke', 'http.request']

test('a profile that signs in but cannot crawl says the pages behind the sign-in stay unreached', () => {
  // Scan applies the profile per action: a profile that allows only the sign-in signs in and then
  // crawls anonymously, which the picker presented as a fully usable identity.
  const note = credentialScanCoverageNote(SIGN_IN_ONLY, { families: [] })
  assert.match(note, /crawl/)
  assert.match(note, /anonymously/)
})

test('selected active families name the verifiers that would run without the identity', () => {
  const allowed = [...SIGN_IN_ONLY, 'web.crawl', 'web.browser_crawl']
  const note = credentialScanCoverageNote(allowed, { families: ['xss', 'sqli', 'recon'] })
  assert.match(note, /XSS/)
  assert.match(note, /SQL injection/)
  assert.equal(
    credentialScanCoverageNote([...allowed, 'xss.verify_batch'], { families: ['xss'] }),
    null,
  )
})

test('a profile that covers the scan, or the historical scan scope, needs no note', () => {
  assert.equal(credentialScanCoverageNote(['web.crawl', 'web.browser_crawl', 'http.request'], { families: ['recon'] }), null)
  assert.equal(credentialScanCoverageNote(['scan.execute'], { families: ['xss', 'sqli'] }), null)
  assert.equal(credentialScanCoverageNote([], { families: ['xss'] }), null)
})
