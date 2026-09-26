import assert from 'node:assert/strict'
import test from 'node:test'

import { discoveryOutcomeMessage, scanStartFailureReasons, targetWithResolvedHost } from './targetDns.ts'
import { getApiErrorMessage } from './apiConfig.ts'

const DNS_REASON = 'www.tidyhelpers.com does not resolve in DNS (no A/AAAA record), so it cannot be scanned. tidyhelpers.com does resolve; use tidyhelpers.com instead.'

test('the API detail of a refused scan reaches the operator', async () => {
  const response = new Response(JSON.stringify({ detail: DNS_REASON }), { status: 422 })
  assert.equal(await getApiErrorMessage(response, 'Failed to start scan'), DNS_REASON)
})

test('FastAPI validation arrays become a readable sentence', async () => {
  const response = new Response(JSON.stringify({
    detail: [
      { loc: ['body', 'budget_profile'], msg: 'Input should be fast, balanced or thorough' },
      { loc: ['body', 'policy'], msg: 'Field required' },
    ],
  }), { status: 422 })
  assert.equal(
    await getApiErrorMessage(response, 'Failed to start scan'),
    'Input should be fast, balanced or thorough; Field required',
  )
})

test('a non-JSON error body falls back to the fixed message', async () => {
  const response = new Response('<html>bad gateway</html>', { status: 502 })
  assert.equal(await getApiErrorMessage(response, 'Failed to start scan'), 'Failed to start scan')
})

test('Scan All names the distinct refusal reasons', () => {
  const results = [
    { status: 'fulfilled', value: { scan_id: 's1' } },
    { status: 'rejected', reason: new Error(DNS_REASON) },
    { status: 'rejected', reason: new Error(DNS_REASON) },
    { status: 'rejected', reason: new Error('Scan queue is full') },
    { status: 'rejected', reason: new Error('Target not found') },
  ]
  assert.deepEqual(scanStartFailureReasons(results), [DNS_REASON, 'Scan queue is full', 'and 1 other reason'])
  assert.deepEqual(scanStartFailureReasons([{ status: 'rejected', reason: 'boom' }]), ['boom'])
  assert.deepEqual(scanStartFailureReasons([{ status: 'fulfilled', value: {} }]), [])
})

test('a target registered under its www twin is scanned under that name', () => {
  const fallback = { requested_host: 'example.com', resolved_host: 'www.example.com' }
  assert.equal(targetWithResolvedHost('example.com', fallback), 'www.example.com')
  assert.equal(targetWithResolvedHost('https://example.com', fallback), 'https://www.example.com')
  assert.equal(targetWithResolvedHost('https://example.com:8443/app?x=1', fallback), 'https://www.example.com:8443/app?x=1')
  // Nothing to do without a fallback, or when the typed host is not the one that was replaced.
  assert.equal(targetWithResolvedHost('https://example.com', null), 'https://example.com')
  assert.equal(targetWithResolvedHost('https://other.example.org', fallback), 'https://other.example.org')
})

test('a finished discovery says how many names were skipped for having no address record', () => {
  const skipped = discoveryOutcomeMessage('tidyhelpers.com', {
    status: 'completed', subdomains_found: 3, new_subdomains: 1,
    resolution: { added: 1, unresolved_count: 2 },
  })
  assert.equal(skipped.kind, 'info')
  assert.match(skipped.message, /found 3 names; 1 new target added/)
  assert.match(skipped.message, /2 names found but not resolving in DNS \(no A\/AAAA record\) were skipped/)

  const clean = discoveryOutcomeMessage('example.com', {
    status: 'completed', subdomains_found: 1, new_subdomains: 1, resolution: { added: 1, unresolved_count: 0 },
  })
  assert.equal(clean.kind, 'success')
  assert.doesNotMatch(clean.message, /skipped/)

  const failed = discoveryOutcomeMessage('example.com', { status: 'failed', error_message: 'subfinder missing' })
  assert.equal(failed.kind, 'error')
  assert.match(failed.message, /subfinder missing/)
})
