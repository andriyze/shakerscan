import assert from 'node:assert/strict'
import test from 'node:test'

import { discoveryOutcomeMessage, scanStartFailureReasons, sourceFailureReason, targetForRegisteredDnsFallback, targetWithResolvedHost } from './targetDns.ts'
import { getApiErrorMessage } from './apiConfig.ts'

const DNS_REASON = 'www.example.net does not resolve in DNS (no A/AAAA record), so it cannot be scanned. example.net does resolve; use example.net instead.'

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

test('a historical target retains its URL so Scan admission reuses its ID and authorization', () => {
  const fallback = { requested_host: 'example.com', resolved_host: 'www.example.com' }
  assert.equal(targetForRegisteredDnsFallback('example.com', 'https://example.com', fallback), 'example.com')
  assert.equal(targetForRegisteredDnsFallback('example.com', 'https://www.example.com', fallback), 'www.example.com')
  assert.equal(targetForRegisteredDnsFallback('example.com', 'https://other.test', fallback), 'example.com')
})

test('a finished discovery says how many names were skipped for having no address record', () => {
  const skipped = discoveryOutcomeMessage('example.net', {
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

test('a source that failed never reads as "no subdomains exist"', () => {
  const partial = discoveryOutcomeMessage('example.com', {
    status: 'completed', subdomains_found: 0, new_subdomains: 0, resolution: { added: 0, unresolved_count: 0 },
    source_errors: { crtsh: 'crt.sh HTTP 503; Certificate Transparency results are incomplete' },
  })
  assert.equal(partial.kind, 'warning')
  assert.equal(partial.persistent, true)
  // The source is named once, and its reason does not repeat the incompleteness the sentence states.
  assert.match(partial.message, /Results may be incomplete: crt\.sh \(HTTP 503\) did not answer/)
  assert.equal(partial.message.match(/crt\.sh/g).length, 1)
  assert.match(partial.message, /run discovery again later/)

  const allFailed = discoveryOutcomeMessage('example.com', {
    status: 'failed',
    error_message: 'No discovery source answered (crt.sh: crt.sh HTTP 503; results are incomplete); subdomains were not checked, try again later',
    source_errors: { crtsh: 'crt.sh HTTP 503; results are incomplete' },
  })
  assert.equal(allFailed.kind, 'error')
  assert.equal(allFailed.persistent, true)
  assert.equal(allFailed.message.match(/crt\.sh/g).length, 1)
  assert.match(allFailed.message, /crt\.sh \(HTTP 503\)/)

  assert.equal(sourceFailureReason('subfinder', 'subfinder timed out'), 'timed out')
  assert.equal(sourceFailureReason('crtsh', 'connection refused'), 'connection refused')
  assert.equal(sourceFailureReason('crtsh', 'crt.sh: results are incomplete'), 'crt.sh: results are incomplete')

  const none = discoveryOutcomeMessage('example.com', {
    status: 'completed', subdomains_found: 0, new_subdomains: 0, resolution: { added: 0, unresolved_count: 0 },
    source_errors: {},
  })
  assert.equal(none.kind, 'success')
  assert.doesNotMatch(none.message, /incomplete/)
})
