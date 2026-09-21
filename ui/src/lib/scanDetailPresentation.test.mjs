import assert from 'node:assert/strict'
import test from 'node:test'

import { carriedOverFromDecision, carriedOverSummary, releaseLine, scanFindingIdentity, scanLogEntry, scanPhasePresentation, scanResultPresentation } from './scanDetailPresentation.mjs'

test('running phases are explained in operator language', () => {
  assert.deepEqual(scanPhasePresentation({ status: 'running', current_phase: 'active_sqli', progress: 60 }), {
    label: 'Testing the attack surface',
    description: 'Running the checks permitted by this scan’s policy and resource budget.',
    progress: 60,
  })
  assert.equal(scanPhasePresentation({ status: 'pending' }).label, 'Waiting for a worker')
})

test('progress logs become readable milestones without discarding raw evidence', () => {
  const entry = scanLogEntry('[progress] phase=validation pct=92 message=finding validation complete')
  assert.equal(entry.kind, 'milestone')
  assert.equal(entry.message, 'finding validation complete')
  assert.equal(entry.meta, '92% · validation')
  assert.match(entry.raw, /phase=validation/)
  assert.equal(scanLogEntry('WARNING: request budget reached').kind, 'warning')
})

test('successful diagnostics with empty error fields remain neutral', () => {
  const probe = scanLogEntry('Diagnostic Discover Web Probe · outcome=success · reason=none · error=none · execution=unknown · limiter=within_ceiling')
  const crawl = scanLogEntry('Diagnostic Discover Web Crawl · outcome=success · reason=none · error=none · http=0/121/150 observed/hard/reserved')
  assert.equal(probe.kind, 'detail')
  assert.equal(probe.label, 'activity')
  assert.equal(crawl.kind, 'detail')
})

test('structured diagnostic failures and real exceptions remain errors', () => {
  assert.equal(scanLogEntry('Diagnostic Discover Web Crawl · outcome=failed · error=connection_refused').kind, 'error')
  assert.equal(scanLogEntry('[error] worker aborted').kind, 'error')
  assert.equal(scanLogEntry('Traceback: connection failed').kind, 'error')
  assert.equal(scanLogEntry('Diagnostic · outcome=success · error=connection_refused').kind, 'error')
})

test('budget-skipped diagnostics are warnings even when the adapter records an error class', () => {
  const entry = scanLogEntry('Diagnostic Discover Web Content · outcome=skipped · reason=insufficient_plan_budget · error=unclassified_adapter_error · execution=not_started')
  assert.equal(entry.kind, 'warning')
  assert.equal(entry.label, 'attention')
})

test('a shallow clean scan leads with an honest conclusion instead of a perfect score', () => {
  const result = scanResultPresentation({
    score: 100,
    grade: 'A',
    result: {
      findings: [{ severity: 'info', title: 'Missing headers' }],
      result: { risk_score: 100, risk_grade: 'A' },
      http: { missing_security_headers: ['content-security-policy'] },
      scan_metadata: { budget_used: { http_requests: 161 } },
    },
    options: {
      budget_profile: 'fast',
      scan_execution_plan: {
        budget_profile: 'fast',
        policy: { active_testing: false },
        resolved_families: ['recon', 'nuclei_passive'],
      },
    },
  }, { band: 'weak', label: 'Weak coverage' })

  assert.equal(result.headline, 'No material vulnerability confirmed in this run')
  assert.equal(result.confidence, 'Weak coverage — this is not a clean bill of health.')
  assert.equal(result.observedRiskScore, 100)
  assert.deepEqual(result.missingHeaders, ['content-security-policy'])
})

test('an unobservable application leads with not examined instead of clean', () => {
  const result = scanResultPresentation({
    result: {
      findings: [],
      result: {
        risk_score: 100,
        risk_grade: 'A',
        grade_reliable: false,
        risk_assessment_state: 'not_examined',
      },
      http: { status: 401, posture_observed: false, missing_security_headers: [] },
    },
  }, { band: 'limited', label: 'Limited coverage' })

  assert.equal(result.headline, 'Application was not examined')
  assert.match(result.explanation, /authentication challenge/)
  assert.equal(result.notExamined, true)
})

test('a bound origin that only redirects is explained as a redirect, not a login wall', () => {
  const result = scanResultPresentation({
    result: {
      findings: [],
      result: { risk_assessment_state: 'not_examined', application_observed: false },
      http: { status: 301, posture_observed: false, missing_security_headers: [] },
      coverage: { reasons: ['application_not_observed', 'bound_origin_redirects_off_origin'] },
    },
  }, { band: 'limited', label: 'Limited coverage' })

  assert.equal(result.headline, 'Application was not examined')
  assert.match(result.explanation, /redirect to another origin/)
  assert.doesNotMatch(result.explanation, /authentication challenge/)
})

test('confirmed and candidate material findings get distinct conclusions', () => {
  const confirmed = scanResultPresentation({
    result: { findings: [{ severity: 'high', verified: true, proof_state: 'verified' }] },
  }, { band: 'strong', label: 'Strong coverage' })
  assert.match(confirmed.headline, /confirmed material issue requires action/)

  const candidate = scanResultPresentation({
    result: { findings: [{ severity: 'high', suspected: true }] },
  }, { band: 'limited', label: 'Limited coverage' })
  assert.match(candidate.headline, /potential material issue needs verification/)
})

test('ambiguous v3 reports claim posture deductions only when they carry one', () => {
  const legacy = scanResultPresentation({
    result: {
      result: { score_policy: 'risk_and_assurance/v3', score: 100 },
      http: { missing_security_headers: ['content-security-policy'] },
    },
  }, { band: 'weak', label: 'Weak coverage' })
  assert.equal(legacy.postureIncluded, false)

  const postureAware = scanResultPresentation({
    result: {
      result: { score_policy: 'risk_and_assurance/v3', score: 78, posture_penalty: 22 },
      http: { missing_security_headers: ['content-security-policy'] },
    },
  }, { band: 'weak', label: 'Weak coverage' })
  assert.equal(postureAware.postureIncluded, true)
  assert.equal(postureAware.posturePenalty, 22)
})

test('raw and persisted forms of the same scan finding share one UI identity', () => {
  const raw = {
    title: 'Legacy TLS protocol negotiated',
    url: 'https://gap-analytics.com/',
    tool: 'tls.inspect',
    cwe: 'CWE-326',
  }
  const persistedSummary = {
    id: 'finding-1',
    title: 'Legacy TLS protocol negotiated',
    url: 'https://gap-analytics.com/',
    tool: 'tls.inspect',
  }

  assert.equal(scanFindingIdentity(raw), scanFindingIdentity(persistedSummary))
})

test('finding identity is the persisted fingerprint when there is one, and paths keep their case', () => {
  const a = { fingerprint: 'fp-a', title: 'Reflected XSS', url: 'http://app/q', tool: 'xss' }
  const b = { fingerprint: 'fp-b', title: 'Reflected XSS', url: 'http://app/q', tool: 'xss' }
  assert.notEqual(scanFindingIdentity(a), scanFindingIdentity(b))
  assert.equal(scanFindingIdentity(a), scanFindingIdentity({ fingerprint: 'fp-a', title: 'renamed' }))
  assert.notEqual(
    scanFindingIdentity({ title: 'Exposed panel', url: 'http://app/Admin', tool: 'probe' }),
    scanFindingIdentity({ title: 'Exposed panel', url: 'http://app/admin', tool: 'probe' }),
  )
})

test('requested coverage failures are promoted into the result summary', () => {
  const result = scanResultPresentation({
    result: {
      findings: [],
      result: { risk_score: 94, risk_grade: 'A' },
      coverage: {
        status: 'partial',
        reasons: ['subdomain_discovery_failed'],
      },
    },
  }, { band: 'weak', label: 'Weak coverage' })

  assert.deepEqual(result.coverageWarnings, ['subdomain discovery failed'])
})


test('the testing tile names what active permission bought, or warns that it bought nothing', () => {
  const ran = scanResultPresentation({
    options: { scan_execution_plan: { policy: { active_testing: true }, resolved_families: ['recon', 'nuclei_passive', 'xss', 'sqli', 'sensitive_exposure'] } },
    result: { findings: [], result: {} },
  }, { band: 'limited', label: 'Limited coverage' })
  assert.equal(ran.testingSummary, 'Active · XSS, SQLi, exposure')
  assert.equal(ran.testingWarning, null)

  const permittedOnly = scanResultPresentation({
    options: { scan_execution_plan: { policy: { active_testing: true }, resolved_families: ['recon', 'nuclei_passive'] } },
    result: { findings: [], result: {} },
  }, { band: 'limited', label: 'Limited coverage' })
  assert.equal(permittedOnly.testingSummary, 'Active allowed · none selected')
  assert.match(permittedOnly.testingWarning, /standard active preset/)

  const passive = scanResultPresentation({
    options: { scan_execution_plan: { policy: { active_testing: false }, resolved_families: ['recon'] } },
    result: { findings: [], result: {} },
  }, { band: 'limited', label: 'Limited coverage' })
  assert.equal(passive.testingSummary, 'Passive only')
})


test('the conclusion names the next step for each limit it reports', () => {
  const redirected = scanResultPresentation({
    target_url: 'https://a3sec.net',
    result: {
      findings: [],
      result: { risk_assessment_state: 'not_examined', application_observed: false },
      http: { status: 301, redirect_location: 'https://www.a3sec.net/' },
      coverage: { reasons: ['application_not_observed', 'bound_origin_redirects_off_origin'] },
    },
  }, { band: 'weak', label: 'Weak coverage' })
  assert.deepEqual(redirected.nextSteps.map((step) => step.key), ['serving-origin'])
  assert.equal(redirected.nextSteps[0].label, 'Scan www.a3sec.net instead')
  assert.equal(redirected.nextSteps[0].href, '/scan/new?target=https%3A%2F%2Fwww.a3sec.net')

  const permittedOnly = scanResultPresentation({
    target_url: 'http://crapi-web',
    options: { scan_execution_plan: { policy: { active_testing: true }, resolved_families: ['recon', 'nuclei_passive'] } },
    result: { findings: [], result: {} },
  }, { band: 'limited', label: 'Limited coverage' })
  assert.deepEqual(permittedOnly.nextSteps.map((step) => step.key), ['standard-active', 'credentials'])
  assert.match(permittedOnly.nextSteps[0].href, /preset=standard_active/)

  const authenticated = scanResultPresentation({
    options: { scan_execution_plan: { policy: { active_testing: true }, resolved_families: ['recon', 'xss'] }, credential_profile_refs: ['cred-1'] },
    result: { findings: [], result: {}, smart_coverage: { auth_states_tested: ['anonymous', 'user'] } },
  }, { band: 'adequate', label: 'Adequate coverage' })
  assert.deepEqual(authenticated.nextSteps, [])
})


test('carried over counts only active rows this run neither wrote, last saw, nor reported by fingerprint', () => {
  const scan = { id: 'scan-2', result: { findings: [{ fingerprint: 'fp-xfo', title: 'Missing HTTP response header: X-Frame-Options', url: 'http://app/', tool: 'nuclei' }] } }
  const rows = [
    { severity: 'high', status: 'active', scan_id: 'scan-1', last_seen_scan_id: 'scan-1', title: 'Sensitive exposure: environment secret file', url: 'http://app/.env', tool: 'probe' },
    { severity: 'high', status: 'resolved', scan_id: 'scan-1', last_seen_scan_id: 'scan-1', title: 'Old thing', url: 'http://app/x', tool: 't' },
    { severity: 'medium', status: 'false_positive', scan_id: 'scan-1', last_seen_scan_id: 'scan-1', title: 'FP', url: 'http://app/y', tool: 't' },
    // Same fingerprint as a reported finding: observed by this run even though linkage lags.
    { severity: 'info', status: 'active', scan_id: 'scan-1', last_seen_scan_id: 'scan-3', fingerprint: 'fp-xfo', title: 'Missing HTTP response header: X-Frame-Options', url: 'http://app/', tool: 'nuclei' },
    { severity: 'info', status: 'active', scan_id: 'scan-2', last_seen_scan_id: 'scan-2', title: 'Seen here', url: 'http://app/z', tool: 't' },
  ]
  const summary = carriedOverSummary(scan, rows)
  assert.deepEqual(summary, { state: 'ready', count: 1, material: 1, highest: 'high', complete: true })
  assert.equal(carriedOverSummary(scan, [], 'loading').state, 'loading')
  assert.equal(carriedOverSummary(scan, [], 'error').count, 0)
})

test('a distinct fingerprint with the same display strings stays carried over', () => {
  // The old display-string key collapsed these two and dropped an unresolved finding.
  const scan = { id: 'scan-2', result: { findings: [{ fingerprint: 'fp-new', title: 'Reflected XSS', url: 'http://app/q', tool: 'xss', template_id: 'xss-002' }] } }
  const rows = [
    { severity: 'high', status: 'active', scan_id: 'scan-1', last_seen_scan_id: 'scan-1', fingerprint: 'fp-old', title: 'Reflected XSS', url: 'http://app/q', tool: 'xss', template_id: 'xss-001' },
  ]
  assert.equal(carriedOverSummary(scan, rows).count, 1)
  // No fingerprint and no linkage is uncertainty, never proof of re-observation.
  const unlinked = [{ severity: 'medium', status: 'active', title: 'Reflected XSS', url: 'http://app/q', tool: 'xss' }]
  assert.equal(carriedOverSummary(scan, unlinked).count, 1)
})

test('a partial history never reads as an all-clear', () => {
  const scan = { id: 'scan-2', result: { findings: [] } }
  const summary = carriedOverSummary(scan, [], 'partial')
  assert.equal(summary.state, 'partial')
  assert.equal(summary.complete, false)
  assert.equal(summary.count, 0)
})

test('the release line claims an earlier-scan origin only when the decision says so', () => {
  const carried = releaseLine({
    decision: 'block',
    blocking_findings: [{ id: 'f1', from_target_active: true, scan_id: 'scan-1' }],
  }, 'scan-2', 0)
  assert.match(carried.text, /from earlier scans that this run did not re-examine/)

  const current = releaseLine({
    decision: 'block',
    blocking_findings: [{ id: 'f2', scan_id: 'scan-2' }],
  }, 'scan-2', 0)
  assert.doesNotMatch(current.text, /earlier scans/)
  assert.match(current.text, /1 unresolved finding on this target/)

  const review = releaseLine({ decision: 'needs_review', rationale: 'Required deployment evidence is missing or incomplete.', blocking_findings: [{ id: 'f1' }] }, 'scan-2', 0)
  assert.equal(review.tone, 'review')
  assert.match(review.text, /^Required deployment evidence is missing or incomplete\. 1 unresolved finding on this target\.$/)
  assert.equal(releaseLine(null, 'scan-2', 0), null)
})


test('a parallel child prefix stays visible as the entry origin instead of being eaten as the source', () => {
  const entry = scanLogEntry('[Discovery] [scan] Started Discover Web Probe · 5%')
  assert.equal(entry.child, 'Discovery')
  assert.equal(entry.source, 'scan')
  assert.equal(entry.kind, 'milestone')
  assert.match(entry.meta, /^Discovery/)
  const shard = scanLogEntry('[Shard 3] [scan] Finished Verify XSS · timed_out · 44%')
  assert.equal(shard.child, 'Shard 3')
  assert.equal(scanLogEntry('[scan] plain line').child, '')
})


test('the server summary from the decision wins over the client fallback', () => {
  assert.deepEqual(
    carriedOverFromDecision({ carried_over: { count: 3, material: 2, highest: 'High', complete: true } }),
    { state: 'ready', count: 3, material: 2, highest: 'high', complete: true, source: 'server' },
  )
  const partial = carriedOverFromDecision({ carried_over: { count: 0, complete: false, unloaded_active: 40 } })
  assert.equal(partial.state, 'partial')
  assert.equal(partial.complete, false)
  assert.equal(carriedOverFromDecision({ carried_over: null }), null)
  assert.equal(carriedOverFromDecision({}), null)
  assert.equal(carriedOverFromDecision(null), null)
})
