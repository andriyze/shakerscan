import assert from 'node:assert/strict'
import test from 'node:test'

import { scanFindingIdentity, scanLogEntry, scanPhasePresentation, scanResultPresentation } from './scanDetailPresentation.mjs'

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
