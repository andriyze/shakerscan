import assert from 'node:assert/strict'
import test from 'node:test'

import {
  carriedOverFromDecision,
  carriedOverSummary,
  domainRatePresentation,
  formatResumeTime,
  groupScanFindings,
  isProvenFinding,
  notExaminedExplanation,
  reconciledScanFindings,
  releaseLine,
  scanFindingIdentity,
  scanLogEntry,
  scanPhasePresentation,
  scanResultPresentation,
} from './scanDetailPresentation.mjs'

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

test('selected active families without candidate actions are named as examination gaps', () => {
  const result = scanResultPresentation({
    status: 'completed',
    options: { scan_execution_plan: {
      budget_profile: 'thorough',
      policy: { active_testing: true },
      resolved_families: ['recon', 'xss', 'sqli', 'bola', 'sensitive_exposure'],
    } },
    result: {
      findings: [],
      result: { risk_score: 100, risk_grade: 'A', grade_reliable: true },
      coverage: { family_coverage: [
        { family: 'bola', planned_candidates: 0, attempted_candidates: 0, coverage_status: 'complete', reason: 'no_candidates' },
        { family: 'sensitive_exposure', planned_candidates: 12, attempted_candidates: 12, coverage_status: 'complete' },
      ] },
    },
  }, { band: 'strong', label: 'Strong coverage' })

  assert.deepEqual(result.candidateGapFamilies, ['xss', 'sqli', 'bola'])
  assert.equal(result.coverageIncomplete, true)
  assert.doesNotMatch(result.confidence, /supports this run-level conclusion/)
  assert.doesNotMatch(result.confidence, /did not finish everything it planned/)
  assert.match(result.confidence, /listed coverage gaps limit/)
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

test('proof is the server projection, never the scanner word or a second boolean', () => {
  // GET /scans/{id} projects the findings API vocabulary onto every report finding; the honey
  // scan proved ten critical/high exposures and the page said "0 proven, need verification".
  const proven = { severity: 'critical', verified: true, proof_state: 'verified', scan_time_proof_state: 'exploited' }
  const lead = { severity: 'medium', proof_state: 'suspected', scan_time_proof_state: 'candidate' }
  const result = scanResultPresentation({ result: { findings: [proven, proven, lead] } }, { band: 'limited', label: 'Limited coverage' })
  assert.equal(result.confirmedCount, 2)
  assert.equal(result.candidateCount, 1)
  assert.match(result.headline, /^2 confirmed material issues require action/)
  // The scanner's own word alone is not the projection; neither is a generic verified flag.
  assert.equal(isProvenFinding({ proof_state: 'exploited', verified: true }), false)
  assert.equal(isProvenFinding({ verified: true }), false)
  assert.equal(isProvenFinding({ proof_state: 'verified' }), true)
})

test('the Findings tab groups by proof, lists a title once, and orders by severity', () => {
  const exposure = (path, severity = 'critical') => ({ title: 'Sensitive exposure: cloud credential material', severity, proof_state: 'verified', url: `https://t.test${path}` })
  const groups = groupScanFindings([
    { title: 'Missing HTTP response header: Referrer-Policy', severity: 'info', proof_state: 'suspected' },
    { title: 'Git Configuration - Detect', severity: 'medium', proof_state: 'suspected' },
    { title: 'Sensitive exposure: version control exposure', severity: 'high', proof_state: 'verified' },
    exposure('/.aws/credentials'), exposure('/settings.py'), exposure('/actuator/env'),
    { title: 'Possible SQL injection', severity: 'critical', proof_state: 'suspected' },
  ])
  assert.deepEqual(groups.proven.map((c) => [c.severity, c.title, c.findings.length]), [
    ['critical', 'Sensitive exposure: cloud credential material', 3],
    ['high', 'Sensitive exposure: version control exposure', 1],
  ])
  // An unproven critical is a lead to verify, never folded into the informational rest.
  assert.deepEqual(groups.verify.map((c) => c.severity), ['critical', 'medium'])
  assert.deepEqual(groups.informational.map((c) => c.title), ['Missing HTTP response header: Referrer-Policy'])
  assert.deepEqual(groupScanFindings(null), { proven: [], verify: [], informational: [] })
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
    url: 'https://example.net/',
    tool: 'tls.inspect',
    cwe: 'CWE-326',
  }
  const persistedSummary = {
    id: 'finding-1',
    title: 'Legacy TLS protocol negotiated',
    url: 'https://example.net/',
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
    target_url: 'https://example.org',
    result: {
      findings: [],
      result: { risk_assessment_state: 'not_examined', application_observed: false },
      http: { status: 301, redirect_location: 'https://www.example.org/' },
      coverage: { reasons: ['application_not_observed', 'bound_origin_redirects_off_origin'] },
    },
  }, { band: 'weak', label: 'Weak coverage' })
  assert.deepEqual(redirected.nextSteps.map((step) => step.key), ['serving-origin'])
  assert.equal(redirected.nextSteps[0].label, 'Scan www.example.org instead')
  assert.equal(redirected.nextSteps[0].href, '/scan/new?target=https%3A%2F%2Fwww.example.org')

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

test('a report finding without a fingerprint joins its durable row once', () => {
  const raw = { title: 'Sensitive exposure', url: 'http://app/.env', tool: 'probe', severity: 'high', proof_state: 'verified' }
  const saved = { ...raw, id: 'finding-1', fingerprint: 't:canonical', scan_id: 'scan-2', verified: true }
  const scan = { id: 'scan-2', result: { findings: [raw] }, findings: [saved] }
  const result = reconciledScanFindings(scan, [saved])
  assert.equal(result.current.length, 1)
  assert.equal(result.persistedCurrentCount, 1)
  assert.equal(result.current[0].id, 'finding-1')
  assert.equal(result.current[0]._persisted, true)
})

test('display fallback matches one-to-one and does not collapse distinct fingerprints', () => {
  const raw = { title: 'Same label', url: 'http://app/Item', tool: 'probe', severity: 'high' }
  const rows = ['first', 'second'].map((id) => ({ ...raw, id, fingerprint: `fp-${id}`, last_seen_scan_id: 'scan-2' }))
  const once = reconciledScanFindings({ id: 'scan-2', result: { findings: [raw] } }, rows)
  assert.equal(once.current.length, 2)
  assert.equal(once.persistedCurrentCount, 2)
  const named = reconciledScanFindings({ id: 'scan-2', result: { findings: [{ ...raw, fingerprint: 'fp-new' }] } }, rows)
  assert.equal(named.current.length, 3)
  const differentCase = reconciledScanFindings({ id: 'scan-2', result: { findings: [{ ...raw, url: 'http://app/item' }] } }, rows)
  assert.equal(differentCase.current.length, 3)
})

test('history rows from earlier scans stay outside this scan findings', () => {
  const old = { id: 'old', fingerprint: 'fp-old', scan_id: 'scan-1', last_seen_scan_id: 'scan-1', title: 'Old' }
  const result = reconciledScanFindings({ id: 'scan-2', result: { findings: [] } }, [old])
  assert.equal(result.current.length, 0)
  assert.equal(result.persistedCurrentCount, 0)
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

test('an unreachable scheme-less target names the origins that did not answer', () => {
  const text = notExaminedExplanation({
    reachability: {
      status: 'unavailable',
      transport: {
        effective_origin: null,
        attempts: [
          { origin: 'https://dark.example.com/', outcome: 'unreachable', error: 'request_error:ConnectError' },
          { origin: 'http://dark.example.com/', outcome: 'unreachable', error: 'request_error:ConnectError' },
        ],
      },
    },
    coverage: { reasons: ['target_unreachable'] },
  })
  assert.match(text, /No origin of this target answered/)
  assert.match(text, /https:\/\/dark\.example\.com \(request_error:ConnectError\)/)
  assert.match(text, /http:\/\/dark\.example\.com \(request_error:ConnectError\)/)
})

test('a redirect-only origin says where the application is', () => {
  const text = notExaminedExplanation({
    coverage: {
      reasons: ['application_not_observed', 'bound_origin_redirects_off_origin'],
      not_examined_reason: "the target redirects to https://honey.example.com, outside this scan's origin",
    },
    http: { status: 301 },
  })
  assert.match(text, /redirects to https:\/\/honey\.example\.com, outside this scan's origin/)
})

test('a quota wait names the domain and the estimated resume time instead of blaming workers', () => {
  const scan = {
    status: 'queued',
    current_phase: 'waiting_for_domain_rate',
    progress: 5,
    domain_rate: {
      state: 'waiting',
      work_class: 'background',
      root_domain: 'ukrtampa.com',
      cap_per_hour: 1000,
      resume_estimate: '2026-09-27T16:40:00Z',
    },
  }
  const phase = scanPhasePresentation(scan, { timeZone: 'UTC' })
  assert.equal(phase.label, "Waiting for ukrtampa.com's hourly test budget (resumes about 16:40)")
  assert.match(phase.description, /1000 tested endpoints per hour/)
  assert.match(phase.description, /estimated about 16:40/)
  assert.equal(phase.progress, 5)
  const unknown = scanPhasePresentation({ ...scan, domain_rate: { ...scan.domain_rate, resume_estimate: null } }, { timeZone: 'UTC' })
  assert.equal(unknown.label, "Waiting for ukrtampa.com's hourly test budget")
  // A queued scan without a quota wait is still waiting for a worker.
  assert.equal(scanPhasePresentation({ status: 'queued' }).label, 'Waiting for a worker')
})

test('a past wait is not presented as the current reason', () => {
  const scan = { status: 'running', current_phase: 'active_sqli', domain_rate: { state: 'waited', root_domain: 'example.com' } }
  assert.equal(domainRatePresentation(scan), null)
  assert.equal(scanPhasePresentation(scan).label, 'Testing the attack surface')
})

test('a quota budget reduction is shown in plain words', () => {
  const reason = "Background ASM batch reduced to 20 of 50 endpoints by ukrtampa.com's hourly test budget (1000 endpoints per hour across its targets); the rest return to the inventory."
  const quota = domainRatePresentation({
    status: 'completed',
    domain_rate: { state: 'reduced', root_domain: 'ukrtampa.com', reduction: { requested: 50, granted: 20, reason } },
  })
  assert.equal(quota.kind, 'reduced')
  assert.equal(quota.label, "Budget reduced by ukrtampa.com's hourly test budget")
  assert.equal(quota.description, reason)
  assert.equal(domainRatePresentation({ status: 'completed', domain_rate: { state: 'admitted', work_class: 'operator' } }), null)
  assert.equal(formatResumeTime('not a date'), '')
})
