import assert from 'node:assert/strict'
import test from 'node:test'

import { scanLogEntry, scanPhasePresentation, scanResultPresentation } from './scanDetailPresentation.mjs'

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
