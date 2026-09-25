import { test } from 'node:test';
import assert from 'node:assert/strict';
import { factualResponse } from '../src/checks/factual.ts';
import type { Observation } from '../src/types.ts';

test('factual response reports measurements and scope without legacy judgments', () => {
  const data: Observation = { schema_version: '1', target: 'example.com', checked_at: new Date().toISOString(),
    summary: '1 observation worth reviewing', limitations: ['No redirects followed.'], checks: [
      { id: 'mail.spf', name: 'SPF', group: 'mail', status: 'warn', detail: 'Review the policy.',
        evidence: { record_count: 1, all_qualifier: '?', recursive_evaluation: false } },
      { id: 'http.headers', name: 'HTTPS security headers', group: 'http', status: 'warn', detail: 'Weak policy.',
        evidence: { hsts_max_age: 31536000, missing_headers: ['permissions-policy'], issues: ['missing:permissions-policy'] } },
      { id: 'mail.dkim', name: 'DKIM', group: 'mail', status: 'unknown', detail: 'Not checked.' }
    ] };
  const output = factualResponse(data, false, 'request-1');
  assert.equal(output.schema_version, '2');
  assert.deepEqual(output.observations.map(x => x.result), [
    { record_count: 1, all_qualifier: '?', recursive_evaluation: false },
    { hsts_max_age: 31536000, present_headers: ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy'], absent_headers: ['permissions-policy'] }, null
  ]);
  assert.ok(output.observations.every(x => typeof x.scope === 'string'));
  for (const key of ['summary', 'status', 'warn', 'pass', 'issues', 'detail']) assert.equal(JSON.stringify(output).includes(`"${key}"`), false);
});
