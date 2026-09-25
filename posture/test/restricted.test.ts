import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isRestrictedTarget } from '../src/checks/restricted.ts';
import { handle, type Event } from '../src/checks/service.ts';
import type { Store } from '../src/checks/store.ts';

test('government, military and intergovernmental names are restricted', () => {
  for (const host of ['whitehouse.gov', 'www.cisa.gov', 'army.mil', 'nato.int', 'gov.uk', 'www.gov.uk', 'service.gov.uk', 'interieur.gouv.fr',
    'sat.gob.mx', 'mofa.go.jp', 'dia.govt.nz', 'eb.mil.br', 'usda.fed.us', 'dmv.ca.gov', 'dot.state.tx.us', 'ci.boston.ma.us',
    'canada.ca', 'cra-arc.gc.ca', 'bund.de', 'www.admin.ch', 'europa.eu', 'usps.com', 'si.edu', 'xn--mxtq1m', 'www.gov.cn', 'WHITEHOUSE.GOV.']) {
    assert.equal(isRestrictedTarget(host), true, host);
  }
});

test('ordinary names that merely contain government-like words are allowed', () => {
  for (const host of ['shakerscan.com', 'go.dev', 'govexec.com', 'military.com', 'gov.io.example.com', 'government.nl.example.org',
    'mil.example.com', 'internet.org', 'example.co.uk', 'gouvernement.fr', 'google.com', 'gob.example.com', 'army.com']) {
    assert.equal(isRestrictedTarget(host), false, host);
  }
});

test('restricted targets are refused before cache, quota or DNS', async () => {
  let touched = 0;
  const store: Store = { async consume() { touched++; return true; }, async get() { touched++; return null; }, async put() { touched++; } };
  const event: Event = { version: '2.0', rawPath: '/v1/check', rawQueryString: '', headers: { 'content-type': 'application/json' },
    body: '{"target":"www.whitehouse.gov"}', requestContext: { http: { method: 'POST', sourceIp: '198.51.100.5' } } };
  const r = await handle(event, store, 'test-only-secret-at-least-32-characters', true, async () => { touched++; throw Error('DNS called'); });
  assert.equal(r.statusCode, 403);
  assert.equal(JSON.parse(r.body).error.code, 'target_restricted');
  // Only the per-minute caller limit runs before request parsing.
  assert.equal(touched, 1);
});
