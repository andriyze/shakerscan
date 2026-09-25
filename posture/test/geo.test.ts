import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../src/budget.ts';
import { checkCallerCountry, BLOCKED_COUNTRIES, type CallerCountryCache } from '../src/checks/geo.ts';
import { handle, type Event } from '../src/checks/service.ts';
import type { Store } from '../src/checks/store.ts';

const secret = 'test-only-secret-at-least-32-characters';
const ip = '198.51.100.5';
const event: Event = { version: '2.0', rawPath: '/v1/check', rawQueryString: '',
  headers: { 'content-type': 'application/json', 'cf-connecting-ip': '8.8.8.8' },
  body: '{"target":"example.com"}', requestContext: { http: { method: 'POST', sourceIp: ip } } };

test('requested countries are blocked and a trusted source IP controls the decision', async () => {
  assert.deepEqual([...BLOCKED_COUNTRIES].sort(), ['BR', 'CN', 'HK', 'ID', 'IN', 'IR', 'KP', 'NG', 'PK', 'RU']);
  const values = new Map<string, string>();
  const cache: CallerCountryCache = {
    async get(key) { return values.get(key) ?? null; },
    async put(key, country) { values.set(key, country); }
  };
  let lookups = 0, checks = 0;
  const lookup = async (url: string, init?: RequestInit) => {
    lookups++;
    assert.equal(url, `https://api.ipinfo.io/lite/${ip}`);
    assert.equal((init?.headers as Record<string, string>).Authorization, 'Bearer test-token');
    return new Response(JSON.stringify({ ip, country_code: 'CN' }), { headers: { 'content-type': 'application/json' } });
  };
  const store: Store = { callerCountry: cache,
    async consume() { checks++; return true; },
    async get() { checks++; return null; },
    async put() { checks++; }
  };
  const first = await handle(event, store, secret, true, async () => { checks++; throw Error('DNS called'); }, 'test-token', lookup, true);
  assert.equal(first.statusCode, 403);
  assert.equal(JSON.parse(first.body).error.code, 'region_not_supported');
  assert.equal(lookups, 1); assert.equal(checks, 0);
  assert.equal(values.size, 1);
  assert.equal([...values.keys()][0]?.includes(ip), false);
  const second = await handle(event, store, secret, true, async () => { checks++; throw Error('DNS called'); }, 'test-token', lookup, true);
  assert.equal(second.statusCode, 403); assert.equal(lookups, 1); assert.equal(checks, 0);
});

test('country lookup is validated and fails closed without charging quota', async () => {
  const responses = [
    new Response('{}', { headers: { 'content-type': 'application/json' } }),
    new Response(JSON.stringify({ ip: '8.8.8.8', country_code: 'US' }), { headers: { 'content-type': 'application/json' } }),
    new Response('oops', { status: 503 })
  ];
  for (const response of responses) {
    let consumed = false;
    const store: Store = { async consume() { consumed = true; return true; }, async get() { return null; }, async put() {} };
    const result = await handle(event, store, secret, true, async () => { throw Error('DNS called'); }, 'test-token', async () => response, true);
    assert.equal(result.statusCode, 503); assert.equal(consumed, false);
  }
  const noToken = await handle(event, { async consume() { throw Error('quota called'); }, async get() { return null; }, async put() {} },
    secret, true, async () => { throw Error('DNS called'); }, '', async () => { throw Error('lookup called'); }, true);
  assert.equal(noToken.statusCode, 503);
});

test('an allowed country passes the gate and cached country avoids another IPinfo call', async () => {
  const budget = new Budget();
  const values = new Map<string, string>();
  const cache: CallerCountryCache = { async get(key) { return values.get(key) ?? null; }, async put(key, value) { values.set(key, value); } };
  let calls = 0;
  const lookup = async () => { calls++; return new Response(JSON.stringify({ ip, country_code: 'US' }), { headers: { 'content-type': 'application/json' } }); };
  try {
    await checkCallerCountry(ip, 'pseudonym', 'test-token', budget, lookup, cache);
    await checkCallerCountry(ip, 'pseudonym', 'test-token', budget, lookup, cache);
    assert.equal(calls, 1);
  } finally { budget.close(); }
});

test('every listed country code is denied from cached country evidence', async () => {
  const budget = new Budget();
  try {
    for (const country of BLOCKED_COUNTRIES) {
      await assert.rejects(
        checkCallerCountry(ip, 'pseudonym', 'test-token', budget,
          async () => { throw Error('lookup should be cached'); }, { async get() { return country; }, async put() {} }),
        { code: 'region_not_supported' }
      );
    }
  } finally { budget.close(); }
});
