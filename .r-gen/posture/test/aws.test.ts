import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pinnedOptions, pinnedHead, webChecks, selectAddressSamples, httpsResponseStatus, redirectChain } from '../src/checks/probe.ts';
import { handle, type Event } from '../src/checks/service.ts';
import { Budget } from '../src/budget.ts';
import { observation } from '../src/check.ts';
import { resolve } from '../src/dns.ts';
import { mockDns, name, rr } from './helpers.ts';
import { packet, queryInfo, soa } from './helpers.ts';
import { generateKeyPairSync } from 'node:crypto';
import { isObservation } from '../src/cache.ts';
import { CORS_PROBE_ORIGIN, corsCheck, headerCheck } from '../src/checks/policy.ts';
import { parseCheckRequest } from '../src/request.ts';
import { dkimCheck } from '../src/checks/dkim.ts';
import { transientResult, type Store } from '../src/checks/store.ts';
import type { Observation } from '../src/types.ts';
const secret = 'test-only-secret-at-least-32-characters';
function event(body = '{"target":"example.com"}'): Event {
  return { version: '2.0', rawPath: '/v1/check', rawQueryString: '', headers: { 'content-type': 'application/json', authorization: 'SECRET', cookie: 'SECRET', 'cf-connecting-ip': '8.8.8.8' }, body, requestContext: { http: { method: 'POST', sourceIp: '198.51.100.5' } } };
}
function memory() {
  const counts = new Map<string, number>(), cache = new Map<string, Observation>();
  const store: Store = {
    async consume(key, limit) { const n = counts.get(key) ?? 0; if (n >= limit) return false; counts.set(key, n + 1); return true; },
    async get(host) { return cache.get(host) ?? null; },
    async put(data) { cache.set(data.target, data); }
  };
  return { counts, cache, store };
}
test('AWS transport pins an approved address while preserving SNI, Host and certificate verification', async () => {
  const options = pinnedOptions('example.com', '93.184.216.34', true);
  assert.equal(options.hostname, 'example.com'); assert.equal(options.servername, 'example.com');
  assert.equal(options.rejectUnauthorized, true); assert.equal(options.agent, false);
  assert.equal(options.method, 'HEAD'); assert.equal(options.path, '/'); assert.equal(options.port, 443);
  const result = await new Promise(resolve => (options.lookup as Function)('rebound.invalid', {}, (...args: unknown[]) => resolve(args)));
  assert.deepEqual(result, [null, '93.184.216.34', 4]);
  assert.equal(JSON.stringify(options).includes('SECRET'), false);
  for (const ip of ['127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', '::ffff:127.0.0.1', '2001:db8::1']) assert.throws(() => pinnedOptions('example.com', ip, true));
  assert.throws(() => pinnedOptions('example.com:443', '8.8.8.8', true));
  assert.equal(pinnedOptions('example.com', '8.8.8.8', true, 'cors', '/api').method, 'GET');
  assert.equal(pinnedOptions('example.com', '8.8.8.8', true, 'preflight', '/api').method, 'OPTIONS');
  assert.equal(pinnedOptions('example.com', '8.8.8.8', true, 'tls13').minVersion, 'TLSv1.3');
  assert.equal(pinnedOptions('example.com', '8.8.8.8', true, 'tls13').maxVersion, 'TLSv1.3');
});
test('v2 accepts a bounded CORS path while v1 rejects it', () => {
  assert.equal(parseCheckRequest('{"target":"example.com","path":"/api/v1"}', true, true).path, '/api/v1');
  for (const path of ['//metadata', '/../private', '/a/./b', '/query?x=1', '/%2fprivate']) {
    assert.throws(() => parseCheckRequest(JSON.stringify({ target: 'example.com', path }), true, true));
  }
  assert.throws(() => parseCheckRequest('{"target":"example.com","path":"/api"}'));
});
test('mixed addresses and exhausted deadline never open a socket', async () => {
  const b = new Budget();
  try { assert.ok((await webChecks('example.com', ['8.8.8.8', '127.0.0.1'], b)).every(c => c.status === 'unknown')); assert.equal(b.operations, 0); }
  finally { b.close(); }
  await assert.rejects(pinnedHead('example.com', '8.8.8.8', true, b));
});
test('AWS samples up to two IPv4 addresses and reports 5xx as reviewable', async () => {
  assert.deepEqual(selectAddressSamples(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']), ['8.8.8.8', '1.1.1.1']);
  assert.deepEqual(selectAddressSamples(['8.8.8.8', '2606:4700:4700::1111']), ['8.8.8.8', undefined]);
  assert.deepEqual(selectAddressSamples(['2606:4700:4700::1111']), [undefined, undefined]);
  const budget = new Budget();
  try {
    const checks = await webChecks('example.com', ['2606:4700:4700::1111'], budget);
    assert.equal(checks.find(c => c.id === 'http.response')?.status, 'unknown');
    assert.match(checks.find(c => c.id === 'http.response')!.detail, /no IPv6 egress/);
    assert.equal(budget.operations, 0);
  } finally { budget.close(); }
  assert.equal(httpsResponseStatus([200, 503]), 'warn');
  assert.equal(httpsResponseStatus([200, 404]), 'pass');
  assert.equal(httpsResponseStatus([]), 'unknown');
});
test('redirect chain follows only bounded same-host locations on the pinned address', async () => {
  const calls: string[] = [], budget = new Budget();
  const response = (status: number, location?: string) => ({ status, headers: new Map(location ? [['location', location]] : []) });
  const probe = async (_host: string, ip: string, secure: boolean, _budget: Budget, _kind: string, path: string) => {
    calls.push(`${ip} ${secure ? 'https' : 'http'} ${path}`);
    return path === '/next' ? response(302, 'final') : response(200);
  };
  try {
    const chain = await redirectChain('example.com', '8.8.8.8', response(301, 'https://example.com/next'), budget, probe as typeof pinnedHead);
    assert.deepEqual(chain.chain, ['301 same_host_https', '302 same_host_https', '200 none']);
    assert.deepEqual(calls, ['8.8.8.8 https /next', '8.8.8.8 https /final']);
    assert.equal(chain.complete, true);
    calls.length = 0;
    const refused = await redirectChain('example.com', '8.8.8.8', response(302, 'http://evil.example.org/'), budget, probe as typeof pinnedHead);
    assert.equal(refused.complete, false);
    assert.deepEqual(calls, []);
  } finally { budget.close(); }
});
test('AWS routing, JSON limits and secret non-reflection', async () => {
  const cases: [Partial<Event>, number][] = [
    [{ rawPath: '/health', requestContext: { http: { method: 'GET', sourceIp: '' } } }, 200],
    [{ rawPath: '/nope' }, 404], [{ rawPath: '/v2/check' }, 404], [{ rawQueryString: 'a=b' }, 400],
    [{ requestContext: { http: { method: 'GET', sourceIp: '198.51.100.5' } } }, 405],
    [{ body: 'x'.repeat(2049) }, 413],
    [{ body: Buffer.from('x'.repeat(2049)).toString('base64'), isBase64Encoded: true }, 413],
    [{ headers: { 'content-type': 'text/plain' } }, 415],
    [{ body: '{"target":"127.0.0.1"}' }, 403],
    [{ body: '{"target":"example.com","secret":"SECRET"}' }, 400],
    [{ body: '{"target":"example.com","target":"example.org"}' }, 400]
  ];
  for (const [override, status] of cases) {
    const r = await handle({ ...event(), ...override }, memory().store, secret, true, mockDns());
    assert.equal(r.statusCode, status); assert.equal(r.body.includes('SECRET'), false);
    assert.equal(r.headers['x-content-type-options'], 'nosniff'); assert.equal(r.headers['access-control-allow-origin'], undefined);
  }
});
test('AWS cache hits consume no hourly or daily quota but count toward the per-minute caller limit', async () => {
  const m = memory(), b = new Budget();
  const data = observation('example.com', await resolve('example.com', b, mockDns())); b.close();
  m.cache.set('example.com', data);
  const responses = await Promise.all(Array.from({ length: 30 }, () => handle(event(), m.store, secret, true)));
  assert.ok(responses.every(r => r.statusCode === 200 && JSON.parse(r.body).cache.hit));
  assert.deepEqual([...m.counts.keys()].filter(k => !k.startsWith('min:')), []);
  const limited = await handle(event(), m.store, secret, true);
  assert.equal(limited.statusCode, 429); assert.equal(JSON.parse(limited.body).error.code, 'rate_limited');
  assert.ok(Number(limited.headers['retry-after']) >= 1 && Number(limited.headers['retry-after']) <= 60);
});
test('AWS v2 returns only measured facts and reuses its cache entry', async () => {
  const m = memory();
  const first = await handle(event(), m.store, secret, true, mockDns({ A: [], AAAA: [] }));
  assert.equal(first.statusCode, 200);
  assert.equal(isObservation(m.cache.get('example.com'), 'example.com'), true);
  const withCertificate = structuredClone(m.cache.get('example.com')!);
  withCertificate.v2_extras![5]!.result = { connections: [{ ip: '8.8.8.8', certificate: { san_names: ['example.com'] } }] };
  assert.equal(isObservation(withCertificate, 'example.com'), true);
  const second = await handle(event(), m.store, secret, true);
  assert.equal(second.statusCode, 200);
  const body = JSON.parse(second.body);
  assert.equal(body.schema_version, '2');
  assert.equal(body.cache.hit, true);
  assert.equal(body.observations.length, 20);
  assert.deepEqual(body.observations.slice(14).map((item: { id: string }) => item.id),
    ['ip.network', 'mail.mta_sts', 'mail.tls_rpt', 'http.security_txt', 'dns.https', 'http.connections']);
  assert.equal(body.observations[0].result.a_count, 0);
  assert.equal(body.observations[7].result, null);
  assert.equal(Object.hasOwn(body, 'summary'), false);
  assert.equal(Object.hasOwn(body.observations[0], 'status'), false);
  assert.equal(Object.hasOwn(body.observations[0], 'detail'), false);
  assert.equal([...m.counts.keys()].filter(k => k.startsWith('day:')).length, 1);
});
test('AWS permits 25 uncached attempts per UTC hour and ignores spoofed IP headers', async () => {
  const m = memory(), fetcher = mockDns({ A: [rr(1, [8, 8, 8, 8]), rr(1, [10, 0, 0, 1])] });
  for (let i = 0; i < 25; i++) {
    const r = await handle({ ...event(), headers: { ...event().headers, 'cf-connecting-ip': `8.8.8.${i}`, 'x-forwarded-for': `8.8.4.${i}` } }, m.store, secret, true, fetcher);
    assert.equal(r.statusCode, 403);
  }
  let fetched = false;
  const rejected = await handle({ ...event(), headers: { ...event().headers, 'cf-connecting-ip': '1.1.1.1' } }, m.store, secret, true, async () => { fetched = true; throw Error(); });
  assert.equal(rejected.statusCode, 429);
  assert.equal(JSON.parse(rejected.body).error.code, 'hourly_quota_exceeded');
  assert.ok(Number(rejected.headers['retry-after']) >= 1 && Number(rejected.headers['retry-after']) <= 3600);
  assert.equal(fetched, false);
  assert.equal([...m.counts.keys()].filter(k => k.startsWith('hour:')).length, 1);
  assert.equal([...m.counts].find(([key]) => key.startsWith('day:'))?.[1], 25);
});
test('AWS daily quota fails closed before DNS and disabled checks retain health', async () => {
  let fetched = false;
  const store = memory().store;
  store.consume = async key => !key.startsWith('day:');
  const r = await handle(event(), store, secret, true, async () => { fetched = true; throw Error(); });
  assert.equal(r.statusCode, 429); assert.equal(JSON.parse(r.body).error.code, 'daily_quota_exceeded'); assert.equal(fetched, false);
  assert.equal((await handle(event(), store, secret, false)).statusCode, 503);
  assert.equal((await handle({ ...event(), rawPath: '/health', requestContext: { http: { method: 'GET', sourceIp: '' } } }, store, '', false)).statusCode, 200);
});
test('AWS mixed DNS answer is refused before HTTP; quota counts admitted failed attempts', async () => {
  const m = memory();
  const r = await handle(event(), m.store, secret, true, mockDns({ A: [rr(1, [8, 8, 8, 8]), rr(1, [10, 0, 0, 1])] }));
  assert.equal(r.statusCode, 403);
  assert.equal([...m.counts.keys()].filter(k => k.startsWith('day:')).length, 1);
});
test('AWS accepts a bounded DKIM selector, validates its DNS key and keeps selector-specific cache data', async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const record = `v=DKIM1; k=rsa; p=${Buffer.from(publicKey.export({ format: 'der', type: 'pkcs1' })).toString('base64')}`;
  const owner = 'mail._domainkey.example.com';
  const bytes = Buffer.from(record);
  const segments: number[] = [];
  for (let at = 0; at < bytes.length; at += 200) { const part = bytes.subarray(at, at + 200); segments.push(part.length, ...part); }
  const basic = mockDns({ A: [], AAAA: [] });
  const calls: string[] = [];
  const fetcher = async (url: string, init: RequestInit) => {
    const q = queryInfo(init.body); calls.push(q.host);
    if (q.host !== owner) return basic(url, init);
    return new Response(packet(q.host, q.type, q.id, [rr(16, segments, owner)]), { headers: { 'Content-Type': 'application/dns-message' } });
  };
  const m = memory(); const selectors: (string | undefined)[] = []; let stored: Observation | undefined;
  m.store.put = async (data, selector) => { selectors.push(selector); stored = data; };
  const r = await handle(event('{"dkim_selector":"MAIL","target":"example.com"}'), m.store, secret, true, fetcher);
  assert.equal(r.statusCode, 200);
  const data = JSON.parse(r.body);
  assert.equal(data.observations.length, 20);
  assert.equal(data.observations[7].id, 'mail.dkim');
  assert.equal(data.observations[7].result.key_bits, 2048);
  assert.equal(data.observations[7].result.selector, 'mail');
  assert.equal(calls.filter(x => x === owner).length, 1);
  assert.deepEqual(selectors, ['mail']);
  assert.equal(isObservation(stored, 'example.com'), true);
  assert.equal(stored!.checks[7]!.evidence?.selector, 'mail');
  assert.equal((await handle(event('{"target":"example.com","dkim_selector":"bad.selector"}'), memory().store, secret, true, fetcher)).statusCode, 400);
});
test('AWS header and CORS checks report values and fixed-origin behavior', () => {
  const head = { status: 200, headers: new Map([
    ['strict-transport-security', 'max-age=0'], ['content-security-policy', "script-src 'unsafe-inline' 'unsafe-eval'"],
    ['x-content-type-options', 'none'], ['referrer-policy', 'unsafe-url'], ['permissions-policy', 'geolocation=()'],
    ['access-control-allow-origin', CORS_PROBE_ORIGIN], ['access-control-allow-credentials', 'true']
  ]) };
  const headers = headerCheck(head), cors = corsCheck(head);
  assert.equal(headers.status, 'warn');
  assert.deepEqual(headers.evidence?.issues, ['disabled:hsts', 'weak:csp-unsafe-eval', 'weak:csp-unsafe-inline', 'invalid:x-content-type-options', 'weak:referrer-policy']);
  assert.equal(cors.status, 'warn');
  assert.equal(cors.evidence?.allow_origin, 'probe_origin');
  assert.equal(cors.evidence?.allow_origin_value, CORS_PROBE_ORIGIN);
  const absent = corsCheck({ status: 200, headers: new Map() });
  assert.equal(absent.status, 'pass');
  assert.equal(absent.evidence?.allow_origin, 'none');
  const empty = corsCheck({ status: 200, headers: new Map([['access-control-allow-origin', ''], ['access-control-allow-credentials', 'true']]) });
  assert.equal(empty.evidence?.allow_origin, 'empty');
  assert.equal(empty.evidence?.allow_origin_value, undefined);
  assert.equal(empty.status, 'pass');
});
test('AWS DKIM resolves a CNAME to a valid SPKI RSA key', async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const record = `v=DKIM1; k=rsa; p=${Buffer.from(publicKey.export({ format: 'der', type: 'spki' })).toString('base64')}`;
  const owner = 's1._domainkey.example.com', alias = 's1.keys.example.net';
  const bytes = Buffer.from(record), segments: number[] = [];
  for (let at = 0; at < bytes.length; at += 200) { const part = bytes.subarray(at, at + 200); segments.push(part.length, ...part); }
  const budget = new Budget();
  try {
    const check = await dkimCheck('example.com', 's1', budget, async (_url, init) => {
      const q = queryInfo(init.body);
      return new Response(packet(q.host, q.type, q.id, [rr(5, name(alias), owner), rr(16, segments, alias)]), { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal(check.status, 'pass');
    assert.equal(check.evidence?.key_bits, 2048);
  } finally { budget.close(); }
});
test('AWS caches unavailable or incomplete evidence only briefly', async () => {
  const b = new Budget();
  const data = observation('example.com', await resolve('example.com', b, mockDns())); b.close();
  const settled = structuredClone(data);
  settled.checks.push({ id: 'http.response', name: 'HTTPS response', group: 'http', status: 'pass', detail: 'ok' });
  settled.checks[5]!.detail = 'SPF include/redirect records were retrieved; sender authorization was not evaluated.';
  assert.equal(transientResult(settled), false);
  for (const detail of ['NS discovery was incomplete.', 'SPF include/redirect expansion was incomplete.', 'MX DNS evidence was unavailable.',
    'SPF DNS evidence was unavailable.', 'Local DNSSEC validation of the A RRset was unavailable.']) {
    const degraded = structuredClone(settled);
    degraded.checks[1]!.detail = detail;
    assert.equal(transientResult(degraded), true, detail);
  }
});

test('v1 serves the factual format and the former v2 route no longer exists', async () => {
  const m = memory();
  const r = await handle(event('{"target":"example.com","path":"/api"}'), m.store, secret, true, mockDns({ A: [], AAAA: [] }));
  assert.equal(r.statusCode, 200);
  const body = JSON.parse(r.body);
  assert.equal(body.schema_version, '2');
  assert.equal(body.observations.length, 20);
  assert.equal(Object.hasOwn(body, 'checks'), false);
  const gone = await handle({ ...event(), rawPath: '/v2/check' }, m.store, secret, true, async () => { throw Error('DNS called'); });
  assert.equal(gone.statusCode, 404);
});
