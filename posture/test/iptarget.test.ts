import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ipObservation, parseIpTarget, restrictedNetwork, reverseDns, reverseName } from '../src/checks/iptarget.ts';
import { pinnedOptions } from '../src/checks/probe.ts';
import { handle, type Event } from '../src/checks/service.ts';
import { redirectKind } from '../src/http.ts';
import { isObservation } from '../src/cache.ts';
import { factualResponse } from '../src/checks/factual.ts';
import { Budget } from '../src/budget.ts';
import { PublicError } from '../src/response.ts';
import { packet, queryInfo, rr } from './helpers.ts';
import { TYPES } from '../src/wire.ts';
import type { Store } from '../src/checks/store.ts';
import type { Check } from '../src/types.ts';

const secret = 'test-only-secret-at-least-32-characters';
const refused = (value: string) => assert.throws(() => parseIpTarget(value), (e: unknown) => e instanceof PublicError && e.code === 'target_not_allowed', value);

test('only canonical public IP literals become IP targets', () => {
  assert.equal(parseIpTarget('37.19.200.164'), '37.19.200.164');
  assert.equal(parseIpTarget(' 8.8.8.8 '), '8.8.8.8');
  assert.equal(parseIpTarget('[2606:4700:4700::1111]'), '2606:4700:4700::1111');
  assert.equal(parseIpTarget('2606:4700:4700:0:0:0:0:1111'), '2606:4700:4700::1111');
  assert.equal(parseIpTarget('2606:4700:4700::1111'.toUpperCase()), '2606:4700:4700::1111');
  for (const value of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '192.168.1.1', '0.0.0.0', '255.255.255.255', '198.51.100.5',
    '::1', 'fe80::1', 'fc00::1', '::ffff:8.8.8.8', '::ffff:127.0.0.1', '64:ff9b::808:808', '2002:808:808::1', '2001:db8::1', 'fe80::1%eth0', '[::1]', '2606:4700::1111:zz']) refused(value);
  // Legacy numeric spellings are not IP targets; hostname validation rejects them.
  for (const value of ['0x7f.0.0.1', '2130706433', '127.1', '010.8.8.8', '08.8.8.8', '8.8.8.8.', 'example.com', '1.2.3']) assert.equal(parseIpTarget(value), null, value);
});

test('reverse names and government network screening', () => {
  assert.equal(reverseName('37.19.200.164'), '164.200.19.37.in-addr.arpa');
  assert.equal(reverseName('2606:4700:4700::1111'), '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa');
  const cf = { ip: '1.1.1.1', asn: 'AS13335', as_domain: 'cloudflare.com', as_name: 'Cloudflare, Inc.' };
  assert.equal(restrictedNetwork({ ip: '8.8.4.4', asn: 'AS721', as_domain: 'nic.mil', as_name: 'DoD Network Information Center' }, []), true);
  assert.equal(restrictedNetwork({ ip: '8.8.4.4', asn: 'AS1', as_domain: 'example.net', as_name: 'Department of Defense' }, []), true);
  assert.equal(restrictedNetwork({ ip: '8.8.4.4', asn: 'AS1', as_domain: 'gov.uk', as_name: 'UK Government' }, []), true);
  assert.equal(restrictedNetwork(cf, ['web.agency.gov']), true);
  // IANA-registered DoD/MoD blocks and unrouted space without an owner are refused.
  for (const ip of ['6.6.6.6', '11.1.1.1', '25.0.0.1', '214.3.1.1']) assert.equal(restrictedNetwork({ ...cf, ip }, null), true, ip);
  assert.equal(restrictedNetwork({ ip: '5.5.5.5', country_code: 'DE' }, null), true);
  assert.equal(restrictedNetwork(cf, ['one.one.one.one']), false);
  assert.equal(restrictedNetwork({ ip: '37.19.200.164', asn: 'AS212238', as_domain: 'datacamp.co.uk', as_name: 'Datacamp Limited' }, null), false);
});

test('IP-target probes pin the literal, send no SNI and keep redirects on the same address', () => {
  const options = pinnedOptions('8.8.8.8', '8.8.8.8', true);
  assert.equal(options.hostname, '8.8.8.8');
  assert.equal(options.servername, undefined);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal((options.headers as Record<string, string>).Host, '8.8.8.8');
  assert.throws(() => pinnedOptions('8.8.8.8', '1.1.1.1', true));
  assert.throws(() => pinnedOptions('10.0.0.1', '10.0.0.1', true));
  assert.equal(redirectKind('https://8.8.8.8/login', '8.8.8.8', false), 'same_host_https');
  assert.equal(redirectKind('/login', '8.8.8.8', true), 'same_host_https');
  assert.equal(redirectKind('https://1.1.1.1/', '8.8.8.8', false), 'refused');
  assert.equal(redirectKind('https://example.com/', '8.8.8.8', false), 'refused');
  assert.equal(pinnedOptions('example.com', '8.8.8.8', true).servername, 'example.com');
});

test('reverse DNS reads PTR names for the address', async () => {
  const owner = '8.8.8.8.in-addr.arpa';
  const target = 'dns.google';
  const fetcher = async (_url: string, init: RequestInit) => {
    const q = queryInfo(init.body);
    assert.equal(q.host, owner); assert.equal(q.type, 'PTR');
    return new Response(packet(q.host, q.type, q.id, [rr(TYPES.PTR, target.split('.').flatMap(l => [l.length, ...Buffer.from(l)]).concat(0), owner)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
  const budget = new Budget();
  try { assert.deepEqual(await reverseDns('8.8.8.8', budget, fetcher), ['dns.google']); } finally { budget.close(); }
});

test('an IP observation keeps the cached schema and marks DNS and mail checks not applicable', async () => {
  const budget = new Budget();
  try {
    const web = async (host: string, addresses: string[], _b: Budget, path = '/') => {
      assert.equal(host, '8.8.8.8'); assert.deepEqual(addresses, ['8.8.8.8']); assert.equal(path, '/api');
      return ['http.response', 'tls.handshake', 'tls.ciphers', 'http.headers', 'http.cors', 'http.redirect']
        .map(id => ({ id, name: id, group: id.split('.')[0] as Check['group'], status: 'unknown' as const, detail: 'stub', ...(id === 'http.cors' ? { evidence: { path } } : {}) }));
    };
    const contact = async () => ({ id: 'http.security_txt', name: 'Security contact', group: 'http' as const, scope: 'stub', result: null });
    const data = await ipObservation('8.8.8.8', { addresses: [{ ip: '8.8.8.8', asn: 'AS15169' }], reverse_dns: ['dns.google'] }, budget, '/api', web, contact);
    assert.equal(isObservation(data, '8.8.8.8'), true);
    const body = factualResponse(data, false, 'id');
    assert.equal(body.observations.length, 20);
    assert.equal(body.observations[1]!.result, null);
    assert.deepEqual(body.observations[0]!.result, { a_count: 1, aaaa_count: 0 });
    assert.equal(body.observations[0]!.scope, 'The IP address target itself; no DNS lookup is made');
    for (const item of body.observations.slice(1, 8)) assert.equal(item.scope, 'Not applicable to an IP address target', item.id);
    assert.match(String(body.observations[8]!.scope), /HTTPS HEAD/);
    assert.deepEqual((body.observations[14]!.result as Record<string, unknown>).reverse_dns, ['dns.google']);
  } finally { budget.close(); }
});

function ipEvent(target: string, extra = ''): Event {
  return { version: '2.0', rawPath: '/v1/check', rawQueryString: '', headers: { 'content-type': 'application/json' },
    body: `{"target":"${target}"${extra}}`, requestContext: { http: { method: 'POST', sourceIp: '198.51.100.5' } } };
}
function memory() {
  const counts = new Map<string, number>();
  const store: Store = { async consume(key, limit) { const n = counts.get(key) ?? 0; if (n >= limit) return false; counts.set(key, n + 1); return true; },
    async get() { return null; }, async put() {} };
  return { counts, store };
}
const noPtr = async (_url: string, init: RequestInit) => {
  const q = queryInfo(init.body);
  return new Response(packet(q.host, q.type, q.id, [], 0x8183), { headers: { 'Content-Type': 'application/dns-message' } });
};

test('government networks are refused before quota and before any connection', async () => {
  const m = memory();
  const ipinfo = async () => Response.json({ '9.9.9.8': { ip: '9.9.9.8', asn: 'AS721', as_name: 'DoD Network Information Center', as_domain: 'nic.mil', country_code: 'US' } });
  const r = await handle(ipEvent('9.9.9.8'), m.store, secret, true, noPtr, 'test-token', ipinfo);
  assert.equal(r.statusCode, 403);
  assert.equal(JSON.parse(r.body).error.code, 'target_restricted');
  assert.deepEqual([...m.counts.keys()].filter(k => !k.startsWith('min:')), []);
});

test('IP targets fail closed without network ownership evidence and refuse unsafe forms', async () => {
  const m = memory();
  const unavailable = await handle(ipEvent('8.8.8.8'), m.store, secret, true, noPtr, 'test-token', async () => new Response('down', { status: 503 }));
  assert.equal(unavailable.statusCode, 503);
  assert.deepEqual([...m.counts.keys()].filter(k => !k.startsWith('min:')), []);
  for (const target of ['127.0.0.1', '169.254.169.254', '0x7f.0.0.1', '2130706433', '::ffff:127.0.0.1', '[::1]']) {
    const r = await handle(ipEvent(target), memory().store, secret, true, async () => { throw Error('DNS called'); });
    assert.equal(r.statusCode, 403, target);
  }
  const selector = await handle(ipEvent('8.8.8.8', ',"dkim_selector":"mail"'), memory().store, secret, true, noPtr);
  assert.equal(selector.statusCode, 400);
});
