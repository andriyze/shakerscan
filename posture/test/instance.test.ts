import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configureTargetPolicy, isPublicAddress } from '../src/safety.ts';
import { normalizeTarget } from '../src/target.ts';
import { handle, INSTANCE_POLICY, type Event } from '../src/checks/service.ts';
import { unlimitedStore } from '../src/checks/store.ts';
import { parseIpTarget } from '../src/checks/iptarget.ts';
import { RESOLVER } from '../src/dns.ts';
import { encodeQuery, TYPES } from '../src/wire.ts';
import { systemNameserver, systemResolverFetcher } from '../src/resolver.ts';
import { mockDns, packet, queryInfo, rr } from './helpers.ts';

const secret = 'test-only-secret-at-least-32-characters';
const event = (target: string): Event => ({ version: '2.0', rawPath: '/v1/check', rawQueryString: '', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ target }), requestContext: { http: { method: 'POST', sourceIp: '127.0.0.1' } } });

function withPolicy(policy: 'any' | 'public', run: () => Promise<void> | void) {
  return async () => { configureTargetPolicy(policy); try { await run(); } finally { configureTargetPolicy('public'); } };
}

test('the hosted policy refuses internal names and private addresses', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.10', 'fd00::1']) assert.equal(isPublicAddress(ip), false, ip);
  assert.throws(() => normalizeTarget('jira'));
  assert.throws(() => normalizeTarget('intranet.local'));
  assert.throws(() => parseIpTarget('10.0.0.5'));
});

test('an instance permits internal names and any connectable address', withPolicy('any', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.10', 'fd00::1', '8.8.8.8']) assert.equal(isPublicAddress(ip), true, ip);
  for (const ip of ['0.0.0.0', '224.0.0.1', '255.255.255.255', 'ff02::1', '::']) assert.equal(isPublicAddress(ip), false, ip);
  assert.equal(normalizeTarget('Jira'), 'jira');
  assert.equal(normalizeTarget('intranet.local'), 'intranet.local');
  assert.equal(parseIpTarget('10.0.0.5'), '10.0.0.5');
  // Ambiguous numeric spellings stay refused regardless of policy.
  assert.throws(() => normalizeTarget('0x7f.0.0.1'));
  assert.throws(() => normalizeTarget('2130706433'));
}));

test('an instance neither restricts government targets nor charges quota', withPolicy('any', async () => {
  let consumed = 0;
  const store = { ...unlimitedStore(), async consume() { consumed++; return true; } };
  const response = await handle(event('whitehouse.gov'), store, secret, true, mockDns({ A: [], AAAA: [] }), '', fetch, false, INSTANCE_POLICY);
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(response.body).target, 'whitehouse.gov');
  const internal = await handle(event('jira'), store, secret, true, mockDns({ A: [], AAAA: [] }), '', fetch, false, INSTANCE_POLICY);
  assert.equal(internal.statusCode, 200);
  assert.ok(consumed > 0); // the unlimited store admits every call
}));

test('resolv.conf nameserver selection', () => {
  const dir = mkdtempSync(join(tmpdir(), 'resolv-'));
  writeFileSync(join(dir, 'resolv.conf'), '# comment\nsearch lan\nnameserver not-an-ip\nnameserver 127.0.0.11\nnameserver 1.1.1.1\n');
  assert.equal(systemNameserver(join(dir, 'resolv.conf')), '127.0.0.11');
  assert.equal(systemNameserver(join(dir, 'missing.conf')), null);
});

test('the system resolver carries the same wire query over UDP', async () => {
  const server = dgram.createSocket('udp4');
  await new Promise<void>(resolve => server.bind(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  server.on('message', (message, remote) => {
    const q = queryInfo(new Uint8Array(message));
    server.send(Buffer.from(packet(q.host, q.type, q.id, [rr(TYPES.A, [10, 0, 0, 5], q.host)])), remote.port, remote.address);
  });
  try {
    const fetcher = systemResolverFetcher('127.0.0.1', fetch, port);
    const response = await fetcher(RESOLVER, { method: 'POST', body: encodeQuery('jira.corp', 'A', 4242), signal: AbortSignal.timeout(2000) });
    assert.equal(response.headers.get('content-type'), 'application/dns-message');
    const bytes = new Uint8Array(await response.arrayBuffer());
    assert.equal((bytes[0]! << 8) | bytes[1]!, 4242);
    assert.deepEqual([...bytes.subarray(bytes.length - 4)], [10, 0, 0, 5]);
  } finally { server.close(); }
});
