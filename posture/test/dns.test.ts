import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../src/budget.ts';
import { answers, query, resolve, RESOLVER } from '../src/dns.ts';
import { decodeAnswer, encodeQuery, TYPES } from '../src/wire.ts';
import { mockDns, packet, rr, name, soa, queryInfo } from './helpers.ts';

const expected = { host: 'example.com', type: 'A' as const, id: 12 };
test('DNS codec checks transaction, question, flags and record framing', () => {
  const data = packet('example.com', 'A', 12, [rr(1, [1, 1, 1, 1])]);
  assert.equal(decodeAnswer(data, expected).records[0]!.value, '1.1.1.1');
  for (const mutate of [(b: Uint8Array) => b[1] = 3, (b: Uint8Array) => b[2] = 0x83, (b: Uint8Array) => b[4] = 2, (b: Uint8Array) => b[7] = 129]) {
    const copy = data.slice(); mutate(copy); assert.throws(() => decodeAnswer(copy, expected));
  }
  assert.throws(() => decodeAnswer(data.slice(0, -1), expected));
  assert.throws(() => decodeAnswer(new Uint8Array([...data, 1]), expected));
  assert.throws(() => decodeAnswer(data, { ...expected, host: 'other.com' }));
});
test('DNS codec rejects compression loops and forward pointers', () => {
  const data = packet('example.com', 'A', 12);
  data[12] = 0xc0; data[13] = 12;
  assert.throws(() => decodeAnswer(data, expected));
  data[13] = 20; assert.throws(() => decodeAnswer(data, expected));
});
test('record limits, TXT segments and malformed RDATA are bounded', () => {
  assert.throws(() => decodeAnswer(packet('example.com', 'A', 12, [rr(1, [1, 2, 3])]), expected));
  assert.throws(() => decodeAnswer(packet('example.com', 'A', 12, [rr(16, [255, 1])]), expected));
  const txt = decodeAnswer(packet('example.com', 'A', 12, [rr(16, [3, 97, 98, 99, 2, 100, 101])]), expected);
  assert.equal(txt.records[0]!.value, 'abcde');
  assert.throws(() => encodeQuery('x'.repeat(254), 'A', 12));
});
test('alias loops and incomplete aliases are not truncated into successful data', () => {
  for (const records of [[rr(5, name('example.com'))], [rr(5, name('other.com'))]]) {
    assert.throws(() => answers(decodeAnswer(packet('example.com', 'A', 12, records), expected), 'example.com', 1));
  }
  const complete = decodeAnswer(packet('example.com', 'A', 12, [rr(5, name('other.com')), rr(1, [1, 1, 1, 1], 'other.com')]), expected);
  assert.equal(answers(complete, 'example.com', 1)[0]!.value, '1.1.1.1');
});
test('only seven POST calls to fixed DoH endpoint; no caller credentials; max concurrency three', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const budget = new Budget(); let active = 0, max = 0;
  const dns = mockDns({}, calls);
  try {
    await resolve('example.com', budget, async (url, init) => {
      active++; max = Math.max(max, active); await new Promise(r => setTimeout(r, 5));
      try { return await dns(url, init); } finally { active--; }
    });
    assert.equal(calls.length, 7); assert.equal(budget.operations, 7); assert.equal(max, 3);
    for (const { url, init } of calls) {
      assert.equal(url, RESOLVER); assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'manual');
      assert.equal(new Headers(init.headers).has('Authorization'), false);
      assert.equal(new Headers(init.headers).has('Cookie'), false);
    }
  } finally { budget.close(); }
});
test('mixed public/private address data and private additional records are unsafe', async () => {
  for (const values of [[rr(1, [1, 1, 1, 1]), rr(1, [127, 0, 0, 1])], [rr(1, [10, 0, 0, 1], 'other.com')]]) {
    const budget = new Budget();
    try { await assert.rejects(resolve('example.com', budget, mockDns({ A: values })), { code: 'target_not_allowed' }); }
    finally { budget.close(); }
  }
});
test('resolver redirects, SERVFAIL and oversized responses never cause follow-up fetch', async () => {
  for (const response of [new Response(null, { status: 302, headers: { Location: 'http://127.0.0.1/' } }), new Response(new Uint8Array(32769), { headers: { 'Content-Type': 'application/dns-message' } })]) {
    const budget = new Budget(); let calls = 0;
    try { assert.equal((await query('example.com', 'A', budget, async () => { calls++; return response; })).state, 'unavailable'); assert.equal(calls, 1); }
    finally { budget.close(); }
  }
});
test('deadline aborts hung fetch and refuses new operations', async () => {
  const budget = new Budget(15); let signal: AbortSignal | undefined;
  try {
    const result = await query('example.com', 'A', budget, async (_url, init) => { signal = init.signal!; return new Promise(() => {}); });
    assert.equal(result.state, 'timeout'); assert.equal(signal?.aborted, true); assert.throws(() => budget.reserve());
  } finally { budget.close(); }
});
test('SERVFAIL in either address family prevents a success; NXDOMAIN remains distinct', async () => {
  const budget = new Budget();
  try {
    await assert.rejects(resolve('example.com', budget, async (_url, init) => {
      const q = queryInfo(init.body);
      return new Response(packet(q.host, q.type, q.id, [], q.type === 'AAAA' ? 0x8182 : 0x8180, [soa(q.host)]), { headers: { 'Content-Type': 'application/dns-message' } });
    }), { code: 'dns_unavailable' });
  } finally { budget.close(); }
  const negative = new Budget();
  try {
    const result = await resolve('example.com', negative, async (_url, init) => {
      const q = queryInfo(init.body);
      return new Response(packet(q.host, q.type, q.id, [], 0x81a3, [soa(q.host)]), { headers: { 'Content-Type': 'application/dns-message' } });
    });
    assert.equal(result.A.state === 'ok' && result.A.rcode, 3);
  } finally { negative.close(); }
});
test('inconsistent A/AAAA aliases are rejected, not reused as connection authorization', async () => {
  const budget = new Budget();
  try { await assert.rejects(resolve('example.com', budget, mockDns({ A: [rr(5, name('alias.example.com')), rr(1, [1, 1, 1, 1], 'alias.example.com')] })), { code: 'dns_unavailable' }); }
  finally { budget.close(); }
});
test('packet mutations are bounded and never escape the decoder', () => {
  const base = packet('example.com', 'A', 12, [rr(1, [1, 1, 1, 1])]);
  for (let i = 0; i < base.length; i++) {
    for (const byte of [0, 63, 128, 192, 255]) {
      const changed = base.slice(); changed[i] = byte;
      try { const decoded = decodeAnswer(changed, expected); assert.ok(decoded.records.length <= 128); }
      catch (error) { assert.ok(error instanceof Error); }
    }
  }
});
