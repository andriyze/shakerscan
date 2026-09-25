import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../src/budget.ts';
import { httpsDnsFact, mailTransportFacts, securityTextFact } from '../src/checks/extra.ts';
import { name, packet, queryInfo, rr, soa } from './helpers.ts';
import { TYPES } from '../src/wire.ts';
import type { Fetcher } from '../src/types.ts';

const txt = (owner: string, value: string) => rr(TYPES.TXT, [Buffer.byteLength(value), ...Buffer.from(value)], owner);
test('MTA-STS and TLS-RPT report published facts without contacting MX hosts', async () => {
  const queries: string[] = [], getCalls: string[] = [];
  const fetcher: Fetcher = async (_url, init) => {
    const q = queryInfo(init.body); queries.push(`${q.host} ${q.type}`);
    const records = q.host === '_mta-sts.example.com' ? [txt(q.host, 'v=STSv1; id=20260923')] :
      q.host === '_smtp._tls.example.com' ? [txt(q.host, 'v=TLSRPTv1; rua=mailto:reports@example.com')] :
      q.host === 'mta-sts.example.com' ? [rr(TYPES.A, [8, 8, 8, 8], q.host)] : [];
    return new Response(packet(q.host, q.type, q.id, records, 0x81a0, records.length ? [] : [soa(q.host)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
  const getText = async (host: string, ip: string, path: string) => {
    getCalls.push(`${host} ${ip} ${path}`);
    return { status: 200, body: 'version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n' };
  };
  const budget = new Budget();
  try {
    const [mta, rpt] = await mailTransportFacts('example.com', true, budget, fetcher, getText);
    assert.deepEqual(mta.result, { record_count: 1, policy_status_code: 200, mode: 'enforce', max_age: 86400, mx_patterns: ['*.example.com'] });
    assert.deepEqual(rpt.result, { record_count: 1, rua_count: 1, destination_schemes: ['mailto'] });
    assert.deepEqual(getCalls, ['mta-sts.example.com 8.8.8.8 /.well-known/mta-sts.txt']);
    assert.equal(queries.some(query => query.includes('mx.example.com')), false);
  } finally { budget.close(); }
});

test('security.txt reports contact methods and expiry without exposing contact values', async () => {
  const budget = new Budget();
  try {
    const result = await securityTextFact('example.com', '8.8.8.8', budget, async (_host, _ip, path) => {
      assert.equal(path, '/.well-known/security.txt');
      return { status: 200, content_type: 'text/plain; charset=utf-8', body: 'Contact: mailto:secret@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt\n' };
    });
    assert.deepEqual(result.result, { status_code: 200, content_type: 'text/plain', charset: 'utf-8', contact_count: 1, contact_schemes: ['mailto'],
      canonical_count: 1, expires: '2027-01-01T00:00:00.000Z', format: 'basic_valid' });
    assert.equal(JSON.stringify(result).includes('secret@example.com'), false);
  } finally { budget.close(); }
});

test('security.txt with duplicate Expires or a non-UTF-8 charset is not reported as basically valid', async () => {
  const budget = new Budget();
  const body = 'Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n';
  try {
    const duplicate = await securityTextFact('example.com', '8.8.8.8', budget,
      async () => ({ status: 200, content_type: 'text/plain; charset=utf-8', body }));
    assert.equal(duplicate.result?.format, 'invalid');
    const charset = await securityTextFact('example.com', '8.8.8.8', budget,
      async () => ({ status: 200, content_type: 'text/plain; charset=iso-8859-1', body: body.split('\nExpires: 2028')[0]! }));
    assert.equal(charset.result?.format, 'invalid');
  } finally { budget.close(); }
});

test('security.txt distinguishes a 200 HTML fallback from a valid contact file', async () => {
  const budget = new Budget();
  try {
    const result = await securityTextFact('example.com', '8.8.8.8', budget,
      async () => ({ status: 200, content_type: 'text/html; charset=utf-8', body: '<!doctype html><html></html>' }));
    assert.deepEqual(result.result, { status_code: 200, content_type: 'text/html', charset: 'utf-8', format: 'html_fallback' });
  } finally { budget.close(); }
});

test('HTTPS DNS observation exposes advertised ALPN and ECH presence', async () => {
  const fetcher: Fetcher = async (_url, init) => {
    const q = queryInfo(init.body);
    const data = [0, 1, ...name(''), 0, 1, 0, 3, 2, 104, 50, 0, 5, 0, 1, 1];
    return new Response(packet(q.host, q.type, q.id, [rr(TYPES.HTTPS, data, q.host)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
  const budget = new Budget();
  try {
    const result = await httpsDnsFact('example.com', budget, fetcher);
    assert.deepEqual(result.result, { count: 1, records: [{ priority: 1, target: '.', ttl: 60, parameters: ['alpn=h2', 'ech=present'] }] });
  } finally { budget.close(); }
});
