import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../src/budget.ts';
import { query } from '../src/dns.ts';
import { caaPolicy } from '../src/checks/caa.ts';
import { dmarcPolicy } from '../src/checks/dmarc.ts';
import { mxTargets } from '../src/checks/mx.ts';
import { spfTree } from '../src/checks/spf.ts';
import { dnssecPublishedKeys } from '../src/checks/dnssec.ts';
import type { Check } from '../src/types.ts';
import { nameserverHealth } from '../src/checks/nameservers.ts';
import { name, packet, queryInfo, rr, soa } from './helpers.ts';
import { TYPES, encodeQuery } from '../src/wire.ts';
import type { Fetcher } from '../src/types.ts';

function dns(records: Record<string, number[][]>, queried: string[]): Fetcher {
  return async (_url, init) => {
    const { host: questionHost, type, id } = queryInfo(init.body);
    const host = questionHost || '.';
    queried.push(`${type}:${host}`);
    const values = records[`${type}:${host}`] ?? [];
    return new Response(packet(host, type, id, values, 0x81a0, values.length ? [] : [soa(host === '.' ? '' : host)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
}

test('DNSSEC root DNSKEY question uses one root label and the DNSKEY type', () => {
  const packet = encodeQuery('.', 'DNSKEY', 42);
  assert.equal(packet.length, 28);
  assert.equal(packet[12], 0);
  assert.equal((packet[13]! << 8) | packet[14]!, TYPES.DNSKEY);
});

test('CAA policy walks parents and reports the actual record without exposing iodef mailboxes', async () => {
  const queried: string[] = [];
  const caa = (tag: string, value: string) => rr(TYPES.CAA, [0, tag.length, ...Buffer.from(tag), ...Buffer.from(value)], 'example.com');
  const fetcher = dns({ 'CAA:example.com': [caa('issue', 'letsencrypt.org'), caa('iodef', 'mailto:private@example.com')] }, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('app.example.com', 'CAA', budget, fetcher);
    const check = await caaPolicy('app.example.com', initial, budget, fetcher);
    assert.equal(check.evidence?.policy_domain, 'example.com');
    assert.deepEqual(check.evidence?.checked_names, ['app.example.com', 'example.com']);
    assert.deepEqual(check.evidence?.records, ['0 issue letsencrypt.org', '0 iodef [redacted]']);
    assert.equal(JSON.stringify(check).includes('private@example.com'), false);
    assert.deepEqual(queried, ['CAA:app.example.com', 'CAA:example.com']);
  } finally { budget.close(); }
});

test('CAA walk can observe a root policy rather than claiming the tree ended at the TLD', async () => {
  const queried: string[] = [];
  const record = rr(TYPES.CAA, [0, 5, ...Buffer.from('issue'), ...Buffer.from('ca.example')], '');
  const fetcher = dns({ 'CAA:.': [record] }, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('example.com', 'CAA', budget, fetcher);
    const check = await caaPolicy('example.com', initial, budget, fetcher);
    assert.equal(check.evidence?.policy_domain, '.');
    assert.deepEqual(check.evidence?.checked_names, ['example.com', 'com', '.']);
  } finally { budget.close(); }
});

test('DMARC discovers a parent policy and applies sp to an existing subdomain', async () => {
  const queried: string[] = [];
  const policy = 'v=DMARC1; p=quarantine; sp=reject; psd=n; rua=mailto:private@example.com';
  const fetcher = dns({ 'TXT:_dmarc.example.com': [rr(TYPES.TXT, [policy.length, ...Buffer.from(policy)], '_dmarc.example.com')] }, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('_dmarc.app.example.com', 'TXT', budget, fetcher);
    const check = await dmarcPolicy('app.example.com', initial, true, budget, fetcher);
    assert.equal(check.evidence?.policy_domain, 'example.com');
    assert.equal(check.evidence?.applied_policy, 'reject');
    assert.equal(check.evidence?.policy_tag, 'sp');
    assert.equal(check.evidence?.inherited, true);
    assert.equal(JSON.stringify(check).includes('private@example.com'), false);
    assert.deepEqual(queried, ['TXT:_dmarc.app.example.com', 'TXT:_dmarc.example.com']);
  } finally { budget.close(); }
});

test('MX target resolution reports each sampled host and its address outcome', async () => {
  const queried: string[] = [];
  const mx = (priority: number, target: string) => rr(TYPES.MX,
    [(priority >> 8) & 255, priority & 255, ...target.split('.').flatMap(label => [label.length, ...Buffer.from(label)]), 0], 'example.com');
  const fetcher = dns({
    'MX:example.com': [mx(10, 'mx1.example.com'), mx(20, 'mx2.example.com')],
    'A:mx1.example.com': [rr(TYPES.A, [8, 8, 8, 8], 'mx1.example.com')]
  }, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('example.com', 'MX', budget, fetcher);
    const check = await mxTargets('example.com', initial, budget, fetcher);
    assert.deepEqual(check.evidence?.targets, ['10 mx1.example.com', '20 mx2.example.com']);
    assert.deepEqual(check.evidence?.resolved_targets, ['mx1.example.com']);
    assert.deepEqual(check.evidence?.unresolved_targets, ['mx2.example.com']);
    assert.ok(queried.includes('AAAA:mx2.example.com'));
  } finally { budget.close(); }
});

test('absent MX reports the SMTP implicit address-record fallback without probing SMTP', async () => {
  const queried: string[] = [];
  const fetcher = dns({}, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('example.com', 'MX', budget, fetcher);
    const check = await mxTargets('example.com', initial, budget, fetcher);
    assert.equal(check.evidence?.implicit_mx_fallback_applies, true);
    assert.deepEqual(queried, ['MX:example.com']);
  } finally { budget.close(); }
});

test('SPF follows include references but keeps sender authorization unevaluated', async () => {
  const queried: string[] = [];
  const txt = (host: string, value: string) => rr(TYPES.TXT, [value.length, ...Buffer.from(value)], host);
  const fetcher = dns({
    'TXT:example.com': [txt('example.com', 'v=spf1 include:_spf.example.com -all')],
    'TXT:_spf.example.com': [txt('_spf.example.com', 'v=spf1 ip4:8.8.8.8 ~all')]
  }, queried);
  const budget = new Budget(8000, undefined, 10);
  try {
    const initial = await query('example.com', 'TXT', budget, fetcher);
    const check = await spfTree('example.com', initial, budget, fetcher);
    assert.deepEqual(check.evidence?.checked_domains, ['example.com', '_spf.example.com']);
    assert.equal(check.evidence?.expansion_complete, true);
    assert.equal(check.evidence?.recursive_evaluation, false);
    assert.deepEqual(queried, ['TXT:example.com', 'TXT:_spf.example.com']);
  } finally { budget.close(); }
});

test('name-server probe distinguishes authoritative SOA answers from parent delegation', async () => {
  const queried: string[] = [];
  const ns = (owner: string, target: string) => rr(TYPES.NS, name(target), owner);
  const fetcher = dns({
    'NS:example.com': [ns('example.com', 'ns1.example.net'), ns('example.com', 'ns2.example.net')],
    'NS:com': [ns('com', 'a.gtld-servers.net')],
    'A:ns1.example.net': [rr(TYPES.A, [8, 8, 8, 8], 'ns1.example.net')],
    'A:ns2.example.net': [rr(TYPES.A, [1, 1, 1, 1], 'ns2.example.net')],
    'A:a.gtld-servers.net': [rr(TYPES.A, [9, 9, 9, 9], 'a.gtld-servers.net')]
  }, queried);
  const budget = new Budget(8000, undefined, 20);
  const exchange = async (ip: string, request: Uint8Array) => {
    const { host, type, id } = queryInfo(request);
    assert.equal(request[2]! & 1, 0);
    if (ip === '9.9.9.9') return packet(host, type, id, [], 0x8000,
      [ns('example.com', 'ns1.example.net'), ns('example.com', 'ns2.example.net')]);
    return packet(host, type, id, [soa(host)], 0x8400);
  };
  try {
    const initial = await query('example.com', 'NS', budget, fetcher);
    const check = await nameserverHealth('example.com', initial, budget, fetcher, exchange);
    assert.deepEqual(check.evidence?.responding_names, ['ns1.example.net', 'ns2.example.net']);
    assert.deepEqual(check.evidence?.sampled_names, ['ns1.example.net', 'ns2.example.net']);
    assert.deepEqual(check.evidence?.untested_names, []);
    assert.deepEqual(check.evidence?.parent_sampled_names, ['a.gtld-servers.net']);
    assert.deepEqual(check.evidence?.delegation_names, ['ns1.example.net', 'ns2.example.net']);
    assert.equal(check.evidence?.delegation_matches, true);
  } finally { budget.close(); }
});

test('name-server coverage names the untested servers', async () => {
  const queried: string[] = [];
  const ns = (owner: string, target: string) => rr(TYPES.NS, name(target), owner);
  const fetcher = dns({ 'NS:example.com': ['ns1', 'ns2', 'ns3', 'ns4'].map(part => ns('example.com', `${part}.example.net`)) }, queried);
  const budget = new Budget(8000, undefined, 20);
  try {
    const initial = await query('example.com', 'NS', budget, fetcher);
    const check = await nameserverHealth('example.com', initial, budget, fetcher, async () => { throw Error('unreachable'); });
    assert.deepEqual(check.evidence?.sampled_names, ['ns1.example.net', 'ns2.example.net']);
    assert.deepEqual(check.evidence?.untested_names, ['ns3.example.net', 'ns4.example.net']);
    assert.deepEqual(check.evidence?.unresponsive_names, ['ns1.example.net', 'ns2.example.net']);
  } finally { budget.close(); }
});

const txtRecord = (host: string, value: string) => rr(TYPES.TXT, [value.length, ...Buffer.from(value)], host);
async function spfFor(records: Record<string, string>) {
  const queried: string[] = [];
  const fetcher = dns(Object.fromEntries(Object.entries(records).map(([host, value]) => [`TXT:${host}`, [txtRecord(host, value)]])), queried);
  const budget = new Budget(8000, undefined, 20);
  try { return await spfTree('example.com', await query('example.com', 'TXT', budget, fetcher), budget, fetcher); }
  finally { budget.close(); }
}

test('SPF terminal policy qualifiers decide the status', async () => {
  for (const [record, status] of [['v=spf1 ip4:8.8.8.8 +all', 'warn'], ['v=spf1 all', 'warn'], ['v=spf1 ip4:8.8.8.8 ?all', 'warn'],
    ['v=spf1 ip4:8.8.8.8', 'warn'], ['v=spf1 -all ~all', 'warn'], ['v=spf1 ip4:8.8.8.8 -all', 'pass'], ['v=spf1 ip4:8.8.8.8 ~all', 'pass']] as const) {
    const check = await spfFor({ 'example.com': record });
    assert.equal(check.status, status, record);
  }
  assert.match((await spfFor({ 'example.com': 'v=spf1 +all' })).detail, /permits all senders/);
});

test('SPF counts a shared include each time and reports only real loops', async () => {
  const shared = await spfFor({
    'example.com': 'v=spf1 include:a.example.net include:b.example.net -all',
    'a.example.net': 'v=spf1 include:c.example.net -all',
    'b.example.net': 'v=spf1 include:c.example.net -all',
    'c.example.net': 'v=spf1 a mx -all'
  });
  assert.deepEqual(shared.evidence?.cycles, []);
  assert.equal(shared.status, 'pass');
  // 2 (root) + 1 (a) + 1 (b) + 2 (c via a) + 2 (c via b)
  assert.equal(shared.evidence?.referenced_lookup_terms, 8);
  assert.deepEqual(shared.evidence?.checked_domains, ['example.com', 'a.example.net', 'c.example.net', 'b.example.net']);
  const loop = await spfFor({
    'example.com': 'v=spf1 include:a.example.net -all',
    'a.example.net': 'v=spf1 include:example.com -all'
  });
  assert.deepEqual(loop.evidence?.cycles, ['example.com']);
  assert.equal(loop.status, 'warn');
});

test('DMARC stops discovery at a name with multiple or malformed records', async () => {
  const parent = 'v=DMARC1; p=reject';
  for (const direct of [['v=DMARC1; p=none', 'v=DMARC1; p=reject'], ['v=DMARC1; p=bogus']]) {
    const queried: string[] = [];
    const fetcher = dns({
      'TXT:_dmarc.app.example.com': direct.map(value => txtRecord('_dmarc.app.example.com', value)),
      'TXT:_dmarc.example.com': [txtRecord('_dmarc.example.com', parent)]
    }, queried);
    const budget = new Budget(8000, undefined, 10);
    try {
      const check = await dmarcPolicy('app.example.com', await query('_dmarc.app.example.com', 'TXT', budget, fetcher), true, budget, fetcher);
      assert.equal(check.status, 'warn');
      assert.equal(check.evidence?.record_count, direct.length);
      assert.deepEqual(queried, ['TXT:_dmarc.app.example.com']);
    } finally { budget.close(); }
  }
});

test('DMARC tag values are compared case-insensitively', async () => {
  const fetcher = dns({ 'TXT:_dmarc.example.com': [txtRecord('_dmarc.example.com', 'v=DMARC1; P=Reject; ADKIM=S')] }, []);
  const budget = new Budget(8000, undefined, 10);
  try {
    const check = await dmarcPolicy('example.com', await query('_dmarc.example.com', 'TXT', budget, fetcher), true, budget, fetcher);
    assert.equal(check.status, 'pass');
    assert.equal(check.evidence?.applied_policy, 'reject');
    assert.equal(check.evidence?.dkim_alignment, 's');
  } finally { budget.close(); }
});

test('MX accepts many resolvable hosts but warns when null MX is mixed with real targets', async () => {
  const mx = (priority: number, target: string) => rr(TYPES.MX,
    [(priority >> 8) & 255, priority & 255, ...(target ? target.split('.').flatMap(label => [label.length, ...Buffer.from(label)]) : []), 0], 'example.com');
  const hosts = ['mx1', 'mx2', 'mx3', 'mx4', 'mx5'].map(label => `${label}.example.com`);
  const many = dns({ 'MX:example.com': hosts.map((host, i) => mx(i + 1, host)),
    ...Object.fromEntries(hosts.map(host => [`A:${host}`, [rr(TYPES.A, [8, 8, 8, 8], host)]])) }, []);
  const mixed = dns({ 'MX:example.com': [mx(0, ''), mx(10, 'mx1.example.com')], 'A:mx1.example.com': [rr(TYPES.A, [8, 8, 8, 8], 'mx1.example.com')] }, []);
  const budget = new Budget(8000, undefined, 20);
  try {
    assert.equal((await mxTargets('example.com', await query('example.com', 'MX', budget, many), budget, many)).status, 'pass');
    const check = await mxTargets('example.com', await query('example.com', 'MX', budget, mixed), budget, mixed);
    assert.equal(check.status, 'warn');
    assert.equal(check.evidence?.null_mx, false);
  } finally { budget.close(); }
});

test('an empty parent DS answer settles an unavailable validation as an unsigned zone', async () => {
  const fetcher = dns({}, []);
  const budget = new Budget(8000, undefined, 10);
  try {
    const check: Check = { id: 'dns.dnssec', name: 'DNSSEC', group: 'dns', status: 'unknown', detail: 'Local DNSSEC validation of the A RRset was unavailable.',
      evidence: { validated_queries: [], local_validation: 'unavailable', validation_reason: 'validator_unavailable', validation_queries: 6 } };
    await dnssecPublishedKeys(check, 'example.com', budget, fetcher);
    assert.equal(check.evidence?.local_validation, 'insecure');
    assert.equal(check.evidence?.validation_reason, undefined);
    assert.equal(check.evidence?.parent_ds_count, 0);
    assert.match(check.detail, /not DNSSEC-signed/);
    const deadline: Check = { ...check, detail: 'Local DNSSEC validation of the A RRset was unavailable.',
      evidence: { validated_queries: [], local_validation: 'unavailable', validation_reason: 'deadline', validation_queries: 6 } };
    await dnssecPublishedKeys(deadline, 'example.com', budget, fetcher);
    assert.equal(deadline.evidence?.local_validation, 'unavailable');
  } finally { budget.close(); }
});
