// Property-based fuzzing of the checks that interpret DNS records and HTTP bodies a target
// controls: SPF and DMARC walks, CAA, MTA-STS, TLS-RPT, security.txt and HTTPS records.
// Walks must stay bounded and every result must remain valid cacheable evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { Budget } from '../src/budget.ts';
import { caaPolicy } from '../src/checks/caa.ts';
import { dmarcPolicy } from '../src/checks/dmarc.ts';
import { httpsDnsFact, mailTransportFacts, securityTextFact } from '../src/checks/extra.ts';
import { spfTree } from '../src/checks/spf.ts';
import { query } from '../src/dns.ts';
import type { Fetcher } from '../src/types.ts';
import { TYPES } from '../src/wire.ts';
import { cacheAccepts, name, packet, queryInfo, rr, runs, soa } from './helpers.ts';

type Zone = Map<string, number[][] | 'servfail'>;
/** Serves records keyed by "TYPE name" and records every question asked. */
function zoneFetcher(zone: Zone, asked: string[]): Fetcher {
  return async (_url, init) => {
    const q = queryInfo(init.body), host = q.host || '.';
    asked.push(`${q.type} ${host}`);
    const entry = zone.get(`${q.type} ${host}`) ?? [];
    const records = entry === 'servfail' ? [] : entry;
    return new Response(packet(host, q.type, q.id, records, entry === 'servfail' ? 0x8182 : 0x8180, records.length ? [] : [soa(host === '.' ? '' : host)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
}
const txtData = (value: string) => {
  const bytes = [...Buffer.from(value, 'latin1')], data: number[] = [];
  for (let i = 0; i === 0 || i < bytes.length; i += 255) data.push(Math.min(255, bytes.length - i), ...bytes.slice(i, i + 255));
  return data;
};
const txtZone = (entries: Record<string, string[] | 'servfail'>): Zone =>
  new Map(Object.entries(entries).map(([owner, values]) => [`TXT ${owner}`, values === 'servfail' ? values : values.map(v => rr(TYPES.TXT, txtData(v), owner))]));
const latin1 = (maxLength: number) => fc.uint8Array({ maxLength }).map(b => Buffer.from(b).toString('latin1'));
async function withBudget<T>(run: (budget: Budget) => Promise<T>): Promise<T> {
  const budget = new Budget(8000, undefined, 200);
  try { return await run(budget); } finally { budget.close(); }
}
const hostLabels = fc.array(fc.constantFrom('a', 'b', 'mail', 'co', 'uk', 'example', 'x-1'), { minLength: 2, maxLength: 10 });
const suffixes = (labels: string[]) => labels.map((_, i) => labels.slice(i).join('.'));

const DOMAINS = ['example.com', 'a.example.com', 'b.example.net', 'c.example.org', 'd.example.com', 'e.example.net', 'f.example.org', 'g.example.com'];
const reference = fc.oneof({ weight: 6, arbitrary: fc.constantFrom(...DOMAINS) }, fc.integer({ min: 0, max: 30 }).map(i => `n${i}.example.net`),
  fc.constantFrom('A.EXAMPLE.COM', 'x.local', 'localhost', '..', 'a', '-x.example.com', `${'x'.repeat(70)}.com`, '%{d}.example.com', 'example.com.'));
const spfTerm = fc.oneof(reference.map(d => `include:${d}`), reference.map(d => `redirect=${d}`), reference.map(d => `-include:${d}`),
  fc.constantFrom('a', 'mx', 'ptr', 'a:x.example.com', 'mx/24', 'exists:%{i}.x.example.com', 'ip4:192.0.2.1', 'ip6:2001:db8::1', '-all', '~all', '?all', '+all', 'all', 'exp=x.example.com', 'garbage'));
const spfRecord = fc.tuple(fc.constantFrom('v=spf1', 'v=spf1', 'V=SPF1', 'v=spf10', 'v=spf1 '), fc.array(spfTerm, { maxLength: 14 }), fc.constantFrom(' ', ' ', '  ', '\t'))
  .map(([version, terms, separator]) => [version, ...terms].join(separator));
// Mostly one record per name, so that walks go deep; SERVFAIL, none and several stay common.
const entry = <T>(record: fc.Arbitrary<T>, other: fc.Arbitrary<T>) => fc.oneof({ weight: 1, arbitrary: fc.constant('servfail' as const) },
  { weight: 5, arbitrary: fc.array(record, { minLength: 1, maxLength: 1 }) }, { weight: 2, arbitrary: fc.array(fc.oneof(record, other), { maxLength: 2 }) });
const spfEntry = entry(spfRecord, latin1(30));

test('fuzz: SPF include trees stay within their evaluation bounds and fetch each name once', async () => {
  const zone = fc.tuple(fc.record(Object.fromEntries(DOMAINS.map(d => [d, spfEntry]))), fc.dictionary(fc.integer({ min: 0, max: 30 }).map(i => `n${i}.example.net`), spfEntry, { maxKeys: 6 }));
  await fc.assert(fc.asyncProperty(zone, ([named, extra]) => withBudget(async budget => {
    const asked: string[] = [], fetcher = zoneFetcher(txtZone({ ...named, ...extra }), asked);
    const initial = await query('example.com', 'TXT', budget, fetcher);
    asked.length = 0;
    const check = await spfTree('example.com', initial, budget, fetcher);
    const evidence = check.evidence ?? {};
    assert.equal(new Set(asked).size, asked.length, asked.join());
    assert.ok(asked.length <= 100); // at most ten evaluations, each prefetching at most ten names
    if (check.status === 'pass') assert.ok(evidence.expansion_complete === true && (evidence.cycles as string[]).length === 0 && evidence.missing_or_multiple_records === 0);
    assert.ok(cacheAccepts(check), JSON.stringify(evidence));
  })), { numRuns: runs(1000) });
});

const dmarcTag = fc.oneof(
  fc.constantFrom('p=none', 'p=quarantine', 'p=reject', 'p=REJECT', 'p=bogus', 'sp=reject', 'sp=x', 'np=quarantine', 'psd=y', 'psd=n', 'psd=q', 't=y', 't=n',
    'adkim=s', 'aspf=r', 'adkim=x', 'pct=50', 'fo=1', 'P=none', '=x', 'p', ''),
  // Past 128 report URIs on purpose: the cache bound was once 128, so a record listing more
  // could never be cached.
  fc.integer({ min: 0, max: 400 }).map(n => `rua=${Array.from({ length: n }, () => 'mailto:a@e.x').join(',')}`),
  fc.integer({ min: 0, max: 400 }).map(n => `ruf=${',mailto:f@e.x'.repeat(n)}`));
const validTags = fc.uniqueArray(fc.constantFrom('sp=reject', 'sp=none', 'np=quarantine', 'psd=y', 'psd=n', 't=y', 't=n', 'adkim=s', 'aspf=r', 'pct=50', 'fo=1',
  'rua=mailto:a@e.x', 'ruf=mailto:f@e.x,mailto:g@e.x'), { selector: tag => tag.split('=')[0], maxLength: 4 });
const dmarcRecord = fc.oneof(
  fc.tuple(fc.constantFrom('none', 'quarantine', 'reject', 'REJECT'), validTags, fc.constantFrom(';', '; ', ' ;')).map(([p, tags, separator]) => ['v=DMARC1', `p=${p}`, ...tags].join(separator)),
  fc.tuple(fc.constantFrom('v=DMARC1', 'v=DMARC1 ', 'v=dmarc1', 'v=DMARC2'), fc.array(dmarcTag, { maxLength: 6 }), fc.constantFrom(';', '; ', ' ;'))
    .map(([version, tags, separator]) => [version, ...tags].join(separator)));
const dmarcEntry = fc.oneof({ weight: 3, arbitrary: fc.constant<string[]>([]) }, { weight: 2, arbitrary: entry(dmarcRecord, latin1(20)) });

test('fuzz: the DMARC policy walk stays on the target\'s ancestors and reports a coherent policy', async () => {
  const scenario = hostLabels.chain(labels => fc.record({ labels: fc.constant(labels), exists: fc.boolean(),
    entries: fc.tuple(...suffixes(labels).map(() => dmarcEntry)) }));
  await fc.assert(fc.asyncProperty(scenario, ({ labels, exists, entries }) => withBudget(async budget => {
    const host = labels.join('.'), names = suffixes(labels);
    const asked: string[] = [], fetcher = zoneFetcher(txtZone(Object.fromEntries(names.map((n, i) => [`_dmarc.${n}`, entries[i]!]))), asked);
    const initial = await query(`_dmarc.${host}`, 'TXT', budget, fetcher);
    asked.length = 0;
    const check = await dmarcPolicy(host, initial, exists, budget, fetcher);
    const evidence = check.evidence!, checked = evidence.checked_names as string[];
    assert.ok(checked[0] === host && checked.length <= 8 && checked.every(n => names.includes(n)), checked.join());
    assert.ok(new Set(asked).size === asked.length && asked.length <= 7, asked.join());
    if (check.status === 'pass') assert.ok(['quarantine', 'reject'].includes(String(evidence.applied_policy)) && evidence.test_mode !== 'y');
    if (evidence.policy_domain !== undefined) assert.ok(checked.includes(String(evidence.policy_domain)));
    assert.ok(cacheAccepts(check, host), JSON.stringify(evidence));
  })), { numRuns: runs(1000) });
});

const caaRecord = fc.record({ flags: fc.integer({ min: 0, max: 255 }),
  tag: fc.oneof({ weight: 3, arbitrary: fc.constantFrom('issue', 'issuewild', 'iodef', 'IODEF', 'tbs') }, latin1(16)),
  value: fc.oneof(fc.stringMatching(/^[\x20-\x7e]{0,40}$/), latin1(40), fc.stringMatching(/^[\x20-\x7e]{1,4}$/).map(s => s.repeat(150))) });

test('fuzz: CAA discovery climbs to the root at most eight names and redacts iodef', async () => {
  const scenario = hostLabels.chain(labels => fc.record({ labels: fc.constant(labels),
    entries: fc.tuple(...[...suffixes(labels), '.'].map(() => fc.oneof(fc.constant('servfail' as const), fc.array(caaRecord, { maxLength: 3 })))) }));
  await fc.assert(fc.asyncProperty(scenario, ({ labels, entries }) => withBudget(async budget => {
    const host = labels.join('.'), names = [...suffixes(labels), '.'];
    const zone: Zone = new Map(names.map((owner, i) => {
      const set = entries[i]!;
      return [`CAA ${owner}`, set === 'servfail' ? set : set.map(r => rr(TYPES.CAA, [r.flags, r.tag.length, ...Buffer.from(r.tag, 'latin1'), ...Buffer.from(r.value, 'latin1')], owner === '.' ? '' : owner))];
    }));
    const asked: string[] = [], fetcher = zoneFetcher(zone, asked);
    const initial = await query(host, 'CAA', budget, fetcher);
    asked.length = 0;
    const check = await caaPolicy(host, initial, budget, fetcher);
    const evidence = check.evidence ?? {}, checked = evidence.checked_names as string[];
    assert.ok(checked[0] === host && checked.length <= 8 && checked.every(n => names.includes(n)), checked.join());
    assert.ok(new Set(asked).size === asked.length && asked.length <= 7, asked.join());
    for (const shown of (evidence.records ?? []) as string[]) {
      assert.ok(shown.length <= 580);
      if (shown.split(' ')[1] === 'iodef') assert.ok(shown.endsWith(' [redacted]'), shown);
    }
    assert.ok(cacheAccepts(check, host), JSON.stringify(evidence));
  })), { numRuns: runs(1000) });
});

const contentType = fc.option(fc.oneof(
  fc.constantFrom('text/plain', 'text/plain; charset=utf-8', 'TEXT/PLAIN;charset="UTF-8"', 'text/html', 'text/plain; charset=iso-8859-1', 'application/octet-stream'),
  latin1(128)), { nil: undefined });
const bodyLine = fc.oneof(
  fc.constantFrom('Contact: mailto:security@example.com', 'Contact: https://example.com/report', 'contact: tel:+1-201-555-0123', 'Contact: ftp://x',
    'Expires: 2099-01-01T00:00:00Z', 'Expires: 2000-01-01T00:00:00Z', 'Expires: soon', 'Expires: 275760-09-13T00:00:00Z', 'Canonical: https://example.com/.well-known/security.txt',
    '<!doctype html>', '<html>', 'version: STSv1', 'mode: enforce', 'mode: testing', 'mode: bogus', 'mx: mail.example.com', 'mx: *.example.net',
    'mx: bad host!', 'max_age: 604800', 'max_age: 99999999999999999999', 'max_age: -1', ''),
  latin1(40));
const body = fc.array(bodyLine, { maxLength: 24 }).chain(lines => fc.constantFrom(lines.join('\n'), lines.join('\r\n')));
const response = fc.record({ status: fc.oneof(fc.constantFrom(200, 200, 404, 410, 500), fc.integer({ min: 100, max: 599 })), body, content_type: contentType });

test('regression found by fuzzing security.txt: control characters in Content-Type', async () => {
  for (const contentType of ['text/plain\u0085', 'text/plain; charset=\u0085x', 'text/\u0000plain']) {
    const fact = await withBudget(budget => securityTextFact('example.com', '93.184.216.34', budget, async () => ({ status: 200, body: '', content_type: contentType })));
    assert.ok(cacheAccepts(fact), contentType);
  }
});

test('fuzz: security.txt facts from any response are bounded and cacheable', async () => {
  await fc.assert(fc.asyncProperty(response, reply => withBudget(async budget => {
    const fact = await securityTextFact('example.com', '93.184.216.34', budget, async () => reply);
    const result = fact.result as Record<string, unknown> | null;
    if (result) {
      assert.ok(['basic_valid', 'invalid', 'html_fallback', 'absent', 'http_error'].includes(String(result.format)));
      assert.ok(((result.contact_schemes ?? []) as string[]).every(s => ['mailto', 'https', 'tel'].includes(s)));
    }
    assert.ok(cacheAccepts(fact), JSON.stringify(result));
  })), { numRuns: runs(2000) });
});

test('fuzz: MTA-STS and TLS-RPT facts are bounded and cacheable, and a policy is fetched only from a public address', async () => {
  const rpt = fc.oneof(fc.constantFrom('v=TLSRPTv1; rua=mailto:r@example.com', 'v=TLSRPTv1;rua=https://r.example.com,mailto:a@b', 'v=TLSRPTv1', 'v=TLSRPTv2; rua=x'),
    fc.integer({ min: 0, max: 200 }).map(n => `v=TLSRPTv1; rua=${',mailto:a@e.x'.repeat(n)}`), latin1(30));
  const sts = fc.oneof(fc.constantFrom('v=STSv1; id=20240101', 'v=STSv1', 'v=STSv1;', 'V=stsv1; id=x', 'v=STSv2'), latin1(30));
  const scenario = fc.record({ sts: fc.oneof(fc.constant('servfail' as const), fc.array(sts, { maxLength: 2 })), rpt: fc.oneof(fc.constant('servfail' as const), fc.array(rpt, { maxLength: 2 })),
    address: fc.constantFrom<number[]>([93, 184, 216, 34], [10, 0, 0, 1], [127, 0, 0, 1]), reply: response });
  await fc.assert(fc.asyncProperty(scenario, s => withBudget(async budget => {
    const zone = txtZone({ '_mta-sts.example.com': s.sts, '_smtp._tls.example.com': s.rpt });
    zone.set('A mta-sts.example.com', [rr(TYPES.A, s.address, 'mta-sts.example.com')]);
    let fetched = 0;
    const [mta, tls] = await mailTransportFacts('example.com', true, budget, zoneFetcher(zone, []), async (_host, ip) => { fetched++; assert.equal(ip, '93.184.216.34'); return s.reply; });
    assert.ok(fetched <= 1);
    const policy = mta.result as Record<string, unknown> | null;
    if (policy?.mode !== undefined) assert.ok(['enforce', 'testing', 'none'].includes(String(policy.mode)));
    if (policy?.mx_patterns !== undefined) assert.ok((policy.mx_patterns as string[]).length <= 16);
    assert.ok(cacheAccepts(mta), JSON.stringify(mta.result));
    assert.ok(cacheAccepts(tls), JSON.stringify(tls.result));
  })), { numRuns: runs(1000) });
});

test('fuzz: HTTPS record facts from any RDATA are bounded and cacheable', async () => {
  const param = fc.tuple(fc.integer({ min: 0, max: 8 }), fc.uint8Array({ maxLength: 12 })).map(([key, value]) => [key >> 8, key & 255, value.length >> 8, value.length & 255, ...value]);
  const https = fc.record({ priority: fc.integer({ min: 0, max: 65535 }), target: fc.constantFrom('', 'svc.example.com', 'example.com'),
    params: fc.array(param, { maxLength: 4 }), tail: fc.uint8Array({ maxLength: 4 }) });
  await fc.assert(fc.asyncProperty(fc.array(https, { maxLength: 12 }), records => withBudget(async budget => {
    const zone: Zone = new Map([['HTTPS example.com', records.map(r => rr(TYPES.HTTPS, [r.priority >> 8, r.priority & 255, ...name(r.target), ...r.params.flat(), ...r.tail]))]]);
    const fact = await httpsDnsFact('example.com', budget, zoneFetcher(zone, []));
    const result = fact.result as { count: number; records: unknown[] } | null;
    if (result) assert.ok(result.count <= 8 && result.records.length === result.count);
    assert.ok(cacheAccepts(fact), JSON.stringify(result));
  })), { numRuns: runs(1000) });
});
